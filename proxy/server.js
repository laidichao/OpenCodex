// server.js —— openCodeProxy：OpenCodex 设备反连中继 + 设备看板
//
// 架构（方案 B）：
//   - PC 端 OpenCodex 内嵌反连客户端，主动出站 WSS 连到本进程 /openCodeProxy，把本机
//     gateway 的整个 HTTP+WS 能力反推上来。PC 侧零入站端口、零穿透客户端、零公网暴露。
//   - 浏览器访问 https://<vps>/ 看到设备看板；进入 /d/<deviceId>/ 即该设备的 Codex Desktop UI。
//   - 设备 UI 的 HTML 使用根绝对路径引用资源（/official-patched-v8/...、/codex-web-config.js）
//     与运行时 API（/api/*、/backend-api/*），因此除看板自身固定路由外，所有根路径请求都按
//     「设备 cookie（ocx_device）」反代到对应设备——这是设备页能完整加载的关键。
//   - 设备（PC）侧鉴权：每设备一密 secret，/openCodeProxy 升级后 register 帧校验（密钥值匹配 + re-bind）。
//   - 浏览器侧鉴权：账号密码登录（默认 admin/admin，首次登录强制改密）+ HttpOnly 会话 cookie。
//     账号数据以 AES-256-GCM 加密存 JSON（auth.json），主密钥独立存放（.auth.key）。
//
// 持久化：
//   - devices.json：设备（deviceId / secret / name）。首次启动从 DEVICE_SECRETS 环境变量导入。
//   - auth.json：加密后的账号数据。首次启动自动创建 admin/admin（mustChange=true）。

const http = require("http");
const https = require("https");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { WebSocketServer } = require("ws");

const PORT = Number(process.env.RELAY_PORT || 8443);
const HOST = process.env.RELAY_HOST || "0.0.0.0";
const TLS_KEY = process.env.TLS_KEY || "";
const TLS_CERT = process.env.TLS_CERT || "";
const DEVICES_FILE = process.env.RELAY_DEVICES_FILE || path.join(__dirname, "devices.json");
const AUTH_FILE = process.env.RELAY_AUTH_FILE || path.join(__dirname, "auth.json");
const AUTH_KEY_FILE = process.env.RELAY_AUTH_KEY_FILE || path.join(__dirname, ".auth.key");
const PROXY_ENDPOINT = "/openCodeProxy";

const SESSION_TTL_MS = 12 * 60 * 60 * 1000; // 12h，滑动续期
const SESSION_COOKIE = "ocx_session";
const DEVICE_COOKIE = "ocx_device";
const DEVICE_COOKIE_TTL_S = 7 * 24 * 60 * 60; // 7 天

function parseEnvSecrets() {
  const raw = process.env.DEVICE_SECRETS || process.env.AGENT_SECRETS || "";
  const out = new Map();
  for (const pair of raw.split(",")) {
    const idx = pair.indexOf("=");
    if (idx <= 0) continue;
    const id = pair.slice(0, idx).trim();
    const secret = pair.slice(idx + 1).trim();
    if (id && secret) out.set(id, secret);
  }
  return out;
}

function sanitizeDeviceId(name) {
  const base = String(name || "")
    .toLowerCase()
    .replace(/[^a-z0-9_-]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 40);
  return base || `device-${crypto.randomBytes(2).toString("hex")}`;
}

// ---------- devices.json：设备与密钥持久化 ----------
function saveDevices(registry) {
  const obj = {};
  for (const [id, info] of registry) obj[id] = { secret: info.secret, name: info.name || id };
  try {
    fs.writeFileSync(DEVICES_FILE, JSON.stringify(obj, null, 2));
  } catch (error) {
    console.error("[proxy] save devices.json failed:", error.message);
  }
}

function loadDevices() {
  const registry = new Map();
  try {
    const obj = JSON.parse(fs.readFileSync(DEVICES_FILE, "utf8"));
    for (const [id, info] of Object.entries(obj)) {
      if (!id || !info || !info.secret) continue;
      registry.set(String(id), { secret: String(info.secret), name: String(info.name || id) });
    }
  } catch {}
  if (registry.size === 0) {
    for (const [id, secret] of parseEnvSecrets()) registry.set(id, { secret, name: id });
    if (registry.size) saveDevices(registry);
  }
  return registry;
}

const DEVICE_REGISTRY = loadDevices();

// ---------- 账号存储：AES-256-GCM 加密 JSON + scrypt 口令哈希 ----------
function loadMasterKey() {
  try {
    const key = fs.readFileSync(AUTH_KEY_FILE, "utf8").trim();
    if (/^[0-9a-f]{64}$/i.test(key)) return Buffer.from(key, "hex");
  } catch {}
  const key = crypto.randomBytes(32);
  try {
    fs.writeFileSync(AUTH_KEY_FILE, key.toString("hex"), { mode: 0o600 });
  } catch (error) {
    console.error("[proxy] save auth key failed:", error.message);
  }
  return key;
}

const MASTER_KEY = loadMasterKey();

function hashPassword(password, salt) {
  return crypto.scryptSync(String(password), salt, 64, { N: 16384, r: 8, p: 1 }).toString("hex");
}

function verifyPassword(password, salt, expectedHash) {
  const actual = Buffer.from(hashPassword(password, salt), "hex");
  const expected = Buffer.from(expectedHash, "hex");
  return actual.length === expected.length && crypto.timingSafeEqual(actual, expected);
}

function encryptAuthPayload(obj) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", MASTER_KEY, iv);
  const data = Buffer.concat([cipher.update(JSON.stringify(obj), "utf8"), cipher.final()]);
  return { v: 1, iv: iv.toString("base64"), tag: cipher.getAuthTag().toString("base64"), data: data.toString("base64") };
}

function decryptAuthPayload(payload) {
  try {
    const decipher = crypto.createDecipheriv("aes-256-gcm", MASTER_KEY, Buffer.from(payload.iv, "base64"));
    decipher.setAuthTag(Buffer.from(payload.tag, "base64"));
    const data = Buffer.concat([decipher.update(Buffer.from(payload.data, "base64")), decipher.final()]);
    return JSON.parse(data.toString("utf8"));
  } catch (error) {
    console.error("[proxy] decrypt auth.json failed:", error.message);
    return null;
  }
}

function saveUsers(users) {
  try {
    fs.writeFileSync(AUTH_FILE, JSON.stringify(encryptAuthPayload({ users }), null, 2), { mode: 0o600 });
  } catch (error) {
    console.error("[proxy] save auth.json failed:", error.message);
  }
}

function loadUsers() {
  try {
    const payload = JSON.parse(fs.readFileSync(AUTH_FILE, "utf8"));
    const decrypted = decryptAuthPayload(payload);
    if (decrypted && Array.isArray(decrypted.users) && decrypted.users.length) return decrypted.users;
  } catch {}
  // 首次启动：默认账号 admin/admin，首次登录强制改密。
  const salt = crypto.randomBytes(16).toString("hex");
  const users = [
    { username: "admin", salt, hash: hashPassword("admin", salt), mustChange: true, createdAt: new Date().toISOString() },
  ];
  saveUsers(users);
  console.log("[proxy] created default account admin/admin (must change password on first login)");
  return users;
}

let USERS = loadUsers();

function findUser(username) {
  return USERS.find((u) => u.username === username) || null;
}

// ---------- 会话（内存态，重启后需重新登录） ----------
const sessions = new Map(); // token -> { username, expiresAt, mustChange }

const loginAttempts = new Map(); // ip -> { fails, lockedUntil }
const LOGIN_MAX_FAILS = 5;
const LOGIN_LOCK_MS = 10 * 60 * 1000; // 密码连续错 5 次 → 该 IP 冻结 10 分钟

// 返回 { allowed, retryAfterSec }：冻结期 denied 且带剩余秒数，供登录页显示倒计时。
function loginAllowed(ip) {
  const rec = loginAttempts.get(ip);
  if (!rec || !rec.lockedUntil || rec.lockedUntil <= Date.now()) return { allowed: true, retryAfterSec: 0 };
  return { allowed: false, retryAfterSec: Math.max(1, Math.ceil((rec.lockedUntil - Date.now()) / 1000)) };
}

function loginFailed(ip) {
  const rec = loginAttempts.get(ip) || { fails: 0, lockedUntil: 0 };
  rec.fails += 1;
  if (rec.fails >= LOGIN_MAX_FAILS) {
    rec.lockedUntil = Date.now() + LOGIN_LOCK_MS;
    rec.fails = 0;
  }
  loginAttempts.set(ip, rec);
}

function loginSucceeded(ip) {
  loginAttempts.delete(ip);
}

function createSession(user) {
  const token = crypto.randomBytes(32).toString("hex");
  sessions.set(token, { username: user.username, expiresAt: Date.now() + SESSION_TTL_MS, mustChange: !!user.mustChange });
  return token;
}

function destroySession(token) {
  if (token) sessions.delete(token);
}

function parseCookies(req) {
  const header = req.headers.cookie || "";
  const out = {};
  for (const part of header.split(";")) {
    const idx = part.indexOf("=");
    if (idx <= 0) continue;
    out[part.slice(0, idx).trim()] = decodeURIComponent(part.slice(idx + 1).trim());
  }
  return out;
}

function getSession(req) {
  const token = parseCookies(req)[SESSION_COOKIE];
  if (!token) return null;
  const session = sessions.get(token);
  if (!session) return null;
  if (session.expiresAt < Date.now()) {
    sessions.delete(token);
    return null;
  }
  session.expiresAt = Date.now() + SESSION_TTL_MS; // 滑动续期
  return { token, ...session };
}

function sessionCookie(token) {
  return `${SESSION_COOKIE}=${token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${Math.floor(SESSION_TTL_MS / 1000)}`;
}

const CLEAR_SESSION_COOKIE = `${SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0`;

// ---------- 设备路径解析 ----------
// /d/<deviceId>/... -> { deviceId, rest }
function parseDevicePath(urlPath) {
  const m = urlPath.match(/^\/d\/([^/]+)(\/.*)?$/);
  if (!m) return null;
  return { deviceId: decodeURIComponent(m[1]), rest: m[2] || "/" };
}

// ---------- 设备在线表 ----------
const devices = new Map(); // deviceId -> { socket, name, online, lastSeen, streams }
const genId = () => crypto.randomBytes(10).toString("hex");

function deviceOnline(id) {
  const dev = devices.get(id);
  return !!(dev && dev.online && dev.socket && dev.socket.readyState === 1);
}

// 根路径资源归属设备：优先设备 cookie；否则当恰好只有一台在线设备时用它。
function resolveProxyDevice(req) {
  const cookieDevice = parseCookies(req)[DEVICE_COOKIE];
  if (cookieDevice && deviceOnline(cookieDevice)) return devices.get(cookieDevice);
  const online = [...devices.values()].filter((d) => d.online && d.socket && d.socket.readyState === 1);
  return online.length === 1 ? online[0] : null;
}

// ---------- 页面：登录 / 改密 / 看板 ----------
function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

function escapeJs(s) {
  return String(s).replace(/\\/g, "\\\\").replace(/'/g, "\\'");
}

const BASE_STYLE = `
 *{box-sizing:border-box}
 body{font-family:system-ui,-apple-system,"Segoe UI",Roboto,"PingFang SC","Microsoft YaHei",sans-serif;background:#0d1017;color:#e6e8ee;margin:0;min-height:100vh}
 a{color:inherit;text-decoration:none}
 button{cursor:pointer;border:none;border-radius:9px;font-size:13px;font-weight:500}
 input{font-family:inherit}
 #toast{position:fixed;left:50%;bottom:28px;transform:translateX(-50%);background:#2563eb;color:#fff;padding:9px 20px;border-radius:9px;font-size:13px;opacity:0;transition:opacity .2s;pointer-events:none;z-index:9}
 #toast.show{opacity:1}
 #toast.err{background:#b91c1c}
`;

function authPageHtml({ mode }) {
  const isChange = mode === "change";
  const title = isChange ? "修改密码" : "登录 OpenCodex 控制台";
  return `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${title}</title>
<style>${BASE_STYLE}
 .wrap{display:flex;align-items:center;justify-content:center;min-height:100vh;padding:24px}
 .card{width:360px;max-width:100%;background:#141821;border:1px solid #232a37;border-radius:14px;padding:30px 28px;box-shadow:0 12px 40px rgba(0,0,0,.35)}
 .brand{display:flex;align-items:center;gap:10px;margin-bottom:6px}
 .dot{width:10px;height:10px;border-radius:50%;background:#3b82f6;box-shadow:0 0 12px #3b82f6}
 .brand b{font-size:17px;letter-spacing:.2px}
 h1{font-size:14px;font-weight:400;color:#9aa1ad;margin:0 0 22px}
 label{display:block;font-size:12.5px;color:#9aa1ad;margin:14px 0 6px}
 input[type=text],input[type=password]{width:100%;background:#0f131b;border:1px solid #262d3a;border-radius:9px;color:#e6e8ee;padding:11px 12px;font-size:14px;outline:none;transition:border-color .15s}
 input:focus{border-color:#3b82f6}
 .submit{width:100%;margin-top:22px;background:#2563eb;color:#fff;padding:11px;font-size:14px}
 .submit:hover{background:#1d4ed8}
 .hint{font-size:12px;color:#6b7280;margin-top:16px;line-height:1.6}
 .err{display:none;background:#3a1416;border:1px solid #7f1d1d;color:#fca5a5;font-size:12.5px;border-radius:8px;padding:9px 12px;margin-top:14px}
</style></head><body><div class="wrap"><div class="card">
<div class="brand"><span class="dot"></span><b>OpenCodex 控制台</b></div>
<h1>${isChange ? "首次登录需要设置新密码" : "请输入账号密码"}</h1>
<form id="f">
 ${isChange ? '<label>当前密码</label><input type="password" id="old" autocomplete="current-password" />' : ""}
 <label>${isChange ? "新密码" : "用户名"}</label>
 <input type="${isChange ? "password" : "text"}" id="${isChange ? "new1" : "username"}" autocomplete="${isChange ? "new-password" : "username"}" ${isChange ? "" : 'value="" autofocus'} />
 ${isChange ? "" : '<label>密码</label><input type="password" id="password" autocomplete="current-password" />'}
 ${isChange ? '<label>确认新密码</label><input type="password" id="new2" autocomplete="new-password" />' : ""}
 <button class="submit" type="submit">${isChange ? "保存并继续" : "登 录"}</button>
</form>
<div class="err" id="err"></div>
<div class="hint">${isChange ? "密码至少 6 位。修改后此账号的强制改密要求即解除。" : "默认账号 admin / admin，登录后将要求你设置新密码。"}</div>
</div></div><div id="toast"></div>
<script>
var f=document.getElementById('f'),err=document.getElementById('err');
function showErr(m){err.textContent=m;err.style.display='block';}
f.addEventListener('submit',async function(e){
 e.preventDefault();err.style.display='none';
 try{
  ${isChange
    ? `var body={oldPassword:document.getElementById('old').value,newPassword:document.getElementById('new1').value};
     if(document.getElementById('new1').value!==document.getElementById('new2').value)return showErr('两次输入的新密码不一致');
     if(body.newPassword.length<6)return showErr('新密码至少 6 位');
     var r=await fetch('/change-password',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(body)});`
    : `var body={username:document.getElementById('username').value,password:document.getElementById('password').value};
     var r=await fetch('/login',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(body)});`}
  var d=await r.json();
  if(d.ok){location.href=d.mustChange?'/change-password':'/';}
  else if(d.retryAfterSec>0){
   // IP 冻结中：显示剩余时间倒计时，期间禁用登录按钮，归零后恢复。
   var left=Math.max(1,parseInt(d.retryAfterSec,10)||1),btn=f.querySelector('.submit');
   if(btn)btn.disabled=true;btn&&(btn.style.opacity=.6);
   var tick=function(){
    var m=Math.floor(left/60),s=left%60;
    showErr('尝试过多，IP 已暂时冻结，请 '+(m>0?m+' 分 ':'')+(s<10?'0':'')+s+' 秒后再试');
    if(left<=0){err.style.display='none';if(btn){btn.disabled=false;btn.style.opacity=1;}return;}
    left--;setTimeout(tick,1000);
   };tick();
  }
  else showErr(d.error||('失败：'+r.status));
 }catch(ex){showErr('请求失败：'+ex.message);}
});
</script></body></html>`;
}

function dashboardHtml(username) {
  const userLabel = escapeHtml(username);
  return `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>OpenCodex 设备看板</title>
<style>${BASE_STYLE}
 header{display:flex;align-items:center;justify-content:space-between;padding:18px 28px;background:#12161f;border-bottom:1px solid #202634;position:sticky;top:0;z-index:5}
 .hd-left{display:flex;align-items:center;gap:10px}
 .dot{width:10px;height:10px;border-radius:50%;background:#3b82f6;box-shadow:0 0 12px #3b82f6}
 .hd-left b{font-size:16px;letter-spacing:.2px}
 .hd-left .sub{color:#6b7280;font-size:12px;margin-left:6px}
 .hd-right{display:flex;align-items:center;gap:12px;font-size:13px;color:#9aa1ad}
 .avatar{width:28px;height:28px;border-radius:50%;background:#1d4ed8;color:#fff;display:inline-flex;align-items:center;justify-content:center;font-size:13px;font-weight:600}
 .logout{background:#232a37;color:#c9cdd4;padding:7px 14px}
 .logout:hover{background:#2d3646}
 main{max-width:860px;margin:0 auto;padding:30px 24px 60px}
 .manage{display:flex;gap:10px;margin:0 0 24px}
 .manage input{flex:1;background:#141821;border:1px solid #262d3a;border-radius:9px;color:#e6e8ee;padding:11px 13px;font-size:14px;outline:none}
 .manage input:focus{border-color:#3b82f6}
 .manage button{background:#2563eb;color:#fff;padding:11px 20px}
 .manage button:hover{background:#1d4ed8}
 .grid{display:grid;gap:14px}
 .card{background:#141821;border:1px solid #232a37;border-radius:13px;padding:18px 20px;display:flex;align-items:center;justify-content:space-between;gap:16px;transition:border-color .15s}
 .card:hover{border-color:#31405c}
 .card.offline{opacity:.6}
 .dev-main{min-width:0;display:flex;flex-direction:column;gap:6px}
 .dev-name{font-size:15.5px;font-weight:600;display:flex;align-items:center;gap:10px}
 .dev-name a:hover{text-decoration:underline;text-underline-offset:3px}
 .devid{color:#6b7280;font-size:12px;font-family:ui-monospace,SFMono-Regular,monospace}
 .secret-row{display:flex;align-items:center;gap:8px;max-width:460px}
 .secret{color:#5b6472;font-size:11px;font-family:ui-monospace,SFMono-Regular,monospace;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:330px;user-select:all}
 .status{display:inline-flex;align-items:center;gap:6px;font-size:12px;padding:3px 11px;border-radius:999px;flex-shrink:0}
 .status .led{width:7px;height:7px;border-radius:50%}
 .st-online{background:#0e2f1c;color:#5fd38a}.st-online .led{background:#22c55e;box-shadow:0 0 8px #22c55e}
 .st-offline{background:#33211a;color:#e08a6b}.st-offline .led{background:#9a6b55}
 .actions{display:flex;align-items:center;gap:8px;flex-shrink:0}
 .open-btn{background:#2563eb;color:#fff;padding:8px 16px}
 .open-btn:hover{background:#1d4ed8}
 .mini{background:#232a37;color:#c9cdd4;padding:7px 12px}
 .mini:hover{background:#2d3646}
 .mini.danger:hover{background:#7f1d1d;color:#fecaca}
 .empty{color:#8b8f98;background:#141821;border:1px dashed #2a3140;border-radius:13px;padding:34px;text-align:center;font-size:13.5px;line-height:1.9}
 .empty b{color:#c9cdd4}
</style></head><body>
<header>
 <div class="hd-left"><span class="dot"></span><b>OpenCodex 设备看板</b><span class="sub">设备反连 · 零公网暴露</span></div>
 <div class="hd-right"><span class="avatar">${escapeHtml(username.slice(0, 1).toUpperCase())}</span><span>${userLabel}</span><button class="logout" onclick="renameSelf()">改用户名</button><button class="logout" onclick="location.href='/change-password'">改密码</button><button class="logout" onclick="logout()">退出</button></div>
</header>
<main>
 <div class="manage">
  <input id="newName" placeholder="设备名称（如 办公机），可留空自动生成" />
  <button onclick="addDevice()">＋ 添加设备</button>
 </div>
 <div class="grid" id="grid"></div>
</main>
<div id="toast"></div>
<script>
var secretVisible=false;
function toast(msg,isErr){var t=document.getElementById('toast');t.textContent=msg;t.className=isErr?'err show':'show';setTimeout(function(){t.classList.remove('show')},2200);}
function copyText(s){if(navigator.clipboard){navigator.clipboard.writeText(s).then(function(){toast('已复制')});}else{toast('复制失败，请手动选择',true);}}
async function addDevice(){var n=document.getElementById('newName');try{var r=await fetch('/api/devices',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({name:n.value})});var d=await r.json();if(d.ok){toast('已生成设备：'+d.id);n.value='';load();}else{toast('失败：'+(d.error||r.status),true);}}catch(e){toast('失败：'+e.message,true);}}
async function delDevice(id){if(!confirm('删除设备 '+id+'？其密钥立即失效，在线连接将被踢出。'))return;try{var r=await fetch('/api/devices/'+encodeURIComponent(id),{method:'DELETE'});var d=await r.json();if(d.ok){toast('已删除 '+id);load();}else{toast('失败：'+(d.error||r.status),true);}}catch(e){toast('失败：'+e.message,true);}}
async function logout(){try{await fetch('/logout',{method:'POST'});}catch(e){}location.href='/login';}
async function renameSelf(){
 var n=prompt('新用户名（2-32 位，字母/数字/中划线/下划线）','');if(n===null)return;
 n=(n||'').trim();if(!n)return;
 try{var r=await fetch('/change-username',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({newUsername:n})});var d=await r.json();
 if(d.ok){toast('已改用户名：'+d.username+'，页面即将刷新');setTimeout(function(){location.reload()},900);}
 else{toast('失败：'+(d.error||r.status),true);}}catch(e){toast('失败：'+e.message,true);}
}
function esc(s){return String(s).replace(/[&<>"']/g,function(c){return{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c];});}
async function load(){
 var r,d;
 try{ r=await fetch('/api/devices'); d=await r.json(); }catch(e){ return; }
 // 会话失效（服务重启后内存会话清空）：跳回登录页，而不是把 401 误显示成「暂无设备」。
 if(r.status===401){ location.href='/login'; return; }
 var g=document.getElementById('grid');
 if(!d.ok||!d.devices.length){g.innerHTML='<div class="empty"><b>暂无设备</b><br>先在上方「添加设备」生成设备密钥，再到 PC 端 OpenCodex 设置选「服务器」模式填入 IP 与密钥。<br>设备首次连接后会自动以本机 ID 登记。</div>';return;}
 g.innerHTML=d.devices.map(function(x){
  var on=!!x.online;
  return '<div class="card'+(on?'':' offline')+'">'
   +'<div class="dev-main">'
   +'<div class="dev-name"><a href="/d/'+encodeURIComponent(x.id)+'/" title="打开该设备的 Codex Desktop">'+esc(x.name||x.id)+'</a>'
   +'<span class="status '+(on?'st-online':'st-offline')+'"><span class="led"></span>'+(on?'在线':'离线')+'</span></div>'
   +'<span class="devid">'+esc(x.id)+'</span>'
   +'<div class="secret-row"><span class="secret" title="设备密钥（PC 端粘贴用）">'+esc(x.secret)+'</span>'
   +'<button class="mini" onclick="copyText(\\''+esc(x.secret)+'\\')">复制密钥</button></div>'
   +'</div>'
   +'<div class="actions">'
   +'<a class="open-btn" href="/d/'+encodeURIComponent(x.id)+'/">'+(on?'打开':'打开(离线)')+'</a>'
   +'<button class="mini danger" onclick="delDevice(\\''+esc(x.id)+'\\')">删除</button>'
   +'</div></div>';
 }).join('');
}
load();setInterval(load,5000);
</script></body></html>`;
}

// ---------- 通用工具 ----------
function readJsonBody(req) {
  return new Promise((resolve) => {
    const chunks = [];
    let len = 0;
    req.on("data", (c) => {
      len += c.length;
      if (len > 65536) {
        resolve({});
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on("end", () => {
      try {
        resolve(JSON.parse(Buffer.concat(chunks).toString("utf8") || "{}"));
      } catch {
        resolve({});
      }
    });
    req.on("error", () => resolve({}));
  });
}

function json(res, status, payload, extraHeaders) {
  res.writeHead(status, Object.assign({ "content-type": "application/json" }, extraHeaders || {}));
  res.end(JSON.stringify(payload));
}

function listDevices() {
  const list = [];
  for (const [id, info] of DEVICE_REGISTRY) {
    const dev = devices.get(id);
    list.push({ id, name: info.name || id, secret: info.secret, online: !!(dev && dev.online) });
  }
  return list;
}

async function handleDevicesApi(req, res, pathname) {
  if (req.method === "GET" && pathname === "/api/devices") {
    return json(res, 200, { ok: true, devices: listDevices() });
  }
  if (req.method === "POST" && pathname === "/api/devices") {
    const body = await readJsonBody(req);
    const wanted = sanitizeDeviceId(body.name);
    let id = wanted;
    while (DEVICE_REGISTRY.has(id)) id = `${wanted}-${crypto.randomBytes(2).toString("hex")}`;
    const secret = crypto.randomBytes(16).toString("hex");
    const name = String(body.name || "").trim() || id;
    DEVICE_REGISTRY.set(id, { secret, name });
    saveDevices(DEVICE_REGISTRY);
    return json(res, 200, { ok: true, id, secret, name });
  }
  const delMatch = pathname.match(/^\/api\/devices\/([^/]+)$/);
  if (req.method === "DELETE" && delMatch) {
    const id = decodeURIComponent(delMatch[1]);
    if (!DEVICE_REGISTRY.delete(id)) return json(res, 404, { ok: false, error: "unknown device" });
    saveDevices(DEVICE_REGISTRY);
    // 踢掉在线连接，让其密钥立即失效。
    const dev = devices.get(id);
    if (dev && dev.socket) {
      try {
        dev.socket.close(1000, "removed");
      } catch {}
    }
    return json(res, 200, { ok: true });
  }
  return null;
}

// ---------- 反向代理：浏览器 -> 隧道 ----------
function proxyHttpRequest(req, res, parsed, { bindDeviceCookie = false } = {}) {
  const dev = devices.get(parsed.deviceId);
  if (!dev || !dev.online || !dev.socket || dev.socket.readyState !== 1) {
    res.writeHead(502, { "content-type": "text/plain; charset=utf-8" });
    res.end("Device offline");
    return;
  }
  const id = genId();
  const rest = parsed.rest;
  const headers = Object.assign({}, req.headers);
  delete headers["connection"];
  // 清掉浏览器侧会话 cookie/凭证，PC 网关有自己的访问控制，不透传 VPS 这层。
  delete headers["authorization"];
  delete headers["cookie"];

  const fwdHeaders = {};
  for (const [k, v] of Object.entries(headers)) fwdHeaders[k] = v;

  // config.js 需要整包重写 gatewayWsUrl，标记后缓冲；其余响应流式转发。
  const stream = {
    role: "http",
    res,
    deviceId: dev.id,
    _setCookie: bindDeviceCookie
      ? `${DEVICE_COOKIE}=${encodeURIComponent(dev.id)}; Path=/; SameSite=Lax; Max-Age=${DEVICE_COOKIE_TTL_S}`
      : "",
    _rewrite: /\/codex-web-config\.js$/.test(rest),
    _buf: [],
    _headWritten: false,
  };
  dev.streams.set(id, stream);

  const bodyChunks = [];
  let bodyLen = 0;
  req.on("data", (c) => {
    bodyChunks.push(c);
    bodyLen += c.length;
  });
  req.on("end", () => {
    dev.socket.send(JSON.stringify({ t: "open", id, method: req.method, path: rest, headers: fwdHeaders }));
    if (bodyLen > 0) {
      const full = Buffer.concat(bodyChunks);
      dev.socket.send(JSON.stringify({ t: "data", id, chunk: full.toString("base64") }));
    }
    dev.socket.send(JSON.stringify({ t: "end", id }));
  });
  req.on("error", () => {
    try {
      dev.socket.send(JSON.stringify({ t: "end", id }));
    } catch {}
  });
}

function handleProxyFrame(dev, msg) {
  if (msg.t === "head") {
    const s = dev.streams.get(msg.id);
    if (!s || s.role !== "http") return;
    s._status = msg.status;
    s._headers = msg.headers || {};
    // 设备页访问时绑定设备 cookie：之后该浏览器的根路径资源请求都反代到这台设备。
    if (s._setCookie) {
      const existing = s._headers["set-cookie"];
      s._headers["set-cookie"] = Array.isArray(existing) ? existing.concat(s._setCookie) : [s._setCookie];
    }
    if (s._rewrite) return; // 等 end 再整包重写
    try {
      s.res.writeHead(msg.status, s._headers);
      s._headWritten = true;
    } catch {}
  } else if (msg.t === "data") {
    const s = dev.streams.get(msg.id);
    if (!s) return;
    const buf = Buffer.from(msg.chunk || "", "base64");
    if (s.role === "ws") {
      // 保留 WS 帧类型：文本帧回传文本帧（浏览器 JSON.parse(event.data) 依赖 string），
      // 二进制帧回传二进制帧。缺 bin 字段（旧客户端）时退回 binary（兼容现状）。
      try {
        s.browserWs.send(buf, { binary: msg.bin === undefined ? true : !!msg.bin });
      } catch {}
      return;
    }
    if (s._rewrite) {
      s._buf.push(buf);
      return;
    }
    try {
      s.res.write(buf);
    } catch {}
  } else if (msg.t === "end") {
    const s = dev.streams.get(msg.id);
    if (!s) return;
    if (s.role === "http") {
      let out = null;
      if (s._rewrite) out = rewriteConfigWsUrl(Buffer.concat(s._buf), dev.id);
      try {
        if (!s._headWritten) s.res.writeHead(s._status || 200, s._headers || {});
        if (out) s.res.end(out);
        else s.res.end();
      } catch {}
      dev.streams.delete(msg.id);
    }
  } else if (msg.t === "ws-close") {
    const s = dev.streams.get(msg.id);
    if (s && s.role === "ws" && s.browserWs) {
      try {
        s.browserWs.close(msg.code || 1000);
      } catch {}
      dev.streams.delete(msg.id);
    }
  } else if (msg.t === "pong") {
    dev.lastSeen = Date.now();
  }
}

// config.js 重写：把 gatewayWsUrl 从 location.origin+/ws 改为 +/d/<id>/ws
function rewriteConfigWsUrl(buf, deviceId) {
  let text = buf.toString("utf8");
  text = text.replace(/(\.replace\(\/\^http\/,\s*"ws"\))\s*\+\s*"\/ws"/, `$1 + "/d/${deviceId}/ws"`);
  return Buffer.from(text, "utf8");
}

// ---------- HTTP 服务 ----------
const tlsOpts =
  TLS_KEY && TLS_CERT && fs.existsSync(TLS_KEY) && fs.existsSync(TLS_CERT)
    ? { key: fs.readFileSync(TLS_KEY), cert: fs.readFileSync(TLS_CERT) }
    : null;

function clientIp(req) {
  return (req.socket && req.socket.remoteAddress) || "unknown";
}

function isPageRequest(req) {
  const accept = String(req.headers.accept || "");
  return accept.includes("text/html");
}

// 会话校验：页面导航未登录时 302 到登录页；API/资源未登录时 401（避免资源请求拿到 HTML）。
function requireSession(req, res) {
  const session = getSession(req);
  if (session) return session;
  if (isPageRequest(req)) {
    res.writeHead(302, { location: "/login" });
    res.end();
  } else {
    json(res, 401, { ok: false, error: "authentication required" });
  }
  return null;
}

const server = (tlsOpts ? https.createServer(tlsOpts) : http.createServer()).on(
  "request",
  async (req, res) => {
    try {
      const url = new URL(req.url, `http://${req.headers.host || "localhost"}`);
      const pathname = url.pathname;

      // PC 反连端点只走 WebSocket 升级；HTTP 请求到此一律拒绝。
      if (pathname === PROXY_ENDPOINT) {
        return json(res, 426, { ok: false, error: "websocket upgrade required" });
      }

      // ---------- 登录 / 改密 / 登出（无会话也可访问登录页） ----------
      if (pathname === "/login" && req.method === "GET") {
        const session = getSession(req);
        if (session && !session.mustChange) {
          res.writeHead(302, { location: "/" });
          return res.end();
        }
        res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
        return res.end(authPageHtml({ mode: "login" }));
      }
      if (pathname === "/login" && req.method === "POST") {
        const ip = clientIp(req);
        const { allowed, retryAfterSec } = loginAllowed(ip);
        if (!allowed) return json(res, 429, { ok: false, error: "尝试过多，IP 已暂时冻结", retryAfterSec });
        const body = await readJsonBody(req);
        const user = findUser(String(body.username || ""));
        const ok = user && verifyPassword(String(body.password || ""), user.salt, user.hash);
        if (!ok) {
          loginFailed(ip);
          return json(res, 200, { ok: false, error: "用户名或密码错误" });
        }
        loginSucceeded(ip);
        const token = createSession(user);
        return json(res, 200, { ok: true, mustChange: !!user.mustChange }, { "set-cookie": sessionCookie(token) });
      }
      if (pathname === "/logout" && req.method === "POST") {
        destroySession(parseCookies(req)[SESSION_COOKIE]);
        return json(res, 200, { ok: true }, { "set-cookie": CLEAR_SESSION_COOKIE });
      }
      if (pathname === "/change-password") {
        const session = getSession(req);
        if (!session) {
          if (req.method === "GET") {
            res.writeHead(302, { location: "/login" });
            return res.end();
          }
          return json(res, 401, { ok: false, error: "authentication required" });
        }
        if (req.method === "GET") {
          res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
          return res.end(authPageHtml({ mode: "change" }));
        }
        if (req.method === "POST") {
          const body = await readJsonBody(req);
          const user = findUser(session.username);
          if (!user) return json(res, 200, { ok: false, error: "账号不存在" });
          if (!verifyPassword(String(body.oldPassword || ""), user.salt, user.hash)) {
            return json(res, 200, { ok: false, error: "当前密码错误" });
          }
          const newPassword = String(body.newPassword || "");
          if (newPassword.length < 6) return json(res, 200, { ok: false, error: "新密码至少 6 位" });
          user.salt = crypto.randomBytes(16).toString("hex");
          user.hash = hashPassword(newPassword, user.salt);
          user.mustChange = false;
          user.passwordChangedAt = new Date().toISOString();
          saveUsers(USERS);
          sessions.set(session.token, Object.assign(session, { mustChange: false }));
          return json(res, 200, { ok: true });
        }
      }
      if (pathname === "/change-username" && req.method === "POST") {
        const session = getSession(req);
        if (!session) return json(res, 401, { ok: false, error: "authentication required" });
        const body = await readJsonBody(req);
        const newUsername = String(body.newUsername || "").trim();
        if (!/^[a-zA-Z0-9_-]{2,32}$/.test(newUsername)) {
          return json(res, 200, { ok: false, error: "用户名需 2-32 位，仅限字母、数字、中划线、下划线" });
        }
        const user = findUser(session.username);
        if (!user) return json(res, 200, { ok: false, error: "账号不存在" });
        if (newUsername !== user.username && findUser(newUsername)) {
          return json(res, 200, { ok: false, error: "该用户名已被占用" });
        }
        const oldUsername = user.username;
        user.username = newUsername;
        saveUsers(USERS);
        // 同步该账号全部在途会话：改名后当前登录态不失效、看板顶栏显示新名。
        for (const [, s] of sessions) {
          if (s.username === oldUsername) s.username = newUsername;
        }
        session.username = newUsername;
        return json(res, 200, { ok: true, username: newUsername });
      }

      // ---------- 设备隧道 /d/<id>/* ----------
      const parsed = parseDevicePath(pathname);
      if (parsed) {
        const session = requireSession(req, res);
        if (!session) return;
        if (session.mustChange) {
          res.writeHead(302, { location: "/change-password" });
          return res.end();
        }
        return proxyHttpRequest(req, res, parsed, { bindDeviceCookie: true });
      }

      // ---------- 看板自身路由（固定清单） ----------
      if (pathname === "/" || pathname === "/index.html") {
        // 看板入口是纯页面路由：未登录一律 302 到登录页（不依赖 Accept 头判定）。
        const session = getSession(req);
        if (!session) {
          res.writeHead(302, { location: "/login" });
          return res.end();
        }
        if (session.mustChange) {
          res.writeHead(302, { location: "/change-password" });
          return res.end();
        }
        res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
        return res.end(dashboardHtml(session.username));
      }
      if (pathname === "/api/status") {
        const session = requireSession(req, res);
        if (!session) return;
        const list = [];
        for (const [id, dev] of devices) list.push({ id, name: dev.name, online: dev.online });
        return json(res, 200, { ok: true, connected: list });
      }
      if (pathname === "/api/devices" || pathname.startsWith("/api/devices/")) {
        const session = requireSession(req, res);
        if (!session) return;
        const handled = await handleDevicesApi(req, res, pathname);
        if (handled !== null) return;
      }

      // ---------- 其余根路径：按设备 cookie 反代到设备（设备 UI 的资源/运行时 API） ----------
      // 设备 UI 的 HTML 引用根绝对路径资源（/official-patched-v8/...、/codex-web-config.js 等），
      // 运行时也会请求根路径 API，必须全部转发到对应设备，否则设备页加载不出（资源 404 风暴）。
      const session = requireSession(req, res);
      if (!session) return;
      if (session.mustChange) {
        res.writeHead(302, { location: "/change-password" });
        return res.end();
      }
      const dev = resolveProxyDevice(req);
      if (!dev) {
        res.writeHead(503, { "content-type": "text/plain; charset=utf-8" });
        return res.end("No online device bound. Open the dashboard and enter a device page first.");
      }
      return proxyHttpRequest(req, res, { deviceId: dev.id, rest: url.pathname + url.search });
    } catch (error) {
      console.error("[proxy] request error:", error);
      try {
        res.writeHead(500, { "content-type": "text/plain; charset=utf-8" });
        res.end("Internal error");
      } catch {}
    }
  }
);

// ---------- 设备（PC）WebSocket：/openCodeProxy ----------
const proxyWss = new WebSocketServer({ noServer: true });
proxyWss.on("connection", (ws, req) => {
  const url = new URL(req.url, "http://localhost");
  const rawDeviceId = url.searchParams.get("device") || "";
  const secret = url.searchParams.get("secret") || "";
  // 设备 ID 规范化：小写字母/数字/中划线/下划线，最长 64（支持用户自定义访问后缀）。
  const deviceId = rawDeviceId.toLowerCase().replace(/[^a-z0-9_-]/g, "").slice(0, 64);
  // 设备 ID 由 PC 端自报（本机 MAC 或自定义访问后缀），服务端只校验密钥值；
  // 密钥命中后，把「添加设备」时占位的登记条目迁移到该设备 ID 名下。
  const entry = [...DEVICE_REGISTRY.entries()].find(([, info]) => info.secret === secret);
  if (!secret || !deviceId || !entry) {
    try {
      ws.send(JSON.stringify({ t: "register-reject", reason: "bad secret or missing device id" }));
    } catch {}
    try {
      ws.close(1008, "auth failed");
    } catch {}
    return;
  }
  const [boundId, boundInfo] = entry;
  if (boundId !== deviceId) {
    // 目标 ID 已被另一台在线设备占用（如两台 PC 填了同一个自定义后缀）→ 拒绝注册，
    // 避免互相顶号导致流量错乱；PC 端会收到 register-reject 原因。
    const existingDev = devices.get(deviceId);
    if (existingDev && existingDev.socket && existingDev.socket.readyState === 1) {
      try {
        ws.send(JSON.stringify({ t: "register-reject", reason: `device id '${deviceId}' is already in use by another online device` }));
      } catch {}
      try {
        ws.close(1008, "device id in use");
      } catch {}
      console.log(`[proxy] register rejected: id '${deviceId}' in use (request from '${boundId}')`);
      return;
    }
    DEVICE_REGISTRY.delete(boundId);
    DEVICE_REGISTRY.set(deviceId, {
      secret: boundInfo.secret,
      name: boundInfo.name && boundInfo.name !== boundId ? boundInfo.name : deviceId,
    });
    saveDevices(DEVICE_REGISTRY);
    console.log(`[proxy] device re-bound: ${boundId} -> ${deviceId}`);
  }
  const dev = {
    id: deviceId,
    name: deviceId,
    socket: ws,
    online: true,
    lastSeen: Date.now(),
    streams: new Map(),
  };
  devices.set(deviceId, dev);

  const heartbeat = setInterval(() => {
    if (ws.readyState === 1) ws.send(JSON.stringify({ t: "ping" }));
    if (Date.now() - dev.lastSeen > 70_000) {
      dev.online = false;
    }
  }, 25_000);

  ws.on("message", (raw) => {
    let msg;
    try {
      msg = JSON.parse(raw);
    } catch {
      return;
    }
    if (msg.t === "register") {
      dev.name = msg.name || deviceId;
      dev.online = true;
      // 设备名变化时持久化，离线后看板仍显示最新名称。
      const info = DEVICE_REGISTRY.get(deviceId);
      if (info && msg.name && info.name !== msg.name) {
        info.name = msg.name;
        saveDevices(DEVICE_REGISTRY);
      }
      ws.send(JSON.stringify({ t: "register-ok", deviceId }));
      return;
    }
    if (msg.t === "pong") {
      dev.lastSeen = Date.now();
      dev.online = true;
      return;
    }
    handleProxyFrame(dev, msg);
  });
  ws.on("close", () => {
    clearInterval(heartbeat);
    dev.online = false;
    // 清理未完成的浏览器流
    for (const [, s] of dev.streams) {
      try {
        if (s.res && !s.res.writableEnded) s.res.end();
        if (s.browserWs) s.browserWs.close();
      } catch {}
    }
    dev.streams.clear();
  });
  ws.on("error", () => {});
});

// ---------- 浏览器 WebSocket：/d/<id>/ws 与根路径 WS ----------
// 浏览器 WS 不在 VPS 本机直连任何端口：通过 ws-open 隧道帧交给对应设备的
// 反连客户端，由它连 PC 本机 gateway 的 /ws 并双向转发（data / ws-close 帧）。
const browserWss = new WebSocketServer({ noServer: true });
browserWss.on("connection", (bws, req) => {
  const url = new URL(req.url, "http://localhost");
  const parsed = parseDevicePath(url.pathname);
  if (!parsed) {
    bws.close(1008, "bad path");
    return;
  }
  const dev = devices.get(parsed.deviceId);
  if (!dev || !dev.online || !dev.socket || dev.socket.readyState !== 1) {
    bws.close(1011, "device offline");
    return;
  }
  const streamId = genId();
  const stream = { role: "ws", browserWs: bws };
  dev.streams.set(streamId, stream);
  // client 端收到 ws-open 后连 PC 本机 gateway /ws（自动附带本地访问 token）。
  dev.socket.send(JSON.stringify({ t: "ws-open", id: streamId, path: parsed.rest || "/ws", headers: {} }));
  const b64 = (buf) => Buffer.from(buf).toString("base64");
  bws.on("message", (raw, isBinary) => {
    try {
      // 保留帧类型：浏览器文本帧 → 设备端以文本帧交给本地 gateway。
      dev.socket.send(JSON.stringify({ t: "data", id: streamId, chunk: b64(raw), bin: !!isBinary }));
    } catch {}
  });
  bws.on("close", (code) => {
    try {
      dev.socket.send(JSON.stringify({ t: "ws-close", id: streamId, code: code || 1000 }));
    } catch {}
    dev.streams.delete(streamId);
  });
  bws.on("error", () => {});
});

// ---------- 在 HTTP server 上分发 upgrade ----------
server.on("upgrade", (req, socket, head) => {
  const url = new URL(req.url, `http://${req.headers.host || "localhost"}`);
  const pathname = url.pathname;

  // 设备（PC）反连端点不做浏览器会话校验：PC 端不携带浏览器凭据，
  // 其鉴权由连接后的 register 密钥校验承担（devices.json 密钥值匹配）。
  if (pathname === PROXY_ENDPOINT) {
    proxyWss.handleUpgrade(req, socket, head, (ws) => proxyWss.emit("connection", ws, req));
    return;
  }

  // 其余 WS 一律要求浏览器会话。
  const session = getSession(req);
  if (!session) {
    socket.destroy();
    return;
  }

  // /d/<id>/...：直接对应设备；根路径 WS（如 /ws）：按设备 cookie 转发。
  let parsed = parseDevicePath(pathname);
  if (!parsed) {
    const dev = resolveProxyDevice(req);
    if (!dev) {
      socket.destroy();
      return;
    }
    req.url = `/d/${encodeURIComponent(dev.id)}${pathname}${url.search}`;
  }
  browserWss.handleUpgrade(req, socket, head, (ws) => browserWss.emit("connection", ws, req));
});

// ---------- 启动 ----------
function start() {
  const useTls = !!tlsOpts;
  const listenCb = () => {
    const proto = useTls ? "https" : "http";
    const wsproto = useTls ? "wss" : "ws";
    console.log(`[proxy] listening on ${proto}://${HOST}:${PORT}`);
    console.log(`[proxy] device endpoint: ${wsproto}://<this-host>:${PORT}${PROXY_ENDPOINT}`);
    console.log(`[proxy] dashboard: ${proto}://<this-host>/`);
    console.log(`[proxy] browser auth: account login (default admin/admin, must change on first login)`);
    console.log(`[proxy] auth file: ${AUTH_FILE} (AES-256-GCM encrypted)`);
    console.log(`[proxy] registered devices: ${DEVICE_REGISTRY.size} (file: ${DEVICES_FILE})`);
  };
  if (useTls) server.listen(PORT, HOST, listenCb);
  else server.listen(PORT, HOST, listenCb);
}

start();
