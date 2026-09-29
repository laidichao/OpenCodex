# openCodeProxy —— OpenCodex 反向隧道代理（VPS 统一入口）

部署在**有公网 IP 的 VPS** 上的单文件代理服务：接收 PC 端 OpenCodex 的主动反连，提供设备导航看板，并把浏览器对 `/d/<deviceId>/*` 的 HTTP 与 WebSocket 请求透明代理到对应 PC。

```
浏览器 ──HTTPS/WSS──> VPS(openCodeProxy :8443) <──WSS /openCodeProxy 反连── PC1 (OpenCodex gateway)
                                      │<──WSS /openCodeProxy 反连── PC2 (OpenCodex gateway)
```

- PC 端**零入站端口、零公网暴露**：由 PC 主动出站反连，VPS 是唯一公网入口。
- 依赖仅 `ws`，无数据库、无外部服务，单文件 `server.js`。
- 本目录随 OpenCodex 仓库分发；PC 端反连客户端实现在 `../gateway/runtime/relay/`，随安装包内置，无需单独部署。

## 目录结构

```
proxy/
├── server.js         # 代理服务端（唯一运行文件）
├── package.json      # 依赖声明（ws）
├── test-harness.cjs  # 本地端到端验证脚本
├── devices.json      # 运行时自动生成：设备与密钥持久化
├── key.pem/cert.pem  # 运行时自备：TLS 证书（公网必配）
└── README.md
```

## VPS 部署步骤

### 1. 安装 Node.js（≥16）

```bash
# CentOS Stream 9
dnf install -y nodejs npm
# 或使用 NodeSource 安装新版
curl -fsSL https://rpm.nodesource.com/setup_20.x | bash - && dnf install -y nodejs
```

### 2. 上传代码并安装依赖

```bash
mkdir -p /opt/proxy
# 将本目录 server.js package.json 上传到 /opt/proxy/
cd /opt/proxy && npm install --omit=dev
```

### 3. 生成自签 TLS 证书（有域名可换 Let's Encrypt）

```bash
cd /opt/proxy
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem \
  -days 3650 -nodes -subj "/CN=your.domain.com"
```

### 4. systemd 开机自启

```ini
# /etc/systemd/system/openCodeProxy.service
[Unit]
Description=openCodeProxy - OpenCodex reverse tunnel proxy
After=network.target

[Service]
WorkingDirectory=/opt/proxy
Environment=RELAY_PORT=8443
Environment=DEVICE_SECRETS=PC1=设备1密钥,PC2=设备2密钥
Environment=TLS_KEY=/opt/proxy/key.pem
Environment=TLS_CERT=/opt/proxy/cert.pem
ExecStart=/usr/bin/node server.js
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
```

```bash
systemctl daemon-reload
systemctl enable --now openCodeProxy
systemctl status openCodeProxy
journalctl -u openCodeProxy -n 20 --no-pager   # 看日志
```

### 5. 放行防火墙与云安全组

```bash
firewall-cmd --permanent --add-port=8443/tcp && firewall-cmd --reload
# 腾讯云/阿里云还需在控制台安全组放行 8443/TCP 入站
```

## 环境变量

| 变量 | 默认 | 说明 |
|---|---|---|
| `RELAY_PORT` | `8443` | 监听端口 |
| `RELAY_HOST` | `0.0.0.0` | 监听地址 |
| `DEVICE_SECRETS` | 空 | 初始设备密钥表，`{"PC1":"s1"}` 或 `PC1=s1,PC2=s2`；**仅首次启动导入 devices.json**，兼容旧名 `AGENT_SECRETS` |
| `RELAY_DEVICES_FILE` | `./devices.json` | 设备与密钥持久化文件 |
| `RELAY_AUTH_FILE` | `./auth.json` | 账号数据持久化文件（AES-256-GCM 加密存储） |
| `RELAY_AUTH_KEY_FILE` | `./.auth.key` | 账号数据加密主密钥（首启自动生成，务必备份；丢失则账号数据不可解密，需删除 auth.json 重建） |
| `TLS_KEY` / `TLS_CERT` | 空 | PEM 证书路径；设置后启用 HTTPS/WSS（公网务必设置） |

## 浏览器登录（账号密码）

看板与设备页使用账号密码登录（不再使用 Basic Auth，旧 `BROWSER_PASSWORD` 环境变量已弃用）：

- 首次启动自动创建默认账号 **admin / admin**，并标记「首次登录必须改密」。
- 登录后若未改密，访问任何页面都会被重定向到改密页；改密成功后解除。
- 账号数据（用户名、scrypt 口令哈希）整体以 **AES-256-GCM** 加密写入 `auth.json`（权限 600），主密钥独立存放于 `.auth.key`（权限 600）。
- 会话为 HttpOnly Cookie（12 小时滑动续期），服务重启后需重新登录。
- 登录连续失败 5 次将锁定该来源 IP 60 秒。

## 设备与密钥管理（看板）

设备表持久化在 `devices.json`（deviceId / secret / name）。首次启动从 `DEVICE_SECRETS` 导入并落盘，之后**以文件为准**，改环境变量不再生效。

浏览器打开 `https://<vps>:8443/`，用账号密码登录（首次部署为 admin/admin，登录后强制改密）：

- **添加设备**：输入名称（可留空），服务端生成 deviceId 与 32 位随机密钥，界面直接展示并可复制。
- **复制密钥**：每台设备行内有「复制密钥」按钮。
- **删除设备**：密钥立即失效；在线连接会被踢掉。
- PC 端上线后注册的设备名会自动写回 `devices.json`。

设备管理 API（受登录会话保护）：

| 方法 | 路径 | 说明 |
|---|---|---|
| `GET` | `/api/devices` | 列出全部注册设备（含密钥与在线状态） |
| `POST` | `/api/devices` | 添加设备，body `{"name":"办公机"}`，返回生成的 id/secret |
| `DELETE` | `/api/devices/<id>` | 删除设备 |
| `GET` | `/api/status` | 当前在线连接列表 |

## PC 端配置（OpenCodex）

1. 安装带中继功能的 OpenCodex（本 fork 构建的安装包）。
2. 打开设置 → **启动地址** 选 **「服务器」**（面板仅在此模式下显示）。
3. 填写：
   - **服务器 IP**：VPS 公网 IP（端口默认 8443，可改）
   - **设备 ID**：留空自动生成，或与看板上的设备对应
   - **本机名称**：留空用计算机名
   - **设备密钥**：从看板「添加设备」生成后复制粘贴
   - **跳过 TLS 校验**：用自签证书时勾选
4. 保存后自动重启服务，PC 主动反连 VPS；看板出现该设备即成功。

完整反连地址由 PC 端自动拼接：`wss://<服务器IP>:<端口>/openCodeProxy`。

## 端点一览

| 路径 | 说明 |
|---|---|
| `WS /openCodeProxy?device=<id>&secret=<s>` | PC 端反连接入点（注册即校验密钥） |
| `GET /` | 设备导航看板 |
| `GET/WS /d/<deviceId>/*` | 该设备的 Codex Desktop（HTTP + WS 经隧道盲代理） |
| `GET/POST/DELETE /api/devices[/<id>]` | 设备管理 API |
| `GET /api/status` | 在线连接列表 |

## 透明代理关键点

浏览器访问 `/d/<id>/codex-web-config.js` 时，服务端会把其中的 `gatewayWsUrl` 从
`location.origin + "/ws"` 自动改写为 `location.origin + "/d/<id>/ws"`，使 web-shell **无需改源码**即走隧道路径。

## 安全清单

- [ ] 首次登录 admin/admin 后已立即修改密码；`.auth.key` 已备份到安全位置
- [ ] TLS 已启用（自签即可，PC 端勾「跳过 TLS 校验」；有域名建议 Let's Encrypt）
- [ ] 云安全组仅放行 `8443/TCP` 与 SSH
- [ ] 每台 PC 一个独立密钥；淘汰设备及时在看板删除

## 本地联调

```bash
cd proxy
npm install        # 需要 ws（OpenCodex 仓库根已有则可跳过）
node test-harness.cjs
# 期望输出：[test] ALL PASS ✅
```

harness 会启动 mock gateway + 真实 server.js + 真实 PC 端反连客户端，验证 HTTP 代理、config.js 重写、WebSocket 隧道三项核心链路。
