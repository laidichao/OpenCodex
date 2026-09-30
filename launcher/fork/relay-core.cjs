// launcher/fork/relay-core.cjs
// [OCX-FORK] 服务器中继（反连隧道）的全部可独立逻辑，集中在此单文件。
// 目标：fork 合并 upstream 时，原 launcher/main.cjs 只保留极薄的调用点（见各 [OCX-FORK] 标记），
// 业务改动都发生在这个 upstream 没有的新文件里，冲突面最小。
//
// 依赖注入约定：本文件不 require launcher/main.cjs（避免循环依赖），
// 一切来自 main.cjs 的函数（saveLauncherSettings / readAuthEnabled / appendLog 等）
// 都通过 createRelayCore(deps) 传入；纯函数（normalize 系列 / URL 拼接）在模块级直接导出。

// 显式使用 Node.js 系统模块，避免 Electron 的全局 Web Crypto 被误当作设备 ID 随机源。
const crypto = require("node:crypto");
const os = require("node:os");

// ---------- 纯函数（无外部依赖） ----------

// 与 main.cjs 的 normalizeHostMode 语义保持一致（upstream 原有函数，这里独立副本避免反向依赖）。
function hostModeOf(value) {
  if (value === "lan") return "lan";
  if (value === "server") return "server";
  return "local";
}

// 与 main.cjs 的 normalizePort 语义保持一致（upstream 原有函数的独立副本）。
function normalizePort(value) {
  const port = Number(value);
  if (!Number.isInteger(port) || port < 1 || port > 65535) return null;
  return port;
}

function normalizeRelayString(value) {
  return String(value || "").trim();
}

// UI 只让用户填 IP；这里容错处理直接粘贴完整地址的情况，自动抽取纯主机部分。
function normalizeRelayHost(value) {
  let text = String(value || "").trim();
  if (!text) return "";
  text = text.replace(/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//, "");
  text = text.split(/[/?#]/)[0];
  if (text.includes("@")) text = text.slice(text.lastIndexOf("@") + 1);
  if (!text.includes("]")) text = text.split(":")[0];
  return text.trim();
}

// 端口留空或非法时回退到默认 8443。
function normalizeRelayPort(value) {
  const port = normalizePort(value);
  return port || 8443;
}

// 自定义访问后缀：小写字母/数字开头，允许小写字母、数字、中划线、下划线，长度 2-32。
// 留空表示使用首次生成并保存的随机设备 ID。设备页地址 = https://<vps>:<port>/d/<后缀或设备ID>/
function normalizeRelayPath(value) {
  const text = String(value || "")
    .trim()
    .toLowerCase()
    .replace(/\s+/g, "-");
  if (!text) return "";
  if (!/^[a-z0-9][a-z0-9_-]{1,31}$/.test(text)) return "";
  return text;
}

// settings 的 relay 字段默认值（defaultSettings / load / save 三处共用同一份 schema）。
const RELAY_DEFAULT_FIELDS = Object.freeze({
  relayHost: "",
  relayPort: 8443,
  relaySecret: "",
  relayDeviceId: "",
  relayDeviceName: "",
  relayCustomPath: "",
  relayTlsInsecure: false,
});

// 对任意来源（磁盘 JSON / 内存 settings / IPC 入参）的 relay 字段做统一 normalize。
// 兼容 v3 的 relayUrl（完整地址）——relayHost 缺失时自动从 relayUrl 抽取主机。
function normalizeRelayFields(source) {
  const src = source && typeof source === "object" ? source : {};
  return {
    relayHost: normalizeRelayHost(src.relayHost || src.relayUrl),
    relayPort: normalizeRelayPort(src.relayPort),
    relaySecret: normalizeRelayString(src.relaySecret),
    relayDeviceId: normalizeRelayString(src.relayDeviceId),
    relayDeviceName: normalizeRelayString(src.relayDeviceName),
    relayCustomPath: normalizeRelayPath(src.relayCustomPath),
    relayTlsInsecure: src.relayTlsInsecure === true,
  };
}

// 服务器模式顶部访问地址：VPS 统一入口里本机设备的页面。
// 有自定义访问后缀时优先用后缀（反连注册也用同一 ID，保证地址真实可达）。
// 返回 null 表示非服务器模式或信息不全，调用方回退原有 LAN/local 逻辑。
function relayPrimaryUrl(settings) {
  const relay = settings || {};
  const relayHost = normalizeRelayHost(relay.relayHost);
  if (hostModeOf(relay.hostMode) !== "server" || !relayHost) return null;
  const accessId = normalizeRelayPath(relay.relayCustomPath) || normalizeRelayString(relay.relayDeviceId);
  if (!accessId) return null;
  return `https://${relayHost}:${normalizeRelayPort(relay.relayPort)}/d/${encodeURIComponent(accessId)}/`;
}

// 「打开 OpenCodex」按钮在服务器模式下的行为判定：返回应打开的 URL，或 null（走原有流程）。
function relayServerEntryUrl(settings, primaryUrl) {
  const relay = settings || {};
  const relayHost = normalizeRelayHost(relay.relayHost);
  const relayDeviceId = normalizeRelayString(relay.relayDeviceId);
  if (hostModeOf(relay.hostMode) === "server" && relayHost && relayDeviceId && primaryUrl) {
    return primaryUrl;
  }
  return null;
}

// ---------- 需要注入 main.cjs 依赖的部分 ----------

function createRelayCore(deps) {
  const { saveLauncherSettings } = deps;

  // 设备 ID 与本机名称支持零配置：首次切到服务器模式时自动生成并持久化。
  // 首次生成随机码并保存，后续启动保留原 ID，避免设备访问地址漂移。
  // 返回值可能经过 saveLauncherSettings 落盘，与原 main.cjs 内嵌版本行为一致。
  function ensureRelayIdentity(paths, settings) {
    const merged = { ...settings };
    let dirty = false;
    if (!normalizeRelayString(merged.relayDeviceId)) {
      // 地址不包含网卡、主机名或开发者身份。
      merged.relayDeviceId = crypto.randomBytes(8).toString("hex");
      dirty = true;
    }
    if (!normalizeRelayString(merged.relayDeviceName)) {
      merged.relayDeviceName = os.hostname() || merged.relayDeviceId;
      dirty = true;
    }
    if (!dirty) return merged;
    return saveLauncherSettings(paths, merged);
  }

  // 服务器模式：把 relay 配置转译为 OCX_RELAY_* 环境变量（gateway 启动后反连 VPS）。
  // 网关只在本地监听（relay 负责把流量推出去），未填服务器地址时回退本机模式避免起不来。
  // 返回 null 表示非服务器模式（调用方跳过）；否则返回 { env, settings }——settings 可能已被
  // ensureRelayIdentity 补齐身份字段并落盘，调用方需要写回 gatewayState.settings。
  function relayChildEnv(settings, paths) {
    if (hostModeOf(settings && settings.hostMode) !== "server") return null;
    const next = ensureRelayIdentity(paths, settings);
    const relay = next || {};
    const env = {};
    const relayHost = normalizeRelayHost(relay.relayHost);
    const relayCustomPath = normalizeRelayPath(relay.relayCustomPath);
    if (relayHost) {
      env.OCX_RELAY_ENABLED = "1";
      // UI 只填 IP + 端口，完整反连地址统一在这里拼接。
      env.OCX_RELAY_URL = `wss://${relayHost}:${normalizeRelayPort(relay.relayPort)}/openCodeProxy`;
      if (relay.relaySecret) env.OCX_RELAY_SECRET = relay.relaySecret;
      // 反连注册 ID：有自定义访问后缀时用它（与顶部访问地址 /d/<后缀>/ 保持一致），
      // 服务端会自动把登记条目 re-bind 到该 ID；否则用已保存的随机设备 ID。
      const registerId = relayCustomPath || normalizeRelayString(relay.relayDeviceId);
      if (registerId) env.OCX_RELAY_DEVICE_ID = registerId;
      if (relay.relayDeviceName) env.OCX_RELAY_DEVICE_NAME = relay.relayDeviceName;
      if (relay.relayTlsInsecure) env.OCX_RELAY_TLS_INSECURE = "1";
    } else {
      env.HOST = "127.0.0.1";
    }
    return { env, settings: next };
  }

  // launcher:update-relay IPC handler。deps 全部来自 main.cjs（清单见 FORK-NOTES.md）。
  function createRelayIpcHandler(handlerDeps) {
    const {
      appendLog,
      runtimePaths,
      ensureRuntimeLayout,
      gatewayState,
      loadLauncherSettings,
      readAuthEnabled,
      restartGateway,
    } = handlerDeps;
    return async function handleUpdateRelay(_event, relay) {
      const relayInput = relay && typeof relay === "object" ? relay : {};
      appendLog(
        `[launcher] update-relay invoked host=${relayInput.relayHost ? "<set>" : "<empty>"} port=${JSON.stringify(relayInput.relayPort)} secret=${relayInput.relaySecret ? "<set>" : "<empty>"} tls=${relayInput.relayTlsInsecure} path=${JSON.stringify(relayInput.relayCustomPath || "")}\n`
      );
      const paths = runtimePaths();
      ensureRuntimeLayout(paths);
      gatewayState.paths = paths;
      // 保存表单只覆盖可编辑连接项，设备身份从当前持久化设置取得。
      const currentSettings = gatewayState.settings || loadLauncherSettings(paths);
      const merged = {
        ...currentSettings,
        ...normalizeRelayFields(relayInput),
        // UI 不提交设备码；保存面板时沿用已持久化的身份，且不允许 IPC 替换它。
        relayDeviceId: normalizeRelayString(currentSettings.relayDeviceId),
        // 显式覆盖：IPC 入参的布尔必须精确 true/false，不吞 undefined。
        relayTlsInsecure: relayInput.relayTlsInsecure === true,
      };
      // 服务器模式强制设置访问密码：自定义后缀的地址好记也可被猜测，公网入口必须有密码保护。
      if (
        hostModeOf(merged.hostMode) === "server" &&
        merged.relayHost &&
        !readAuthEnabled(paths.configPath)
      ) {
        throw new Error("服务器模式必须先设置访问密码（设置区的「访问密码」），再保存中继配置");
      }
      // 设备 ID 不接受外部传入：缺失时由 ensureRelayIdentity 生成随机码。
      // 必须先把用户保存的中继配置显式落盘：ensureRelayIdentity 只在需要补身份字段
      // （dirty=true）时才写文件；设备 ID/名称已存在时它不会保存，若不在前面显式落盘，
      // restartGateway 会从磁盘读回旧配置覆盖内存态，表现为「保存即清空」。
      gatewayState.settings = ensureRelayIdentity(paths, saveLauncherSettings(paths, merged));
      return restartGateway();
    };
  }

  return {
    ensureRelayIdentity,
    relayChildEnv,
    createRelayIpcHandler,
  };
}

module.exports = {
  createRelayCore,
  // 纯函数直接导出，方便测试与 renderer 侧复用。
  hostModeOf,
  normalizeRelayString,
  normalizeRelayHost,
  normalizeRelayPort,
  normalizeRelayPath,
  normalizeRelayFields,
  RELAY_DEFAULT_FIELDS,
  relayPrimaryUrl,
  relayServerEntryUrl,
};
