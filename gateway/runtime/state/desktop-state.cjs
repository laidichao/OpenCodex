const fs = require("fs");
const path = require("path");
const { CODEX_HOME, officialDataDir } = require("../core/config.cjs");
const { readOfficialFeatureCache } = require("./official-feature-cache.cjs");

// 官方 Desktop 把 Electron UI 状态放在 CODEX_HOME 下；OpenCodex 只读取它来生成首屏快照。
const DESKTOP_GLOBAL_STATE_PATH = path.join(CODEX_HOME, ".codex-global-state.json");
const DESKTOP_GLOBAL_STATE_BACKUP_PATH = `${DESKTOP_GLOBAL_STATE_PATH}.bak`;
const DESKTOP_PERSISTED_ATOMS_KEY = "electron-persisted-atom-state";
const COMPOSER_PERMISSION_MODE_VISIBILITY_KEY = "composer-permission-mode-visibility";
const DEFAULT_COMPOSER_PERMISSION_MODE_VISIBILITY = {
  "guardian-approvals": true,
  "full-access": true,
};

function isPlainObject(value) {
  return !!value && typeof value === "object" && !Array.isArray(value);
}

function readJsonObject(filePath) {
  try {
    const parsed = JSON.parse(fs.readFileSync(filePath, "utf8"));
    return isPlainObject(parsed) ? parsed : null;
  } catch {
    return null;
  }
}

function loadDesktopGlobalState() {
  // 官方会同时维护主文件和 .bak；主文件损坏时按官方思路读取备份，避免首屏状态直接丢失。
  return readJsonObject(DESKTOP_GLOBAL_STATE_PATH) || readJsonObject(DESKTOP_GLOBAL_STATE_BACKUP_PATH) || {};
}

function normalizePromptHistoryForRenderer(value) {
  if (Array.isArray(value)) return value.filter((item) => typeof item === "string");
  if (!isPlainObject(value)) return [];
  if (Array.isArray(value.global)) return value.global.filter((item) => typeof item === "string");
  if (Array.isArray(value["new-conversation"])) {
    return value["new-conversation"].filter((item) => typeof item === "string");
  }
  return [];
}

function normalizePersistedAtomForRenderer(key, value) {
  // 这两个兼容转换沿用旧 gateway 逻辑，保证官方 renderer 拿到的是自己期望的形态。
  if (key === "prompt-history") return normalizePromptHistoryForRenderer(value);
  if (key === COMPOSER_PERMISSION_MODE_VISIBILITY_KEY) {
    return {
      ...DEFAULT_COMPOSER_PERMISSION_MODE_VISIBILITY,
      ...(isPlainObject(value) ? value : {}),
    };
  }
  return value;
}

function desktopPersistedAtoms() {
  const atoms = loadDesktopGlobalState()[DESKTOP_PERSISTED_ATOMS_KEY];
  return isPlainObject(atoms) ? atoms : {};
}

function persistedAtomSnapshotForRenderer() {
  return Object.fromEntries(
    Object.entries(desktopPersistedAtoms()).map(([key, value]) => [key, normalizePersistedAtomForRenderer(key, value)])
  );
}

/** 只读取官方登录身份的展示字段，令牌和认证权限仍由官方 runtime 处理。 */
function desktopAccountProfileForRenderer() {
  // 本机登录已包含姓名与邮箱；远端 /me 网络请求不能阻塞侧栏的首次身份展示。
  const auth = readJsonObject(path.join(CODEX_HOME, "auth.json"));
  if (auth?.auth_mode !== "chatgpt" || typeof auth?.tokens?.id_token !== "string") return null;
  try {
    const claims = JSON.parse(Buffer.from(auth.tokens.id_token.split(".")[1], "base64url").toString("utf8"));
    const identity = claims["https://api.openai.com/auth"];
    if (typeof identity?.chatgpt_user_id !== "string" || typeof identity?.chatgpt_account_id !== "string") return null;
    // 仅发布明确白名单，不能把 JWT、组织权限或其他 claims 带到浏览器。
    return {
      accountId: identity.chatgpt_account_id,
      userId: identity.chatgpt_user_id,
      id: identity.chatgpt_user_id,
      name: typeof claims.name === "string" ? claims.name : null,
      email: typeof claims.email === "string" ? claims.email : null,
    };
  } catch {
    return null;
  }
}

/** 只发布当前桌面真实功能布尔值，缓存中的用户信息和完整响应不得进入配置。 */
function desktopFeatureGatesForRenderer(profile, appVersion, locale) {
  if (!profile) return {};
  // 官方持久化的身份缓存用于确认设备稳定 ID 的归属，不从其中推断侧栏开关。
  const atoms = desktopPersistedAtoms();
  let stableId = null;
  try {
    const identity = JSON.parse(atoms["mini-style-cache"]?.key || "null");
    if (identity?.accountId === profile.accountId && identity?.userId === profile.userId
        && identity?.appVersion === appVersion && identity?.locale === locale) stableId = identity.stableId;
  } catch {
    // 身份缓存不完整时只接受带完整账号身份的真实 evaluations。
  }
  // 复用项目的官方数据目录解析，不绑定任何用户名或开发者路径。
  const profileRoot = path.join(officialDataDir(), "web", "Codex");
  // 只读官方 profile，并以账号、用户、应用版本和语言限制缓存复用。
  const cached = readOfficialFeatureCache(profileRoot, { ...profile, appVersion, locale, stableId });
  const gates = {};
  for (const [key, gate] of Object.entries(cached || {})) {
    if (!gate || typeof gate.value !== "boolean") continue;
    gates[key] = gate.value;
  }
  return gates;
}

module.exports = {
  DESKTOP_GLOBAL_STATE_PATH,
  DESKTOP_PERSISTED_ATOMS_KEY,
  persistedAtomSnapshotForRenderer,
  desktopAccountProfileForRenderer,
  desktopFeatureGatesForRenderer,
};
