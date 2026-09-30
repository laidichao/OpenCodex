// relay-config.cjs
// 反向隧道客户端的运行配置，全部来自环境变量（不引入 js-yaml，不改 YAML 解析器）。
// 这样 OpenCodex 本身完全无感，只在 env 打开时才激活反连。
const crypto = require("crypto");

function readRelayConfig() {
  const enabled = process.env.OCX_RELAY_ENABLED === "1";
  const url = String(process.env.OCX_RELAY_URL || "").trim();
  const secret = String(process.env.OCX_RELAY_SECRET || "").trim();
  const deviceName = String(
    process.env.OCX_RELAY_DEVICE_NAME ||
      process.env.OCX_DEVICE_NAME ||
      process.env.COMPUTERNAME ||
      process.env.HOSTNAME ||
      "device"
  ).trim();
  // launcher 注入的是 OCX_RELAY_DEVICE_ID（与 OCX_RELAY_* 前缀保持一致）；
  // 旧名 OCX_DEVICE_ID 仅作兼容。都缺失时才退回随机 ID。
  const deviceId = String(
    process.env.OCX_RELAY_DEVICE_ID || process.env.OCX_DEVICE_ID || crypto.randomBytes(8).toString("hex")
  ).trim();
  let localPort = 3737;
  try {
    localPort = Number(require("../core/config.cjs").PORT) || 3737;
  } catch {}
  // 隧道配置只描述设备连接；Gateway 密码由访问它的浏览器分别校验。
  return {
    enabled,
    url,
    secret,
    deviceId,
    deviceName,
    localHost: "127.0.0.1",
    localPort,
  };
}

module.exports = { readRelayConfig };
