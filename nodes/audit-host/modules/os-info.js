"use strict";

const os = require("os");

/** Segundos a "Xd Xh Xm"; los días y las horas se omiten si son cero. */
function formatUptime(seconds) {
  const d = Math.floor(seconds / 86400);
  const h = Math.floor((seconds % 86400) / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const parts = [];
  if (d > 0) parts.push(`${d}d`);
  if (h > 0) parts.push(`${h}h`);
  parts.push(`${m}m`);
  return parts.join(" ");
}

/** Identidad del equipo auditado, para la cabecera del informe. */
function getOsInfo() {
  const uptimeSec = Math.floor(os.uptime());
  return {
    platform: os.platform(),
    arch: os.arch(),
    hostname: os.hostname(),
    uptimeSec,
    uptimeHuman: formatUptime(uptimeSec),
    release: os.release(),         // el kernel, no la versión del SO: en Windows 10 y 11 sale 10.0.x
    type: os.type(),
  };
}

module.exports = { getOsInfo };
