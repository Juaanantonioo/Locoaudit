"use strict";

/**
 * os-info.js — Información del sistema operativo usando el módulo nativo `os`.
 *
 * Recolecta: platform, arch, hostname, uptime (segundos y legible),
 *            release, type.
 *
 * Sin dependencias externas ni llamadas a child_process.
 *
 * Exporta:
 *   getOsInfo() → Object
 */

const os = require("os");

/**
 * Convierte segundos a una cadena legible "Xd Xh Xm".
 * @param {number} seconds
 * @returns {string}
 */
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

/**
 * Recolecta información del sistema operativo.
 * @returns {{
 *   platform: string,
 *   arch: string,
 *   hostname: string,
 *   uptimeSec: number,
 *   uptimeHuman: string,
 *   release: string,
 *   type: string
 * }}
 */
function getOsInfo() {
  const uptimeSec = Math.floor(os.uptime());
  return {
    platform: os.platform(),       // 'darwin' | 'linux' | 'win32'
    arch: os.arch(),               // 'x64' | 'arm64' | ...
    hostname: os.hostname(),
    uptimeSec,
    uptimeHuman: formatUptime(uptimeSec),
    release: os.release(),         // versión del kernel
    type: os.type(),               // 'Darwin' | 'Linux' | 'Windows_NT'
  };
}

module.exports = { getOsInfo };
