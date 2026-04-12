"use strict";

/**
 * disk-storage.js — Uso de disco por partición montada.
 *
 * macOS/Linux: parsea salida de "df -k"
 * Windows:     parsea salida de "wmic logicaldisk get Caption,Size,FreeSpace"
 *
 * Exporta:
 *   getDiskInfo() → Promise<Array<{
 *     mount: string,
 *     totalGB: number,
 *     usedGB: number,
 *     freeGB: number,
 *     usedPercent: number
 *   }>>
 */

const { execCommand } = require("../../../lib/executor");

const KB = 1024;
const GB = KB * KB * KB;

// ── Parsers ─────────────────────────────────────────────────────────────────

/**
 * Parsea la salida de "df -k" (macOS / Linux).
 * La cabecera varía ligeramente entre sistemas, pero los campos
 * numéricos siempre están en las columnas 2 (1K-blocks), 3 (Used), 4 (Available).
 */
function parseDfOutput(stdout) {
  const lines = stdout.trim().split("\n");
  const results = [];

  for (const line of lines.slice(1)) { // saltar cabecera
    // df -k puede partir líneas largas en dos; ignoramos líneas sin cifras
    const parts = line.trim().split(/\s+/);
    if (parts.length < 6) continue;

    const totalKB = parseInt(parts[1], 10);
    const usedKB = parseInt(parts[2], 10);
    const freeKB = parseInt(parts[3], 10);
    const mount = parts[parts.length - 1]; // último campo = punto de montaje

    if (isNaN(totalKB) || totalKB === 0) continue;
    // Ignorar pseudo-filesystems (devtmpfs, tmpfs, udev, etc.)
    if (!mount.startsWith("/")) continue;
    // Ignorar pseudo-filesystems de macOS APFS y /dev
    if (mount === "/dev") continue;
    if (mount.startsWith("/System/Volumes/")) continue;

    const totalGB = Math.round((totalKB * KB) / GB * 100) / 100;
    // Ignorar volúmenes sin espacio real (< 1 GB: RAM disks, snapshots, etc.)
    if (totalGB < 1) continue;

    const usedPercent = Math.round((usedKB / totalKB) * 100);

    results.push({
      mount,
      totalGB,
      usedGB: Math.round((usedKB * KB) / GB * 100) / 100,
      freeGB: Math.round((freeKB * KB) / GB * 100) / 100,
      usedPercent,
    });
  }

  return results;
}

/**
 * Parsea la salida de "wmic logicaldisk get Caption,FreeSpace,Size" (Windows).
 * Las columnas aparecen en orden alfabético: Caption, FreeSpace, Size.
 */
function parseWmicOutput(stdout) {
  const lines = stdout.trim().split("\n");
  const results = [];

  for (const line of lines.slice(1)) { // saltar cabecera
    const parts = line.trim().split(/\s+/);
    if (parts.length < 3) continue;

    const caption = parts[0];   // e.g. "C:"
    const freeBytes = parseInt(parts[1], 10);
    const totalBytes = parseInt(parts[2], 10);

    if (isNaN(totalBytes) || totalBytes === 0) continue;

    const usedBytes = totalBytes - freeBytes;
    const usedPercent = Math.round((usedBytes / totalBytes) * 100);

    results.push({
      mount: caption,
      totalGB: Math.round(totalBytes / GB * 100) / 100,
      usedGB: Math.round(usedBytes / GB * 100) / 100,
      freeGB: Math.round(freeBytes / GB * 100) / 100,
      usedPercent,
    });
  }

  return results;
}

// ── API pública ─────────────────────────────────────────────────────────────

/**
 * Recolecta el uso de disco por partición montada.
 * @returns {Promise<Array<{mount, totalGB, usedGB, freeGB, usedPercent}>>}
 */
async function getDiskInfo() {
  if (process.platform === "win32") {
    const stdout = await execCommand(
      "wmic logicaldisk get Caption,FreeSpace,Size",
      10000
    );
    return parseWmicOutput(stdout);
  }

  // macOS y Linux
  const stdout = await execCommand("df -k", 10000);
  return parseDfOutput(stdout);
}

module.exports = { getDiskInfo };
