"use strict";

/** Una entrada por sistema de ficheros, no por punto de montaje: btrfs repite el mismo disco en cada subvolumen. */

const { execCommand } = require("../../../lib/executor");

const KB = 1024;
const GB = KB * KB * KB;

// RAM e interfaces del kernel: df los lista, pero no son discos.
const PSEUDO_FS_TYPES = new Set([
  "tmpfs", "devtmpfs", "ramfs", "devfs", "overlay", "squashfs", "efivarfs",
  "autofs", "proc", "sysfs", "devpts", "cgroup", "cgroup2", "debugfs",
  "tracefs", "configfs", "securityfs", "pstore", "bpf", "mqueue",
  "hugetlbfs", "binfmt_misc", "fusectl", "nsfs", "selinuxfs", "none",
]);

// Sin columna de tipo (macOS, busybox) solo queda el nombre: estos lo son en cualquier Unix.
const PSEUDO_DEVICES = new Set([
  "tmpfs", "devtmpfs", "ramfs", "devfs", "udev", "dev", "run", "none",
  "overlay", "shm", "proc", "sysfs", "systemd-1", "map",
]);

function toGB(kb) {
  return Math.round((kb * KB) / GB * 100) / 100;
}

function isPseudo(device, fsType) {
  if (fsType && PSEUDO_FS_TYPES.has(fsType.toLowerCase())) return true;
  if (fsType) return false;               // hay tipo y no está en la lista: es real
  return PSEUDO_DEVICES.has(String(device).toLowerCase());
}

/** Clave de deduplicado: el dispositivo, o el pool en ZFS (sus datasets comparten espacio). */
function fsGroupKey(device, fsType) {
  if (fsType && fsType.toLowerCase() === "zfs") return "zfs:" + String(device).split("/")[0];
  return "dev:" + device;
}

/** btrfs repite la misma cifra; en ZFS el usado se suma y el libre se toma una vez. */
function collapseRows(rows) {
  const first = rows[0];
  const mounts = rows.map((r) => r.mount).sort(function (a, b) {
    return a.length - b.length || a.localeCompare(b);
  });

  let totalGB, usedGB, freeGB, usedPercent;
  if (first.fsType && first.fsType.toLowerCase() === "zfs") {
    const usedKB = rows.reduce(function (acc, r) { return acc + r.usedKB; }, 0);
    const freeKB = Math.max.apply(null, rows.map(function (r) { return r.freeKB; }));
    usedGB = toGB(usedKB);
    freeGB = toGB(freeKB);
    totalGB = Math.round((usedGB + freeGB) * 100) / 100;
    usedPercent = usedKB + freeKB > 0 ? Math.round((usedKB / (usedKB + freeKB)) * 100) : 0;
  } else {
    totalGB = toGB(first.totalKB);
    usedGB = toGB(first.usedKB);
    freeGB = toGB(first.freeKB);
    // Sobre los KB crudos, no sobre los GB redondeados: un disco al 75,4 % cambiaba de banda.
    usedPercent = Math.round((first.usedKB / first.totalKB) * 100);
  }

  return {
    mount: mounts[0],
    mounts,
    device: first.device,
    fsType: first.fsType,
    totalGB,
    usedGB,
    freeGB,
    usedPercent,
  };
}

function dedupeByFilesystem(rows) {
  const groups = new Map();
  for (const r of rows) {
    const key = fsGroupKey(r.device, r.fsType);
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(r);
  }
  return Array.from(groups.values())
    .map(collapseRows)
    // Menos de 1 GB no es un disco que auditar: RAM disks, snapshots, /boot/efi.
    .filter(function (d) { return d.totalGB >= 1; });
}

/** Salida de `df -k` (macOS) o `df -kPT` / `df -kP` (Linux); hasType dice si viene la columna Type. */
function parseDfOutput(stdout, hasType) {
  const lines = String(stdout).trim().split("\n");
  const rows = [];

  for (const line of lines.slice(1)) {
    // df parte en dos las líneas con nombres largos; las que quedan sin cifras se ignoran.
    const parts = line.trim().split(/\s+/);
    const min = hasType ? 7 : 6;
    if (parts.length < min) continue;

    const device = parts[0];
    const fsType = hasType ? parts[1] : null;
    const base = hasType ? 2 : 1;
    const totalKB = parseInt(parts[base], 10);
    const usedKB = parseInt(parts[base + 1], 10);
    const freeKB = parseInt(parts[base + 2], 10);
    const mount = parts[parts.length - 1];

    if (isNaN(totalKB) || totalKB === 0) continue;
    if (!mount.startsWith("/")) continue;
    if (mount === "/dev") continue;
    // tmpfs en /run, /tmp o /dev/shm no es almacenamiento.
    if (isPseudo(device, fsType)) continue;
    // /System/Volumes/Data es el disco del usuario; el resto de volúmenes APFS son internos.
    if (mount.startsWith("/System/Volumes/") && mount !== "/System/Volumes/Data") continue;

    rows.push({ device, fsType, mount, totalKB, usedKB, freeKB });
  }

  return dedupeByFilesystem(rows);
}

/** wmic devuelve las columnas en orden alfabético. En Windows cada letra es un filesystem. */
function parseWmicOutput(stdout) {
  const lines = String(stdout).trim().split("\n");
  const results = [];

  for (const line of lines.slice(1)) {
    const parts = line.trim().split(/\s+/);
    if (parts.length < 3) continue;

    const caption = parts[0];
    const freeBytes = parseInt(parts[1], 10);
    const totalBytes = parseInt(parts[2], 10);

    if (isNaN(totalBytes) || totalBytes === 0) continue;

    const usedBytes = totalBytes - freeBytes;
    const usedPercent = Math.round((usedBytes / totalBytes) * 100);

    results.push({
      mount: caption,
      mounts: [caption],
      device: caption,
      fsType: null,
      totalGB: Math.round(totalBytes / GB * 100) / 100,
      usedGB: Math.round(usedBytes / GB * 100) / 100,
      freeGB: Math.round(freeBytes / GB * 100) / 100,
      usedPercent,
    });
  }

  return results;
}

async function getDiskInfo() {
  if (process.platform === "win32") {
    const stdout = await execCommand(
      "wmic logicaldisk get Caption,FreeSpace,Size",
      10000
    );
    return parseWmicOutput(stdout);
  }

  if (process.platform === "linux") {
    // -T da el tipo (para zfs y tmpfs); -P fuerza una línea por montaje.
    try {
      const stdout = await execCommand("df -kPT", 10000);
      return parseDfOutput(stdout, true);
    } catch (e) {
      // busybox no tiene -T: se pierde el tipo, pero se sigue deduplicando por dispositivo.
      const stdout = await execCommand("df -kP", 10000);
      return parseDfOutput(stdout, false);
    }
  }

  // El df de BSD no imprime el tipo: ahí -T sirve para filtrar tipos, no para mostrarlos.
  const stdout = await execCommand("df -k", 10000);
  return parseDfOutput(stdout, false);
}

module.exports = { getDiskInfo, parseDfOutput, parseWmicOutput };
