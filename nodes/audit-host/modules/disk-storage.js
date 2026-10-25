"use strict";

/** Una entrada por sistema de ficheros, no por punto de montaje: btrfs repite el mismo disco en cada subvolumen. */

const { ejecutar } = require("../../../lib/executor");

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

function aGB(kb) {
  return Math.round((kb * KB) / GB * 100) / 100;
}

function esPseudo(device, fsType) {
  if (fsType && PSEUDO_FS_TYPES.has(fsType.toLowerCase())) return true;
  if (fsType) return false;               // hay tipo y no está en la lista: es real
  return PSEUDO_DEVICES.has(String(device).toLowerCase());
}

/** Clave de deduplicado: el dispositivo, o el pool en ZFS (sus datasets comparten espacio). */
function claveSistemaFicheros(device, fsType) {
  if (fsType && fsType.toLowerCase() === "zfs") return "zfs:" + String(device).split("/")[0];
  return "dev:" + device;
}

/** btrfs repite la misma cifra; en ZFS el usado se suma y el libre se toma una vez. */
function juntarFilas(rows) {
  const first = rows[0];
  const mounts = rows.map((r) => r.mount).sort(function (a, b) {
    return a.length - b.length || a.localeCompare(b);
  });

  let totalGB, usedGB, freeGB, usedPercent;
  if (first.fsType && first.fsType.toLowerCase() === "zfs") {
    const usedKB = rows.reduce(function (acc, r) { return acc + r.usedKB; }, 0);
    const freeKB = Math.max.apply(null, rows.map(function (r) { return r.freeKB; }));
    usedGB = aGB(usedKB);
    freeGB = aGB(freeKB);
    totalGB = Math.round((usedGB + freeGB) * 100) / 100;
    if (usedKB + freeKB > 0) {
      usedPercent = Math.round((usedKB / (usedKB + freeKB)) * 100);
    } else {
      usedPercent = 0;
    }
  } else {
    totalGB = aGB(first.totalKB);
    usedGB = aGB(first.usedKB);
    freeGB = aGB(first.freeKB);
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

function quitarDuplicados(rows) {
  const groups = new Map();
  for (const r of rows) {
    const key = claveSistemaFicheros(r.device, r.fsType);
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(r);
  }
  return Array.from(groups.values())
    .map(juntarFilas)
    // Menos de 1 GB no es un disco que auditar: RAM disks, snapshots, /boot/efi.
    .filter(function (d) { return d.totalGB >= 1; });
}

/** Salida de `df -k` (macOS) o `df -kPT` / `df -kP` (Linux); hasType dice si viene la columna Type. */
function leerDf(stdout, hasType) {
  const lines = String(stdout).trim().split("\n");
  const rows = [];

  for (const line of lines.slice(1)) {
    // df parte en dos las líneas con nombres largos; las que quedan sin cifras se ignoran.
    const parts = line.trim().split(/\s+/);
    let min;
    if (hasType) {
      min = 7;
    } else {
      min = 6;
    }
    if (parts.length < min) continue;

    const device = parts[0];
    let fsType;
    if (hasType) {
      fsType = parts[1];
    } else {
      fsType = null;
    }
    let base;
    if (hasType) {
      base = 2;
    } else {
      base = 1;
    }
    const totalKB = parseInt(parts[base], 10);
    const usedKB = parseInt(parts[base + 1], 10);
    const freeKB = parseInt(parts[base + 2], 10);
    const mount = parts[parts.length - 1];

    if (isNaN(totalKB) || totalKB === 0) continue;
    if (!mount.startsWith("/")) continue;
    if (mount === "/dev") continue;
    // tmpfs en /run, /tmp o /dev/shm no es almacenamiento.
    if (esPseudo(device, fsType)) continue;
    // /System/Volumes/Data es el disco del usuario; el resto de volúmenes APFS son internos.
    if (mount.startsWith("/System/Volumes/") && mount !== "/System/Volumes/Data") continue;

    rows.push({ device, fsType, mount, totalKB, usedKB, freeKB });
  }

  return quitarDuplicados(rows);
}

/** wmic devuelve las columnas en orden alfabético. En Windows cada letra es un filesystem. */
function leerWmic(stdout) {
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

async function infoDisco() {
  if (process.platform === "win32") {
    const stdout = await ejecutar(
      "wmic logicaldisk get Caption,FreeSpace,Size",
      10000
    );
    return leerWmic(stdout);
  }

  if (process.platform === "linux") {
    // -T da el tipo (para zfs y tmpfs); -P fuerza una línea por montaje.
    try {
      const stdout = await ejecutar("df -kPT", 10000);
      return leerDf(stdout, true);
    } catch (e) {
      // busybox no tiene -T: se pierde el tipo, pero se sigue deduplicando por dispositivo.
      const stdout = await ejecutar("df -kP", 10000);
      return leerDf(stdout, false);
    }
  }

  // El df de BSD no imprime el tipo: ahí -T sirve para filtrar tipos, no para mostrarlos.
  const stdout = await ejecutar("df -k", 10000);
  return leerDf(stdout, false);
}

module.exports = { infoDisco, leerDf, leerWmic };
