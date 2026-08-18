"use strict";

/**
 * disk-storage.js — Uso de disco por sistema de ficheros montado.
 *
 * macOS:   parsea "df -k"
 * Linux:   parsea "df -kPT" (con tipo de sistema de ficheros; degrada a "df -kP")
 * Windows: parsea "wmic logicaldisk get Caption,Size,FreeSpace"
 *
 * IMPORTANTE — una entrada por SISTEMA DE FICHEROS, no por punto de montaje.
 * En btrfs (CachyOS, Fedora, openSUSE) el layout por defecto monta varios
 * subvolúmenes —/, /home, /var/log, /var/cache, /root, /srv…— desde el MISMO
 * dispositivo, y `df` repite la misma fila con distinto "Mounted on". Sin
 * deduplicar, cada subvolumen generaba un finding HOST-DISK-*, inflando la
 * cabecera y el donut del dashboard con 6-8 copias del mismo disco.
 *
 * Exporta:
 *   getDiskInfo() → Promise<Array<{
 *     mount: string,          // punto de montaje representativo (el más corto)
 *     mounts: string[],       // todos los puntos de montaje de ese filesystem
 *     device: string,         // dispositivo / dataset según df
 *     fsType: string|null,    // tipo (solo Linux); null si df no lo reporta
 *     totalGB: number,
 *     usedGB: number,
 *     freeGB: number,
 *     usedPercent: number
 *   }>>
 */

const { execCommand } = require("../../../lib/executor");

const KB = 1024;
const GB = KB * KB * KB;

// Tipos que no son almacenamiento persistente: viven en RAM o son interfaces
// del kernel. `df` los lista con tamaños de varios GB (tmpfs = media RAM), así
// que sin filtrarlos aparecían como "discos" en el informe.
const PSEUDO_FS_TYPES = new Set([
  "tmpfs", "devtmpfs", "ramfs", "devfs", "overlay", "squashfs", "efivarfs",
  "autofs", "proc", "sysfs", "devpts", "cgroup", "cgroup2", "debugfs",
  "tracefs", "configfs", "securityfs", "pstore", "bpf", "mqueue",
  "hugetlbfs", "binfmt_misc", "fusectl", "nsfs", "selinuxfs", "none",
]);

// Cuando df no reporta el tipo (macOS, busybox) solo queda el nombre del
// dispositivo. Estos nombres son pseudo-filesystems en cualquier Unix.
const PSEUDO_DEVICES = new Set([
  "tmpfs", "devtmpfs", "ramfs", "devfs", "udev", "dev", "run", "none",
  "overlay", "shm", "proc", "sysfs", "systemd-1", "map",
]);

// ── Helpers ─────────────────────────────────────────────────────────────────

function toGB(kb) {
  return Math.round((kb * KB) / GB * 100) / 100;
}

function isPseudo(device, fsType) {
  if (fsType && PSEUDO_FS_TYPES.has(fsType.toLowerCase())) return true;
  if (fsType) return false;               // tipo conocido y real → no es pseudo
  return PSEUDO_DEVICES.has(String(device).toLowerCase());
}

/**
 * Clave de agrupación: qué filas de `df` describen el MISMO almacenamiento.
 *
 * - Caso general (btrfs, ext4, xfs, apfs, bind mounts): el dispositivo. Varios
 *   montajes del mismo dispositivo son el mismo filesystem; df repite cifras
 *   idénticas.
 * - ZFS: cada dataset es un "dispositivo" distinto (`pool/ROOT/default`,
 *   `pool/home`) pero TODOS consumen el espacio libre del mismo pool — df
 *   reporta el mismo "Available" en todos. La unidad real de capacidad es el
 *   pool, así que la clave es el primer componente del dataset.
 *   Requiere conocer el tipo, o sea Linux: en macOS (OpenZFS) no se agrupa y
 *   cada dataset sigue dando su propia entrada.
 */
function fsGroupKey(device, fsType) {
  if (fsType && fsType.toLowerCase() === "zfs") return "zfs:" + String(device).split("/")[0];
  return "dev:" + device;
}

/**
 * Colapsa las filas de un mismo filesystem en una sola entrada.
 *
 * btrfs y compañía: las filas son la misma cifra repetida → se toma una.
 * ZFS: los datasets son cifras DISTINTAS que comparten el espacio libre del
 * pool → el usado se suma y el libre (idéntico en todas) se toma una vez.
 */
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
    // El porcentaje se calcula sobre los KB crudos, no sobre los GB ya
    // redondeados: si no, un disco al 75,4 % podía saltar de banda de severidad.
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
    // Ignorar volúmenes sin espacio real (< 1 GB: RAM disks, snapshots, /boot/efi).
    .filter(function (d) { return d.totalGB >= 1; });
}

// ── Parsers ─────────────────────────────────────────────────────────────────

/**
 * Parsea la salida de `df -k` (macOS) o `df -kPT` / `df -kP` (Linux).
 * @param {string} stdout
 * @param {boolean} hasType  true si la salida incluye la columna Type (df -T)
 */
function parseDfOutput(stdout, hasType) {
  const lines = String(stdout).trim().split("\n");
  const rows = [];

  for (const line of lines.slice(1)) { // saltar cabecera
    // df -k puede partir líneas largas en dos; ignoramos líneas sin cifras
    const parts = line.trim().split(/\s+/);
    const min = hasType ? 7 : 6;
    if (parts.length < min) continue;

    const device = parts[0];
    const fsType = hasType ? parts[1] : null;
    const base = hasType ? 2 : 1;
    const totalKB = parseInt(parts[base], 10);
    const usedKB = parseInt(parts[base + 1], 10);
    const freeKB = parseInt(parts[base + 2], 10);
    const mount = parts[parts.length - 1]; // último campo = punto de montaje

    if (isNaN(totalKB) || totalKB === 0) continue;
    if (!mount.startsWith("/")) continue;
    if (mount === "/dev") continue;
    // Pseudo-filesystems: tmpfs en /run, /tmp, /dev/shm… no son almacenamiento.
    if (isPseudo(device, fsType)) continue;
    // /System/Volumes/Data es el volumen de datos del usuario en macOS APFS
    // (contiene /Users, /Applications, etc.) — debe mostrarse aunque sea un
    // subvolumen de /System/Volumes/. Los demás subvolúmenes APFS son internos
    // del sistema y no aportan información útil al usuario.
    if (mount.startsWith("/System/Volumes/") && mount !== "/System/Volumes/Data") continue;

    rows.push({ device, fsType, mount, totalKB, usedKB, freeKB });
  }

  return dedupeByFilesystem(rows);
}

/**
 * Parsea la salida de "wmic logicaldisk get Caption,FreeSpace,Size" (Windows).
 * Las columnas aparecen en orden alfabético: Caption, FreeSpace, Size.
 * Windows no tiene subvolúmenes: una letra de unidad = un filesystem.
 */
function parseWmicOutput(stdout) {
  const lines = String(stdout).trim().split("\n");
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

// ── API pública ─────────────────────────────────────────────────────────────

/**
 * Recolecta el uso de disco, una entrada por sistema de ficheros.
 * @returns {Promise<Array<{mount, mounts, device, fsType, totalGB, usedGB, freeGB, usedPercent}>>}
 */
async function getDiskInfo() {
  if (process.platform === "win32") {
    const stdout = await execCommand(
      "wmic logicaldisk get Caption,FreeSpace,Size",
      10000
    );
    return parseWmicOutput(stdout);
  }

  if (process.platform === "linux") {
    // -T añade la columna Type (necesaria para distinguir zfs y descartar
    // tmpfs); -P fuerza salida POSIX en una línea por montaje.
    try {
      const stdout = await execCommand("df -kPT", 10000);
      return parseDfOutput(stdout, true);
    } catch (e) {
      // busybox/toybox df no implementan -T: se pierde el tipo, pero el
      // deduplicado por dispositivo (el caso btrfs) sigue funcionando.
      const stdout = await execCommand("df -kP", 10000);
      return parseDfOutput(stdout, false);
    }
  }

  // macOS: BSD df no imprime el tipo (-T selecciona tipos, no los muestra).
  const stdout = await execCommand("df -k", 10000);
  return parseDfOutput(stdout, false);
}

module.exports = { getDiskInfo, parseDfOutput, parseWmicOutput };
