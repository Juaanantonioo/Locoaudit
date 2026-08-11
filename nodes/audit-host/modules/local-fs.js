"use strict";

/**
 * local-fs.js — ¿Un directorio vive en almacenamiento LOCAL del equipo?
 *
 * LoCoAudit audita el almacenamiento local: las unidades de red y el
 * almacenamiento en la nube quedan fuera de ámbito por definición, no por
 * limitación técnica. Su contenido no es software que este equipo ejecute, y
 * recorrerlo obliga a materializar ficheros remotos (lento, y con montajes que
 * no responden aborta el escaneo entero).
 *
 * La detección es NATIVA por plataforma —tipo de sistema de ficheros y marcas
 * del propio SO—, nunca una lista de nombres de carpeta: "Google Drive" puede
 * llamarse de cualquier forma, y una carpeta llamada "OneDrive" puede ser un
 * directorio normal.
 *
 * Exporta:
 *   classifyDir(dir) → { local: boolean, kind: 'local'|'network'|'cloud'|'unknown', detail: string }
 */

const { execSync } = require("child_process");

/**
 * Tipos de sistema de ficheros REMOTOS en Linux (stat -f -c %T).
 * El prefijo "fuse." cubre sshfs, rclone, gdrive, s3fs… sin enumerarlos.
 * Nota: "fuseblk" NO entra — es ntfs-3g, un disco local.
 */
const LINUX_REMOTE = new Set([
  "nfs", "nfs4", "cifs", "smb", "smb2", "smbfs", "afs", "webdav", "davfs", "sshfs", "9p",
]);

/** Tipos remotos en macOS (columna de tipo de `mount`). */
const DARWIN_REMOTE = new Set([
  "smbfs", "nfs", "afpfs", "webdav", "ftp", "macfuse", "osxfuse", "dfsfuse_dfs",
]);

function sh(cmd) {
  return execSync(cmd, { timeout: 5000, stdio: ["ignore", "pipe", "ignore"] }).toString().trim();
}

/** Linux: el tipo de sistema de ficheros lo da stat, sin parsear /proc/mounts. */
function classifyLinux(dir) {
  const type = sh(`stat -f -c %T ${JSON.stringify(dir)}`).toLowerCase();
  if (type.startsWith("fuse.") || LINUX_REMOTE.has(type)) {
    return { local: false, kind: "network", detail: `sistema de ficheros ${type}` };
  }
  return { local: true, kind: "local", detail: `sistema de ficheros ${type}` };
}

/**
 * macOS: dos señales distintas y ambas necesarias.
 *
 *   1. Montaje de red real (SMB/NFS/AFP/FUSE) → aparece en `mount`.
 *   2. Almacenamiento en la nube SINCRONIZADO (Google Drive, iCloud, OneDrive,
 *      Dropbox). MEDIDO: NO es un montaje — vive en el APFS local
 *      (/System/Volumes/Data) y `mount` no lo lista. Lo delata el atributo
 *      extendido `com.apple.file-provider-domain-id`, que macOS pone en la raíz
 *      de cada dominio de File Provider. Sin esta segunda comprobación, Google
 *      Drive se clasificaría como local y volvería a tumbar el escaneo.
 */
function classifyDarwin(dir) {
  try {
    const attrs = sh(`xattr ${JSON.stringify(dir)}`);
    if (/com\.apple\.file-provider-domain-id/.test(attrs)) {
      return { local: false, kind: "cloud", detail: "dominio de File Provider (nube sincronizada)" };
    }
  } catch (_) { /* sin xattr legibles: se sigue con el montaje */ }

  const mountPoint = sh(`df -P ${JSON.stringify(dir)}`).split("\n").pop().split(/\s+/).slice(5).join(" ");
  const mounts = sh("mount");
  for (const line of mounts.split("\n")) {
    // Formato: "<origen> on <punto> (<tipo>, <opciones…>)"
    const m = line.match(/^(.*) on (.*) \(([^,)]+)/);
    if (!m) continue;
    if (m[2] === mountPoint) {
      const type = m[3].trim().toLowerCase();
      if (DARWIN_REMOTE.has(type)) {
        return { local: false, kind: "network", detail: `montaje ${type}` };
      }
      return { local: true, kind: "local", detail: `montaje ${type}` };
    }
  }
  return { local: true, kind: "local", detail: "montaje no identificado" };
}

/** Windows: DriveType 4 = unidad de red (Win32_LogicalDisk). */
function classifyWin32(dir) {
  const drive = (dir.match(/^([A-Za-z]:)/) || [])[1];
  if (!drive) return { local: true, kind: "unknown", detail: "sin letra de unidad" };
  const out = sh(
    `powershell -NoProfile -Command "(Get-CimInstance Win32_LogicalDisk -Filter \\"DeviceID='${drive}'\\").DriveType"`
  );
  if (out.trim() === "4") {
    return { local: false, kind: "network", detail: "unidad de red (DriveType 4)" };
  }
  return { local: true, kind: "local", detail: `DriveType ${out.trim() || "?"}` };
}

/**
 * Clasifica un directorio como almacenamiento local o no.
 * Nunca lanza: ante cualquier fallo devuelve 'unknown' con local:true, para no
 * excluir por error una carpeta legítima. Un directorio que no responda se
 * detecta igualmente al escanearlo, y ahí se aísla (ver trivy-fs.js).
 *
 * @param {string} dir  Ruta absoluta.
 * @returns {{ local: boolean, kind: 'local'|'network'|'cloud'|'unknown', detail: string }}
 */
function classifyDir(dir) {
  try {
    if (process.platform === "linux")  return classifyLinux(dir);
    if (process.platform === "darwin") return classifyDarwin(dir);
    if (process.platform === "win32")  return classifyWin32(dir);
    return { local: true, kind: "unknown", detail: `plataforma ${process.platform} sin sonda` };
  } catch (err) {
    return { local: true, kind: "unknown", detail: `no se pudo determinar: ${(err && err.message) || err}` };
  }
}

module.exports = { classifyDir, LINUX_REMOTE, DARWIN_REMOTE };
