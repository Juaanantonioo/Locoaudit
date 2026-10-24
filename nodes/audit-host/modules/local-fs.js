"use strict";

/** Red y nube quedan fuera de ámbito; se detectan por sistema de ficheros, nunca por el nombre de la carpeta. */

const { execSync, execFileSync } = require("child_process");

/** Tipos remotos en Linux (stat -f -c %T). "fuseblk" no entra: es ntfs-3g, disco local. */
const LINUX_REMOTE = new Set([
  "nfs", "nfs4", "cifs", "smb", "smb2", "smbfs", "afs", "webdav", "davfs", "sshfs", "9p",
]);

/** Tipos remotos en macOS (columna de tipo de `mount`). */
const DARWIN_REMOTE = new Set([
  "smbfs", "nfs", "afpfs", "webdav", "ftp", "macfuse", "osxfuse", "dfsfuse_dfs",
]);

const EXEC_OPTS = { timeout: 5000, stdio: ["ignore", "pipe", "ignore"] };

function sh(cmd) {
  return execSync(cmd, EXEC_OPTS).toString().trim();
}

/** Sin shell: el nombre de la carpeta es externo. Sin "--" porque las rutas son absolutas y el xattr de macOS no lo garantiza. */
function run(file, args) {
  return execFileSync(file, args, EXEC_OPTS).toString().trim();
}

/** Linux: el tipo de sistema de ficheros lo da stat, sin parsear /proc/mounts. */
function classifyLinux(dir) {
  const type = run("stat", ["-f", "-c", "%T", dir]).toLowerCase();
  if (type.startsWith("fuse.") || LINUX_REMOTE.has(type)) {
    return { local: false, kind: "network", detail: `sistema de ficheros ${type}` };
  }
  return { local: true, kind: "local", detail: `sistema de ficheros ${type}` };
}

/** macOS: los montajes de red salen en `mount`; la nube sincronizada se reconoce por su xattr file-provider. */
function classifyDarwin(dir) {
  try {
    const attrs = run("xattr", [dir]);
    if (/com\.apple\.file-provider-domain-id/.test(attrs)) {
      return { local: false, kind: "cloud", detail: "dominio de File Provider (nube sincronizada)" };
    }
  } catch (_) { /* sin xattr legibles: se sigue con el montaje */ }

  const mountPoint = run("df", ["-P", dir]).split("\n").pop().split(/\s+/).slice(5).join(" ");
  const mounts = sh("mount");
  for (const line of mounts.split("\n")) {
    // "<origen> on <punto> (<tipo>, <opciones…>)"
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

/** Nunca lanza: si la sonda falla, 'unknown' con local:true para no dejar software sin auditar. */
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
