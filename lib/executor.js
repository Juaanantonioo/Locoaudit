"use strict";

/** Lanzador de procesos externos con timeout. */

const { exec } = require("child_process");
const fs = require("fs");
const path = require("path");

/** Ruta del ejecutable dentro del PATH, o null. */
function which(cmd) {
  const paths = (process.env.PATH || "").split(path.delimiter);
  for (const p of paths) {
    const full = path.join(p, cmd);
    try {
      if (fs.existsSync(full)) return full;
      if (process.platform === "win32" && fs.existsSync(full + ".exe")) {
        return full + ".exe";
      }
    } catch (_) { /* directorio ilegible */ }
  }
  return null;
}

/** ¿Está el comando en el PATH? */
async function commandExists(cmd) {
  return which(cmd) !== null;
}

/**
 * Ejecuta un comando y resuelve con su stdout; al fallar rechaza con err.stdout,
 * err.stderr y err.code.
 */
function execCommand(cmd, timeoutMs = 10000, opts = {}) {
  return new Promise((resolve, reject) => {
    const child = exec(
      cmd,
      {
        timeout: timeoutMs,
        maxBuffer: opts.maxBuffer || 10 * 1024 * 1024, // trivy image pasa de 10 MiB de JSON en imágenes gordas
        // cmd.exe explícita: sin ella hay comandos que no resuelven en Windows
        ...(process.platform === "win32" ? { shell: "cmd.exe" } : {}),
      },
      (err, stdout, stderr) => {
        if (err) {
          err.stdout = stdout || "";
          err.stderr = stderr || "";
          return reject(err);
        }
        resolve(stdout || "");
      }
    );

    // El timeout no cubre el fallo al lanzar el proceso; 'error' sí.
    child.on("error", (err) => reject(err));
  });
}

module.exports = { commandExists, execCommand, which };
