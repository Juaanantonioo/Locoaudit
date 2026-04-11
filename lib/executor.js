"use strict";

/**
 * executor.js — Lanzador de procesos externos con timeout y manejo de errores.
 *
 * Exporta:
 *   commandExists(cmd)              → Promise<boolean>
 *   execCommand(cmd, timeoutMs)     → Promise<string>  (stdout)
 */

const { exec } = require("child_process");
const fs = require("fs");
const path = require("path");

/**
 * Busca un ejecutable en el PATH del sistema.
 * @param {string} cmd
 * @returns {string|null} Ruta completa o null si no existe.
 */
function which(cmd) {
  const paths = (process.env.PATH || "").split(path.delimiter);
  for (const p of paths) {
    const full = path.join(p, cmd);
    try {
      if (fs.existsSync(full)) return full;
      if (process.platform === "win32" && fs.existsSync(full + ".exe")) {
        return full + ".exe";
      }
    } catch (_) { /* skip */ }
  }
  return null;
}

/**
 * Comprueba si un comando está disponible en el PATH.
 * @param {string} cmd
 * @returns {Promise<boolean>}
 */
async function commandExists(cmd) {
  return which(cmd) !== null;
}

/**
 * Ejecuta un comando de shell con timeout.
 * Resuelve con stdout (string) si el comando termina con código 0.
 * Rechaza con un error enriquecido (err.stdout, err.stderr, err.code) si falla.
 *
 * @param {string} cmd          Comando completo a ejecutar.
 * @param {number} [timeoutMs]  Timeout en milisegundos (por defecto 10 000).
 * @returns {Promise<string>}   stdout del proceso.
 */
function execCommand(cmd, timeoutMs = 10000) {
  return new Promise((resolve, reject) => {
    const child = exec(
      cmd,
      {
        timeout: timeoutMs,
        maxBuffer: 10 * 1024 * 1024, // 10 MiB
        // En Windows, algunos comandos necesitan shell explícita
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

    // child_process ya maneja el timeout internamente con la opción timeout,
    // pero añadimos el evento por si el proceso se cuelga sin salir.
    child.on("error", (err) => reject(err));
  });
}

module.exports = { commandExists, execCommand, which };
