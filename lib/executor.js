"use strict";

/** Lanzador de procesos externos con timeout. */

const { exec, execFile } = require("child_process");
const fs = require("fs");
const os = require("os");
const path = require("path");
const crypto = require("crypto");
// utils.js no importa executor.js: no hay ciclo.
const { withTempFile } = require("./utils");

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

// Directorios que Debian no pone en el PATH de un usuario normal (lynis vive en /usr/sbin). Solo Linux.
const LINUX_SBIN_DIRS = ["/usr/local/sbin", "/usr/sbin", "/sbin"];

/** ¿Existe y es ejecutable? Un fichero sin bit de ejecución no cuenta como la herramienta. */
function _isExecutable(file) {
  try {
    fs.accessSync(file, fs.constants.X_OK);
    return fs.statSync(file).isFile();
  } catch (_) {
    return false;
  }
}

/** Ruta absoluta del comando, o null. Devuelve la ruta para lanzar ese binario concreto,
 *  que puede estar fuera del PATH (p. ej. /usr/sbin/lynis). */
async function commandExists(cmd) {
  const inPath = which(cmd);
  if (inPath) return inPath;

  // Respaldo solo en Linux y solo si el PATH no lo encontró.
  if (process.platform !== "linux") return null;

  for (const dir of LINUX_SBIN_DIRS) {
    const full = path.join(dir, cmd);
    if (_isExecutable(full)) return full;
  }
  return null;
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
        // Algunas herramientas avisan por stderr aunque salgan con 0 (journalctl sin permisos).
        resolve(opts.withStderr ? { stdout: stdout || "", stderr: stderr || "" } : stdout || "");
      }
    );

    // El timeout no cubre el fallo al lanzar el proceso; 'error' sí.
    child.on("error", (err) => reject(err));
  });
}

/** Como execCommand pero sin shell: programa y argumentos por separado. Para datos externos. */
function execFileCommand(file, args, timeoutMs = 10000, opts = {}) {
  return new Promise((resolve, reject) => {
    const child = execFile(
      file,
      args,
      { timeout: timeoutMs, maxBuffer: opts.maxBuffer || 10 * 1024 * 1024 },
      (err, stdout, stderr) => {
        if (err) {
          err.stdout = stdout || "";
          err.stderr = stderr || "";
          return reject(err);
        }
        resolve(stdout || "");
      }
    );
    child.on("error", (err) => reject(err));
  });
}

/** Ejecuta buildCmd(ruta) (línea de shell, o array [programa, ...args] sin shell) y devuelve el JSON que deja en el fichero;
 *  a fichero para que el tamaño no choque con maxBuffer. Nunca lanza por la salida: devuelve { skipped, kind, reason }. */
async function execToFile(buildCmd, timeoutMs = 10000, opts = {}) {
  const { prefix = "lcaudit-", ext = ".json" } = opts;
  // Nombre impredecible: el tmpdir es compartido y un nombre adivinable permite plantar un symlink.
  const name = `${prefix}${process.pid}-${Date.now()}-${crypto.randomBytes(6).toString("hex")}${ext}`;
  const file = path.join(os.tmpdir(), name);

  try {
    try {
      const cmd = buildCmd(file);
      if (Array.isArray(cmd)) await execFileCommand(cmd[0], cmd.slice(1), timeoutMs, opts);
      else await execCommand(cmd, timeoutMs, opts);
    } catch (err) {
      // Un exit distinto de cero no es concluyente (trivy lo da al encontrar vulnerabilidades): decide el fichero.
      if (err.code === "ERR_CHILD_PROCESS_STDIO_MAXBUFFER") {
        return {
          skipped: true,
          kind: "output-too-large",
          reason:
            `El comando escupió por stdout más de lo que cabe en el buffer (${opts.maxBuffer || 10 * 1024 * 1024} bytes) ` +
            "y el proceso fue terminado antes de acabar. La salida capturada está cortada a mitad y no se usa.",
        };
      }
      if (!fs.existsSync(file)) {
        const detail = (err.stderr || err.message || "unknown error").trim();
        const timedOut = err.killed || err.signal === "SIGTERM";
        return {
          skipped: true,
          kind: timedOut ? "timeout" : "error",
          reason: timedOut
            ? `El comando superó el límite de ${Math.round(timeoutMs / 1000)} s sin terminar y no dejó ninguna salida.`
            : `El comando falló sin dejar salida: ${detail}`,
        };
      }
      // Hay fichero: sigue adelante y que lo juzgue su contenido.
    }

    let content;
    try {
      content = fs.readFileSync(file, "utf8");
    } catch (readErr) {
      return {
        skipped: true,
        kind: "empty-output",
        reason: `El comando terminó pero no se pudo leer su salida en ${file}: ${readErr.message}`,
      };
    }

    if (!content.trim()) {
      return {
        skipped: true,
        kind: "empty-output",
        reason: "El comando terminó sin escribir nada en su fichero de salida.",
      };
    }

    try {
      return JSON.parse(content);
    } catch (parseErr) {
      return {
        skipped: true,
        kind: "invalid-json",
        // El principio de la salida suele ser el mensaje de error de la herramienta.
        reason:
          `La salida del comando no es JSON válido (${parseErr.message}). ` +
          `Primeros 200 caracteres: ${content.slice(0, 200)}`,
      };
    }
  } finally {
    // El temporal se borra siempre, también si hubo error.
    try { fs.rmSync(file, { force: true }); } catch (_) { /* ya no está, o no es nuestro */ }
  }
}

/** Cabecera de todo script de PowerShell: salida en UTF-8 sin BOM para que los acentos no lleguen como mojibake.
 *  Se fija en el script y no con `chcp 65001`, que cambiaría la consola entera. */
const PS_UTF8_PRELUDE = [
  "[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding $false",
  "$OutputEncoding = [Console]::OutputEncoding",
].join("\n");

/** Ejecuta un script de PowerShell desde un .ps1 temporal con BOM y `-File`, no `-Command`: así no hay límite
 *  de 8191 caracteres ni saltos de línea que corten cmd.exe. withTempFile borra el script siempre. */
async function runPowerShell(shell, script, timeoutMs = 10000, opts = {}) {
  const completo = `${PS_UTF8_PRELUDE}\n${script}`;
  return withTempFile(
    completo,
    { prefix: opts.prefix || "lcaudit-ps-", ext: ".ps1", bom: true },
    (scriptPath) =>
      execCommand(
        `${shell} -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "${scriptPath}"`,
        timeoutMs,
        opts
      )
  );
}

module.exports = {
  commandExists,
  execCommand,
  execFileCommand,
  execToFile,
  runPowerShell,
  which,
  LINUX_SBIN_DIRS,
  PS_UTF8_PRELUDE,
};
