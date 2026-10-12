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

/**
 * Directorios de administración que Debian y derivadas NO ponen en el PATH de un usuario normal.
 * lynis se instala en /usr/sbin y `which lynis` falla ahí aunque el binario esté y sea ejecutable;
 * nvm reescribe además el PATH y se lleva por delante lo poco que quedaba. Solo Linux: en macOS
 * /usr/sbin ya está en el PATH por defecto y Windows no tiene este reparto de directorios.
 */
const LINUX_SBIN_DIRS = ["/usr/local/sbin", "/usr/sbin", "/sbin"];

/** ¿Existe el fichero y lo podemos ejecutar? El bit de ejecución importa: un fichero suelto en
 *  /usr/sbin que no se puede ejecutar no es la herramienta, y devolverlo movería el fallo al
 *  momento de lanzarla, con un mensaje mucho peor. */
function _isExecutable(file) {
  try {
    fs.accessSync(file, fs.constants.X_OK);
    return fs.statSync(file).isFile();
  } catch (_) {
    return false;
  }
}

/**
 * Ruta absoluta del comando, o null si no está. Devuelve la ruta y no un booleano para que el
 * llamante ejecute EL binario que se encontró y no otro: en Debian, `commandExists("lynis")`
 * resuelve /usr/sbin/lynis, que no está en el PATH, y lanzar "lynis" a secas volvería a fallar.
 * Sigue siendo truthy/falsy, así que los `if (!(await commandExists(x)))` de siempre valen igual.
 */
async function commandExists(cmd) {
  const inPath = which(cmd);
  if (inPath) return inPath;

  // Solo cuando el PATH ya ha dicho que no, y solo en Linux: macOS y Windows se quedan
  // exactamente como estaban.
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
        resolve(stdout || "");
      }
    );

    // El timeout no cubre el fallo al lanzar el proceso; 'error' sí.
    child.on("error", (err) => reject(err));
  });
}

/**
 * Como execCommand, pero sin shell: el programa y sus argumentos van por separado. Es la forma de
 * pasar datos que no controla LoCoAudit, como nombres de carpeta del home. Con execCommand esos
 * datos acaban dentro de una línea que interpreta /bin/sh, y una carpeta llamada `$(orden)`
 * ejecutaba la orden aunque fuese entre comillas dobles. Aquí ningún carácter tiene significado.
 */
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

/**
 * Ejecuta un comando que escribe su salida a un fichero y devuelve ese JSON ya parseado.
 *
 * Por qué existe, aparte de execCommand: `trivy rootfs /` produce 24 MB de JSON en una Debian 13
 * normal, y exec() acumula stdout en memoria contra `maxBuffer`. Al pasarse, Node MATA el proceso
 * y entrega en err.stdout lo que había capturado hasta el corte: un JSON truncado a medio objeto.
 * Ese trozo tiene toda la pinta de una salida válida —empieza por '{'— y el JSON.parse fallaba con
 * "trivy output is not valid JSON", que manda a diagnosticar la herramienta cuando el problema era
 * nuestro. Escribiendo a fichero no hay techo que rebasar y el tamaño deja de importar.
 *
 * `buildCmd` recibe la ruta del temporal y devuelve la línea a ejecutar: quien llama decide dónde
 * va el -o, que cambia de herramienta a herramienta. Si devuelve un array [programa, ...args] se
 * ejecuta sin shell con execFileCommand, que es lo que toca cuando algún argumento viene de fuera.
 *
 * Nunca lanza por culpa de la salida: los tres fallos posibles salen como { skipped, kind, reason }
 * con el MISMO contrato que los wrappers, para que el llamante decida por `kind` y no por el texto.
 *   - 'output-too-large'  el propio comando reventó el buffer de stdout (no debería, pero si el
 *                         comando ecoa por stdout además de escribir el fichero, se distingue).
 *   - 'empty-output'      terminó sin dejar fichero, o lo dejó vacío: no hay nada que interpretar.
 *   - 'invalid-json'      hay contenido pero no es JSON. Se guardan los primeros 200 caracteres,
 *                         que es lo único que permite diagnosticar sin repetir la ejecución.
 */
async function execToFile(buildCmd, timeoutMs = 10000, opts = {}) {
  const { prefix = "lcaudit-", ext = ".json" } = opts;
  // Nombre único e impredecible: el tmpdir es compartido y un nombre adivinable deja que otro
  // usuario plante ahí un enlace simbólico. PID y timestamp solos no bastan para eso.
  const name = `${prefix}${process.pid}-${Date.now()}-${crypto.randomBytes(6).toString("hex")}${ext}`;
  const file = path.join(os.tmpdir(), name);

  try {
    try {
      const cmd = buildCmd(file);
      if (Array.isArray(cmd)) await execFileCommand(cmd[0], cmd.slice(1), timeoutMs, opts);
      else await execCommand(cmd, timeoutMs, opts);
    } catch (err) {
      // Un exit distinto de cero NO es concluyente: trivy sale con código propio cuando encuentra
      // vulnerabilidades y el fichero está perfectamente escrito. Quien decide es el fichero.
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
        // El principio de los datos reales, no solo el mensaje del parser: casi siempre es un
        // mensaje de error de la herramienta y ahí se lee de un vistazo.
        reason:
          `La salida del comando no es JSON válido (${parseErr.message}). ` +
          `Primeros 200 caracteres: ${content.slice(0, 200)}`,
      };
    }
  } finally {
    // También en el camino de error, también si el parseo lanzó: el temporal no sobrevive.
    try { fs.rmSync(file, { force: true }); } catch (_) { /* ya no está, o no es nuestro */ }
  }
}

/**
 * Cabecera que se antepone a TODO script de PowerShell que lance LoCoAudit.
 *
 * El problema que resuelve: PowerShell escribe su salida en la página de códigos OEM de la
 * consola (CP850 en un Windows en español, CP437 en uno en inglés), y Node lee stdout como UTF-8
 * porque es su valor por defecto. Cualquier acento sale como mojibake — se vio literalmente como
 * "En l�nea" y "Car�cter" en un informe de Windows. No es un fallo de un módulo: afecta a las
 * tres rutas que usan PowerShell (pending-updates, security-events, local-fs), así que la
 * cabecera vive aquí y no en ninguna de ellas.
 *
 * Se hace DENTRO del script y no con `chcp 65001`: `chcp` cambia la página de códigos de la
 * consola entera, puede fallar según la configuración del equipo, y ensucia la línea de comandos.
 * Esto es local al proceso de PowerShell y muere con él.
 *
 * `New-Object` en vez de `[Text.UTF8Encoding]::new()`: funciona igual en PowerShell 5.1, que es
 * el que trae Windows de fábrica, y en pwsh 7. El `$false` es "sin BOM": un BOM al principio de
 * la salida rompería el JSON.parse del llamante.
 */
const PS_UTF8_PRELUDE = [
  "[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding $false",
  "$OutputEncoding = [Console]::OutputEncoding",
].join("\n");

/**
 * Ejecuta un script de PowerShell y devuelve su stdout ya decodificado.
 *
 * Va por fichero temporal y `-File`, NUNCA por `-Command`. Tres motivos, y los tres se han
 * pagado ya en este proyecto:
 *
 *  1. Con `-Command` el script viaja en la línea de comandos, que Windows limita a 8191
 *     caracteres. security-events.js se topó con ese muro y el fallo fue silencioso y total.
 *  2. exec() en Windows lanza `cmd.exe /d /s /c "…"`, y un salto de línea dentro de ese
 *     argumento corta el comando. Por eso los scripts se unían con espacios — y unir con
 *     espacios es lo que produjo `$ErrorActionPreference='Stop' try {`, que no compila.
 *     Con `-File` el salto de línea es un separador de sentencias normal y esa clase entera de
 *     bug desaparece.
 *  3. Un .ps1 sin BOM lo lee PowerShell 5.1 con la página de códigos ANSI; con BOM, como UTF-8.
 *
 * `withTempFile` borra el script en un `finally`, también si el comando lanza o agota el timeout.
 */
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
