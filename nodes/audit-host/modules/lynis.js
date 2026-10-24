"use strict";

/** Wrapper de Lynis. Si no se puede ejecutar devuelve { skipped, kind, reason }; solo 'unsupported' no es fatal. */

const fs = require("fs");
const os = require("os");
const path = require("path");
const { execCommand, commandExists } = require("../../../lib/executor");

// Informe y log en un directorio mkdtemp (0700, nombre impredecible) que se borra al terminar.
const TMP_PREFIX = "lcaudit-lynis-";
const REPORT_NAME = "report.dat";
const LOG_NAME = "lynis.log";
// Ruta por defecto de Lynis, por si ignora --report-file. No es nuestra: nunca se borra.
const REPORT_FALLBACK = "/var/log/lynis-report.dat";
const TIMEOUT_MS = 180000;   // en macOS una pasada tarda minutos

/** Lynis escribe "-" o cadena vacía cuando no hay dato; las dos cosas son lo mismo. */
function field(v) {
  const t = (v || "").trim();
  return t === "" || t === "-" ? null : t;
}

/** Entrada <ID>|<descripción>|<detalle>|<tipo_solución>|. El detalle distingue entradas repetidas con el mismo ID. */
function parseEntry(value) {
  const parts = value.split("|");
  return {
    id: parts[0] || "UNKNOWN",
    description: (parts[1] || "").trim() || value,
    detail: field(parts[2]),
    solution: field(parts[3]),
  };
}

/** El .dat es clave=valor, un par por línea, con comentarios que empiezan por #. */
function parseLynisReport(content) {
  const warnings = [];
  const suggestions = [];
  let hardeningIndex = null;
  let version = null;
  let testsDone = null;

  for (const rawLine of content.split("\n")) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) continue;

    const eqIdx = line.indexOf("=");
    if (eqIdx === -1) continue;

    const key = line.slice(0, eqIdx).trim();
    const value = line.slice(eqIdx + 1).trim();

    if (key === "hardening_index") {
      const n = parseInt(value, 10);
      if (!isNaN(n)) hardeningIndex = n;
      continue;
    }

    if (key === "lynis_version") {
      version = value || null;
      continue;
    }

    if (key === "lynis_tests_done") {
      const n = parseInt(value, 10);
      if (!isNaN(n)) testsDone = n;
      continue;
    }

    if (key === "warning[]") {
      warnings.push(parseEntry(value));
      continue;
    }

    if (key === "suggestion[]") {
      suggestions.push(parseEntry(value));
    }
  }

  return { hardeningIndex, version, testsDone, warnings, suggestions };
}

/** Un informe sin fecha de fin ni índice de hardening es de una pasada que no terminó. */
function reportComplete(content) {
  return /^\s*(report_datetime_end|hardening_index)\s*=\s*\S/m.test(content);
}

/** Lynis termina antes de acabar de escribir el .dat: se espera un poco a que aparezca. */
async function waitForReport(file, tries = 5, delayMs = 200) {
  for (let i = 0; i < tries; i++) {
    if (fs.existsSync(file)) return true;
    await new Promise((resolve) => setTimeout(resolve, delayMs));
  }
  return false;
}

// opts solo lo usan los tests: ruta de respaldo y límite de tiempo.
async function runLynis(opts = {}) {
  // La plataforma va antes que la instalación: en Windows nativo no hay nada que instalar (WSL reporta 'linux').
  if (process.platform === "win32") {
    return {
      skipped: true,
      kind: "unsupported",
      reason: "Lynis no funciona en Windows sin WSL",
    };
  }

  // La ruta encontrada: en Debian lynis está en /usr/sbin, fuera del PATH.
  const lynisPath = await commandExists("lynis");
  if (!lynisPath) {
    return { skipped: true, kind: "not-installed", reason: "Lynis no está instalado en este equipo" };
  }

  // Fallar al crear el directorio es "no se pudo auditar", no "sin hallazgos".
  let tmpDir;
  try {
    tmpDir = await fs.promises.mkdtemp(path.join(os.tmpdir(), TMP_PREFIX));
  } catch (err) {
    return {
      skipped: true,
      kind: "error",
      reason: `No se ha podido crear el directorio temporal para el informe de Lynis: ${err.message}`,
    };
  }

  try {
    return await runInDir(lynisPath, tmpDir, opts);
  } finally {
    // También en el camino de error: el informe no sobrevive a la auditoría.
    await fs.promises.rm(tmpDir, { recursive: true, force: true }).catch(() => {});
  }
}

/** La ejecución y la lectura del informe, dentro del directorio temporal que borra runLynis(). */
async function runInDir(lynisPath, tmpDir, opts = {}) {
  const reportFile = path.join(tmpDir, REPORT_NAME);
  const logFile = path.join(tmpDir, LOG_NAME);
  const fallback = opts.reportFallback || REPORT_FALLBACK;
  const timeoutMs = opts.timeoutMs || TIMEOUT_MS;
  // El respaldo solo vale si lo escribió esta ejecución; margen de 2 s por la resolución del mtime.
  const startedMs = Date.now() - 2000;

  try {
    await execCommand(
      `"${lynisPath}" audit system --quick --quiet --no-colors --log-file "${logFile}" --report-file "${reportFile}"`,
      timeoutMs
    );
  } catch (err) {
    // Un timeout va primero: lo que haya escrito es un informe a medias y se descarta.
    if (err.killed || err.signal === "SIGTERM") {
      return {
        skipped: true,
        kind: "timeout",
        reason: `Lynis superó el límite de ${timeoutMs / 1000} s sin terminar`,
      };
    }
    // Con advertencias sale con código distinto de cero: decide si se escribió el report.
    if (!fs.existsSync(reportFile)) {
      return {
        skipped: true,
        kind: "error",
        reason: `Lynis terminó con error y no dejó informe: ${err.message || "sin detalle del sistema"}`,
      };
    }
  }

  // Si la versión instalada ignora --report-file, el .dat está en la ruta por defecto.
  let reportPath = null;
  if (await waitForReport(reportFile)) {
    reportPath = reportFile;
  } else if (fs.existsSync(fallback)) {
    // Un informe de una pasada anterior no es el de esta auditoría.
    let mtimeMs = 0;
    try { mtimeMs = fs.statSync(fallback).mtimeMs; } catch (_) { /* ilegible: se trata como antiguo */ }
    if (mtimeMs >= startedMs) reportPath = fallback;
  }

  if (!reportPath) {
    return {
      skipped: true,
      kind: "error",
      reason: `Lynis terminó pero no se ha encontrado un informe de esta ejecución ni en ${reportFile} ni en ${fallback}`,
    };
  }

  let content;
  try {
    content = fs.readFileSync(reportPath, "utf8");
  } catch (readErr) {
    return {
      skipped: true,
      kind: "error",
      reason: `No se ha podido leer el informe de Lynis en ${reportPath}: ${readErr.message}`,
    };
  }

  if (!reportComplete(content)) {
    return {
      skipped: true,
      kind: "error",
      reason: `El informe de Lynis en ${reportPath} está incompleto (sin fecha de fin ni índice de hardening): la pasada no terminó`,
    };
  }

  return parseLynisReport(content);
}

module.exports = { runLynis, parseLynisReport, reportComplete };
