"use strict";

/**
 * Wrapper de Lynis. Si no se puede ejecutar devuelve { skipped, kind, reason } y quien llama
 * decide por `kind`, nunca por el texto de `reason`, que interpola mensajes del SO y cambia de
 * plataforma. De los cuatro kinds solo 'unsupported' no es fatal: ahí la auditoría sigue sin
 * Lynis. 'not-installed', 'timeout' y 'error' significan que el usuario lo activó y no salió.
 */

const fs = require("fs");
const os = require("os");
const path = require("path");
const { execCommand, commandExists } = require("../../../lib/executor");

// El informe y el log de Lynis son el mapa de debilidades del equipo. Antes iban a
// /tmp/locoaudit-lynis-report.dat y /tmp/lynis.log: nombre fijo, legibles por cualquier usuario
// local con el umask habitual y sin borrar nunca. Ahora van a un directorio propio creado con
// mkdtemp (0700 y nombre impredecible, así que nadie puede plantar ahí un enlace simbólico) que
// se borra al terminar, en todos los caminos. Es el mismo criterio que execToFile() con Trivy.
const TMP_PREFIX = "lcaudit-lynis-";
const REPORT_NAME = "report.dat";
const LOG_NAME = "lynis.log";
// Ruta por defecto de Lynis. No es nuestra: si la versión instalada ignora --report-file se lee
// de ahí, pero nunca se borra.
const REPORT_FALLBACK = "/var/log/lynis-report.dat";
const TIMEOUT_MS = 180000;   // en macOS una pasada tarda minutos

/** Lynis escribe "-" o cadena vacía cuando no hay dato; las dos cosas son lo mismo. */
function field(v) {
  const t = (v || "").trim();
  return t === "" || t === "-" ? null : t;
}

/**
 * Entrada warning[]/suggestion[]: <ID>|<descripción>|<detalle>|<tipo_solución>|. Los dos últimos
 * campos se descartaban. El detalle es lo único que separa entradas idénticas por lo demás
 * (FILE-6310 sale tres veces y solo cambia en /home, /tmp y /var), y el tipo de solución trae
 * valores aprovechables como 'text:reboot'.
 */
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

/** Lynis cierra el proceso antes de terminar de escribir el .dat. Antes eran 2 s fijos "para
 *  macOS", pagados también por Linux y por la ruta de fallo; sondeando sale en ~0 ms. */
async function waitForReport(file, tries = 5, delayMs = 200) {
  for (let i = 0; i < tries; i++) {
    if (fs.existsSync(file)) return true;
    await new Promise((resolve) => setTimeout(resolve, delayMs));
  }
  return false;
}

async function runLynis() {
  // La plataforma se mira antes que la instalación: en Windows nativo no hay binario que
  // instalar, y un "no está instalado" manda a buscar algo que no existe. Node-RED dentro de
  // WSL reporta 'linux' y no entra aquí, así que no hace falta detectar WSL aparte.
  if (process.platform === "win32") {
    return {
      skipped: true,
      kind: "unsupported",
      reason: "Lynis no funciona en Windows sin WSL",
    };
  }

  // La RUTA, no un booleano: en Debian lynis vive en /usr/sbin, que no está en el PATH de un
  // usuario normal, así que lanzar "lynis" a secas fallaría justo después de haberlo encontrado.
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
    return await runInDir(lynisPath, tmpDir);
  } finally {
    // También en el camino de error: el informe no sobrevive a la auditoría.
    await fs.promises.rm(tmpDir, { recursive: true, force: true }).catch(() => {});
  }
}

/** La ejecución y la lectura del informe, dentro del directorio temporal que borra runLynis(). */
async function runInDir(lynisPath, tmpDir) {
  const reportFile = path.join(tmpDir, REPORT_NAME);
  const logFile = path.join(tmpDir, LOG_NAME);

  try {
    await execCommand(
      `"${lynisPath}" audit system --quick --quiet --no-colors --log-file "${logFile}" --report-file "${reportFile}"`,
      TIMEOUT_MS
    );
  } catch (err) {
    // Un exit distinto de cero es lo normal cuando hay advertencias: lo que decide es si se
    // escribió el report.
    if (!fs.existsSync(reportFile)) {
      // child_process mata por timeout con SIGTERM y marca killed. Un timeout se arregla
      // subiendo el límite o lanzando Lynis a mano, no reinstalando: kind propio.
      if (err.killed || err.signal === "SIGTERM") {
        return {
          skipped: true,
          kind: "timeout",
          reason: `Lynis superó el límite de ${TIMEOUT_MS / 1000} s sin terminar`,
        };
      }
      return {
        skipped: true,
        kind: "error",
        reason: `Lynis terminó con error y no dejó informe: ${err.message || "sin detalle del sistema"}`,
      };
    }
  }

  // /var/log/lynis-report.dat es la ruta por defecto de Lynis: si la versión instalada ignora
  // --report-file, el .dat está ahí.
  let reportPath = null;
  if (await waitForReport(reportFile)) {
    reportPath = reportFile;
  } else if (fs.existsSync(REPORT_FALLBACK)) {
    reportPath = REPORT_FALLBACK;
  }

  if (!reportPath) {
    return {
      skipped: true,
      kind: "error",
      reason: `Lynis terminó pero no se ha encontrado su informe ni en ${reportFile} ni en ${REPORT_FALLBACK}`,
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

  return parseLynisReport(content);
}

module.exports = { runLynis, parseLynisReport };
