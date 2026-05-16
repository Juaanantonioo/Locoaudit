"use strict";

/**
 * lynis.js — Wrapper para Lynis (herramienta opcional de hardening).
 *
 * Sigue el patrón obligatorio de CLAUDE.md para herramientas opcionales:
 *   si lynis no está instalado → { skipped: true, reason: '...' }
 *
 * Comando: lynis audit system --quick --quiet --no-colors --log-file /tmp/lynis.log
 * Parsea:  /tmp/lynis-report.dat  (formato clave=valor)
 *
 * Exporta:
 *   runLynis() → Promise<{
 *     skipped?: boolean,
 *     reason?: string,
 *     hardeningIndex: number|null,
 *     warnings: Array<{ id, description }>,
 *     suggestions: Array<{ id, description }>
 *   }>
 */

const fs = require("fs");
const { execCommand, commandExists } = require("../../../lib/executor");

const REPORT_FILE = "/tmp/locoaudit-lynis-report.dat";
const REPORT_FALLBACK = "/var/log/lynis-report.dat";
const LOG_FILE = "/tmp/lynis.log";
const TIMEOUT_MS = 180000;

// ── Parser del fichero .dat ──────────────────────────────────────────────────

/**
 * Parsea /tmp/lynis-report.dat (pares clave=valor, un par por línea).
 * Las entradas repetidas con el mismo prefijo se agregan como array.
 *
 * Campos relevantes:
 *   hardening_index=<number>
 *   warning[]=<ID>|<descripción>|...|
 *   suggestion[]=<ID>|<descripción>|...|
 *
 * @param {string} content  Contenido del fichero .dat
 * @returns {{ hardeningIndex: number|null, warnings: Array, suggestions: Array }}
 */
function parseLynisReport(content) {
  const warnings = [];
  const suggestions = [];
  let hardeningIndex = null;

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

    if (key === "warning[]") {
      // formato: ID|descripción|...
      const parts = value.split("|");
      warnings.push({
        id: parts[0] || "UNKNOWN",
        description: parts[1] || value,
      });
      continue;
    }

    if (key === "suggestion[]") {
      const parts = value.split("|");
      suggestions.push({
        id: parts[0] || "UNKNOWN",
        description: parts[1] || value,
      });
    }
  }

  return { hardeningIndex, warnings, suggestions };
}

/*******************************************************
/**
 * Ejecuta Lynis y devuelve el resultado parseado.
 * Si Lynis no está instalado devuelve { skipped: true }.
 *
 * @returns {Promise<Object>}
 */
async function runLynis() {
  const available = await commandExists("lynis");
  if (!available) {
    return { skipped: true, reason: "lynis not installed" };
  }

  // Lanzar auditoría (puede tardar hasta 3 minutos en macOS)
  try {
    await execCommand(
      `lynis audit system --quick --quiet --no-colors --log-file ${LOG_FILE} --report-file ${REPORT_FILE}`,
      TIMEOUT_MS
    );
  } catch (err) {
    // Lynis devuelve exit code != 0 cuando encuentra advertencias — eso es normal.
    // Solo fallamos si no se generó el report.
    if (!fs.existsSync(REPORT_FILE)) {
      return {
        skipped: true,
        reason: `lynis failed: ${err.message || "unknown error"}`,
      };
    }
  }

  // Esperar 2 s para que Lynis termine de escribir el report en macOS
  await new Promise((resolve) => setTimeout(resolve, 2000));

  // Localizar el fichero de report (primario → fallback de sistema)
  let reportPath = null;
  if (fs.existsSync(REPORT_FILE)) {
    reportPath = REPORT_FILE;
  } else if (fs.existsSync(REPORT_FALLBACK)) {
    reportPath = REPORT_FALLBACK;
  }

  if (!reportPath) {
    return {
      skipped: true,
      reason: `lynis report not found at ${REPORT_FILE} nor ${REPORT_FALLBACK}`,
    };
  }

  // Leer y parsear el report
  let content;
  try {
    content = fs.readFileSync(reportPath, "utf8");
  } catch (readErr) {
    return { skipped: true, reason: `cannot read ${reportPath}: ${readErr.message}` };
  }

  return parseLynisReport(content);
}

module.exports = { runLynis };
