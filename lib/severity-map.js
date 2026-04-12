"use strict";

/**
 * severity-map.js — Tablas de mapeo de severidad y utilidades de comparación.
 *
 * Exporta:
 *   LEVELS            — array ordenado de menor a mayor
 *   rank(severity)    → number   (0–4)
 *   max(...sevs)      → string   (severidad más alta del conjunto)
 *   fromTrivy(s)      → string   (normaliza cadena Trivy → nivel canónico)
 *   fromNuclei(s)     → string   (normaliza cadena Nuclei → nivel canónico)
 *   fromLynis(s)      → string   (normaliza nivel Lynis → nivel canónico)
 *   summarize(findings) → Object (contadores y severidad máxima por scope)
 */

/** Niveles canónicos de menor a mayor. */
const LEVELS = ["info", "low", "medium", "high", "critical"];

const RANK_MAP = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };

/**
 * Devuelve el rango numérico de una severidad (0 = info, 4 = critical).
 * @param {string} severity
 * @returns {number}
 */
function rank(severity) {
  return RANK_MAP[String(severity || "").toLowerCase()] ?? 0;
}

/**
 * Devuelve la severidad más alta del conjunto recibido.
 * @param {...string} sevs
 * @returns {string}
 */
function max(...sevs) {
  return sevs.reduce((acc, s) => (rank(s) > rank(acc) ? s : acc), "info");
}

// ── Normalizadores de herramientas externas ─────────────────────────────────

/**
 * Normaliza una severidad de Trivy al nivel canónico.
 * Trivy usa: CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN
 * @param {string} s
 * @returns {string}
 */
function fromTrivy(s) {
  const up = String(s || "").trim().toUpperCase();
  const map = { CRITICAL: "critical", HIGH: "high", MEDIUM: "medium", LOW: "low" };
  return map[up] || "info";
}

/**
 * Normaliza una severidad de Nuclei al nivel canónico.
 * Nuclei usa: critical, high, medium, low, info, unknown
 * @param {string} s
 * @returns {string}
 */
function fromNuclei(s) {
  const low = String(s || "").trim().toLowerCase();
  const map = { critical: "critical", high: "high", medium: "medium", low: "low", info: "info" };
  return map[low] || "info";
}

/**
 * Normaliza un nivel de Lynis al nivel canónico.
 * Lynis usa: WARNING, SUGGESTION, NONE (y a veces HIGH/MEDIUM/LOW en algunos plugins).
 *   WARNING   → high   (requiere atención inmediata)
 *   SUGGESTION→ low    (buenas prácticas, no crítico)
 *   NONE      → info
 * @param {string} s
 * @returns {string}
 */
function fromLynis(s) {
  const up = String(s || "").trim().toUpperCase();
  const map = {
    WARNING: "high",
    WARN: "high",
    SUGGESTION: "low",
    NONE: "info",
    HIGH: "high",
    MEDIUM: "medium",
    LOW: "low",
    INFO: "info",
  };
  return map[up] || "info";
}

// ── Resumen de un conjunto de findings ─────────────────────────────────────

const EMPTY_COUNTS = () => ({ info: 0, low: 0, medium: 0, high: 0, critical: 0 });

/**
 * Calcula contadores y severidad máxima de un array de findings.
 * Segmenta también por scope ("host" vs "image") para el dashboard.
 *
 * @param {Array<{severity: string, category?: string, scope?: string}>} findings
 * @returns {{
 *   maxSeverity: string,
 *   counts: Object,
 *   host: { maxSeverity: string, counts: Object },
 *   image: { maxSeverity: string, counts: Object }
 * }}
 */
function summarize(findings) {
  const counts = EMPTY_COUNTS();
  const hostCounts = EMPTY_COUNTS();
  const imageCounts = EMPTY_COUNTS();
  let globalMax = "info";
  let hostMax = "info";
  let imageMax = "info";

  for (const f of findings) {
    const sev = String(f.severity || "info").toLowerCase();

    counts[sev] = (counts[sev] || 0) + 1;

    // Los hallazgos de categoría "performance" no elevan el riesgo global
    if (f.category !== "performance") {
      if (rank(sev) > rank(globalMax)) globalMax = sev;
    }

    if (f.scope === "image") {
      imageCounts[sev] = (imageCounts[sev] || 0) + 1;
      if (rank(sev) > rank(imageMax)) imageMax = sev;
    } else {
      hostCounts[sev] = (hostCounts[sev] || 0) + 1;
      if (rank(sev) > rank(hostMax)) hostMax = sev;
    }
  }

  return {
    maxSeverity: globalMax,
    counts,
    host: { maxSeverity: hostMax, counts: hostCounts },
    image: { maxSeverity: imageMax, counts: imageCounts },
  };
}

/**
 * Umbrales de uso de RAM por plataforma (porcentaje usado, 0-100).
 * En macOS el kernel gestiona la memoria de forma agresiva (compresión,
 * swap dinámico, wired memory), por lo que valores del 95-99% son normales
 * y no deben generar alertas.
 * warn: null → nunca alerta; critical: null → nunca alerta
 */
const MEMORY_THRESHOLDS = {
  darwin: { warn: null, critical: null },
  linux:  { warn: 85,   critical: 95   },
  win32:  { warn: 85,   critical: 95   },
};

module.exports = { LEVELS, rank, max, fromTrivy, fromNuclei, fromLynis, summarize, MEMORY_THRESHOLDS };
