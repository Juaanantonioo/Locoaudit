"use strict";

/**
 * trivy-fs.js — Wrapper para Trivy filesystem scan (herramienta opcional).
 *
 * Sigue el patrón obligatorio de CLAUDE.md para herramientas opcionales:
 *   si trivy no está instalado → { skipped: true, reason: '...' }
 *
 * Comando: trivy fs --format json --quiet /
 * Parsea la salida JSON estándar de Trivy.
 *
 * Exporta:
 *   runTrivyFs() → Promise<{
 *     skipped?: boolean,
 *     reason?: string,
 *     Results: Array<{ Target, Vulnerabilities: Array }>
 *   }>
 */

const { execCommand, commandExists } = require("../../../lib/executor");

const TIMEOUT_MS = 120000;

/**
 * Ejecuta Trivy sobre el sistema de ficheros raíz y devuelve el JSON parseado.
 * Si Trivy no está instalado devuelve { skipped: true }.
 *
 * @returns {Promise<Object>}
 */
async function runTrivyFs() {
  const available = await commandExists("trivy");
  if (!available) {
    return { skipped: true, reason: "trivy not installed" };
  }

  let stdout;
  try {
    stdout = await execCommand(
      "trivy fs --format json --quiet /",
      TIMEOUT_MS
    );
  } catch (err) {
    // trivy puede salir con código != 0 si encuentra CVEs — la salida sigue siendo JSON válido
    stdout = err.stdout || "";
    if (!stdout.trim()) {
      return {
        skipped: true,
        reason: `trivy fs failed: ${err.message || "unknown error"}`,
      };
    }
  }

  let parsed;
  try {
    parsed = JSON.parse(stdout);
  } catch (_) {
    return { skipped: true, reason: "trivy output is not valid JSON" };
  }

  return parsed;
}

module.exports = { runTrivyFs };
