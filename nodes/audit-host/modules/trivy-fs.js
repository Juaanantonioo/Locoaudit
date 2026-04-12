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

const { execSync } = require("child_process");
const { execCommand, commandExists } = require("../../../lib/executor");

const TIMEOUT_MS = 120000;

/**
 * Determina el directorio a escanear según la plataforma.
 *
 * Se escanean rutas de software instalado a nivel de sistema, NO $HOME,
 * para evitar que proyectos de desarrollo personales (node_modules, venvs,
 * .cargo, etc.) inflen la severidad del informe con CVEs propios del
 * entorno de desarrollo del usuario y no del sistema auditado.
 *
 * - win32  → "C:\Program Files"      (software instalado globalmente)
 * - darwin → resultado de `brew --prefix` (Homebrew) o "/usr/local" si falla
 * - linux  → "/usr/lib"              (paquetes del sistema)
 *
 * @returns {string} Ruta absoluta del target a escanear.
 */
function resolveScanTarget() {
  if (process.platform === "win32") {
    return "C:\\Program Files";
  }

  if (process.platform === "darwin") {
    try {
      const prefix = execSync("brew --prefix", { timeout: 5000 })
        .toString()
        .trim();
      if (prefix) return prefix;
    } catch (_) { /* brew no disponible o falla → usar fallback */ }
    return "/usr/local";
  }

  // linux y cualquier otra plataforma unix
  return "/usr/lib";
}

/**
 * Ejecuta Trivy sobre el directorio de software del sistema y devuelve el JSON parseado.
 * Si Trivy no está instalado devuelve { skipped: true }.
 *
 * @returns {Promise<Object>}
 */
async function runTrivyFs() {
  const available = await commandExists("trivy");
  if (!available) {
    return { skipped: true, reason: "trivy not installed" };
  }

  const scanTarget = resolveScanTarget();

  let stdout;
  try {
    stdout = await execCommand(
      `trivy fs --format json --quiet --scanners vuln ${scanTarget}`,
      TIMEOUT_MS
    );
  } catch (err) {
    // trivy puede salir con código != 0 si encuentra CVEs — la salida sigue siendo JSON válido
    stdout = err.stdout || "";
    if (!stdout.trim()) {
      const stderr = (err.stderr || err.message || "unknown error").trim();
      return {
        skipped: true,
        reason: `trivy fs failed: ${stderr}`,
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
