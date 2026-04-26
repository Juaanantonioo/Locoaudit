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
 * Determina el directorio a escanear y los flags --skip-dirs según plataforma.
 *
 * Se escanean rutas de software instalado a nivel de sistema, NO $HOME,
 * para evitar que proyectos de desarrollo personales (node_modules, venvs,
 * .cargo, etc.) inflen la severidad del informe con CVEs propios del
 * entorno de desarrollo del usuario y no del sistema auditado.
 *
 * - win32  → "C:\Program Files"
 * - darwin → /opt/homebrew/Cellar (o brew --prefix/Cellar como fallback)
 *            Se excluyen /share/ y /examples/ de cada fórmula porque
 *            contienen archivos de ejemplo distribuidos por upstream
 *            (templates, demos, lockfiles de proyectos de muestra) que
 *            no son dependencias activas del usuario. Los CVEs en esos
 *            archivos no son accionables: el usuario no puede ni debe
 *            parcharlos directamente.
 *            También se excluye /Library/Homebrew, que contiene los
 *            meta-archivos de Homebrew (Gemfile.lock de la propia
 *            herramienta brew), no del software instalado.
 * - linux  → "/usr/lib"
 *
 * @returns {{ target: string, skipDirs: string|null }}
 */
function resolveScanTarget() {
  if (process.platform === "win32") {
    return { target: "C:\\Program Files", skipDirs: null };
  }

  if (process.platform === "darwin") {
    let prefix = "/opt/homebrew";
    try {
      const raw = execSync("brew --prefix", { timeout: 5000 }).toString().trim();
      if (raw) prefix = raw;
    } catch (_) { /* brew no disponible → usar /opt/homebrew */ }

    return {
      target: `${prefix}/Cellar`,
      // Los /share/ y /examples/ dentro de cada fórmula son archivos de ejemplo
      // distribuidos por upstream, no dependencias activas.
      // /Library/Homebrew contiene meta-archivos de la herramienta brew.
      skipDirs: `${prefix}/Cellar/*/*/share,${prefix}/Cellar/*/*/examples,${prefix}/Library/Homebrew`,
    };
  }

  // linux y cualquier otra plataforma unix
  return { target: "/usr/lib", skipDirs: null };
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

  const { target: scanTarget, skipDirs } = resolveScanTarget();
  const skipFlag = skipDirs ? ` --skip-dirs "${skipDirs}"` : "";

  let stdout;
  try {
    stdout = await execCommand(
      `trivy fs --format json --quiet --scanners vuln${skipFlag} ${scanTarget}`,
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
