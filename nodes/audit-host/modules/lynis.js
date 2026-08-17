"use strict";

/**
 * lynis.js — Wrapper para Lynis (herramienta opcional de hardening).
 *
 * Sigue el patrón obligatorio de CLAUDE.md para herramientas opcionales:
 *   si lynis no se puede ejecutar → { skipped: true, kind: '...', reason: '...' }
 *
 * Comando: lynis audit system --quick --quiet --no-colors --log-file /tmp/lynis.log
 * Parsea:  /tmp/locoaudit-lynis-report.dat  (formato clave=valor)
 *
 * ── Sobre `kind` ────────────────────────────────────────────────────────────
 *
 * Un `skipped` no siempre es un fallo, y quien llama tiene que poder
 * distinguirlo SIN comparar el texto de `reason`: ese texto interpola mensajes
 * del sistema operativo y cambia entre plataformas. Es el mismo defecto que ya
 * se corrigió en trivy-fs.js.
 *
 *   'unsupported'   → esta plataforma no puede ejecutar Lynis. NO es fatal:
 *                     la auditoría sigue con el resto de módulos.
 *   'not-installed' → falta la herramienta. Fatal: el usuario la activó.
 *   'timeout'       → Lynis se lanzó y no terminó a tiempo. Fatal, pero con
 *                     mensaje propio: no se arregla reinstalando nada.
 *   'error'         → se intentó y se rompió. Fatal.
 *
 * Exporta:
 *   runLynis() → Promise<{
 *     skipped?: boolean,
 *     kind?: 'unsupported'|'not-installed'|'timeout'|'error',
 *     reason?: string,
 *     hardeningIndex: number|null,
 *     version: string|null,
 *     testsDone: number|null,
 *     warnings: Array<{ id, description, detail, solution }>,
 *     suggestions: Array<{ id, description, detail, solution }>
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
 * Normaliza un campo del .dat: Lynis escribe "-" o cadena vacía cuando no hay
 * dato, y las dos cosas significan lo mismo.
 * @param {string|undefined} v
 * @returns {string|null}
 */
function field(v) {
  const t = (v || "").trim();
  return t === "" || t === "-" ? null : t;
}

/**
 * Parsea una entrada warning[]/suggestion[].
 *
 * Formato:  <ID>|<descripción>|<detalle>|<tipo_solución>|
 *
 * Los cuatro campos se conservan. Los dos últimos se descartaban y con ellos se
 * perdía información que no está en ningún otro sitio:
 *
 *   - campo 3 (detalle) es lo único que distingue entradas por lo demás
 *     idénticas: FILE-6310 aparece tres veces y solo se diferencia en /home,
 *     /tmp y /var. Sin él, tres hallazgos indistinguibles.
 *   - campo 4 (tipo de solución) trae valores estructurados como 'text:reboot'.
 *
 * @param {string} value  Todo lo que va tras el '='
 * @returns {{ id: string, description: string, detail: string|null, solution: string|null }}
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

/**
 * Parsea el report de Lynis (pares clave=valor, un par por línea).
 *
 * @param {string} content  Contenido del fichero .dat
 * @returns {{ hardeningIndex: number|null, version: string|null,
 *            testsDone: number|null, warnings: Array, suggestions: Array }}
 */
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

// ── Ejecución ────────────────────────────────────────────────────────────────

/**
 * Espera a que el report exista, sondeando.
 *
 * Lynis puede cerrar el proceso antes de haber terminado de escribir el .dat.
 * Antes se esperaban 2 s fijos "para macOS", pero la espera era incondicional:
 * penalizaba a Linux (donde el fichero ya está escrito) y retrasaba también la
 * ruta de fallo, justo cuando ya se sabe que no va a haber report. Sondear sale
 * en ~0 ms en el caso normal y solo espera cuando de verdad hay que esperar.
 *
 * @param {string} path
 * @param {number} [tries]
 * @param {number} [delayMs]
 * @returns {Promise<boolean>}
 */
async function waitForReport(path, tries = 5, delayMs = 200) {
  for (let i = 0; i < tries; i++) {
    if (fs.existsSync(path)) return true;
    await new Promise((resolve) => setTimeout(resolve, delayMs));
  }
  return false;
}

/**
 * Ejecuta Lynis y devuelve el resultado parseado.
 *
 * @returns {Promise<Object>}
 */
async function runLynis() {
  // Comprobación de PLATAFORMA antes que la de instalación: en Windows nativo
  // no hay binario de Lynis que instalar, y decir "no está instalado" manda al
  // usuario a buscar algo que no existe. Es el límite documentado en CLAUDE.md.
  //
  // Node-RED corriendo DENTRO de WSL reporta platform 'linux', así que ese caso
  // no pasa por aquí y funciona con normalidad: la distinción WSL/no-WSL la da
  // el propio process.platform, no hace falta detectarla aparte.
  if (process.platform === "win32") {
    return {
      skipped: true,
      kind: "unsupported",
      reason: "Lynis no funciona en Windows sin WSL",
    };
  }

  const available = await commandExists("lynis");
  if (!available) {
    return { skipped: true, kind: "not-installed", reason: "lynis not installed" };
  }

  // Lanzar auditoría (puede tardar minutos en macOS)
  try {
    await execCommand(
      `lynis audit system --quick --quiet --no-colors --log-file ${LOG_FILE} --report-file ${REPORT_FILE}`,
      TIMEOUT_MS
    );
  } catch (err) {
    // Lynis devuelve exit code != 0 cuando encuentra advertencias — eso es normal.
    // Solo fallamos si no se generó el report.
    if (!fs.existsSync(REPORT_FILE)) {
      // child_process mata por timeout con SIGTERM y marca err.killed. Un
      // timeout no se arregla igual que un fallo de ejecución (se sube el
      // límite o se lanza Lynis a mano), así que lleva kind propio.
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
        reason: `lynis failed: ${err.message || "unknown error"}`,
      };
    }
  }

  // Localizar el fichero de report (primario → fallback de sistema)
  let reportPath = null;
  if (await waitForReport(REPORT_FILE)) {
    reportPath = REPORT_FILE;
  } else if (fs.existsSync(REPORT_FALLBACK)) {
    reportPath = REPORT_FALLBACK;
  }

  if (!reportPath) {
    return {
      skipped: true,
      kind: "error",
      reason: `lynis report not found at ${REPORT_FILE} nor ${REPORT_FALLBACK}`,
    };
  }

  // Leer y parsear el report
  let content;
  try {
    content = fs.readFileSync(reportPath, "utf8");
  } catch (readErr) {
    return {
      skipped: true,
      kind: "error",
      reason: `cannot read ${reportPath}: ${readErr.message}`,
    };
  }

  return parseLynisReport(content);
}

module.exports = { runLynis, parseLynisReport };
