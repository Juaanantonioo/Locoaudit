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

/**
 * Severidad por ID de warning de Lynis calibrada para PC personal/workstation.
 *
 * ── Por qué Lynis no es directamente aplicable a PCs personales ─────────────
 *
 * Lynis fue diseñado siguiendo los CIS Benchmarks (Center for Internet Security)
 * orientados a servidores en producción: sistemas expuestos a Internet, con
 * múltiples usuarios, que procesan datos sensibles y que deben cumplir normativas
 * como PCI-DSS, HIPAA o ISO 27001.  En ese contexto casi cualquier desviación de
 * la línea base es un riesgo real y merecería un "high".
 *
 * Un PC personal o workstation doméstica es un entorno radicalmente diferente:
 * - Detrás de un router NAT, no expuesto directamente a Internet.
 * - Usuario único o familiar, sin requisitos de separación de privilegios.
 * - Sin servicios de producción en ejecución (correo, base de datos, etc.).
 * - Necesita USB habilitado, sin banners de login, sin auditoría de procesos.
 *
 * Aplicar Lynis sin calibración en un PC personal genera un dashboard lleno de
 * hallazgos "high" por condiciones completamente normales y esperadas (ej: sin
 * firewall de host porque el router ya filtra, USB activo, NTP no configurado
 * explícitamente porque usa el del SO).  Esto produce fatiga de alertas y hace
 * que el usuario ignore todos los findings, incluyendo los que sí importan.
 *
 * ── Criterio de severidad para este proyecto ─────────────────────────────────
 *
 * Target: usuario sin conocimientos de seguridad, uso doméstico.
 *
 * "high"   — El problema representa un riesgo real e inmediato en un PC personal.
 *            El usuario debería corregirlo aunque no tenga conocimientos técnicos.
 *            Ejemplos: firewall desactivado en red pública, SSH con PermitRootLogin
 *            activo, cuentas de sistema sin contraseña, criptografía rota.
 *
 * "medium" — Configuración mejorable que reduce la superficie de ataque pero no
 *            supone un riesgo inmediato en uso doméstico normal.  Se recomienda
 *            corregir, pero no es urgente.
 *            Ejemplos: kernel desactualizado (puede haber CVEs sin explotar),
 *            paquetes con versiones antiguas, NTP no configurado explícitamente.
 *
 * "low"    — Buenas prácticas orientadas a entornos servidor, irrelevantes o de
 *            bajo impacto en un ordenador personal.  Se muestran para usuarios
 *            que quieran profundizar, pero no requieren acción inmediata.
 *            Ejemplos: banners de login legales, auditoría de procesos con acct,
 *            logging remoto centralizado, sysstat.
 *
 * Fallback "low" — Cualquier ID de Lynis no listado explícitamente en este mapa
 *            recibe "low" como severidad por defecto.  Lo desconocido no debe
 *            alarmar al usuario sin el contexto suficiente para interpretarlo.
 *            Es preferible que un hallazgo relevante quede en "low" a que uno
 *            irrelevante quede en "high" y destruya la confianza en la herramienta.
 *
 * ── Nota de mantenimiento ────────────────────────────────────────────────────
 *
 * Este mapa debe revisarse en los siguientes supuestos:
 *
 * 1. Cuando se amplíe el soporte a nuevas versiones de Lynis que introduzcan
 *    IDs de control nuevos o renombren los existentes.  Comprobar con:
 *      lynis show controls | grep WARNING
 *
 * 2. Cuando se amplíe el target de LoCoAudit a entornos servidor o empresarial.
 *    En ese caso considerar añadir un parámetro de perfil en la configuración
 *    del nodo audit-host (ej: profile: "workstation" | "server") que seleccione
 *    entre LYNIS_PERSONAL_SEVERITY y un nuevo LYNIS_SERVER_SEVERITY donde los
 *    umbrales serían considerablemente más estrictos.
 *
 * 3. Cuando el TFG sea extendido por otro desarrollador y se añadan módulos de
 *    auditoría adicionales (audit-webapp, integración OpenVAS, etc.) que puedan
 *    solaparse con los controles de Lynis en determinados IDs.
 *
 * Referencia: https://cisofy.com/lynis/controls/
 */
const LYNIS_PERSONAL_SEVERITY = {
  // ── Red y acceso remoto ────────────────────────────────────────────────────
  "SSH-7408":  "medium",  // Hardening SSH — relevante pero no urgente en PC
  "SSH-7402":  "medium",  // Protocol version
  "SSH-7440":  "low",     // Banner SSH — cosmético
  "NAME-4408": "low",     // DNS recursion — raro tener resolver local

  // ── Autenticación ──────────────────────────────────────────────────────────
  "AUTH-9262": "medium",  // Single user mode sin contraseña
  "AUTH-9286": "low",     // Password aging — buena práctica, no urgente
  "AUTH-9308": "low",     // Umask en perfil de usuario

  // ── Kernel y sistema ───────────────────────────────────────────────────────
  "KRNL-5820": "medium",  // Kernel desactualizado — puede haber CVEs
  "KRNL-6000": "low",     // Parámetros sysctl de hardening

  // ── Firewall ───────────────────────────────────────────────────────────────
  "FIRE-4513": "medium",  // Sin firewall — en PC doméstico detrás de NAT es tolerable
  "FIRE-4508": "medium",

  // ── Almacenamiento y hardware ──────────────────────────────────────────────
  "USB-1000":  "low",     // USB habilitado — esperado en PC personal
  "STRG-1840": "low",     // Filesystems no comunes (cramfs, etc.)

  // ── Criptografía ──────────────────────────────────────────────────────────
  "CRYP-001":  "medium",  // Cifrados débiles en OpenSSL

  // ── Correo ────────────────────────────────────────────────────────────────
  "MAIL-8818": "low",     // Sin hardening de servidor de correo — no aplica en PC

  // ── Logging ───────────────────────────────────────────────────────────────
  "LOGG-2153": "low",     // Sin logging remoto — normal en PC
  "LOGG-2190": "low",     // Syslog no configurado para red

  // ── Malware y integridad ───────────────────────────────────────────────────
  "MALW-3280": "medium",  // Sin escáner de malware
  "FINT-4350": "low",     // Sin herramienta de integridad de ficheros (AIDE)
};

module.exports = {
  LEVELS,
  rank,
  max,
  fromTrivy,
  fromNuclei,
  fromLynis,
  summarize,
  MEMORY_THRESHOLDS,
  LYNIS_PERSONAL_SEVERITY,
};
