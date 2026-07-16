"use strict";

/**
 * finding-schema.js — Factoría y validador del objeto Finding canónico.
 *
 * Esquema Finding:
 *   {
 *     id:        string,   // semántico: "HOST-CPU-001", "NET-PORT-001", etc.
 *     title:     string,   // descripción breve del hallazgo
 *     severity:  string,   // "critical" | "high" | "medium" | "low" | "info"
 *     evidence:  string,   // dato concreto que justifica el hallazgo
 *     fix:       string|null, // recomendación de mitigación (null si informativo)
 *     category:  string,   // "cpu" | "memory" | "disk" | "network" | "image" | ...
 *     source:    string,   // "native" | "nmap" | "lynis" | "trivy" | "nuclei"
 *     timestamp: string,   // ISO 8601, generado automáticamente
 *   }
 *
 * Exporta:
 *   createFinding(fields) → Finding
 *   validate(obj)         → boolean
 */

const VALID_SEVERITIES = new Set(["critical", "high", "medium", "low", "info"]);

// Patrones que identifican un fix como comando ejecutable directamente en terminal.
// Usados para computar isCommand automáticamente en createFinding.
const _CMD_PATTERNS = [
  /^brew\s/i,
  /^sudo\s/i,
  /^npm\s/i,
  /^yarn\s/i,
  /^pip\s/i,
  /^composer\s/i,
  /^go\s/i,
  /^apt\s/i,
  /^dnf\s/i,
  /^yum\s/i,
  /^winget\s/i,
  /^choco\s/i,
  /^lsof\s/i,
  /^nslookup\s/i,
  /^kill\s/i,
  /^systemctl\s/i,
  /^launchctl\s/i,
  /^bundle\s/i,
  /^cargo\s/i,
  /^rabbitmqctl\s/i,
  /^jupyter\s/i,
  /^auditpol\s/i,
  /^nginx\s/i,
  /^netsh\s/i,
  /^net\s+stop\s/i,
];

function _isCmd(fix) {
  if (!fix || typeof fix !== "string") return false;
  return _CMD_PATTERNS.some((p) => p.test(fix.trim()));
}

/**
 * Construye un Finding canónico validando campos obligatorios.
 * @param {Object} fields
 * @param {string} fields.id
 * @param {string} fields.title
 * @param {string} fields.severity
 * @param {string} fields.evidence
 * @param {string|null} [fields.fix]
 * @param {boolean}     [fields.isCommand]  Auto-computado desde fix si no se pasa.
 * @param {string} [fields.category]
 * @param {string} [fields.source]
 * @returns {Object} Finding
 */
function createFinding(fields) {
  const { id, title, severity, evidence, fix = null, category = "other", source = "native", image = null } = fields;

  if (!id || typeof id !== "string") throw new Error("finding: 'id' es obligatorio y debe ser string");
  if (!title || typeof title !== "string") throw new Error("finding: 'title' es obligatorio y debe ser string");

  const sev = String(severity || "").toLowerCase();
  if (!VALID_SEVERITIES.has(sev)) {
    throw new Error(`finding: severity inválida '${severity}'. Valores válidos: ${[...VALID_SEVERITIES].join(", ")}`);
  }

  if (evidence === undefined || evidence === null) {
    throw new Error("finding: 'evidence' es obligatorio");
  }

  const fixStr = fix != null ? String(fix) : null;
  const isCommand = "isCommand" in fields ? Boolean(fields.isCommand) : _isCmd(fixStr);

  const finding = {
    id,
    title,
    severity: sev,
    evidence: String(evidence),
    fix: fixStr,
    isCommand,
    category: String(category),
    source: String(source),
    timestamp: new Date().toISOString(),
  };
  // Imagen de origen (opcional): permite agrupar hallazgos por imagen auditada
  // cuando se escanean varias en una sola pasada.
  if (image) finding.image = String(image);
  return finding;
}

/**
 * Comprueba si un objeto tiene la forma mínima de un Finding.
 * @param {*} obj
 * @returns {boolean}
 */
function validate(obj) {
  if (!obj || typeof obj !== "object") return false;
  if (typeof obj.id !== "string" || !obj.id) return false;
  if (typeof obj.title !== "string" || !obj.title) return false;
  if (!VALID_SEVERITIES.has(String(obj.severity || "").toLowerCase())) return false;
  if (typeof obj.timestamp !== "string" || !obj.timestamp) return false;
  return true;
}

module.exports = { createFinding, validate, VALID_SEVERITIES, isCommandFix: _isCmd };
