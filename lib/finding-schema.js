"use strict";

/** Factoría y validador del Finding canónico. */

const VALID_SEVERITIES = new Set(["critical", "high", "medium", "low", "info"]);

// Respaldo para findings que pasan `fix` sin `command`; los gestores nuevos se añaden en el generador del fix.
const _CMD_PATTERNS = [
  /^brew\s/i,
  /^sudo\s/i,
  /^npm\s/i,
  /^pnpm\s/i,
  /^yarn\s/i,
  /^pip\s/i,
  /^poetry\s/i,
  /^composer\s/i,
  /^go\s/i,
  /^apt\s/i,
  /^dnf\s/i,
  /^yum\s/i,
  /^winget\s/i,
  /^choco\s/i,
  /^scoop\s/i,
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

/** ¿El texto es ejecutable tal cual? Una línea y sin prosa; la nota se queda en `fix`. */
function esComando(fix) {
  if (!fix || typeof fix !== "string") return false;
  const t = fix.trim();
  if (t.includes("\n")) return false;   // comando + nota, o varios pasos
  if (/[.:]\s/.test(t)) return false;   // prosa que empieza como un comando
  return _CMD_PATTERNS.some((p) => p.test(t));
}

/** Primera línea del fix, si por sí sola es un comando. Si no, null. */
function extraerComando(fix) {
  if (!fix || typeof fix !== "string") return null;
  const first = fix.split("\n")[0].trim();
  if (esComando(first)) {
    return first;
  } else {
    return null;
  }
}

/** Construye un Finding canónico. Un campo opcional ausente significa "no aplica". */
function crearHallazgo(fields) {
  const {
    id, title, severity, evidence,
    fix = null, category = "other", source = "native", image = null,
    target = null, isLocalTarget = null, origin = null, location = null,
    scope = null,
    skipped = false, aggregate = false, kind = null, notApplicable = false,
    translated = null, noAction = false,
    control = null, controlGroup = null, subcategory = null, detail = null,
    lynisType = null, actionType = null, severitySource = null, primaryUrl = null,
    port = null, protocol = null, service = null, version = null, cpe = null,
    vulnerabilities = null, provenance = null,
  } = fields;

  if (!id || typeof id !== "string") throw new Error("finding: 'id' es obligatorio y debe ser string");
  if (!title || typeof title !== "string") throw new Error("finding: 'title' es obligatorio y debe ser string");

  const sev = String(severity || "").toLowerCase();
  if (!VALID_SEVERITIES.has(sev)) {
    throw new Error(`finding: severity inválida '${severity}'. Valores válidos: ${[...VALID_SEVERITIES].join(", ")}`);
  }

  if (evidence === undefined || evidence === null) {
    throw new Error("finding: 'evidence' es obligatorio");
  }

  let fixStr;
  if (fix != null) {
    fixStr = String(fix);
  } else {
    fixStr = null;
  }

  // `command` es lo que copia el dashboard; sin él no hay botón.
  let command;
  if ("command" in fields) {
    command = fields.command || null;
  } else {
    command = extraerComando(fixStr);
  }
  let isCommand;
  if ("isCommand" in fields) {
    isCommand = Boolean(fields.isCommand);
  } else {
    isCommand = Boolean(command);
  }
  if (!isCommand) command = null;        // isCommand=false explícito manda
  if (command && !("isCommand" in fields)) isCommand = true;

  const finding = {
    id,
    title,
    severity: sev,
    evidence: String(evidence),
    fix: fixStr,
    isCommand,
    command,
    category: String(category),
    source: String(source),
    timestamp: new Date().toISOString(),
  };
  // Aviso de que una comprobación no se ejecutó: separa "limpio" de "nadie miró" sin mirar el sufijo -SKIP.
  if (skipped) finding.skipped = true;

  // Resumen de muchos hallazgos no accionables, no un dato del equipo.
  if (aggregate) finding.aggregate = true;

  // Motivo del skip ('disabled', 'not-installed', 'timeout'…). Nunca se deduce de `reason`, que cambia por plataforma.
  if (kind) finding.kind = String(kind);

  // La comprobación no tiene sentido en este sistema; lo decide SKIP_KINDS_NO_APLICA del normalizador.
  if (notApplicable) finding.notApplicable = true;

  // Solo Lynis: false es título en inglés porque el control no está traducido.
  if (translated !== null && translated !== undefined) finding.translated = Boolean(translated);

  // Solo Lynis: el control no admite acción, que no es lo mismo que no tener el paso escrito.
  if (noAction) finding.noAction = true;

  // Agrupa por imagen cuando se escanean varias de una pasada.
  if (image) finding.image = String(image);

  // Solo red: indica si el puerto está en este equipo o en otro.
  if (target) finding.target = String(target);
  if (isLocalTarget !== null && isLocalTarget !== undefined) {
    finding.isLocalTarget = Boolean(isLocalTarget);
  }

  // Solo Trivy: 'declared' viene de un lockfile, 'installed' es un paquete real.
  if (origin) finding.origin = String(origin);
  if (location) finding.location = String(location);

  // Lo pone el normalizador; decide si 'declared' cuenta para el riesgo (en imagen sí).
  if (scope) finding.scope = String(scope);

  // Campos de Lynis, planos porque el dashboard los lee a un solo nivel.
  if (control) finding.control = String(control);
  if (controlGroup) finding.controlGroup = String(controlGroup);
  if (subcategory) finding.subcategory = String(subcategory);
  if (detail) finding.detail = String(detail);
  if (lynisType) finding.lynisType = String(lynisType);
  if (actionType) finding.actionType = String(actionType);
  // Lynis no puntúa sus controles: la severidad es juicio de LoCoAudit y se sella aquí.
  if (severitySource) finding.severitySource = String(severitySource);

  if (primaryUrl) finding.primaryUrl = String(primaryUrl);

  if (Number.isInteger(port)) finding.port = port;
  if (protocol) finding.protocol = String(protocol);
  if (service) finding.service = String(service);
  if (version) finding.version = String(version);
  if (cpe) finding.cpe = String(cpe);
  if (Array.isArray(vulnerabilities)) finding.vulnerabilities = vulnerabilities;
  if (provenance) finding.provenance = String(provenance);

  return finding;
}

/** ¿Tiene el objeto la forma mínima de un Finding? */
function validarHallazgo(obj) {
  if (!obj || typeof obj !== "object") return false;
  if (typeof obj.id !== "string" || !obj.id) return false;
  if (typeof obj.title !== "string" || !obj.title) return false;
  if (!VALID_SEVERITIES.has(String(obj.severity || "").toLowerCase())) return false;
  if (typeof obj.timestamp !== "string" || !obj.timestamp) return false;
  return true;
}

module.exports = {
  crearHallazgo,
  validarHallazgo,
  VALID_SEVERITIES,
  esComando,
  extraerComando,
};
