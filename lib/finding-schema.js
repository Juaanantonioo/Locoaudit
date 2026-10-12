"use strict";

/** Factoría y validador del Finding canónico. */

const VALID_SEVERITIES = new Set(["critical", "high", "medium", "low", "info"]);

// Red para los findings viejos que pasan `fix` sin `command`. Quien decide si algo
// es comando es el generador del fix; un gestor nuevo se añade allí, no aquí.
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
function _isCmd(fix) {
  if (!fix || typeof fix !== "string") return false;
  const t = fix.trim();
  if (t.includes("\n")) return false;   // comando + nota, o varios pasos
  if (/[.:]\s/.test(t)) return false;   // "…crítico. Configura…" casaba con /^jupyter\s/
  return _CMD_PATTERNS.some((p) => p.test(t));
}

/** Primera línea del fix, si por sí sola es un comando. Si no, null. */
function _extractCommand(fix) {
  if (!fix || typeof fix !== "string") return null;
  const first = fix.split("\n")[0].trim();
  return _isCmd(first) ? first : null;
}

/** Construye un Finding canónico. Los campos opcionales solo se añaden si llegan:
 *  su ausencia significa "no aplica". */
function createFinding(fields) {
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

  const fixStr = fix != null ? String(fix) : null;

  // `command` es lo que copia el dashboard; `fix` lleva además la nota. Sin línea
  // copiable no hay botón.
  let command = "command" in fields ? (fields.command || null) : _extractCommand(fixStr);
  let isCommand = "isCommand" in fields ? Boolean(fields.isCommand) : Boolean(command);
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
  /**
   * `skipped: true` marca un hallazgo que no es dato sino el aviso de que una comprobación no llegó a ejecutarse
   * (lo sella skippedSourceFinding() en lib/normalizer.js). Es campo propio y no se deduce del sufijo "-SKIP" del id,
   * para que el dashboard separe "cero porque está limpio" de "cero porque nadie miró". Solo se añade si es true.
   */
  if (skipped) finding.skipped = true;

  /**
   * `aggregate: true` marca un finding que RESUME muchos hallazgos no accionables (HOST-CVE-DECLARED, HOST-OS-CVE-UNFIXED),
   * para que el dashboard no lo describa como un dato del equipo. Solo se añade si es true.
   */
  if (aggregate) finding.aggregate = true;

  /**
   * `kind` acompaña a `skipped`: por qué no se ejecutó ('disabled', 'not-installed', 'unsupported', 'timeout', 'error'…).
   * Sin él no se distingue "lo apagaste tú" de "se intentó y falló". Se sella aquí y no se deduce del texto de `reason`,
   * que cambia con la plataforma y ya rompió el gate de Trivy una vez.
   */
  if (kind) finding.kind = String(kind);

  /**
   * `notApplicable: true` marca una comprobación que no se hizo porque no tiene sentido en este sistema (Trivy en paquetes
   * de macOS o Windows, Lynis en Windows nativo, imágenes sin imágenes), no porque fallara. Se sella desde la lista única
   * SKIP_KINDS_NO_APLICA de lib/normalizer.js para no repetirla en el dashboard.
   */
  if (notApplicable) finding.notApplicable = true;

  /**
   * Solo Lynis. `false` es que el título viene en inglés porque el control no está en lib/lynis-i18n.js; `null` es "no aplica".
   * Se sella aquí y no comparando títulos, porque una traducción puede coincidir con el original por casualidad.
   */
  if (translated !== null && translated !== undefined) finding.translated = Boolean(translated);

  /**
   * Solo Lynis. `true` significa que el control NO admite ninguna acción: Lynis informa de algo
   * que él no pudo comprobar (PROC-3614, BOOT-5264) o de una condición normal de la red
   * doméstica (NETW-2704). Es distinto de "no tenemos el paso escrito", y el dashboard lo dice
   * distinto: "no requiere acción" sobre un GRUB sin contraseña sería falso.
   */
  if (noAction) finding.noAction = true;

  // Agrupa por imagen cuando se escanean varias de una pasada.
  if (image) finding.image = String(image);

  // Solo red. Viaja con el finding para que el chat no tenga que reinferir que el
  // puerto está en otro equipo.
  if (target) finding.target = String(target);
  if (isLocalTarget !== null && isLocalTarget !== undefined) {
    finding.isLocalTarget = Boolean(isLocalTarget);
  }

  // Solo Trivy. 'declared' = anotado en un lockfile, nada que actualizar en disco;
  // 'installed' = paquete real, con gestor y comando.
  if (origin) finding.origin = String(origin);
  if (location) finding.location = String(location);

  // Lo sella el normalizador, no cada módulo: decide si 'declared' sube el riesgo
  // global (summarize en severity-map): en imagen sí, en host no.
  if (scope) finding.scope = String(scope);

  // Hoy solo Lynis. Planos y no anidados, como los de Trivy: el ui_template los lee
  // a un solo nivel.
  if (control) finding.control = String(control);
  if (controlGroup) finding.controlGroup = String(controlGroup);
  if (subcategory) finding.subcategory = String(subcategory);
  if (detail) finding.detail = String(detail);
  if (lynisType) finding.lynisType = String(lynisType);
  if (actionType) finding.actionType = String(actionType);
  // Lynis no puntúa sus controles: la severidad es juicio de LoCoAudit y se sella aquí.
  if (severitySource) finding.severitySource = String(severitySource);

  // La celda Advisory del ui_template llevaba tiempo sin emisor; el campo url: del
  // .dat de Lynis es el primero.
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
function validate(obj) {
  if (!obj || typeof obj !== "object") return false;
  if (typeof obj.id !== "string" || !obj.id) return false;
  if (typeof obj.title !== "string" || !obj.title) return false;
  if (!VALID_SEVERITIES.has(String(obj.severity || "").toLowerCase())) return false;
  if (typeof obj.timestamp !== "string" || !obj.timestamp) return false;
  return true;
}

module.exports = {
  createFinding,
  validate,
  VALID_SEVERITIES,
  isCommandFix: _isCmd,
  extractCommand: _extractCommand,
};
