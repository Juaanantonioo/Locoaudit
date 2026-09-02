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
    skipped = false, aggregate = false, kind = null,
    control = null, controlGroup = null, subcategory = null, detail = null,
    lynisType = null, actionType = null, severitySource = null, primaryUrl = null,
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
   * `skipped: true` marca un hallazgo que NO es un dato de auditoría, sino el aviso de que una
   * comprobación no llegó a ejecutarse. Es la mitad legible de lo que scanMeta cuenta en
   * estructurado, y lo sella skippedSourceFinding() en lib/normalizer.js.
   *
   * Existe como campo propio y no se deduce del sufijo "-SKIP" del id porque el id es una etiqueta
   * y esto es un hecho: el dashboard tiene que poder separar "cero porque está limpio" de "cero
   * porque nadie miró" sin hacer arqueología sobre cómo se nombraron los ids. Solo se añade cuando
   * es true; su ausencia significa que el hallazgo sí es un dato.
   */
  if (skipped) finding.skipped = true;

  /**
   * `aggregate: true` marca un finding que RESUME muchos hallazgos que el usuario no puede
   * accionar (HOST-CVE-DECLARED, HOST-OS-CVE-UNFIXED). Mismo motivo que `skipped`: el dashboard
   * necesita distinguirlo de un informativo normal —"tu disco está al 42 %"— para no describirlo
   * como un dato del equipo, y sacarlo del prefijo del id sería adivinar. Solo se añade si es
   * true; su ausencia significa que el finding describe una cosa concreta.
   */
  if (aggregate) finding.aggregate = true;

  /**
   * `kind` acompaña a `skipped`: POR QUÉ no se ejecutó la comprobación, con el mismo vocabulario
   * que usan los módulos ('disabled', 'not-installed', 'unsupported', 'timeout', 'error'…).
   *
   * Sin él, `skipped: true` solo dice que falta el dato, y el dashboard no puede separar "lo
   * apagaste tú" de "se intentó y falló" — que es la diferencia entre una nota al pie y una
   * tarjeta ámbar. Se sella aquí y no se deduce del texto de `reason`: ese texto cambia de
   * plataforma y de versión del SO, y compararlo es lo que ya rompió el gate de Trivy una vez.
   */
  if (kind) finding.kind = String(kind);

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
