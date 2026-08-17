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
 *     isCommand: boolean,  // true si hay una línea copiable en `command`
 *     command:   string|null, // SOLO la línea ejecutable (nunca la nota)
 *     category:  string,   // "cpu" | "memory" | "disk" | "network" | "image" | ...
 *     source:    string,   // "native" | "nmap" | "lynis" | "trivy" | "nuclei"
 *     timestamp: string,   // ISO 8601, generado automáticamente
 *   }
 *
 * Campos OPCIONALES (solo hallazgos de red, ver fromNmap en lib/normalizer.js):
 *   target:        string   // host/IP realmente escaneado ("192.168.1.40")
 *   isLocalTarget: boolean  // false → el puerto está en OTRO dispositivo de la red
 *
 * Campos OPCIONALES (solo hallazgos de Trivy, ver fromTrivyJson):
 *   origin:   'declared'|'installed'  // señal única: PkgPath del Vulnerability
 *   location: string                  // PkgPath, con Target como respaldo
 *
 * 'declared' = el paquete está anotado en un fichero de bloqueo (Pipfile.lock,
 * poetry.lock, package-lock.json), NO instalado en disco: no hay nada que
 * actualizar en el equipo. 'installed' = paquete real, con gestor y comando.
 *
 * Campos OPCIONALES (solo hallazgos de Lynis, ver fromLynisRaw):
 *   control:        string   // ID del control ("AUTH-9262"). Metadato, NO el título.
 *   controlGroup:   string   // prefijo del control ("AUTH")
 *   subcategory:    string   // etiqueta en español del grupo ("Autenticación y contraseñas")
 *   detail:         string   // campo 3 del .dat: dónde/qué se encontró ("/home")
 *   lynisType:      'warning'|'suggestion'
 *   actionType:     string   // 'reboot' — del campo 4, vocabulario cerrado
 *   severitySource: 'locoaudit'  // la severidad la pone LoCoAudit, no la herramienta
 *
 * `severitySource` existe porque Lynis NO asigna severidad a sus controles: el
 * nivel que ve el usuario es un juicio de LoCoAudit y el dashboard lo dice en la
 * tarjeta. Cualquier fuente futura que tampoco puntúe (Nuclei sin CVSS, reglas
 * propias) debe sellarlo igual en vez de presentar su nivel como ajeno.
 *
 * Solo se añaden al objeto si el llamante los pasa: un finding de host o de
 * imagen no los lleva, y su AUSENCIA (undefined) significa "no aplica", que es
 * el fallback seguro para todo consumidor (chat con el LLM incluido).
 *
 * Exporta:
 *   createFinding(fields) → Finding
 *   validate(obj)         → boolean
 */

const VALID_SEVERITIES = new Set(["critical", "high", "medium", "low", "info"]);

// FALLBACK defensivo — NO es la fuente de verdad de isCommand.
//
// La decisión de "esto es un comando" la toma AHORA el generador del fix, que es
// quien sabe con certeza lo que está produciendo: getTrivyFixCommand y
// getLynisFixText (lib/normalizer.js) y pkg-manager.js devuelven la línea copiable
// como campo `command` explícito, y createFinding la respeta tal cual.
//
// Estos patrones solo cubren las llamadas a createFinding que todavía pasan un
// `fix` suelto sin `command` (findings nativos legacy). Cuando añadas un gestor
// de paquetes nuevo (cargo/gem/nuget/pnpm/poetry…), añádelo en su GENERADOR
// (TRIVY_LANG_CMD / pkg-manager COMMANDS), NO aquí: aquí es una red de seguridad,
// no el sitio donde se decide.
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

/**
 * ¿Es el texto un comando ejecutable TAL CUAL, sin nada más?
 *
 * Exige UNA sola línea y ausencia de prosa. Sin estas dos condiciones se colaban
 * dos clases de falso positivo:
 *   - "Jupyter expuesto en red es un riesgo crítico. Configura…" → casaba con
 *     /^jupyter\s/ y se marcaba como comando siendo una frase.
 *   - "sudo apt remove --purge telnet\n(en Fedora/RHEL: …)" → el botón «Copiar
 *     comando» copiaba también la nota, produciendo un pegado inejecutable.
 *
 * La nota explicativa no desaparece: sigue en `fix`. Lo que se separa es el
 * texto COPIABLE (campo `command`), que es solo la línea ejecutable.
 *
 * @param {string|null} fix
 * @returns {boolean}
 */
function _isCmd(fix) {
  if (!fix || typeof fix !== "string") return false;
  const t = fix.trim();
  if (t.includes("\n")) return false;   // multilínea: comando + nota, o varios pasos
  if (/[.:]\s/.test(t)) return false;   // prosa: "…crítico. Configura…", "Para X: cmd"
  return _CMD_PATTERNS.some((p) => p.test(t));
}

/**
 * Extrae la línea copiable de un fix: la PRIMERA línea, si por sí sola es un
 * comando puro. Así "comando\n(nota)" conserva su botón de copiar sin arrastrar
 * la nota, y la prosa con un comando embebido sigue sin ofrecer botón.
 *
 * @param {string|null} fix
 * @returns {string|null}
 */
function _extractCommand(fix) {
  if (!fix || typeof fix !== "string") return null;
  const first = fix.split("\n")[0].trim();
  return _isCmd(first) ? first : null;
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
 * @param {string} [fields.target]         Host/IP escaneado (solo red).
 * @param {boolean} [fields.isLocalTarget] false si el target es otro dispositivo (solo red).
 * @param {string} [fields.origin]         'declared'|'installed' (solo Trivy).
 * @param {string} [fields.location]       PkgPath o Target del hallazgo (solo Trivy).
 * @param {string} [fields.scope]          'host'|'network'|'image'. Normalmente NO se
 *                                         pasa aquí: lo sella el punto de entrada del
 *                                         normalizador (normalizeHost/Network/Image).
 * @returns {Object} Finding
 */
function createFinding(fields) {
  const {
    id, title, severity, evidence,
    fix = null, category = "other", source = "native", image = null,
    target = null, isLocalTarget = null, origin = null, location = null,
    scope = null,
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

  // `command` = SOLO la línea ejecutable (lo que copia el dashboard).
  // `fix`     = texto completo, comando + nota explicativa si la hay.
  // isCommand se deriva de command: si no hay línea copiable, no hay botón.
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
  // Imagen de origen (opcional): permite agrupar hallazgos por imagen auditada
  // cuando se escanean varias en una sola pasada.
  if (image) finding.image = String(image);

  // Target escaneado (opcional, solo red). Viaja CON el finding a propósito: es
  // el único modo de que el chat con el LLM sepa que el puerto está en otro
  // dispositivo, en vez de tener que reinferirlo (dos fuentes de verdad).
  if (target) finding.target = String(target);
  if (isLocalTarget !== null && isLocalTarget !== undefined) {
    finding.isLocalTarget = Boolean(isLocalTarget);
  }

  // Procedencia del paquete (opcional, solo Trivy). Distingue "anotado en un
  // lockfile" de "instalado en disco": son hechos distintos con remediaciones
  // distintas, y sin el campo el dashboard no puede separarlos.
  if (origin) finding.origin = String(origin);
  if (location) finding.location = String(location);

  // Nodo que produjo el hallazgo. Decide si `origin: 'declared'` eleva el riesgo
  // global (ver summarize() en lib/severity-map.js): en host NO, en imagen SÍ.
  // Lo sella normalizeHost/normalizeNetwork/normalizeImage, no cada módulo.
  if (scope) finding.scope = String(scope);

  // Metadatos de control (opcionales, hoy solo Lynis). Planos y no anidados,
  // por coherencia con los de Trivy (pkg, cvss, origin…) y para que el
  // ui_template los lea con un solo nivel de acceso, como todo lo demás.
  if (control) finding.control = String(control);
  if (controlGroup) finding.controlGroup = String(controlGroup);
  if (subcategory) finding.subcategory = String(subcategory);
  if (detail) finding.detail = String(detail);
  if (lynisType) finding.lynisType = String(lynisType);
  if (actionType) finding.actionType = String(actionType);
  if (severitySource) finding.severitySource = String(severitySource);

  // URL de referencia. El ui_template ya tenía la celda "🔗 Advisory" leyendo
  // este campo, pero NINGÚN módulo lo producía: siempre pintaba "no disponible".
  // El campo 4 del .dat de Lynis ('url:…') es su primer emisor real.
  if (primaryUrl) finding.primaryUrl = String(primaryUrl);

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

module.exports = {
  createFinding,
  validate,
  VALID_SEVERITIES,
  isCommandFix: _isCmd,
  extractCommand: _extractCommand,
};
