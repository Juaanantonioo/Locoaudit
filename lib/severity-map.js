"use strict";

/**
 * severity-map.js — Tablas de mapeo de severidad y utilidades de comparación.
 *
 * Exporta:
 *   rank(severity)    → number   (0–4)
 *   max(...sevs)      → string   (severidad más alta del conjunto)
 *   fromTrivy(s)      → string   (normaliza cadena Trivy → nivel canónico)
 *   fromLynis(s)      → string   (normaliza nivel Lynis → nivel canónico)
 *   summarize(findings) → Object (contadores y severidad máxima por scope)
 */

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
 * ¿Este hallazgo le pide algo al usuario, o solo le informa?
 *
 * Un hallazgo NO accionable es el que describe algo que no está ocurriendo en el
 * equipo auditado. Hay tres formas de eso:
 *
 *   1. category 'performance' — lentitud, no inseguridad. No hay nada que
 *      arreglar desde el punto de vista de seguridad.
 *   2. origin 'declared' FUERA de una imagen — una versión anotada en un fichero
 *      de dependencias (yarn.lock, bun.lock, pom.xml) de un programa de
 *      terceros. Trivy leyó el fichero, no un paquete instalado: no hay nada
 *      que actualizar. Su CVSS describe la vulnerabilidad si la ejecutaras, y
 *      por eso sigue visible en el desplegable del dashboard — pero no es el
 *      riesgo de ESTE equipo.
 *   3. severity 'info' — informativo por definición.
 *
 * El caso 2 se acota a scope !== 'image' a propósito: en una imagen Docker los
 * CVEs de paquetes del SO llegan SIN PkgPath (medido con trivy 0.72.0 sobre
 * debian:12 → 0 de 169 traen PkgPath), así que la regla
 * `PkgPath ? installed : declared` de normalizer.js los marca 'declared'
 * aunque estén instalados dentro de la imagen y sean perfectamente accionables.
 * Excluirlos dejaría al dashboard de imagen sin nivel de riesgo.
 *
 * Se compara con `!== 'image'` y no con `=== 'host'` para que un payload
 * anterior a la existencia del campo `scope` (que no lo trae) siga
 * comportándose como host, que es el caso mayoritario. No es un descuido:
 * es la opción conservadora en los dos dashboards a la vez — nunca baja el
 * riesgo de una imagen por un campo ausente.
 *
 * @param {{severity?: string, category?: string, origin?: string, scope?: string}} f
 * @returns {boolean}
 */
function isActionable(f) {
  if (!f) return false;
  if (f.category === "performance") return false;
  if (f.origin === "declared" && f.scope !== "image") return false;
  if (String(f.severity || "info").toLowerCase() === "info") return false;
  return true;
}

/**
 * Calcula contadores y severidad máxima de un array de findings.
 * Segmenta también por scope ("host" vs "image") para el dashboard.
 *
 * `actionable` / `informative` son la única fuente de verdad del recuento
 * segmentado del dashboard: el predicado que decide el riesgo global es el
 * mismo que decide en qué bloque cae cada hallazgo, así que no pueden divergir.
 * El ui_template consume estas cifras, no las recalcula.
 *
 * @param {Array<{severity: string, category?: string, scope?: string, origin?: string}>} findings
 * @returns {{
 *   maxSeverity: string,
 *   counts: Object,
 *   host: { maxSeverity: string, counts: Object },
 *   image: { maxSeverity: string, counts: Object },
 *   actionable: { maxSeverity: string, counts: Object, total: number },
 *   informative: { counts: Object, total: number }
 * }}
 */
function summarize(findings) {
  const counts = EMPTY_COUNTS();
  const hostCounts = EMPTY_COUNTS();
  const imageCounts = EMPTY_COUNTS();
  const actionableCounts = EMPTY_COUNTS();
  const informativeCounts = EMPTY_COUNTS();
  let globalMax = "info";
  let hostMax = "info";
  let imageMax = "info";
  let actionableTotal = 0;
  let informativeTotal = 0;

  for (const f of findings) {
    const sev = String(f.severity || "info").toLowerCase();

    counts[sev] = (counts[sev] || 0) + 1;

    // El riesgo global lo elevan SOLO los hallazgos accionables: ver isActionable().
    if (isActionable(f)) {
      if (rank(sev) > rank(globalMax)) globalMax = sev;
      actionableCounts[sev] = (actionableCounts[sev] || 0) + 1;
      actionableTotal++;
    } else {
      informativeCounts[sev] = (informativeCounts[sev] || 0) + 1;
      informativeTotal++;
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
    // maxSeverity de actionable === globalMax por construcción: se deja explícito
    // para que el dashboard lea un solo objeto y no tenga que cruzarlos.
    actionable: { maxSeverity: globalMax, counts: actionableCounts, total: actionableTotal },
    informative: { counts: informativeCounts, total: informativeTotal },
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
 *
 * ── Alcance desde la reestructuración de Lynis ───────────────────────────────
 *
 * Este mapa dejó de ser la fuente PRINCIPAL de severidad y pasó a ser un
 * OVERRIDE que se aplica SOLO A LOS AVISOS (`warning[]`). Dos razones:
 *
 * 1. Está indexado por ID, y los IDs varían con la plataforma: cubre 7 de las
 *    18 entradas del .dat de macOS (test/fixtures/lynis/report-macos.dat), y
 *    KRNL-5830 —el aviso que dispara el caso de CachyOS— ni siquiera existe en
 *    macOS. La base estable entre plataformas es el PREFIJO (LYNIS_GROUP_TIER),
 *    que es además la clave que getLynisFixText() ya usaba.
 *
 * 2. Sus niveles están escritos pensando en avisos ("lynis show controls |
 *    grep WARNING", nota de mantenimiento nº 1 de arriba). Aplicarlos también a
 *    las sugerencias inflaría: AUTH-9262 es "high" como aviso (PAM débil), pero
 *    como sugerencia dice "instala un módulo PAM de robustez de contraseña",
 *    que no es lo mismo. Las sugerencias van siempre por tramo.
 *
 * Lo que este mapa sigue decidiendo, y por eso no se borra: los NETW-2704/2705
 * de abajo son "info" a propósito (falso positivo de ISP doméstico). Sin este
 * override, el tramo NETW los subiría a "medium" y reintroduciríamos el ruido
 * que ya se había eliminado.
 */
const LYNIS_PERSONAL_SEVERITY = {

  // ── HIGH — riesgo real e inmediato en PC personal ──────────────────────────

  // Firewall: ausencia total de filtrado, no sólo configuración débil
  "FIRE-4508": "high",    // No hay firewall activo (iptables/nftables/pf)
  "FIRE-4513": "high",    // No hay software de firewall instalado

  // SSH: vectores de acceso remoto no autenticado o con máximos privilegios
  "SSH-7408":  "high",    // PermitRootLogin yes — acceso root remoto directo
  "SSH-7412":  "high",    // Protocolo SSH versión 1 — roto criptográficamente

  // Autenticación: cuentas accesibles sin credenciales
  "AUTH-9262": "high",    // Configuración PAM débil o permisiva
  "AUTH-9328": "high",    // Cuentas de usuario sin contraseña

  // Criptografía: certificados expirados invalidan cualquier canal TLS
  "CRYP-7902": "high",    // Certificados del sistema expirados

  // Hardware: autorun USB activo — vector de ataque físico frecuente
  "USB-1000":  "high",    // Módulo USB storage activo y sin restricciones

  // ── MEDIUM — mejora recomendable, no urgente ───────────────────────────────

  // Kernel: versiones antiguas pueden tener CVEs locales sin parchear
  "KRNL-5820": "medium",  // Kernel desactualizado
  "KRNL-6000": "medium",  // Parámetros sysctl de hardening no configurados

  // Red: configuraciones que amplían superficie de ataque sin ser críticas
  "NAME-4408": "medium",  // Resolver DNS con recursión abierta
  "MAIL-8818": "medium",  // Servicio de correo sin hardening aplicado

  // Paquetes: software desactualizado con CVEs conocidas pero no explotadas activamente
  "PKGS-7392": "medium",  // Paquetes vulnerables detectados
  "PKGS-7370": "medium",  // Gestor de paquetes sin actualizaciones automáticas

  // Logging y tiempo: sin registro ni sincronización fiable
  "LOGG-2190": "medium",  // Syslog no configurado para red o persistencia
  "TIME-3104": "medium",  // NTP o chrony no configurados explícitamente

  // ── LOW — buenas prácticas de servidor, bajo impacto en PC personal ────────

  // SSH: controles de aspecto o de servidores multi-usuario
  "SSH-7402":  "low",     // Versión del protocolo (informativo si ya es v2)
  "SSH-7440":  "low",     // Banner de advertencia en SSH — cosmético

  // Autenticación: políticas útiles en entorno multi-usuario, no en PC personal
  "AUTH-9286": "low",     // Password aging — positivo pero no urgente
  "AUTH-9308": "low",     // Umask en perfil de usuario

  // Logging remoto: relevante en flotas, no en PC doméstico
  "LOGG-2153": "low",     // Sin logging remoto centralizado

  // Criptografía: cifrados débiles en contextos no críticos
  "CRYP-001":  "low",     // Cifrados débiles en OpenSSL (sin contexto específico)

  // Auditoría de procesos: útil en servidores, overhead en PC personal
  "ACCT-9622": "low",     // Process accounting (acct) no habilitado
  "ACCT-9626": "low",     // Sysstat no instalado

  // Filesystem: módulos de kernels raros, difícilmente explotables en PC doméstico
  "STRG-1840": "low",     // Filesystems no comunes (cramfs, freevxfs…)
  "STRG-1846": "low",     // Módulo squashfs activo

  // Herramientas de seguridad: recomendables pero no críticas
  "TOOL-5002": "low",     // Sin herramienta de detección de rootkits (rkhunter, chkrootkit)
  "MALW-3280": "low",     // Sin escáner de malware instalado
  "FINT-4350": "low",     // Sin herramienta de integridad de ficheros (AIDE)

  // Banners y mensajes legales: obligatorios en corporativo, irrelevantes en PC
  "BANN-7126": "low",     // Sin banner legal en /etc/motd o /etc/issue

  // ── INFO — falsos positivos en redes domésticas ───────────────────────────

  // IDs NETW de nameservers: Lynis verifica que los nameservers respondan
  // a consultas SOA, pero los ISP domésticos (Vodafone, Movistar, etc.)
  // filtran este tipo de consultas. El DNS funciona correctamente para
  // uso normal pero Lynis lo reporta como advertencia. Clasificado como
  // "info" para evitar falsos positivos en entornos domésticos.
  "NETW-2704": "info",    // nameserver no responde a SOA, normal en redes de ISP doméstico
  "NETW-2705": "info",    // menos de 2 nameservers responsivos, normal en redes domésticas
  "NETW-2706": "info",    // variante del mismo control de nameservers
  "NETW-3200": "info",    // configuración de red doméstica normal
};

/**
 * Tramo de riesgo por PREFIJO de control de Lynis.
 *
 * ── ESTE CRITERIO ES DE LoCoAudit, NO DE LYNIS ───────────────────────────────
 *
 * Lynis NO asigna severidad a sus controles: emite avisos y sugerencias sin
 * ordenarlos. Cualquier nivel que muestre el dashboard en un hallazgo de Lynis
 * lo pone LoCoAudit. Por eso todo finding de Lynis viaja con
 * `severitySource: 'locoaudit'` y el dashboard lo dice en la tarjeta: el
 * usuario tiene derecho a saber de quién es el juicio que está leyendo.
 *
 * Se indexa por PREFIJO y no por ID porque el prefijo es lo único estable entre
 * plataformas (ver la nota de alcance de LYNIS_PERSONAL_SEVERITY) y porque es
 * la misma clave que getLynisFixText() usa en lib/normalizer.js para elegir el
 * paso de resolución: una sola taxonomía para decidir gravedad y remedio.
 *
 *   A — exposición directa: el equipo está expuesto AHORA. Sin cortafuegos, con
 *       root por SSH, con cuentas sin contraseña. Se actúa hoy.
 *   B — superficie endurecible: amplía el riesgo sin materializarlo. Kernel sin
 *       parámetros de hardening, DNS incompleto, permisos amplios.
 *   C — observabilidad y utillaje: no cambia la exposición del equipo. Logs,
 *       auditoría de procesos, banners legales, herramientas recomendadas.
 *
 * Prefijo desconocido → DEFAULT_LYNIS_TIER. Lynis añade controles en cada
 * versión y la lista de abajo envejece; el tramo intermedio evita las dos
 * formas de equivocarse (alarmar por algo que no se entiende, o esconderlo).
 */
const LYNIS_GROUP_TIER = {
  // A · exposición directa
  FIRE: "A", SSH: "A", AUTH: "A", CRYP: "A", USB: "A",
  // B · superficie endurecible
  KRNL: "B", BOOT: "B", NETW: "B", NAME: "B", PKGS: "B", FILE: "B",
  HOME: "B", STRG: "B", PROC: "B", HRDN: "B",
  // C · observabilidad y utillaje
  LOGG: "C", ACCT: "C", TOOL: "C", BANN: "C", MAIL: "C", TIME: "C", HTTP: "C",
  FINT: "C",   // integridad de ficheros (AIDE): detecta, no reduce exposición
};

const DEFAULT_LYNIS_TIER = "B";

/**
 * Matriz tramo × tipo.
 *
 * Un AVISO es un defecto que Lynis ha detectado; una SUGERENCIA es una buena
 * práctica que no está aplicada. No son lo mismo y no pueden pesar igual: por
 * eso un aviso siempre queda por encima de la sugerencia de su mismo tramo.
 *
 * Las sugerencias son "info" salvo en el tramo A. Es la decisión que sostiene
 * el volumen: crear un hallazgo por sugerencia multiplica por 8 los findings de
 * Lynis, pero solo suma al contador de "requieren tu atención" aquello cuya
 * ausencia deja el equipo expuesto de verdad — "no tienes cortafuegos
 * configurado" entra; "considera instalar sysstat" no.
 */
const LYNIS_TIER_SEVERITY = {
  A: { warning: "high",   suggestion: "low"  },
  B: { warning: "medium", suggestion: "info" },
  C: { warning: "low",    suggestion: "info" },
};

/**
 * Prefijo de un control de Lynis. "AUTH-9262" → "AUTH".
 * @param {string} control
 * @returns {string}
 */
function lynisGroup(control) {
  if (!control || typeof control !== "string") return "";
  return control.split("-")[0].toUpperCase();
}

/**
 * Severidad de un hallazgo de Lynis — criterio de LoCoAudit.
 *
 * @param {string} control  ID del control ("AUTH-9262")
 * @param {string} type     'warning' | 'suggestion'
 * @returns {string}        severidad canónica
 */
function lynisSeverity(control, type) {
  const kind = type === "warning" ? "warning" : "suggestion";

  // El override por ID manda, pero SOLO en avisos: ver la nota de alcance de
  // LYNIS_PERSONAL_SEVERITY. Es lo que mantiene NETW-2704/2705 en "info".
  if (kind === "warning") {
    const override = LYNIS_PERSONAL_SEVERITY[control];
    if (override) return override;
  }

  const tier = LYNIS_GROUP_TIER[lynisGroup(control)] || DEFAULT_LYNIS_TIER;
  return LYNIS_TIER_SEVERITY[tier][kind];
}

/**
 * Reglas de severidad para el submódulo security-events de audit-host.
 *
 * ── Delimitación con Lynis ───────────────────────────────────────────────────
 * Lynis audita la CONFIGURACIÓN de SSH (hardening: PermitRootLogin, protocolo,
 * banners...). security-events audita los EVENTOS: quién entró, cuándo y desde
 * dónde en una ventana temporal. No duplicar aquí chequeos de configuración.
 *
 * Sigue el patrón de MEMORY_THRESHOLDS: constantes centralizadas que el
 * normalizador consume — los módulos solo recolectan datos crudos.
 *
 * Criterio (PC personal / doméstico, foto fija de las últimas N horas):
 *   - Un login SSH correcto no es un problema per se → info (visibilidad).
 *   - Login SSH de root sí: máximo privilegio por red → high.
 *   - Fallos SSH aislados son ruido normal → low agregado; a partir de
 *     SSH_BRUTE_FORCE_THRESHOLD en la ventana el patrón sugiere fuerza
 *     bruta → high.
 *   - sudo correcto es uso normal del sistema → info agregado.
 *   - Fallos de sudo repetidos (>= SUDO_FAIL_THRESHOLD) pueden indicar intento
 *     de escalada local → medium; menos → low.
 *   - Sesión remota activa ahora → info (visibilidad).
 *
 * ── Windows ──────────────────────────────────────────────────────────────────
 * La rama win32 (eventos 4624/4625/4672) reutiliza estas MISMAS claves y
 * umbrales — no duplicar constantes:
 *   4624 remoto (LogonType 10/3) ↔ SSH_ACCEPTED
 *   4625 fallidos                ↔ SSH_FAILED_FEW/MANY + SSH_BRUTE_FORCE_THRESHOLD
 *   4672 desde sesión remota     ↔ SSH_ACCEPTED_ROOT (análogo a login de root)
 *   sesión RDP activa            ↔ REMOTE_SESSION
 */
const SECURITY_EVENT_RULES = {
  SSH_ACCEPTED: "info",          // login SSH correcto desde IP remota
  SSH_ACCEPTED_ROOT: "high",     // login SSH correcto como root
  SSH_FAILED_FEW: "low",         // 1..(threshold-1) fallidos en la ventana
  SSH_FAILED_MANY: "high",       // >= threshold → posible fuerza bruta
  SSH_BRUTE_FORCE_THRESHOLD: 10,
  SUDO_OK: "info",               // usos correctos de sudo (agregado)
  SUDO_FAIL_FEW: "low",          // < threshold fallos de autenticación sudo
  SUDO_FAIL_MANY: "medium",      // >= threshold fallos
  SUDO_FAIL_THRESHOLD: 3,
  REMOTE_SESSION: "info",        // sesión remota activa ahora
};

module.exports = {
  rank,
  max,
  fromTrivy,
  fromLynis,
  isActionable,
  summarize,
  MEMORY_THRESHOLDS,
  LYNIS_PERSONAL_SEVERITY,
  LYNIS_GROUP_TIER,
  LYNIS_TIER_SEVERITY,
  DEFAULT_LYNIS_TIER,
  lynisGroup,
  lynisSeverity,
  SECURITY_EVENT_RULES,
};
