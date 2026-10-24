"use strict";

/** Tablas de severidad y utilidades de comparación. */

const RANK_MAP = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };

/** Rango numérico de una severidad: 0 info … 4 critical. */
function rank(severity) {
  return RANK_MAP[String(severity || "").toLowerCase()] ?? 0;
}

/** La severidad más alta del conjunto. */
function max(...sevs) {
  return sevs.reduce((acc, s) => (rank(s) > rank(acc) ? s : acc), "info");
}

/** Normaliza una severidad de Trivy (CRITICAL…UNKNOWN) al nivel canónico. */
function fromTrivy(s) {
  const up = String(s || "").trim().toUpperCase();
  const map = { CRITICAL: "critical", HIGH: "high", MEDIUM: "medium", LOW: "low" };
  return map[up] || "info";
}

/** Puntuación CVSS (escala v3) al nivel canónico. Sin nota da 'medium' y no 'info',
 *  para que un CVE sin puntuar no desaparezca del riesgo. */
function fromCvss(score) {
  const n = typeof score === "number" ? score : parseFloat(String(score == null ? "" : score).trim());
  if (!Number.isFinite(n) || n <= 0) return "medium";
  if (n >= 9.0) return "critical";
  if (n >= 7.0) return "high";
  if (n >= 4.0) return "medium";
  return "low";
}

/** Normaliza un nivel de Lynis: WARNING → high, SUGGESTION → low, NONE → info. */
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

const EMPTY_COUNTS = () => ({ info: 0, low: 0, medium: 0, high: 0, critical: 0 });

/** ¿El hallazgo le pide algo al usuario? 'declared' solo cuenta en imagen, donde los paquetes
 *  del SO llegan sin PkgPath; un finding sin `scope` se trata como host. */
function isActionable(f) {
  if (!f) return false;
  if (f.category === "performance") return false;
  if (f.origin === "declared" && f.scope !== "image") return false;
  if (String(f.severity || "info").toLowerCase() === "info") return false;
  return true;
}

/** Contadores y severidad máxima por scope y por accionable/informativo, para el dashboard. */
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

    // Solo los accionables elevan el riesgo global.
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
    // Repite globalMax para que el dashboard lea un solo objeto.
    actionable: { maxSeverity: globalMax, counts: actionableCounts, total: actionableTotal },
    informative: { counts: informativeCounts, total: informativeTotal },
  };
}

/** Umbrales de RAM por plataforma (% usado). null es no alertar: en macOS un 95-99 % es normal. */
const MEMORY_THRESHOLDS = {
  darwin: { warn: null, critical: null },
  linux:  { warn: 85,   critical: 95   },
  win32:  { warn: 85,   critical: 95   },
};

/** Severidad por ID de aviso de Lynis, calibrada para un PC personal y no para un servidor.
 *  Solo se aplica a avisos: en sugerencias las inflaría. */
const LYNIS_PERSONAL_SEVERITY = {

  "FIRE-4508": "high",    // No hay firewall activo (iptables/nftables/pf)
  "FIRE-4513": "high",    // No hay software de firewall instalado

  "SSH-7408":  "high",    // PermitRootLogin yes — acceso root remoto directo
  "SSH-7412":  "high",    // Protocolo SSH versión 1 — roto criptográficamente

  "AUTH-9262": "high",    // Configuración PAM débil o permisiva
  "AUTH-9328": "high",    // Cuentas de usuario sin contraseña

  "CRYP-7902": "high",    // Certificados del sistema expirados

  "USB-1000":  "high",    // Módulo USB storage activo y sin restricciones

  "KRNL-5820": "medium",  // Kernel desactualizado
  "KRNL-6000": "medium",  // Parámetros sysctl de hardening no configurados

  "NAME-4408": "medium",  // Resolver DNS con recursión abierta
  "MAIL-8818": "medium",  // Servicio de correo sin hardening aplicado

  "PKGS-7392": "medium",  // Paquetes vulnerables detectados
  "PKGS-7370": "medium",  // Gestor de paquetes sin actualizaciones automáticas

  "LOGG-2190": "medium",  // Syslog no configurado para red o persistencia
  "TIME-3104": "medium",  // NTP o chrony no configurados explícitamente

  "SSH-7402":  "low",     // Versión del protocolo (informativo si ya es v2)
  "SSH-7440":  "low",     // Banner de advertencia en SSH — cosmético

  "AUTH-9286": "low",     // Password aging — positivo pero no urgente
  "AUTH-9308": "low",     // Umask en perfil de usuario

  "LOGG-2153": "low",     // Sin logging remoto centralizado

  "CRYP-001":  "low",     // Cifrados débiles en OpenSSL (sin contexto específico)

  "ACCT-9622": "low",     // Process accounting (acct) no habilitado
  "ACCT-9626": "low",     // Sysstat no instalado

  "STRG-1840": "low",     // Filesystems no comunes (cramfs, freevxfs…)
  "STRG-1846": "low",     // Módulo squashfs activo

  "TOOL-5002": "low",     // Sin herramienta de detección de rootkits (rkhunter, chkrootkit)
  "MALW-3280": "low",     // Sin escáner de malware instalado
  "FINT-4350": "low",     // Sin herramienta de integridad de ficheros (AIDE)

  "BANN-7126": "low",     // Sin banner legal en /etc/motd o /etc/issue

  // Los ISP domésticos filtran las consultas SOA: el DNS funciona y Lynis avisa igual.
  "NETW-2704": "info",    // nameserver no responde a SOA, normal en redes de ISP doméstico
  "NETW-2705": "info",    // menos de 2 nameservers responsivos, normal en redes domésticas
  "NETW-2706": "info",    // variante del mismo control de nameservers
  "NETW-3200": "info",    // configuración de red doméstica normal
};

/** Tramo de riesgo por prefijo del control (Lynis no puntúa, el criterio es de LoCoAudit).
 *  A: exposición directa · B: superficie endurecible · C: observabilidad y utillaje. */
const LYNIS_GROUP_TIER = {
  FIRE: "A", SSH: "A", AUTH: "A", CRYP: "A", USB: "A",
  KRNL: "B", BOOT: "B", NETW: "B", NAME: "B", PKGS: "B", FILE: "B",
  HOME: "B", STRG: "B", PROC: "B", HRDN: "B",
  LOGG: "C", ACCT: "C", TOOL: "C", BANN: "C", MAIL: "C", TIME: "C", HTTP: "C",
  FINT: "C",   // integridad de ficheros (AIDE): detecta, no reduce exposición
};

const DEFAULT_LYNIS_TIER = "B";

/** Matriz tramo × tipo. El aviso pesa más que la sugerencia, y las sugerencias son "info"
 *  salvo en el tramo A para no inflar el contador de atención. */
const LYNIS_TIER_SEVERITY = {
  A: { warning: "high",   suggestion: "low"  },
  B: { warning: "medium", suggestion: "info" },
  C: { warning: "low",    suggestion: "info" },
};

/** Prefijo de un control: "AUTH-9262" → "AUTH". */
function lynisGroup(control) {
  if (!control || typeof control !== "string") return "";
  return control.split("-")[0].toUpperCase();
}

/** Severidad de un hallazgo de Lynis, según el criterio de LoCoAudit. */
function lynisSeverity(control, type) {
  const kind = type === "warning" ? "warning" : "suggestion";

  // El override por ID manda, pero solo en avisos.
  if (kind === "warning") {
    const override = LYNIS_PERSONAL_SEVERITY[control];
    if (override) return override;
  }

  const tier = LYNIS_GROUP_TIER[lynisGroup(control)] || DEFAULT_LYNIS_TIER;
  return LYNIS_TIER_SEVERITY[tier][kind];
}

/** Reglas de severidad de security-events. Windows reutiliza las claves: 4624 remoto ≈ SSH_ACCEPTED,
 *  4625 ≈ fallidos, 4672 ≈ SSH_ACCEPTED_ROOT. */
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
  fromCvss,
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
