"use strict";

/**
 * normalizer.js — Convierte salidas raw de módulos al esquema Finding canónico.
 *
 * API pública:
 *   normalizeHost(raw, source)    → Finding[]
 *   normalizeNetwork(raw, source) → Finding[]
 *   normalizeImage(raw, source)   → Finding[]
 *
 * Internamente delega a subfunciones por herramienta/módulo:
 *   fromCpuMemory(raw)    — módulo cpu-memory.js
 *   fromDisk(raw)         — módulo disk-storage.js
 *   fromNative(raw)       — raw findings ya formateados por módulos nativos
 *   fromNmap(raw)         — nmap-wrapper
 *   fromLynisRaw(raw)     — lynis wrapper
 *   fromTrivyJson(raw)    — trivy fs / trivy image
 */

const { createFinding, isCommandFix } = require("./finding-schema");
const { fromTrivy, fromLynis, max, MEMORY_THRESHOLDS, LYNIS_PERSONAL_SEVERITY, SECURITY_EVENT_RULES } = require("./severity-map");
const { getFixForProcess, DANGEROUS_SERVICES } = require("./process-fix");

// ── Helpers internos ────────────────────────────────────────────────────────

function safe(val, fallback = "—") {
  return val != null ? String(val) : fallback;
}

function counter(n) {
  return String(n + 1).padStart(3, "0");
}

// ── Umbrales de severidad para métricas del host ────────────────────────────

/**
 * Clasifica el porcentaje de uso de disco según umbrales fijos.
 * @param {number} pct
 * @returns {string}
 */
// Umbrales para uso doméstico: el objetivo es alertar solo cuando el disco
// está realmente lleno, no generar ruido con porcentajes normales de uso
// cotidiano (un disco al 68% con espacio libre suficiente no es un riesgo).
function diskSeverity(pct) {
  if (pct >= 95) return "critical";  // disco casi lleno, riesgo real de fallo
  if (pct >= 90) return "high";      // muy poco espacio, acción necesaria
  if (pct >= 85) return "medium";    // espacio limitado, conviene revisar
  return "info";                     // informativo, sin acción necesaria
}

/**
 * Clasifica el porcentaje de uso de RAM según los umbrales de la plataforma.
 * En macOS siempre devuelve "info" porque el kernel usa la RAM agresivamente.
 * @param {number} usedPct   0..100
 * @param {string} platform  'darwin' | 'linux' | 'win32' | ...
 * @returns {string}
 */
function memorySeverity(usedPct, platform) {
  const thresholds = MEMORY_THRESHOLDS[platform] || MEMORY_THRESHOLDS.linux;
  if (thresholds.critical !== null && usedPct >= thresholds.critical) return "high";
  if (thresholds.warn !== null && usedPct >= thresholds.warn) return "medium";
  return "info";
}

/**
 * Clasifica el hardening index de Lynis.
 * @param {number} index  0..100
 * @returns {string}
 */
function lynisIndexSeverity(index) {
  if (index < 30) return "high";
  if (index < 55) return "medium";
  return "info";
}

// ── Normalizadores específicos por módulo ───────────────────────────────────

/**
 * Genera findings a partir del raw de cpu-memory.js.
 * @param {{ cpu: Object, memory: Object, platform: string }} raw
 * @param {string} [platform]  Sobrescribe raw.platform si se pasa explícitamente.
 * @returns {Finding[]}
 */
function fromCpuMemory(raw, platform) {
  if (!raw) return [];
  const findings = [];
  const plat = platform || raw.platform || process.platform;

  // CPU — informativo: modelo, cores, load average
  if (raw.cpu) {
    const { model, cores, loadAvg } = raw.cpu;
    const loadStr = Array.isArray(loadAvg)
      ? `1m: ${loadAvg[0]?.toFixed(2)}, 5m: ${loadAvg[1]?.toFixed(2)}, 15m: ${loadAvg[2]?.toFixed(2)}`
      : "N/A (Windows)";

    // Detectar carga alta: loadAvg[0] > cores * 0.8
    let cpuSev = "info";
    if (Array.isArray(loadAvg) && loadAvg[0] != null && cores > 0) {
      const ratio = loadAvg[0] / cores;
      if (ratio >= 1.5) cpuSev = "high";
      else if (ratio >= 0.8) cpuSev = "medium";
    }

    findings.push(
      createFinding({
        id: "HOST-CPU-001",
        title: `CPU: ${model} (${cores} cores)`,
        severity: cpuSev,
        evidence: `Modelo: ${model}, Cores: ${cores}, Load avg: ${loadStr}`,
        fix: cpuSev !== "info"
          ? "Revisar procesos con alto consumo con top/htop."
          : null,
        category: "cpu",
        source: "native",
      })
    );
  }

  // Memoria — finding diferenciado por plataforma
  if (raw.memory) {
    const { totalGiB, usedGiB, freeRatio } = raw.memory;
    const usedRatio = freeRatio != null ? 1 - freeRatio : null;
    const usedPct = usedRatio != null ? Math.round(usedRatio * 100) : null;

    if (plat === "darwin") {
      // macOS: la RAM casi siempre aparece al 95-99% por gestión unificada del kernel.
      // Emitir siempre un finding informativo, nunca alerta.
      findings.push(
        createFinding({
          id: "HOST-MEM-INF",
          title: "Memoria RAM: gestión unificada macOS",
          severity: "info",
          evidence: `Total: ${totalGiB} GiB, Usado: ${usedGiB} GiB (${usedPct ?? "?"}%) — normal en macOS`,
          fix: null,
          category: "memory",
          source: "native",
        })
      );
    } else {
      // Linux / Windows: umbrales estándar
      const sev = usedPct != null ? memorySeverity(usedPct, plat) : "info";
      findings.push(
        createFinding({
          id: "HOST-MEM-001",
          title: `Memoria RAM: ${usedPct ?? "?"}% en uso`,
          severity: sev,
          evidence: `Total: ${totalGiB} GiB, Usado: ${usedGiB} GiB (${usedPct ?? "?"}%)`,
          fix: sev !== "info"
            ? "Identificar procesos con alto consumo de RAM. Considerar ampliar memoria."
            : null,
          category: "memory",
          source: "native",
        })
      );
    }
  }

  return findings;
}

/**
 * Genera findings a partir del array de particiones de disk-storage.js.
 * @param {Array<{mount, totalGB, usedGB, freeGB, usedPercent}>} partitions
 * @returns {Finding[]}
 */
function fromDisk(partitions) {
  if (!Array.isArray(partitions)) return [];
  return partitions.map((p, i) => {
    const sev = diskSeverity(p.usedPercent);
    return createFinding({
      id: `HOST-DISK-${counter(i)}`,
      title: `Disco ${p.mount}: ${p.usedPercent}% en uso`,
      severity: sev,
      evidence: `Montaje: ${p.mount}, Total: ${p.totalGB} GB, Usado: ${p.usedGB} GB, Libre: ${p.freeGB} GB (${p.usedPercent}%)`,
      fix: sev !== "info"
        ? `Liberar espacio en ${p.mount}. Eliminar ficheros temporales o ampliar volumen.`
        : null,
      category: "disk",
      source: "native",
    });
  });
}

/**
 * Genera un finding informativo a partir del inventario de software.
 * No aplica severidad por ahora (se delega a Trivy para CVEs).
 * @param {Array<{name, version, source}>} pkgs
 * @returns {Finding[]}
 */
function fromSwInventory(pkgs) {
  if (!Array.isArray(pkgs) || pkgs.length === 0) return [];
  const findings = [];

  findings.push(
    createFinding({
      id: "HOST-SW-001",
      title: `Software instalado: ${pkgs.length} paquetes`,
      severity: "info",
      evidence: `${pkgs.length} paquetes encontrados. Fuentes: ${[...new Set(pkgs.map((p) => p.source))].join(", ")}`,
      fix: null,
      category: "system",
      source: "native",
    })
  );

  // Detectar servicios peligrosos o innecesarios en el inventario
  let dangerIdx = 1;
  for (const pkg of pkgs) {
    const normalName = pkg.name ? pkg.name.toLowerCase().trim() : "";
    const severity = DANGEROUS_SERVICES.get(normalName);
    if (!severity) continue;

    const fix = getFixForProcess(normalName, process.platform);
    findings.push(
      createFinding({
        id: `HOST-SW-DANGER-${String(dangerIdx++).padStart(3, "0")}`,
        title: `Servicio peligroso instalado: ${pkg.name}`,
        severity,
        evidence: `${pkg.name} ${pkg.version || ""} instalado (fuente: ${pkg.source}). Este servicio transmite datos sin cifrado y supone un riesgo de seguridad.`,
        fix: fix || `Desinstala ${pkg.name} si no lo necesitas activamente.`,
        category: "system",
        source: "native",
      })
    );
  }

  return findings;
}

/**
 * Número máximo de warnings que se emiten como findings individuales.
 * Los warnings adicionales se agrupan en un único finding resumen de severidad
 * "medium" para evitar que un sistema con muchos warnings de Lynis infle
 * artificialmente el dashboard con decenas de findings "high".
 * Las sugerencias siempre se agrupan en un único finding (pueden ser 50+).
 */
const MAX_LYNIS_INDIVIDUAL = 5;

/**
 * Genera findings a partir del resultado de lynis.js.
 *
 * Estrategia de agrupación:
 *   - Hardening index → 1 finding individual (refleja el estado global del sistema).
 *   - Primeros MAX_LYNIS_INDIVIDUAL warnings → 1 finding individual cada uno con
 *     severity "high" y enlace a la base de conocimiento de Lynis.
 *   - Warnings restantes → 1 finding resumen con severity "medium" para no inflar
 *     el dashboard: un sistema con 30 warnings no debe verse como 30 × "high".
 *   - Todas las sugerencias → 1 finding resumen con severity "low"; puede haber
 *     50+ sugerencias y cada una es una buena práctica, no un riesgo inmediato.
 *
 * @param {{ hardeningIndex: number|null, warnings: Array, suggestions: Array }} raw
 * @returns {Finding[]}
 */
function getLynisFixText(id) {
  if (!id) return "Revisar la configuración del sistema para este aviso de Lynis.";
  const prefix = id.split("-")[0].toUpperCase();
  const fixes = {
    NETW: "Revisar la configuración DNS del sistema. En macOS: Ajustes del Sistema → Red → DNS.",
    SSH:  "Revisar /etc/ssh/sshd_config. Desactivar PermitRootLogin y usar autenticación por clave.",
    FIRE: "Activar el firewall. En macOS: Ajustes del Sistema → Red → Firewall → Activar.",
    AUTH: "Revisar la configuración de autenticación PAM en /etc/pam.d/.",
    KRNL: "Revisar parámetros del kernel en /etc/sysctl.conf.",
    PKGS: "Actualizar paquetes del sistema con el gestor de paquetes correspondiente.",
    LOGG: "Revisar la configuración del sistema de logs en /etc/rsyslog.conf o similar.",
    TIME: "Configurar sincronización NTP. En macOS: Ajustes del Sistema → General → Fecha y hora.",
    CRYP: "Revisar la configuración criptográfica del sistema.",
    MAIL: "Revisar la configuración del servidor de correo si está activo.",
    USB:  "Revisar la configuración de dispositivos USB en Ajustes del Sistema → Privacidad.",
    BANN: "Añadir un banner de aviso legal en /etc/motd o /etc/issue.",
    ACCT: "Instalar y activar las herramientas de auditoría de procesos del sistema.",
    STRG: "Revisar los módulos de almacenamiento cargados en el kernel.",
    TOOL: "Considerar instalar herramientas adicionales de seguridad como rkhunter o chkrootkit.",
  };
  return fixes[prefix] || `Revisar la configuración del sistema relacionada con ${id}.`;
}

function fromLynisRaw(raw) {
  if (!raw || raw.skipped) return [];
  const findings = [];

  // 1. Hardening index global
  if (raw.hardeningIndex != null) {
    const sev = lynisIndexSeverity(raw.hardeningIndex);
    findings.push(
      createFinding({
        id: "HOST-LYN-IDX",
        title: `Lynis hardening index: ${raw.hardeningIndex}/100`,
        severity: sev,
        evidence: `Índice de hardening: ${raw.hardeningIndex}/100`,
        fix: sev !== "info"
          ? "Revisar las advertencias y sugerencias de Lynis para mejorar el hardening."
          : null,
        category: "system",
        source: "lynis",
      })
    );
  }

  // 2. Primeros MAX_LYNIS_INDIVIDUAL warnings → finding individual
  const warnings = raw.warnings || [];
  const individualWarnings = warnings.slice(0, MAX_LYNIS_INDIVIDUAL);
  const extraWarnings = warnings.slice(MAX_LYNIS_INDIVIDUAL);

  for (const [i, w] of individualWarnings.entries()) {
    const desc = w.description ? w.description.slice(0, 60) : null;
    const title = desc
      ? `Lynis: ${w.id} — ${desc}`
      : `Lynis: ${w.id}`;

    findings.push(
      createFinding({
        id: `HOST-LYN-${String(i + 1).padStart(3, "0")}`,
        title,
        severity: LYNIS_PERSONAL_SEVERITY[w.id] ?? "low",
        evidence: w.description || w.id || "sin descripción",
        fix: getLynisFixText(w.id),
        category: "system",
        source: "lynis",
      })
    );
  }

  // 3. Warnings adicionales → 1 finding resumen de severidad "medium"
  if (extraWarnings.length > 0) {
    const extraIds = extraWarnings.map((w) => w.id || "UNKNOWN").join(", ");
    const hasNetw = extraWarnings.some((w) => (w.id || "").toUpperCase().startsWith("NETW"));
    const warnFix = hasNetw
      ? "Ejecutar 'lynis show warnings' para ver el detalle completo. Para IDs NETW: verificar manualmente que el DNS funciona abriendo una terminal y ejecutando: nslookup google.com — Si responde con una dirección IP, el aviso es un falso positivo de Lynis en redes domésticas y puedes ignorarlo."
      : "Ejecutar 'lynis show warnings' para ver el detalle completo.";
    findings.push(
      createFinding({
        id: "HOST-LYN-WARN-EXTRA",
        title: `Lynis: ${extraWarnings.length} advertencias adicionales`,
        severity: "medium",
        evidence: extraIds,
        fix: warnFix,
        category: "system",
        source: "lynis",
      })
    );
  }

  // 4. Todas las sugerencias → 1 único finding resumen
  const suggestions = raw.suggestions || [];
  if (suggestions.length > 0) {
    const MAX_IDS = 10;
    const shownIds = suggestions.slice(0, MAX_IDS).map((s) => s.id || "UNKNOWN");
    const remaining = suggestions.length - MAX_IDS;
    const evidenceParts = shownIds.join(", ");
    const evidence = remaining > 0
      ? `${evidenceParts} (+${remaining} más)`
      : evidenceParts;

    findings.push(
      createFinding({
        id: "HOST-LYN-SUG",
        title: `Lynis: ${suggestions.length} sugerencias de hardening`,
        severity: "low",
        evidence,
        fix: "Consultar 'lynis show suggestions' para el detalle.",
        category: "system",
        source: "lynis",
      })
    );
  }

  return findings;
}

// ── security-events (submódulo de eventos: SSH, sudo, sesiones) ─────────────

// Delimitación con Lynis: Lynis audita la CONFIGURACIÓN de SSH (hardening);
// security-events audita los EVENTOS (quién entró, cuándo, desde dónde).
// Las severidades vienen de SECURITY_EVENT_RULES (severity-map.js), patrón
// MEMORY_THRESHOLDS. Los fixes son recomendaciones genéricas NO destructivas:
// nunca comandos que bloqueen usuarios o IPs automáticamente.

const SSH_HARDEN_FIX =
  "Revisar /etc/ssh/sshd_config (PermitRootLogin no, PasswordAuthentication no si se usan claves). " +
  "En Linux, considerar fail2ban para limitar intentos. En macOS, desactivar Sesión remota si no se usa " +
  "(Ajustes del Sistema → General → Compartir → Sesión remota).";

const MAX_SEC_INDIVIDUAL = 10; // logins SSH individuales antes de agregar

function fromSecurityEvents(raw) {
  if (!raw) return [];
  const findings = [];
  const W = raw.windowHours || 24;
  const R = SECURITY_EVENT_RULES;

  // Fuentes no disponibles → finding info explicativo, nunca error
  if (raw.skipped) {
    findings.push(
      createFinding({
        id: "HOST-SEC-SKIP",
        title: "Eventos de seguridad: fuentes de log no disponibles",
        severity: "info",
        evidence: raw.reason || "sin detalle",
        fix:
          "Comprobar el acceso a los logs del sistema: en Linux, journalctl o /var/log/auth.log legible " +
          "(añadir el usuario al grupo adm/systemd-journal si es necesario); en macOS, el comando `log`; " +
          "en Windows, PowerShell disponible y Node-RED ejecutado como administrador. " +
          "Ejecutar Node-RED con un usuario con permisos de lectura sobre los logs.",
        category: "system-logs",
        source: "security-events",
      })
    );
    return findings;
  }

  // Fuentes parciales (p.ej. lastb sin permisos) → un finding info agregado
  if (Array.isArray(raw.partial) && raw.partial.length > 0) {
    findings.push(
      createFinding({
        id: "HOST-SEC-SRC",
        title: `Eventos de seguridad: ${raw.partial.length} fuente(s) no disponibles`,
        severity: "info",
        evidence: raw.partial.map((p) => `${p.source}: ${p.reason}`).join(" · "),
        fix: "La auditoría se completó con las fuentes restantes. Para cobertura completa, revisar permisos de lectura de logs.",
        category: "system-logs",
        source: "security-events",
      })
    );
  }

  // Rama Windows: eventos 4624/4625/4672 en vez de sshd/sudo
  if (raw.platform === "win32" || raw.windows) {
    return findings.concat(fromSecurityEventsWin32(raw));
  }

  const ssh = raw.ssh || { accepted: [], failed: [] };
  const sudo = raw.sudo || { ok: [], failed: [] };
  const sessions = Array.isArray(raw.sessions) ? raw.sessions : [];

  // A) Logins SSH correctos: root → high individual; resto → info individual
  //    (con tope MAX_SEC_INDIVIDUAL + agregado del resto)
  const rootLogins = ssh.accepted.filter((a) => a.user === "root");
  const otherLogins = ssh.accepted.filter((a) => a.user !== "root");

  for (const [i, a] of rootLogins.entries()) {
    findings.push(
      createFinding({
        id: `HOST-SEC-SSH-R-${counter(i)}`,
        title: "Acceso SSH como root detectado",
        severity: R.SSH_ACCEPTED_ROOT,
        evidence: `Usuario: root · IP: ${safe(a.ip)} · Fecha: ${safe(a.timestamp)} · Método: ${safe(a.method)}`,
        fix: SSH_HARDEN_FIX,
        category: "system-logs",
        source: "security-events",
      })
    );
  }

  for (const [i, a] of otherLogins.slice(0, MAX_SEC_INDIVIDUAL).entries()) {
    findings.push(
      createFinding({
        id: `HOST-SEC-SSH-${counter(i)}`,
        title: "Acceso SSH detectado",
        severity: R.SSH_ACCEPTED,
        evidence: `Usuario: ${safe(a.user)} · IP: ${safe(a.ip)} · Fecha: ${safe(a.timestamp)} · Método: ${safe(a.method)}`,
        fix: "Si no reconoces este acceso, revisar /etc/ssh/sshd_config y las claves autorizadas (~/.ssh/authorized_keys).",
        category: "system-logs",
        source: "security-events",
      })
    );
  }
  if (otherLogins.length > MAX_SEC_INDIVIDUAL) {
    const extra = otherLogins.slice(MAX_SEC_INDIVIDUAL);
    findings.push(
      createFinding({
        id: "HOST-SEC-SSH-EXTRA",
        title: `${extra.length} accesos SSH adicionales en las últimas ${W} h`,
        severity: R.SSH_ACCEPTED,
        evidence: extra
          .slice(0, 5)
          .map((a) => `${safe(a.user)}@${safe(a.ip)}`)
          .join(", ") + (extra.length > 5 ? ` (+${extra.length - 5} más)` : ""),
        fix: null,
        category: "system-logs",
        source: "security-events",
      })
    );
  }

  // A) Fallidos SSH: UN finding agregado; >= umbral → posible fuerza bruta
  if (ssh.failed.length > 0) {
    const n = ssh.failed.length;
    const many = n >= R.SSH_BRUTE_FORCE_THRESHOLD;
    const uniqueIps = [...new Set(ssh.failed.map((f) => f.ip).filter(Boolean))];
    const uniqueUsers = [...new Set(ssh.failed.map((f) => f.user).filter(Boolean))];
    findings.push(
      createFinding({
        id: "HOST-SEC-SSHF-001",
        title: many
          ? `Posible intento de fuerza bruta SSH: ${n} intentos fallidos en ${W} h`
          : `${n} intento(s) de acceso SSH fallido(s) en ${W} h`,
        severity: many ? R.SSH_FAILED_MANY : R.SSH_FAILED_FEW,
        evidence:
          `${n} fallidos · IPs: ${uniqueIps.slice(0, 5).join(", ") || "—"}` +
          (uniqueIps.length > 5 ? ` (+${uniqueIps.length - 5} más)` : "") +
          ` · Usuarios probados: ${uniqueUsers.slice(0, 5).join(", ") || "—"}`,
        fix: SSH_HARDEN_FIX,
        category: "system-logs",
        source: "security-events",
      })
    );
  }

  // B) sudo correcto: UN finding info agregado con recuento y muestra
  if (sudo.ok.length > 0) {
    const sampleCmds = [...new Set(sudo.ok.map((s) => s.command).filter(Boolean))].slice(0, 5);
    const users = [...new Set(sudo.ok.map((s) => s.user).filter(Boolean))];
    findings.push(
      createFinding({
        id: "HOST-SEC-SUDO-001",
        title: `${sudo.ok.length} uso(s) de sudo/su en las últimas ${W} h`,
        severity: R.SUDO_OK,
        evidence: `Usuarios: ${users.join(", ") || "—"} · Comandos (muestra): ${sampleCmds.join(" | ") || "—"}`,
        fix: null,
        category: "system-logs",
        source: "security-events",
      })
    );
  }

  // B) Fallos de autenticación sudo/su
  if (sudo.failed.length > 0) {
    const n = sudo.failed.length;
    const users = [...new Set(sudo.failed.map((s) => s.user).filter(Boolean))];
    findings.push(
      createFinding({
        id: "HOST-SEC-SUDOF-001",
        title: `${n} fallo(s) de autenticación sudo/su en las últimas ${W} h`,
        severity: n >= R.SUDO_FAIL_THRESHOLD ? R.SUDO_FAIL_MANY : R.SUDO_FAIL_FEW,
        evidence: `${n} fallos · Usuarios: ${users.join(", ") || "—"}`,
        fix:
          "Verificar qué usuario o proceso está fallando la autenticación. " +
          "Si no lo reconoces, revisar la configuración con visudo y cambiar la contraseña del usuario afectado.",
        category: "system-logs",
        source: "security-events",
      })
    );
  }

  // C) Sesiones remotas activas ahora (las locales quedan solo en raw)
  const remoteSessions = sessions.filter((s) => s.origin);
  for (const [i, s] of remoteSessions.entries()) {
    findings.push(
      createFinding({
        id: `HOST-SEC-SES-${counter(i)}`,
        title: "Sesión remota activa",
        severity: R.REMOTE_SESSION,
        evidence: `Usuario: ${safe(s.user)} · Terminal: ${safe(s.tty)} · Origen: ${safe(s.origin)} · Desde: ${safe(s.since)}`,
        fix: "Si no reconoces esta sesión, ciérrala manualmente y revisa los accesos SSH recientes.",
        category: "system-logs",
        source: "security-events",
      })
    );
  }

  // Sin NINGÚN evento → finding info de comprobación (distinto de skipped)
  const hasEvents =
    ssh.accepted.length > 0 ||
    ssh.failed.length > 0 ||
    sudo.ok.length > 0 ||
    sudo.failed.length > 0 ||
    remoteSessions.length > 0;

  if (!hasEvents) {
    findings.push(
      createFinding({
        id: "HOST-SEC-INF",
        title: `Sin eventos de seguridad relevantes en las últimas ${W} h`,
        severity: "info",
        evidence: `Fuentes consultadas: ${(raw.sources || []).join(", ") || "—"} · Ventana: ${W} h · Sin logins SSH, usos de sudo ni sesiones remotas.`,
        fix: null,
        category: "system-logs",
        source: "security-events",
      })
    );
  }

  return findings;
}

// ── security-events: rama Windows (eventos 4624/4625/4672 + query user) ─────
//
// Equivalencias con la rama Unix (mismas reglas SECURITY_EVENT_RULES, mismo
// umbral SSH_BRUTE_FORCE_THRESHOLD — NO se duplica la constante):
//   4624 tipo 10 (RDP) / 3 (red)  ↔ login SSH aceptado      → SSH_ACCEPTED
//   4624 locales (tipos 2,7,11…)  → solo recuento agregado (filtrado de ruido)
//   4625 fallidos                 ↔ fallidos SSH             → FEW/MANY + umbral
//   4672 desde sesión remota      ↔ login SSH de root        → SSH_ACCEPTED_ROOT
//   sesión RDP activa             ↔ sesión remota activa     → REMOTE_SESSION
// La auditoría de elevación (UAC/4688) NO se implementa en v1: requiere la
// directiva de auditoría de creación de procesos, no activa por defecto.

const RDP_HARDEN_FIX =
  "Si no reconoces estos accesos, desactiva el Escritorio remoto (Configuración → Sistema → Escritorio remoto), " +
  "restringe el puerto 3389 en el Firewall de Windows Defender y exige autenticación a nivel de red (NLA). " +
  "Usa contraseñas robustas en todas las cuentas.";

function fromSecurityEventsWin32(raw) {
  const findings = [];
  const W = raw.windowHours || 24;
  const R = SECURITY_EVENT_RULES;
  const win = raw.windows || {};
  const logons = win.logons || { remote: [], localCount: 0 };
  const remote = Array.isArray(logons.remote) ? logons.remote : [];
  const failed = Array.isArray(win.failed) ? win.failed : [];
  const privileged = Array.isArray(win.privileged) ? win.privileged : [];
  const sessions = Array.isArray(raw.sessions) ? raw.sessions : [];

  // Canal Security sin permisos → finding info explicativo, nunca crash
  if (win.securityLogDenied) {
    findings.push(
      createFinding({
        id: "HOST-SEC-WIN-PERM",
        title: "Eventos de seguridad de Windows no accesibles",
        severity: "info",
        evidence: "Get-WinEvent devolvió acceso denegado al canal Security (requiere privilegios de administrador).",
        fix: "Para auditar eventos de seguridad en Windows, ejecuta Node-RED como administrador.",
        category: "system-logs",
        source: "security-events",
      })
    );
  }

  // A) Logins remotos correctos (LogonType 10 = RDP, 3 = red) → individuales
  for (const [i, l] of remote.slice(0, MAX_SEC_INDIVIDUAL).entries()) {
    findings.push(
      createFinding({
        id: `HOST-SEC-WIN-RDP-${counter(i)}`,
        title: l.logonType === 10 ? "Acceso remoto por RDP detectado" : "Acceso remoto de red detectado",
        severity: R.SSH_ACCEPTED,
        evidence: `Usuario: ${safe(l.user)} · IP: ${safe(l.ip)} · Fecha: ${safe(l.timestamp)} · LogonType: ${safe(l.logonType)}`,
        fix: "Si no reconoces este acceso, revisa quién tiene habilitado el acceso remoto a este equipo. " + RDP_HARDEN_FIX,
        category: "system-logs",
        source: "security-events",
      })
    );
  }
  if (remote.length > MAX_SEC_INDIVIDUAL) {
    const extra = remote.slice(MAX_SEC_INDIVIDUAL);
    findings.push(
      createFinding({
        id: "HOST-SEC-WIN-RDP-EXTRA",
        title: `${extra.length} accesos remotos adicionales en las últimas ${W} h`,
        severity: R.SSH_ACCEPTED,
        evidence:
          extra.slice(0, 5).map((l) => `${safe(l.user)}@${safe(l.ip)}`).join(", ") +
          (extra.length > 5 ? ` (+${extra.length - 5} más)` : ""),
        fix: null,
        category: "system-logs",
        source: "security-events",
      })
    );
  }

  // A) Logins locales: solo recuento agregado, y solo si también hubo remotos
  //    (filtrado de ruido: en un PC sin acceso remoto son actividad normal)
  if (remote.length > 0 && logons.localCount > 0) {
    findings.push(
      createFinding({
        id: "HOST-SEC-WIN-LOC",
        title: `${logons.localCount} inicio(s) de sesión local(es) en las últimas ${W} h`,
        severity: "info",
        evidence: `Eventos 4624 con LogonType local (2, 7, 11…) · Ventana: ${W} h`,
        fix: null,
        category: "system-logs",
        source: "security-events",
      })
    );
  }

  // A) 4625 fallidos: UN finding agregado; mismo umbral que SSH
  if (failed.length > 0) {
    const n = failed.length;
    const many = n >= R.SSH_BRUTE_FORCE_THRESHOLD;
    const uniqueIps = [...new Set(failed.map((f) => f.ip).filter(Boolean))];
    const uniqueUsers = [...new Set(failed.map((f) => f.user).filter(Boolean))];
    findings.push(
      createFinding({
        id: "HOST-SEC-WINF-001",
        title: many
          ? `Posible intento de fuerza bruta: ${n} inicios de sesión fallidos en ${W} h`
          : `${n} inicio(s) de sesión fallido(s) en ${W} h`,
        severity: many ? R.SSH_FAILED_MANY : R.SSH_FAILED_FEW,
        evidence:
          `${n} fallidos (evento 4625) · IPs: ${uniqueIps.slice(0, 5).join(", ") || "—"}` +
          (uniqueIps.length > 5 ? ` (+${uniqueIps.length - 5} más)` : "") +
          ` · Usuarios probados: ${uniqueUsers.slice(0, 5).join(", ") || "—"}`,
        fix: RDP_HARDEN_FIX,
        category: "system-logs",
        source: "security-events",
      })
    );
  }

  // 4672 (privilegios especiales, análogo a login de root):
  // remoto → high individual; local → UN finding info agregado
  const privRemote = privileged.filter((p) => p.remote);
  const privLocal = privileged.filter((p) => !p.remote);

  for (const [i, p] of privRemote.slice(0, MAX_SEC_INDIVIDUAL).entries()) {
    findings.push(
      createFinding({
        id: `HOST-SEC-WIN-PRIV-${counter(i)}`,
        title: "Sesión remota con privilegios de administrador detectada",
        severity: R.SSH_ACCEPTED_ROOT,
        evidence: `Usuario: ${safe(p.user)} · IP: ${safe(p.ip)} · Fecha: ${safe(p.timestamp)} · Evento 4672 correlacionado con login remoto`,
        fix:
          "Verifica que este acceso administrativo remoto es legítimo. " +
          "Evita usar cuentas de administrador para el acceso remoto habitual. " + RDP_HARDEN_FIX,
        category: "system-logs",
        source: "security-events",
      })
    );
  }
  if (privLocal.length > 0) {
    const users = [...new Set(privLocal.map((p) => p.user).filter(Boolean))];
    findings.push(
      createFinding({
        id: "HOST-SEC-WIN-PRIVL",
        title: `${privLocal.length} sesión(es) local(es) con privilegios de administrador en ${W} h`,
        severity: "info",
        evidence: `Evento 4672 · Usuarios: ${users.slice(0, 5).join(", ") || "—"}`,
        fix: null,
        category: "system-logs",
        source: "security-events",
      })
    );
  }

  // B) Escalada (sudo-equivalente): no auditable por defecto en Windows v1.
  //    Solo si el canal Security fue legible (sin él este aviso es redundante).
  if (!win.securityLogDenied) {
    findings.push(
      createFinding({
        id: "HOST-SEC-WIN-UAC",
        title: "Auditoría de elevación de privilegios no disponible en Windows",
        severity: "info",
        evidence:
          "La auditoría de elevación de privilegios en Windows (UAC, evento 4688) requiere habilitar " +
          "la directiva de auditoría de creación de procesos, que no está activa por defecto.",
        fix:
          "Para habilitarla, ejecuta como administrador: " +
          'auditpol /set /subcategory:"Creación del proceso" /success:enable /failure:enable ' +
          '(en Windows en inglés: /subcategory:"Process Creation").',
        category: "system-logs",
        source: "security-events",
      })
    );
  }

  // C) Sesiones activas: RDP → info individual; locales → agregado
  const rdpSessions = sessions.filter((s) => s.origin);
  const localSessions = sessions.filter((s) => !s.origin);

  for (const [i, s] of rdpSessions.entries()) {
    findings.push(
      createFinding({
        id: `HOST-SEC-SES-${counter(i)}`,
        title: "Sesión remota activa",
        severity: R.REMOTE_SESSION,
        evidence: `Usuario: ${safe(s.user)} · Sesión: ${safe(s.tty)} · Origen: ${safe(s.origin)} · Desde: ${safe(s.since)}`,
        fix: "Si no reconoces esta sesión, ciérrala desde el Administrador de tareas (pestaña Usuarios) y revisa los accesos remotos recientes.",
        category: "system-logs",
        source: "security-events",
      })
    );
  }
  if (localSessions.length > 0) {
    findings.push(
      createFinding({
        id: "HOST-SEC-SES-LOC",
        title: `${localSessions.length} sesión(es) local(es) activa(s)`,
        severity: "info",
        evidence: localSessions
          .slice(0, 5)
          .map((s) => `${safe(s.user)} (${safe(s.tty)})`)
          .join(", ") + (localSessions.length > 5 ? ` (+${localSessions.length - 5} más)` : ""),
        fix: null,
        category: "system-logs",
        source: "security-events",
      })
    );
  }

  // Sin NINGÚN evento relevante → finding info de comprobación
  const hasEvents =
    remote.length > 0 ||
    failed.length > 0 ||
    privileged.length > 0 ||
    rdpSessions.length > 0;

  if (!hasEvents && !win.securityLogDenied) {
    findings.push(
      createFinding({
        id: "HOST-SEC-INF",
        title: `Sin eventos de seguridad relevantes en las últimas ${W} h`,
        severity: "info",
        evidence: `Fuentes consultadas: ${(raw.sources || []).join(", ") || "—"} · Ventana: ${W} h · Sin accesos remotos, fallos de login ni sesiones RDP.`,
        fix: null,
        category: "system-logs",
        source: "security-events",
      })
    );
  }

  return findings;
}

// ── Trivy: mapeo ecosistema → gestor ────────────────────────────────────────
// Fuente autoritativa del ecosistema: el campo Type que Trivy asigna a cada
// Result (cargo/npm/pip/gomod/debian/alpine…). NUNCA se adivina por la ruta del
// Target: eso produce comandos de gestor cruzado (npm/brew para un crate Rust).

// Type de lenguaje → comando ejecutable del gestor correspondiente.
const TRIVY_LANG_CMD = {
  cargo:    (pkg)      => `cargo update -p ${pkg}`,
  npm:      (pkg)      => `npm update ${pkg}`,
  pnpm:     (pkg)      => `pnpm update ${pkg}`,
  yarn:     (pkg)      => `yarn upgrade ${pkg}`,
  pip:      (pkg, ver) => `pip install --upgrade ${pkg}${ver ? "==" + ver : ""}`,
  pipenv:   (pkg, ver) => `pip install --upgrade ${pkg}${ver ? "==" + ver : ""}`,
  poetry:   (pkg)      => `poetry update ${pkg}`,
  gomod:    (pkg, ver) => `go get -u ${pkg}@${ver || "latest"}`,
  bundler:  (pkg)      => `bundle update ${pkg}`,
  gemspec:  (pkg)      => `bundle update ${pkg}`,
  composer: (pkg)      => `composer update ${pkg}`,
};

// Type de lenguaje SIN comando único fiable → recomendación en prosa.
const TRIVY_LANG_MANUAL = new Set([
  "jar", "pom", "gradle", "maven",           // Java
  "nuget", "dotnet-core", "packages-props",  // .NET
  "conan",                                   // C/C++
  "pub",                                     // Dart
  "cocoapods", "swift",                      // iOS/Swift
  "hex",                                     // Erlang/Elixir
  "cran",                                    // R
]);

// Type de paquete de sistema operativo (Class = os-pkgs).
const TRIVY_OS_TYPES = new Set([
  "debian", "ubuntu", "alpine", "redhat", "centos", "rocky", "alma",
  "almalinux", "amazon", "oracle", "fedora", "suse", "opensuse",
  "photon", "mariner", "cbl-mariner", "wolfi", "chainguard",
]);

/**
 * Comando para actualizar un paquete del SO en el propio host (trivy fs).
 * El gestor depende de la distribución que Trivy identificó como Type.
 * @param {string} type  Type normalizado (debian/ubuntu/alpine/…)
 * @param {string} pkg
 * @param {string|null} ver
 * @returns {string}
 */
function osHostUpdateCmd(type, pkg, ver) {
  if (/alpine|wolfi|chainguard/.test(type))  return `sudo apk upgrade ${pkg}`;
  if (/debian|ubuntu/.test(type))            return `sudo apt update && sudo apt install --only-upgrade ${pkg}`;
  if (/redhat|centos|rocky|alma|amazon|oracle|fedora|photon|mariner/.test(type))
    return `sudo dnf update ${pkg}`;
  if (/suse/.test(type))                     return `sudo zypper update ${pkg}`;
  const verTxt = ver ? ` a la versión ${ver}` : "";
  return `Actualiza ${pkg}${verTxt} con el gestor de paquetes de tu sistema operativo.`;
}

/**
 * Genera el comando de actualización correcto para un paquete vulnerable.
 *
 * Prioridad de detección:
 *   0. Módulos Go (pkgName con path de módulo): no hay comando simple ejecutable.
 *      En contexto 'image' → actualizar imagen base y reconstruir.
 *      En contexto 'host'  → actualizar la herramienta brew que los incluye.
 *   0b. Contexto 'image' + target sin ruta absoluta (OS layer de contenedor):
 *      El paquete pertenece al SO base del contenedor; el fix es actualizar
 *      la imagen base en el Dockerfile, no un gestor de paquetes del host.
 *   1. Target (path): el ecosistema se infiere del fichero/directorio escaneado.
 *      yarn.lock / node_modules → npm; Pipfile → pip; etc.
 *      Rutas /Cellar/ o /homebrew/lib/ → brew (dependencias internas de Homebrew).
 *   2. Platform: fallback solo si ningún patrón del target coincide.
 *      darwin → brew; linux → apt (o dnf si rpm); win32 → winget.
 *
 * @param {string} target         Target de Trivy (ruta o referencia de imagen).
 * @param {string} pkgName        Nombre del paquete vulnerable.
 * @param {string|null} fixedVersion  Versión que corrige la vulnerabilidad (null si no hay).
 * @param {string} platform       Valor de process.platform ('darwin' | 'linux' | 'win32').
 * @param {'host'|'image'} [context='host']  Tipo de escaneo: 'host' (trivy fs) o 'image' (trivy image).
 * @returns {string|null}         Texto de fix o comando listo para copiar-pegar.
 */
function getTrivyFixCommand(target, pkgName, fixedVersion, platform, context = "host", pkgType = "") {
  if (!pkgName) return null;
  const t = target || "";
  const pkg = pkgName.split("@")[0];
  const ver = fixedVersion || null;
  const type = String(pkgType || "").toLowerCase();

  // ═══ RUTA AUTORITATIVA: usar el Type de Trivy si está presente ══════════════
  // Trivy etiqueta cada Result con Type (cargo/npm/pip/gomod/debian/alpine…). Es
  // la única fuente fiable del ecosistema. Solo si Type falta (llamadas legacy o
  // datos sin tipo) se recurre a la heurística por ruta/plataforma de más abajo.

  // Paquete del sistema operativo ─────────────────────────────────────────────
  if (TRIVY_OS_TYPES.has(type)) {
    if (context === "image") {
      return "Esta vulnerabilidad está en un paquete del sistema base del contenedor. " +
             "Solución: actualizar la imagen base (FROM ubuntu:latest, alpine:latest, etc.) en el Dockerfile y reconstruir el contenedor.";
    }
    return ver ? osHostUpdateCmd(type, pkg, ver)
               : `No hay versión corregida disponible en el repositorio del sistema para ${pkg}. ` +
                 `Vigila las actualizaciones del paquete (${type}) y aplica el parche cuando salga.`;
  }

  // Dependencia de aplicación DENTRO de una imagen → nunca un comando del host ──
  if (context === "image" && (TRIVY_LANG_CMD[type] || TRIVY_LANG_MANUAL.has(type))) {
    const verTxt = ver ? ` a la versión ${ver}` : "";
    return `Esta vulnerabilidad está en ${pkg}, una dependencia de la aplicación dentro de la imagen. ` +
           `Solución: actualizar ${pkg}${verTxt} en su manifiesto de dependencias y reconstruir la imagen (docker build).`;
  }

  // Gestor de lenguaje en el HOST → comando ejecutable del ecosistema correcto ──
  if (TRIVY_LANG_CMD[type]) {
    let cmd = TRIVY_LANG_CMD[type](pkg, ver);
    if (type === "cargo") {
      // cargo update -p respeta la restricción semver de Cargo.toml; si el parche
      // es una versión mayor hay que subir la restricción a mano.
      cmd += `\nSi ${ver ? "la versión " + ver : "la corrección"} es una versión mayor, ` +
             `ajusta la restricción de ${pkg} en Cargo.toml y vuelve a ejecutar cargo update.`;
    }
    return cmd;
  }

  // Lenguaje reconocido pero sin comando fiable → prosa (intervención manual) ───
  if (TRIVY_LANG_MANUAL.has(type)) {
    return ver
      ? `Actualiza ${pkg} a la versión ${ver} en el fichero de construcción del proyecto (${type}) y reconstruye. Requiere intervención manual.`
      : `Actualiza ${pkg} a una versión sin la vulnerabilidad en el fichero de construcción del proyecto (${type}).`;
  }

  // Type presente pero no mapeado → prosa. NUNCA un comando de otro ecosistema. ─
  if (type) {
    return ver
      ? `Actualiza ${pkg} a la versión ${ver} con el gestor de paquetes de ${type}.`
      : `Actualiza ${pkg} a la última versión con el gestor de paquetes de ${type}.`;
  }

  // ═══ SIN Type (compat retro): heurística por ruta/plataforma ════════════════

  // ── PRIORIDAD 0: Módulos Go ──────────────────────────────────────────────────
  // Los paths de módulo Go (github.com/..., golang.org/..., etc.) son binarios
  // compilados embebidos en herramientas o imágenes. No hay un gestor de paquetes
  // que permita actualizarlos directamente; hay que actualizar la fuente que los incluye.
  if (/^(github\.com|google\.golang\.org|golang\.org|gopkg\.in|go\.uber\.org|k8s\.io)\//i.test(pkgName)) {
    if (context === "image") {
      return "Esta vulnerabilidad está en un binario Go embebido en la imagen. " +
             "Solución: actualizar la imagen base del contenedor a la última versión disponible y reconstruir.";
    }
    // host: el binario llegó probablemente vía brew; indicar cómo resolver
    return "Esta vulnerabilidad está en un módulo Go compilado en una herramienta instalada en el sistema. " +
           "Solución: actualizar la herramienta que lo incluye (brew upgrade <herramienta>) o esperar a que publiquen una nueva versión.";
  }

  // ── PRIORIDAD 0b: Imagen Docker — paquetes del SO base del contenedor ────────
  // Cuando trivy escanea una imagen, el Target de los paquetes del OS layer tiene
  // formato "nombre:tag (distro versión)", p. ej. "node:18-alpine (alpine 3.17.0)".
  // Estos targets no empiezan con "/" ni con unidad Windows → son OS layers.
  // En este caso el fix no es un comando del host; hay que actualizar la imagen base.
  if (context === "image" && t && !t.startsWith("/") && !/^[A-Za-z]:[\\\/]/.test(t)) {
    return "Esta vulnerabilidad está en un paquete del sistema base del contenedor. " +
           "Solución: actualizar la imagen base (FROM ubuntu:latest, alpine:latest, etc.) en el Dockerfile y reconstruir el contenedor.";
  }

  // ── PRIORIDAD 0c: Imagen Docker — dependencias de aplicación (target con ruta) ─
  // CVE en un manifiesto de dependencias DENTRO de la imagen (/app/package-lock.json,
  // /src/go.mod, requirements.txt…). El fix NUNCA es un comando del host (npm/pip/brew/
  // apt no arreglan la imagen): hay que actualizar la dependencia en su manifiesto y
  // RECONSTRUIR la imagen. Este guard evita que estos targets caigan en las reglas
  // por-path o el fallback por-plataforma (pensados para escaneos de host).
  if (context === "image") {
    const manifest =
      /yarn\.lock|package-lock\.json|node_modules/i.test(t) ? "package.json" :
      /composer\.(json|lock)/i.test(t)                      ? "composer.json" :
      /go\.(mod|sum)/i.test(t)                              ? "go.mod" :
      /requirements\.txt|Pipfile/i.test(t)                  ? "requirements.txt / Pipfile" :
      /Gemfile(\.lock)?/i.test(t)                           ? "Gemfile" :
      /Cargo\.toml/i.test(t)                                ? "Cargo.toml" :
      /pom\.xml|build\.gradle/i.test(t)                     ? "pom.xml / build.gradle" :
      "el manifiesto de dependencias";
    const verTxt = ver ? ` a la versión ${ver}` : "";
    return `Esta vulnerabilidad está en ${pkg}, una dependencia de la aplicación dentro de la imagen. ` +
           `Solución: actualizar ${pkg}${verTxt} en ${manifest} y reconstruir la imagen (docker build).`;
  }

  // ── PRIORIDAD 1: Detectar por Target (path) ─────────────────────────────────
  // Homebrew Cellar / lib interna → siempre brew, sin importar el contenido
  if (/\/[Cc]ellar\/|\/homebrew\/lib\//i.test(t))
    return `brew upgrade ${pkg}`;

  if (/yarn\.lock|node_modules|package-lock\.json/i.test(t))
    return `npm update ${pkg}`;

  if (/composer\.(json|lock)/i.test(t))
    return `composer update ${pkg}`;

  if (/go\.(mod|sum)/i.test(t))
    return `go get -u ${pkg}@${ver || "latest"}`;

  if (/requirements\.txt|Pipfile/i.test(t))
    return `pip install --upgrade ${pkg}${ver ? "==" + ver : ""}`;

  if (/Gemfile(\.lock)?/i.test(t))
    return `bundle update ${pkg}`;

  if (/Cargo\.toml/i.test(t))
    return `cargo update ${pkg}`;

  if (/pom\.xml|build\.gradle/i.test(t))
    return ver
      ? `Actualizar ${pkg} a la versión ${ver} en tu fichero de construcción Maven/Gradle`
      : `Actualizar ${pkg} en tu fichero de construcción Maven/Gradle`;

  // ── PRIORIDAD 2: Fallback por Platform ──────────────────────────────────────
  if (platform === "darwin")
    return `brew upgrade ${pkg}`;

  if (platform === "linux") {
    if (/\/var\/lib\/rpm|\/usr\/lib64/i.test(t))
      return `sudo dnf update ${pkg}`;
    return `sudo apt update && sudo apt install --only-upgrade ${pkg}`;
  }

  if (platform === "win32")
    return `winget upgrade ${pkg}\n(o con Chocolatey: choco upgrade ${pkg})`;

  // ── Fallback genérico multiplataforma ───────────────────────────────────────
  return ver
    ? `Actualizar ${pkg} a la versión ${ver} usando el gestor de paquetes de tu sistema`
    : `Actualizar ${pkg} a la última versión disponible usando el gestor de paquetes de tu sistema`;
}

/**
 * Determina si un texto de fix es un comando directamente ejecutable en terminal.
 * Útil para que el dashboard muestre el botón "Copiar comando" solo cuando aplica.
 *
 * @param {string|null} fix
 * @returns {boolean}
 */
function isExecutableCommand(fix) {
  // Fuente única de verdad: el mismo predicado que fija finding.isCommand en
  // createFinding (lib/finding-schema.js::_isCmd). Evita divergencias.
  return isCommandFix(fix);
}

/**
 * Convierte la salida JSON de `trivy fs` o `trivy image` a findings.
 * Estructura estándar de Trivy: { Results: [{ Target, Vulnerabilities: [...] }] }
 *
 * Estrategia de agrupación en dos capas:
 *
 *   CAPA 1 — Agrupación por paquete (PkgName + InstalledVersion):
 *     Un paquete con múltiples CVEs genera 1 finding, no N.
 *     Evita que librerías con muchos CVEs (openssl, curl, libpng) generen
 *     ruido visual en el dashboard: la información completa queda en evidence.
 *     1 CVE en el paquete → finding individual con ID del CVE en el título.
 *     2+ CVEs → finding agrupado con recuento en el título y lista en evidence.
 *
 *   CAPA 2 — Agrupación por severidad:
 *     - critical y high → finding individual por paquete (capa 1). Sin límite;
 *       son los que importan y el analista debe verlos todos.
 *     - medium → 1 finding resumen por Target (imagen/fichero escaneado).
 *       Agrupar por Target mantiene la trazabilidad sin generar decenas de
 *       líneas "medium" que empujen los críticos fuera del viewport.
 *     - low e info → 1 único finding resumen global. Son buenas prácticas,
 *       no riesgos inmediatos; no necesitan fila propia.
 *
 * Motivo: un escaneo de 30 imágenes Docker puede producir 500-2000 CVEs.
 * Sin agrupación, los critical/high quedan enterrados en páginas de medium/low.
 *
 * @param {Object} raw         Objeto JSON parseado de Trivy.
 * @param {string} idPrefix    "HOST-CVE" | "IMG-CVE"
 * @param {string} category    "vulnerability"
 * @param {string} source      "trivy"
 * @returns {Finding[]}
 */
function fromTrivyJson(raw, idPrefix, category = "vulnerability", source = "trivy") {
  if (!raw || raw.skipped) return [];
  const context = idPrefix.startsWith("IMG") ? "image" : "host";

  const results = raw.Results || [];

  // ── Paso 1: deduplicar y recopilar con severidad ajustada ──────────────────
  // Acumulamos en una estructura plana antes de agrupar.
  const seen = new Set();
  const allVulns = [];   // { v, target, sev }

  for (const result of results) {
    const target = result.Target || "unknown";
    // Ecosistema autoritativo del Result (cargo/npm/pip/gomod/debian/…). Se
    // propaga hasta getTrivyFixCommand para elegir el gestor correcto.
    const type = result.Type || "";
    // Imagen de origen (la etiqueta cve-checker en cada Result). Permite agrupar
    // los hallazgos por imagen cuando se escanean varias en una sola pasada.
    const image = result.__image || "";

    // Dev dependencies de Homebrew Cellar: bajar un nivel de severidad
    const isDevDependency = (result.Target || "").includes("/Cellar/") &&
      ["phpmyadmin", "protobuf", "playwright", "python"].some((t) =>
        (result.Target || "").toLowerCase().includes(t));

    for (const v of (result.Vulnerabilities || [])) {
      // Deduplicar por Imagen + VulnerabilityID + PkgName + InstalledVersion.
      // Incluir la imagen evita fusionar el mismo CVE entre imágenes distintas.
      const key = `${image}|${v.VulnerabilityID}:${v.PkgName}:${v.InstalledVersion}`;
      if (seen.has(key)) continue;
      seen.add(key);

      let sev = fromTrivy(v.Severity);
      if (isDevDependency && sev === "high")     sev = "medium";
      if (isDevDependency && sev === "critical") sev = "high";

      allVulns.push({ v, target, sev, image, type });
    }
  }

  // ── Paso 2: agrupar por paquete (PkgName:InstalledVersion) ─────────────────
  // Un paquete con N CVEs genera 1 finding. La severidad del grupo es la más alta.
  // pkgGroups: Map< "PkgName:InstalledVersion" → { items: [{v,target,sev}], maxSev, target } >
  const pkgGroups = new Map();
  const medByTarget    = new Map();   // image|target → { image, target, vulns[] }
  const lowInfoByImage = new Map();   // image → { image, count, targets:Set }

  for (const item of allVulns) {
    const { v, target, sev, image, type } = item;
    if (sev === "critical" || sev === "high") {
      // Clave por imagen + paquete: el mismo paquete en dos imágenes son grupos distintos.
      const pkgKey = `${image}|${v.PkgName}:${v.InstalledVersion || ""}`;
      if (!pkgGroups.has(pkgKey)) {
        pkgGroups.set(pkgKey, { items: [], maxSev: sev, target, image, type });
      }
      const grp = pkgGroups.get(pkgKey);
      grp.items.push(item);
      grp.maxSev = max(grp.maxSev, sev);
    } else if (sev === "medium") {
      // Agrupar medium por imagen (fallback al target si no hay imagen)
      const medKey = image || target;
      if (!medByTarget.has(medKey)) medByTarget.set(medKey, { image, target, vulns: [] });
      medByTarget.get(medKey).vulns.push(v);
    } else {
      // low/info agrupados por imagen (fallback global cuando no hay imagen)
      const k = image || "";
      if (!lowInfoByImage.has(k)) lowInfoByImage.set(k, { image, count: 0, targets: new Set() });
      const e = lowInfoByImage.get(k);
      e.count++;
      e.targets.add(target);
    }
  }

  const findings = [];
  let n = 1;

  // ── Paso 3: emitir findings critical/high agrupados por paquete ────────────
  for (const [, grp] of pkgGroups) {
    const { items, maxSev, target, image, type } = grp;
    const first = items[0].v;
    const pkgLabel = `${first.PkgName}@${first.InstalledVersion || "?"}`;

    // Recoger FixedVersion más reciente del grupo (primera no nula)
    const fixedVersion = items.map((i) => i.v.FixedVersion).find(Boolean) || null;

    let title, evidence;

    if (items.length === 1) {
      // 1 CVE → título con ID del CVE
      title    = `${first.VulnerabilityID}: ${pkgLabel}`;
      evidence = `${first.VulnerabilityID} en ${first.PkgName} ${first.InstalledVersion || ""}. ${(first.Description || "").slice(0, 200)}`;
    } else {
      // 2+ CVEs → título con recuento, lista de IDs en evidence
      title = `${items.length} vulnerabilidades en ${pkgLabel}`;
      const MAX_IDS = 5;
      const ids     = items.slice(0, MAX_IDS).map((i) => i.v.VulnerabilityID);
      const rest    = items.length - MAX_IDS;
      const idList  = rest > 0 ? `${ids.join(", ")} y ${rest} más` : ids.join(", ");
      const desc    = (first.Description || "").slice(0, 150);
      evidence = desc ? `${idList}. ${desc}` : idList;
    }

    const fixText = fixedVersion
      ? getTrivyFixCommand(target, first.PkgName, fixedVersion, process.platform, context, type)
      : `No hay versión corregida disponible aún para ${first.PkgName}. Monitorizar actualizaciones del paquete.`;
    // isCommand solo si el fix es un comando puro de una línea. Los fixes con nota
    // (cargo + aviso de versión mayor) o en prosa se marcan false → el dashboard
    // los renderiza con el template híbrido (caja de comando por línea + prosa).
    const fixIsCommand = isExecutableCommand(fixText) && fixText.indexOf("\n") === -1;

    findings.push(
      createFinding({
        id:       `${idPrefix}-${String(n++).padStart(3, "0")}`,
        title,
        severity: maxSev,
        evidence,
        fix:      fixText,
        isCommand: fixIsCommand,
        category,
        source,
        image: image || null,
      })
    );
  }

  // ── Paso 4: medium → 1 finding resumen por imagen (o Target) ───────────────
  let medIdx = 1;
  for (const [, grp] of medByTarget) {
    const { image, target, vulns } = grp;
    const label = image || target;
    const MAX_IDS = 5;
    const shownIds = vulns.slice(0, MAX_IDS).map((v) => v.VulnerabilityID);
    const remaining = vulns.length - MAX_IDS;
    const evidence = remaining > 0
      ? `${shownIds.join(", ")} y ${remaining} más`
      : shownIds.join(", ");

    findings.push(
      createFinding({
        id:       `${idPrefix}-MED-${String(medIdx++).padStart(3, "0")}`,
        title:    `${vulns.length} vulnerabilidades medium en ${label}`,
        severity: "medium",
        evidence,
        fix:      `Actualizar los paquetes afectados en ${label}`,
        category,
        source,
        image: image || null,
      })
    );
  }

  // ── Paso 5: low e info → 1 finding resumen por imagen (global si no hay imagen) ─
  const multiLow = lowInfoByImage.size > 1;
  let lowIdx = 1;
  for (const [, grp] of lowInfoByImage) {
    const { image, count, targets } = grp;
    const targetCount = targets.size;
    const where = image || `${targetCount} target${targetCount !== 1 ? "s" : ""}`;
    findings.push(
      createFinding({
        id:       multiLow ? `${idPrefix}-LOW-${String(lowIdx++).padStart(3, "0")}` : `${idPrefix}-LOW`,
        title:    `${count} vulnerabilidades low/info en ${where}`,
        severity: "low",
        evidence: image
          ? `${count} vulnerabilidades de severidad baja en ${image}`
          : `${count} vulnerabilidades de severidad baja distribuidas en ${targetCount} target${targetCount !== 1 ? "s" : ""}`,
        fix:      "Revisar y actualizar paquetes cuando sea posible",
        category,
        source,
        image:    image || null,
      })
    );
  }

  return findings;
}

/**
 * Convierte un array de findings ya formateados por módulos nativos.
 * @param {Array} raw
 * @param {string} source
 * @returns {Finding[]}
 */
function fromNative(raw, source = "native") {
  if (!Array.isArray(raw)) return [];
  return raw.map((item) =>
    createFinding({
      id: item.id,
      title: item.title,
      severity: item.severity || "info",
      evidence: safe(item.evidence),
      fix: item.fix || null,
      category: item.category || "other",
      source,
    })
  );
}

/**
 * Genera findings a partir del array de puertos abiertos de nmap-wrapper.
 * @param {Array<{port, protocol, state, service, version, severity?}>} raw
 * @returns {Finding[]}
 */
function fromNmap(raw) {
  if (!Array.isArray(raw)) return [];
  return raw
    .filter((p) => p.state === "open")
    .map((p, i) => {
      const service = p.service || "unknown";
      const isUnknownService = service === "unknown" || service === "tcpwrapped";
      const displayService = isUnknownService && p.process ? p.process : service;

      // Título: cuando service es desconocido y hay proceso, el proceso es el servicio
      const title = p.process && !isUnknownService
        ? `Puerto abierto: ${p.port}/tcp (${displayService}) — usado por ${p.process}`
        : `Puerto abierto: ${p.port}/tcp (${displayService})`;

      // Evidence: acumula toda la información disponible
      let evidence = `Puerto ${p.port}/tcp abierto. Servicio: ${service}.`;
      if (p.version) evidence += ` Versión: ${p.version}.`;
      if (p.pid != null && p.process) evidence += ` Proceso: ${p.process} (PID ${p.pid}).`;
      if (p.extra) evidence += ` ${p.extra}`;

      // Si hay proceso conocido, intentar fix específico como override del genérico
      const processFix = p.process ? getFixForProcess(p.process, process.platform) : null;
      // Para nmap también se puede intentar por nombre de servicio si no hay proceso
      const serviceFix = !processFix && p.service ? getFixForProcess(p.service, process.platform) : null;

      return createFinding({
        id:       `NET-PORT-${counter(i)}`,
        title,
        severity: p.severity || "info",
        evidence,
        fix:      processFix || serviceFix || p.fix || null,
        category: "network",
        source:   "nmap",
      });
    });
}

// ── API pública ─────────────────────────────────────────────────────────────

/**
 * Normaliza raw data del nodo audit-host.
 *
 * El objeto `raw` puede contener cualquiera de estas claves:
 *   raw.cpuMemory    → resultado de cpu-memory.js
 *   raw.disk         → resultado de disk-storage.js (array de particiones)
 *   raw.swInventory  → resultado de sw-inventory.js (array de paquetes)
 *   raw.lynis        → resultado de lynis.js
 *   raw.trivy        → resultado de trivy-fs.js
 *
 * Si source es una string simple se usa para compatibilidad con el flow antiguo.
 *
 * @param {Object} raw
 * @param {string} [source]  Ignorado cuando raw es el objeto compuesto.
 * @returns {Finding[]}
 */
function normalizeHost(raw, opts = {}) {
  // opts puede ser string (legacy: source) u objeto { platform, source }
  const source = typeof opts === "string" ? opts : (opts.source || "native");
  const platform = typeof opts === "object" ? opts.platform : undefined;

  // Compatibilidad: si raw tiene la forma del objeto compuesto de audit-host.js
  if (raw && typeof raw === "object" && !Array.isArray(raw)) {
    const findings = [];
    if (raw.cpuMemory) findings.push(...fromCpuMemory(raw.cpuMemory, platform));
    if (raw.disk) findings.push(...fromDisk(raw.disk));
    if (raw.swInventory) findings.push(...fromSwInventory(raw.swInventory));
    if (raw.lynis) findings.push(...fromLynisRaw(raw.lynis));
    if (raw.trivy) findings.push(...fromTrivyJson(raw.trivy, "HOST-CVE"));
    if (raw.securityEvents) findings.push(...fromSecurityEvents(raw.securityEvents));
    return findings;
  }

  // Fallback: source explícito (para tests unitarios)
  if (source === "lynis") return fromLynisRaw(raw);
  if (source === "trivy") return fromTrivyJson(raw, "HOST-CVE");
  return fromNative(Array.isArray(raw) ? raw : [], "native");
}

/**
 * Genera findings a partir del array de puertos de port-scanner.js + service-detect.js.
 * Cada entrada tiene: { port, protocol, state, service, severity, fix, pid?, process?, extra? }
 * Si el array está vacío emite un único finding informativo.
 *
 * @param {Array} ports
 * @returns {Finding[]}
 */
function fromPortScanner(ports) {
  if (!Array.isArray(ports) || ports.length === 0) {
    return [
      createFinding({
        id:       "NET-PORT-INF",
        title:    "Sin puertos abiertos relevantes detectados",
        severity: "info",
        evidence: "El escaneo no encontró puertos abiertos en el catálogo monitoreado.",
        fix:      null,
        category: "network",
        source:   "native",
      }),
    ];
  }

  return ports.map((p, i) => {
    const idx = String(i + 1).padStart(3, "0");
    const service = p.service || "unknown";
    const isUnknownService = service === "unknown" || service === "tcpwrapped";
    const displayService = isUnknownService && p.process ? p.process : service;

    // Título: cuando service es desconocido y hay proceso, el proceso es el servicio
    const title = p.process && !isUnknownService
      ? `Puerto abierto: ${p.port}/tcp (${displayService}) — usado por ${p.process}`
      : `Puerto abierto: ${p.port}/tcp (${displayService})`;

    // Evidence: acumula toda la información disponible
    let evidence = `Puerto ${p.port}/tcp abierto. Servicio: ${displayService}.`;
    if (p.pid != null && p.process) {
      evidence += ` Proceso: ${p.process} (PID ${p.pid}).`;
    }
    if (p.extra) {
      evidence += ` ${p.extra}`;
    }

    // Si hay proceso conocido, intentar fix específico como override del genérico
    const processFix = p.process ? getFixForProcess(p.process, process.platform) : null;

    return createFinding({
      id:       `NET-PORT-${idx}`,
      title,
      severity: p.severity || "low",
      evidence,
      fix:      processFix || p.fix || null,
      category: "network",
      source:   "native",
    });
  });
}

/**
 * Normaliza raw data del nodo audit-network.
 * @param {Array|*} raw
 * @param {"native"|"nmap"} source
 * @returns {Finding[]}
 */
function normalizeNetwork(raw, source = "native") {
  if (source === "nmap") return fromNmap(raw);
  return fromPortScanner(Array.isArray(raw) ? raw : []);
}

/**
 * Normaliza raw data del nodo audit-image.
 * @param {*} raw
 * @param {"docker"|"trivy"} source
 * @returns {Finding[]}
 */
function normalizeImage(raw, source = "docker") {
  if (source === "trivy") return fromTrivyJson(raw, "IMG-CVE", "vulnerability", "trivy");
  return fromNative(Array.isArray(raw) ? raw : [], source);
}

module.exports = {
  normalizeHost,
  normalizeNetwork,
  normalizeImage,
  // Subfunciones expuestas para tests unitarios
  fromCpuMemory,
  fromDisk,
  fromSwInventory,
  fromLynisRaw,
  fromSecurityEvents,
  fromSecurityEventsWin32,
  fromTrivyJson,
  fromNmap,
  fromNative,
  // Utilitaria: detecta si un fix es comando ejecutable directamente
  isExecutableCommand,
};
