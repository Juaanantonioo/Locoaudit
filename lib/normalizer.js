"use strict";

/** Convierte las salidas raw de los módulos al esquema Finding. */

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { createFinding } = require("./finding-schema");
const { fromTrivy, max, MEMORY_THRESHOLDS, lynisGroup, lynisSeverity, SECURITY_EVENT_RULES } = require("./severity-map");
const { getFixForProcess, getFixKind, getSystemService, DANGEROUS_SERVICES } = require("./process-fix");
const { updateAllCmd, upgradeCmd, managerLabel, managerForTrivyType } = require("./pkg-manager");
const { correlateWindowsLogons } = require("./win-logons");

function safe(val, fallback = "—") {
  return val != null ? String(val) : fallback;
}

function counter(n) {
  return String(n + 1).padStart(3, "0");
}

/** Severidad según el porcentaje de uso de disco. */
// Umbrales de uso doméstico: un disco al 68 % no es un riesgo y avisar de eso es ruido.
function diskSeverity(pct) {
  if (pct >= 95) return "critical";
  if (pct >= 90) return "high";
  if (pct >= 85) return "medium";
  return "info";
}

/** Severidad de RAM por plataforma. En macOS siempre "info": el kernel usa toda la que hay. */
function memorySeverity(usedPct, platform) {
  const thresholds = MEMORY_THRESHOLDS[platform] || MEMORY_THRESHOLDS.linux;
  if (thresholds.critical !== null && usedPct >= thresholds.critical) return "high";
  if (thresholds.warn !== null && usedPct >= thresholds.warn) return "medium";
  return "info";
}

// El hardening index ya no genera finding: un 29 metía un "high" que el usuario no podía
// arreglar. Ahora es métrica de cabecera (scanMeta.lynis) y la pinta el gauge.

/** Findings a partir del raw de cpu-memory.js. */
/** Cómo mirar los procesos en cada SO: top/htop no existen en Windows. */
function cpuInspectFix(platform) {
  if (platform === "win32") {
    return "Revisar los procesos con más consumo en el Administrador de tareas (Ctrl+Mayús+Esc), " +
           "pestaña Procesos, ordenando por CPU.";
  }
  if (platform === "darwin") {
    return "Revisar los procesos con más consumo en Monitor de Actividad (pestaña CPU), " +
           "o en Terminal con: top -o cpu";
  }
  return "Revisar los procesos con más consumo con top (o htop si lo tienes instalado).";
}

function fromCpuMemory(raw, platform) {
  if (!raw) return [];
  const findings = [];
  const plat = platform || raw.platform || process.platform;

  if (raw.cpu) {
    const { model, cores, loadAvg } = raw.cpu;
    const loadStr = Array.isArray(loadAvg)
      ? `1m: ${loadAvg[0]?.toFixed(2)}, 5m: ${loadAvg[1]?.toFixed(2)}, 15m: ${loadAvg[2]?.toFixed(2)}`
      : "N/A (Windows)";

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
        fix: cpuSev !== "info" ? cpuInspectFix(plat) : null,
        category: "cpu",
        source: "native",
      })
    );
  }

  if (raw.memory) {
    const { totalGiB, usedGiB, freeRatio } = raw.memory;
    const usedRatio = freeRatio != null ? 1 - freeRatio : null;
    const usedPct = usedRatio != null ? Math.round(usedRatio * 100) : null;

    if (plat === "darwin") {
      // macOS reporta la RAM al 95-99 % por la gestión unificada: informativo, nunca alerta.
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

/** Findings a partir de las particiones de disk-storage.js. */
function fromDisk(partitions) {
  if (!Array.isArray(partitions)) return [];
  return partitions.map((p, i) => {
    const sev = diskSeverity(p.usedPercent);
    // disk-storage entrega una entrada por sistema de ficheros; los demás montajes van en la
    // evidencia. Si no, un disco al 90 % parecía afectar solo a "/" y no a /home o /var.
    const otros = Array.isArray(p.mounts) ? p.mounts.filter((m) => m !== p.mount) : [];
    const compartido = otros.length
      ? `, Compartido con: ${otros.join(", ")}`
      : "";
    return createFinding({
      id: `HOST-DISK-${counter(i)}`,
      title: `Disco ${p.mount}: ${p.usedPercent}% en uso`,
      severity: sev,
      evidence: `Montaje: ${p.mount}, Total: ${p.totalGB} GB, Usado: ${p.usedGB} GB, Libre: ${p.freeGB} GB (${p.usedPercent}%)${compartido}`,
      fix: sev !== "info"
        ? `Liberar espacio en ${p.mount}. Eliminar ficheros temporales o ampliar volumen.`
        : null,
      category: "disk",
      source: "native",
    });
  });
}

/** Finding informativo con el inventario de software; los CVE los pone Trivy. */
function fromSwInventory(pkgs, platform, pkgManager) {
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

  let dangerIdx = 1;
  for (const pkg of pkgs) {
    const normalName = pkg.name ? pkg.name.toLowerCase().trim() : "";
    const severity = DANGEROUS_SERVICES.get(normalName);
    if (!severity) continue;

    const fix = getFixForProcess(normalName, platform || process.platform, pkgManager);
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

/** Etiqueta en español del grupo de control (prefijo del ID). Mismo vocabulario que eligen
 *  el fix y LYNIS_GROUP_TIER; viaja como `subcategory` y es lo que agrupa las tarjetas. */
const LYNIS_GROUP_LABELS = {
  AUTH: "Autenticación y contraseñas",
  SSH:  "Acceso remoto (SSH)",
  FIRE: "Cortafuegos",
  CRYP: "Criptografía y certificados",
  USB:  "Dispositivos USB",
  KRNL: "Núcleo del sistema",
  BOOT: "Arranque y servicios",
  NETW: "Red",
  NAME: "Nombres y DNS",
  PKGS: "Paquetes y actualizaciones",
  FILE: "Ficheros y permisos",
  HOME: "Carpetas personales",
  STRG: "Almacenamiento",
  PROC: "Procesos",
  HRDN: "Endurecimiento del sistema",
  HTTP: "Servidor web",
  MAIL: "Correo",
  LOGG: "Registros del sistema",
  ACCT: "Auditoría de procesos",
  TIME: "Hora del sistema",
  BANN: "Avisos legales",
  TOOL: "Herramientas de seguridad",
  FINT: "Integridad de ficheros",
};

const LYNIS_GROUP_FALLBACK = "Otros controles de Lynis";

/** Vocabulario cerrado del campo 4. El prefijo `tipo:token` es una convención, no un
 *  formato: solo se interpreta el token exacto y la prosa se descarta. */
const LYNIS_ACTION_TOKENS = {
  reboot: "reboot",
};

/** Interpreta el campo 4 (tipo de solución). */
function parseSolutionType(solution) {
  if (!solution) return {};
  const m = /^([a-z]+):(.*)$/.exec(solution.trim());
  if (!m) return {};
  const [, kind, rest] = m;
  if (kind === "url" && rest) return { primaryUrl: rest.trim() };
  if (kind === "text") {
    const token = LYNIS_ACTION_TOKENS[rest.trim().toLowerCase()];
    if (token) return { actionType: token };
  }
  return {};   // prosa libre: manda getLynisFixText()
}

/** Orden ejecutable del campo 3, solo en la forma canónica `Run '…'`. Estrecho a propósito:
 *  el campo trae sobre todo datos ('/home') y un botón que pega basura es peor que ninguno. */
function commandFromDetail(detail) {
  const m = /^Run\s+'([^']+)'/.exec((detail || "").trim());
  return m ? m[1] : null;
}

/** Clave estable: ID + descripción + detalle. El ID solo no identifica nada — AUTH-9286 y
 *  FILE-6310 aparecen varias veces en un .dat real y colapsaban en un único finding. */
function lynisFindingId(entry) {
  const key = [entry.id, entry.description, entry.detail || ""].join("\u0000");
  const hash = crypto.createHash("sha1").update(key).digest("hex").slice(0, 6);
  return `HOST-LYN-${entry.id}-${hash}`;
}

/** Texto de resolución por plataforma, para avisos y sugerencias. `command` solo se rellena
 *  cuando el paso es un comando puro (hoy, PKGS con gestor detectado). */
// Excepciones por control, antes que el prefijo: NETW cubre los nameservers (2704, 2705) y
// los módulos de protocolo del kernel (3200), y el paso de DNS es falso para los segundos.
const LYNIS_FIXES_BY_CONTROL = {
  "NETW-3200": {
    linux: "Comprobar si el protocolo indicado se usa en este equipo. Si no, " +
           "impedir que su módulo se cargue añadiendo un fichero en /etc/modprobe.d/ " +
           "con la línea `install <protocolo> /bin/true`.",
    all:   "Comprobar si el protocolo indicado se usa en este equipo y desactivarlo si no.",
  },
};

function getLynisFixText(id, platform, pkgManager) {
  const plat = platform || process.platform;
  if (!id) return { fix: "Revisar la configuración del sistema para este aviso de Lynis.", command: null };
  const prefix = id.split("-")[0].toUpperCase();

  const porControl = LYNIS_FIXES_BY_CONTROL[id.toUpperCase()];
  if (porControl) {
    return { fix: porControl[plat] || porControl.all, command: null };
  }

  const FIXES_BY_PLATFORM = {
    BOOT: {
      linux:  "Revisar los servicios que arrancan con el sistema (`systemctl list-unit-files --state=enabled`) " +
              "y desactivar los que no uses.",
      darwin: "Revisar los elementos de inicio en Ajustes del Sistema → General → Ítems de inicio.",
    },
    NETW: {
      linux:  "Revisar la configuración DNS del sistema: /etc/resolv.conf y, si usas systemd, `resolvectl status`.",
      darwin: "Revisar la configuración DNS del sistema en Ajustes del Sistema → Red → (tu conexión) → DNS.",
    },
    SSH: {
      all: "Revisar /etc/ssh/sshd_config. Desactivar PermitRootLogin y usar autenticación por clave.",
    },
    FIRE: {
      linux:  "Activar el cortafuegos de tu distribución. Comprueba primero cuál tienes (ufw, firewalld o nftables) " +
              "antes de habilitarlo: una regla en un cortafuegos que no usas no protege nada.",
      darwin: "Activar el cortafuegos en Ajustes del Sistema → Red → Firewall.",
    },
    AUTH: {
      linux:  "Revisar la configuración de autenticación PAM en /etc/pam.d/ y la política de contraseñas.",
      darwin: "Revisar la política de contraseñas del sistema y las cuentas con acceso de administrador.",
    },
    KRNL: {
      linux:  "Revisar los parámetros del kernel en /etc/sysctl.conf o /etc/sysctl.d/.",
      darwin: "Revisar los parámetros del kernel con `sysctl -a`. En macOS la mayoría no son ajustables sin SIP desactivado.",
    },
    PKGS: {
      all: "Actualizar los paquetes del sistema.",
    },
    LOGG: {
      linux:  "Revisar la configuración de logs en /etc/rsyslog.conf o la de journald en /etc/systemd/journald.conf.",
      darwin: "Revisar la configuración de logs unificados de macOS (`log config --status`).",
    },
    TIME: {
      linux:  "Activar la sincronización horaria: sudo timedatectl set-ntp true",
      darwin: "Activar la hora automática en Ajustes del Sistema → General → Fecha y hora.",
    },
    CRYP: {
      all: "Revisar la configuración criptográfica del sistema y la caducidad de los certificados instalados.",
    },
    MAIL: {
      all: "Revisar la configuración del servidor de correo si está activo; si no lo usas, desactívalo.",
    },
    USB: {
      linux:  "Revisar el uso de almacenamiento USB: módulo usb-storage y reglas de udev en /etc/udev/rules.d/.",
      darwin: "Revisar los permisos de acceso a dispositivos en Ajustes del Sistema → Privacidad y seguridad.",
    },
    BANN: {
      linux:  "Añadir un banner de aviso legal en /etc/motd o /etc/issue.",
      darwin: "Añadir un mensaje en la pantalla de bloqueo: Ajustes del Sistema → Pantalla de bloqueo.",
    },
    ACCT: {
      linux:  "Instalar y activar la auditoría de procesos del sistema (auditd o process accounting).",
      darwin: "Revisar la auditoría del sistema (`audit` / BSM). Está desactivada por defecto en macOS reciente.",
    },
    STRG: {
      linux:  "Revisar los módulos de almacenamiento cargados en el kernel (`lsmod`) y deshabilitar los que no uses.",
    },
    TOOL: {
      all: "Considerar instalar herramientas adicionales de seguridad (rkhunter, chkrootkit, aide).",
    },
  };

  const entry = FIXES_BY_PLATFORM[prefix];
  if (!entry) return { fix: `Revisar la configuración del sistema relacionada con ${id}.`, command: null };

  // PKGS: con gestor detectado el paso es un comando. Va en 2ª línea y se expone en `command`
  // porque el extractor solo mira la primera, que aquí es prosa.
  if (prefix === "PKGS") {
    const cmd = updateAllCmd(pkgManager);
    return cmd
      ? { fix: `Actualizar los paquetes del sistema con ${managerLabel(pkgManager)}:\n${cmd}`, command: cmd }
      : { fix: "Actualizar los paquetes del sistema con el gestor de paquetes de tu distribución.", command: null };
  }

  const text = entry[plat] || entry.all;
  // Sin paso para esta plataforma: guía genérica, nunca los pasos de otro SO.
  return {
    fix: text || `Revisar la configuración del sistema relacionada con ${id} en tu sistema operativo.`,
    command: null,
  };
}

/** Empareja aviso y sugerencia del mismo control y detalle: no son un duplicado, son el
 *  problema y su remedio. Por orden de aparición; lo que sobra sale suelto. */
function pairLynisEntries(warnings, suggestions) {
  const byKey = new Map();
  for (const s of suggestions) {
    const key = `${s.id}\u0000${s.detail || ""}`;
    if (!byKey.has(key)) byKey.set(key, []);
    byKey.get(key).push(s);
  }

  const items = [];
  const consumed = new Set();

  for (const w of warnings) {
    const key = `${w.id}\u0000${w.detail || ""}`;
    const pool = byKey.get(key) || [];
    const remedy = pool.find((s) => !consumed.has(s)) || null;
    if (remedy) consumed.add(remedy);
    items.push({ type: "warning", entry: w, remedy });
  }

  for (const s of suggestions) {
    if (consumed.has(s)) continue;
    items.push({ type: "suggestion", entry: s, remedy: null });
  }

  return items;
}

/** Un finding por entrada del .dat. Antes las sugerencias colapsaban en una tarjeta que
 *  remitía a 'lynis show suggestions'; el volumen se controla por severidad, no ocultando. */
function fromLynisRaw(raw, platform, pkgManager) {
  if (!raw || raw.skipped) return [];

  const items = pairLynisEntries(raw.warnings || [], raw.suggestions || []);
  const findings = [];

  for (const { type, entry, remedy } of items) {
    const group = lynisGroup(entry.id);
    const lynFix = getLynisFixText(entry.id, platform, pkgManager);
    const solution = parseSolutionType(entry.solution);

    // Orden del fix: qué conseguir (la sugerencia), cómo se hace en este SO, y la orden exacta
    // si Lynis la da. Un token conocido del campo 4 ('text:reboot') va por delante de todo.
    const steps = [];
    if (solution.actionType === "reboot") {
      steps.push("Reinicia el equipo para que el cambio surta efecto.");
    }
    if (remedy && remedy.description) steps.push(remedy.description);
    // Si el campo 4 da la acción exacta, el texto del prefijo sobra: KRNL-5830 pide reiniciar y
    // el prefijo mandaba a editar /etc/sysctl.conf, que ni reinicia ni arregla.
    if (lynFix.fix && !solution.actionType) steps.push(lynFix.fix);

    // El campo 3 gana como comando: es de esta instancia del control, el del prefijo es genérico.
    const detailCmd = commandFromDetail(entry.detail);
    if (detailCmd) steps.push(detailCmd);

    const evidenceParts = [entry.description];
    if (entry.detail && !detailCmd) evidenceParts.push(entry.detail);

    findings.push(
      createFinding({
        id: lynisFindingId(entry),
        // El título es la descripción; el código va de metadato (antes encabezaba la tarjeta).
        title: entry.description,
        severity: lynisSeverity(entry.id, type),
        evidence: evidenceParts.join(" · "),
        fix: steps.length ? steps.join("\n") : null,
        command: detailCmd || lynFix.command || null,
        category: "system",
        source: "lynis",
        control: entry.id,
        controlGroup: group,
        subcategory: LYNIS_GROUP_LABELS[group] || LYNIS_GROUP_FALLBACK,
        detail: detailCmd ? null : entry.detail,
        lynisType: type,
        actionType: solution.actionType || null,
        primaryUrl: solution.primaryUrl || null,
        // Lynis no puntúa: el nivel lo pone LoCoAudit (LYNIS_GROUP_TIER en severity-map).
        severitySource: "locoaudit",
      })
    );
  }

  return findings;
}

// Lynis audita la configuración de SSH; security-events, los eventos: quién entró, cuándo y
// desde dónde. Los fixes son genéricos y nunca bloquean usuarios ni IPs.

/** Endurecimiento de SSH para el SO real; antes el texto listaba Linux y macOS a la vez. */
/** Rutas de OpenSSH por plataforma, fuente única. En Windows las cuentas administrativas no
 *  usan el authorized_keys del perfil: sshd lee administrators_authorized_keys. */
function sshPaths(platform) {
  if (platform === "win32") {
    return {
      config:    "C:\\ProgramData\\ssh\\sshd_config",
      keys:      "%USERPROFILE%\\.ssh\\authorized_keys",
      adminKeys: "C:\\ProgramData\\ssh\\administrators_authorized_keys",
    };
  }
  return {
    config:    "/etc/ssh/sshd_config",
    keys:      "~/.ssh/authorized_keys",
    adminKeys: null,
  };
}

/** Texto de endurecimiento de SSH; las rutas salen de sshPaths(). */
function sshHardenFix(platform) {
  const p = sshPaths(platform);
  const common =
    `Revisar ${p.config}: PermitRootLogin no, y PasswordAuthentication no si usas claves.`;
  if (platform === "darwin") {
    return `${common}\n` +
      "Si no usas el acceso remoto, desactívalo en Ajustes del Sistema → General → Compartido → Sesión remota.";
  }
  if (platform === "win32") {
    return `Revisar la configuración del Servidor OpenSSH (${p.config}). ` +
      "Si no usas el acceso remoto por SSH, detén y deshabilita el servicio OpenSSH SSH Server en services.msc.";
  }
  return `${common}\n` +
    "Para limitar los intentos repetidos, considera fail2ban.";
}

/** Dónde mirar si no reconoces un acceso SSH correcto. */
function sshReviewFix(platform) {
  const p = sshPaths(platform);
  if (platform === "win32") {
    return `Si no reconoces este acceso, revisar ${p.config} y las claves ` +
      `autorizadas: ${p.keys} para las cuentas normales y ${p.adminKeys} ` +
      "para las cuentas de administrador.";
  }
  return `Si no reconoces este acceso, revisar ${p.config} y las claves autorizadas (${p.keys}).`;
}

// Consejo único para el acceso con cuenta administradora: lo usan las dos vías, el acceso SSH
// y el 4672 suelto. Separados, matizar uno dejaría al otro diciendo otra cosa del mismo riesgo.
const ADMIN_ACCOUNT_FIX =
  "Comprueba que reconoces este acceso. El aviso NO dice que se ejecutara nada con permisos " +
  "elevados: dice que la cuenta con la que se entró es una cuenta de administrador, así que " +
  "quien tenga sus credenciales puede hacer cambios en todo el equipo.\n" +
  "Para el uso remoto del día a día, entra con una cuenta normal y reserva la de administrador " +
  "para cuando de verdad haga falta. Revisa también qué cuentas pueden conectarse en remoto y " +
  "quita de esa lista las que no lo necesiten.";

const MAX_SEC_INDIVIDUAL = 10; // logins SSH individuales antes de agregar

/** ¿El acceso SSH se hizo con una identidad que puede cambiarlo todo? Un solo predicado: root
 *  en Unix, y en Windows un 4672 correlacionado, que dice que la CUENTA es administradora. */
function privilegedSshIdentity(access, ctx) {
  if (access && access.user === "root") return { kind: "root", events: [] };
  const events = typeof ctx.winPrivileged === "function" ? ctx.winPrivileged(access) || [] : [];
  return events.length > 0 ? { kind: "admin-group", events } : null;
}

/** Título según cómo se cumplió el predicado, no según el SO: "root" es mentira en Windows y
 *  "cuenta de administrador" es impreciso para root. */
function privilegedSshTitle(kind) {
  return kind === "root"
    ? "Acceso SSH como root detectado"
    : "Acceso SSH con una cuenta que tiene privilegios de administrador";
}

/** Por qué el acceso se clasificó como privilegiado. En root se ve solo; en Windows no, y sin
 *  el evento y su LogonId el usuario no puede buscarlo en el Visor. */
function privilegedSshNote(identity) {
  if (!identity || identity.kind !== "admin-group") return "";
  const ids = [...new Set(identity.events.map((e) => e.logonId).filter(Boolean))];
  return (
    " · Evento 4672" + (ids.length ? ` (LogonId ${ids.join(", ")})` : "") +
    ": Windows registra que la cuenta pertenece al grupo Administradores"
  );
}

/** Findings de accesos SSH, correctos y fallidos. Vive fuera de las ramas por plataforma: los
 *  mensajes los escribe OpenSSH con el mismo formato en los tres sistemas. */
function sshFindings(ssh, ctx) {
  const { W, R, sshHarden, sshReview } = ctx;
  const findings = [];

  // Identidad privilegiada → high individual; el resto, info con tope MAX_SEC_INDIVIDUAL y un
  // agregado. El reparto sale del predicado, no de comparar el usuario con "root" aquí mismo.
  const clasificados = ssh.accepted.map((a) => ({ a, identity: privilegedSshIdentity(a, ctx) }));
  const privLogins = clasificados.filter((c) => c.identity);
  const otherLogins = clasificados.filter((c) => !c.identity).map((c) => c.a);

  for (const [i, { a, identity }] of privLogins.entries()) {
    findings.push(
      createFinding({
        id: `HOST-SEC-SSH-R-${counter(i)}`,
        title: privilegedSshTitle(identity.kind),
        severity: R.SSH_ACCEPTED_ROOT,
        evidence:
          `Usuario: ${safe(a.user)} · IP: ${safe(a.ip)} · Fecha: ${safe(a.timestamp)} · ` +
          `Método: ${safe(a.method)}` + privilegedSshNote(identity),
        // Con root basta endurecer SSH; con cuenta administradora lo primero es con qué cuenta se entra.
        fix: identity.kind === "root" ? sshHarden : `${ADMIN_ACCOUNT_FIX}\n${sshHarden}`,
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
        fix: sshReview,
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

  // Fallidos: un finding agregado; pasado el umbral, posible fuerza bruta.
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
        fix: sshHarden,
        category: "system-logs",
        source: "security-events",
      })
    );
  }

  return findings;
}

function fromSecurityEvents(raw, platform) {
  if (!raw) return [];
  const findings = [];
  const W = raw.windowHours || 24;
  const R = SECURITY_EVENT_RULES;
  const plat = platform || raw.platform || process.platform;
  const sshHarden = sshHardenFix(plat);
  const sshReview = sshReviewFix(plat);

  // Fuentes no disponibles: finding info, nunca error.
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
          "en Windows, PowerShell disponible y la cuenta en el grupo «Lectores del registro de eventos» " +
          "(«Event Log Readers»), que da lectura del canal Security sin elevar. " +
          "Ejecutar Node-RED con un usuario con permisos de lectura sobre los logs, no con privilegios elevados.",
        category: "system-logs",
        source: "security-events",
      })
    );
    return findings;
  }

  // El canal Security se excluye si ya tiene su propio finding (HOST-SEC-WIN-PERM): si no, la
  // misma fuente se contaba dos veces. partial[] sigue completo, lo necesita HOST-SEC-SKIP.
  const securityDenied = !!(raw.windows && raw.windows.securityLogDenied);
  const partialSources = (Array.isArray(raw.partial) ? raw.partial : []).filter(
    (p) => !(securityDenied && p.source === "Get-WinEvent(Security)")
  );
  if (partialSources.length > 0) {
    findings.push(
      createFinding({
        id: "HOST-SEC-SRC",
        title: `Eventos de seguridad: ${partialSources.length} fuente(s) no disponibles`,
        severity: "info",
        evidence: partialSources.map((p) => `${p.source}: ${p.reason}`).join(" · "),
        fix: "La auditoría se completó con las fuentes restantes. Para cobertura completa, revisar permisos de lectura de logs.",
        category: "system-logs",
        source: "security-events",
      })
    );
  }

  // Windows: 4624/4625/4672 del canal Security. Los accesos SSH llegan por
  // OpenSSH/Operational y los trata el mismo código que en Linux y macOS.
  if (raw.platform === "win32" || raw.windows) {
    const winSsh = raw.ssh || { accepted: [], failed: [] };
    // Misma correlación que buildEventList, calculada una vez y pasada a las dos mitades: cuando
    // cada una decidía por su cuenta, un solo login SSH producía tres findings.
    const corr = correlateWindowsLogons(raw);
    // Entra como dato, no como texto ya redactado: quien decide qué significa es el predicado.
    const winPrivileged = (a) => corr.privilegedFor(a);
    return findings.concat(
      sshFindings(winSsh, { W, R, sshHarden, sshReview, winPrivileged }),
      fromSecurityEventsWin32(raw, corr)
    );
  }

  const ssh = raw.ssh || { accepted: [], failed: [] };
  const sudo = raw.sudo || { ok: [], failed: [] };
  const sessions = Array.isArray(raw.sessions) ? raw.sessions : [];

  findings.push(...sshFindings(ssh, { W, R, sshHarden, sshReview }));


  // sudo correcto: un info agregado con recuento y muestra.
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

  // Sesiones remotas activas ahora; las locales se quedan solo en raw.
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

  // Sin ningún evento: finding info de comprobación, que no es lo mismo que skipped.
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

// Rama Windows, con las mismas reglas y el mismo umbral que la Unix: 4624 tipo 10/3 ≈ login
// SSH, 4625 ≈ fallidos, 4672 remoto ≈ login de root, sesión RDP ≈ sesión remota activa.

// La elevación (UAC/4688) no se audita: el aviso "no disponible en Windows" aparecía con la
// directiva activada y su fix no cambiaba nada de lo que el módulo lee.

// Cerrar y filtrar son cosas distintas: desactivar el Escritorio remoto cierra el acceso, una
// regla de cortafuegos solo lo filtra.
const RDP_HARDEN_FIX =
  "Si no reconoces estos accesos:\n" +
  "1) CERRARLO: desactiva el Escritorio remoto en Configuración → Sistema → Escritorio remoto. " +
  "El servicio deja de escuchar y el puerto 3389 se cierra.\n" +
  "2) Si SÍ necesitas el Escritorio remoto: exige autenticación a nivel de red (NLA), usa contraseñas " +
  "robustas en todas las cuentas y limita quién puede conectarse (Usuarios de escritorio remoto).\n" +
  "Una regla del Firewall de Windows Defender sobre el 3389 solo FILTRA el tráfico de red: el servicio " +
  "sigue activo y el puerto sigue abierto, así que no sustituye al paso 1.";

// S-1-5-32-573 es el SID de "Event Log Readers": estable e independiente del idioma, mientras
// que el nombre está traducido. Add-LocalGroupMember acepta -SID; net localgroup no.
const CMD_EVENT_LOG_READERS = "Add-LocalGroupMember -SID S-1-5-32-573 -Member $env:USERNAME";

const EVENT_LOG_READERS_NOTE =
  "Ejecútalo UNA vez en una consola de PowerShell abierta como administrador, con la sesión de " +
  "Windows del usuario que ejecuta Node-RED, y vuelve a iniciar sesión para que el nuevo grupo entre " +
  "en su token. Node-RED sigue ejecutándose SIN elevar: leer el canal Security no exige ser " +
  "administrador, exige pertenecer al grupo «Lectores del registro de eventos» («Event Log Readers» " +
  "en Windows en inglés). El comando usa el SID y no el nombre porque el nombre está traducido y " +
  "cambia con el idioma del sistema; `net localgroup` no admite SIDs, así que ahí habría que escribir " +
  "el nombre exacto del idioma instalado. Conceder ese permiso es una decisión tuya: mientras no lo " +
  "hagas, el resto de la auditoría se completa y esta comprobación consta como no realizada, que no " +
  "es lo mismo que «sin hallazgos».";

/** Findings del canal Security (4624/4625/4672). Lo que ya cuenta un finding de SSH se descarta
 *  a la entrada; un 4672 remoto sin SSH detrás sigue siendo un hallazgo alto. */
function fromSecurityEventsWin32(raw, corr = correlateWindowsLogons(raw)) {
  const findings = [];
  const W = raw.windowHours || 24;
  const R = SECURITY_EVENT_RULES;
  const win = raw.windows || {};
  const logons = win.logons || { remote: [], localCount: 0 };
  const allRemote = Array.isArray(logons.remote) ? logons.remote : [];
  const allFailed = Array.isArray(win.failed) ? win.failed : [];
  const allPrivileged = Array.isArray(win.privileged) ? win.privileged : [];
  const remote = allRemote.filter((_, i) => !corr.absorbedRemote.has(i));
  const failed = allFailed.filter((_, i) => !corr.absorbedFailed.has(i));
  const privileged = allPrivileged.filter((_, i) => !corr.absorbedPriv.has(i));
  const sessions = Array.isArray(raw.sessions) ? raw.sessions : [];

  // Canal Security sin permisos: finding info, nunca crash.
  if (win.securityLogDenied) {
    findings.push(
      createFinding({
        id: "HOST-SEC-WIN-PERM",
        title: "Eventos de seguridad de Windows no accesibles",
        severity: "info",
        evidence:
          "Get-WinEvent no pudo leer el canal Security: acceso denegado, o cero eventos sobre un canal " +
          "que el sondeo confirma habilitado y con registros. No se ha podido comprobar si hubo accesos, " +
          "fallos de login o elevaciones: no es lo mismo que no haberlos.",
        // El fix no puede ser "ejecuta Node-RED como administrador": es justo lo que descarta CLAUDE.md.
        // El grupo de lectores del registro da el permiso sin elevar. Línea 1, comando; el resto, nota.
        fix: CMD_EVENT_LOG_READERS + "\n" + EVENT_LOG_READERS_NOTE,
        command: CMD_EVENT_LOG_READERS,
        category: "system-logs",
        source: "security-events",
      })
    );
  }

  // Logins remotos correctos (tipo 10 RDP, 3 red): individuales.
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

  // Locales: solo recuento, y solo si también hubo remotos. En un PC sin acceso remoto son ruido.
  if (allRemote.length > 0 && logons.localCount > 0) {
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

  // 4625 fallidos: un agregado, con el mismo umbral que SSH.
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

  // 4672: remoto → high individual; local → agregado. Windows lo emite porque la CUENTA que entra
  // es administradora, no porque la sesión esté elevada, y el texto va sobre la cuenta.
  const privRemote = privileged.filter((p) => p.remote);
  const privLocal = privileged.filter((p) => !p.remote);

  for (const [i, p] of privRemote.slice(0, MAX_SEC_INDIVIDUAL).entries()) {
    findings.push(
      createFinding({
        id: `HOST-SEC-WIN-PRIV-${counter(i)}`,
        title: "Acceso remoto con una cuenta de administrador",
        severity: R.SSH_ACCEPTED_ROOT,
        evidence:
          `Usuario: ${safe(p.user)} · IP: ${safe(p.ip)} · Fecha: ${safe(p.timestamp)} · ` +
          "Evento 4672: al iniciar la sesión, Windows le dio a esta cuenta los permisos propios " +
          "del grupo Administradores, correlacionado con el inicio de sesión remoto",
        fix: `${ADMIN_ACCOUNT_FIX}\n${RDP_HARDEN_FIX}`,
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
        title: `${privLocal.length} inicio(s) de sesión local(es) con una cuenta de administrador en ${W} h`,
        severity: "info",
        evidence:
          "Evento 4672: cuentas del grupo Administradores que iniciaron sesión en el propio equipo " +
          `· Usuarios: ${users.slice(0, 5).join(", ") || "—"}`,
        fix: null,
        category: "system-logs",
        source: "security-events",
      })
    );
  }

  // Sesiones activas: RDP individual, locales agregadas.
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

  // Los accesos SSH cuentan: con el canal Security ilegible pero OpenSSH dando fallidos, decir
  // "sin eventos relevantes" sería falso.
  const winSsh = raw.ssh || { accepted: [], failed: [] };
  const hasEvents =
    remote.length > 0 ||
    failed.length > 0 ||
    privileged.length > 0 ||
    rdpSessions.length > 0 ||
    (winSsh.accepted || []).length > 0 ||
    (winSsh.failed || []).length > 0;

  if (!hasEvents && !win.securityLogDenied) {
    findings.push(
      createFinding({
        id: "HOST-SEC-INF",
        title: `Sin eventos de seguridad relevantes en las últimas ${W} h`,
        severity: "info",
        evidence: `Fuentes consultadas: ${(raw.sources || []).join(", ") || "—"} · Ventana: ${W} h · Sin accesos remotos, intentos SSH, fallos de login ni sesiones RDP.`,
        fix: null,
        category: "system-logs",
        source: "security-events",
      })
    );
  }

  return findings;
}

// El ecosistema sale del campo Type de cada Result, nunca de la ruta del Target: adivinarlo
// produce comandos de gestor cruzado (npm o brew para un crate de Rust).

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

/** Prefijos administrados por el gestor del SO. Comprobar la ruta aquí sí vale: no infiere de
 *  dónde viene, verifica un hecho. En Arch, un pip --upgrade sobre /usr/lib falla por PEP 668. */
const SYSTEM_PREFIXES = [
  "/usr/lib", "/usr/lib64", "/usr/local/lib", "/usr/share", "/opt",
  "/Library/", "/System/Library/",            // macOS
  "C:\\Program Files", "C:\\Windows",         // Windows
];

/** ¿La ruta cuelga de un prefijo del gestor del SO? */
function isSystemPath(location) {
  if (!location) return false;
  const p = String(location);
  return SYSTEM_PREFIXES.some((prefix) =>
    prefix.startsWith("C:") ? p.toLowerCase().startsWith(prefix.toLowerCase()) : p.startsWith(prefix)
  );
}

// Type de paquete de sistema operativo (Class = os-pkgs).
const TRIVY_OS_TYPES = new Set([
  "debian", "ubuntu", "alpine", "redhat", "centos", "rocky", "alma",
  "almalinux", "amazon", "oracle", "fedora", "suse", "opensuse",
  "opensuse-leap", "opensuse-tumbleweed",
  "photon", "mariner", "cbl-mariner", "azurelinux", "wolfi", "chainguard",
  // Sin estos, en Arch el fix caía al fallback y proponía apt.
  "arch", "archlinux", "gentoo",
]);

/** Comando para actualizar un paquete del SO en el host; el gestor sale del Type. */
function osHostUpdateCmd(type, pkg, ver, pkgManager) {
  // Primero el Type de Trivy, que identifica la distro escaneada; si no, el gestor detectado en
  // el equipo. Nunca se asume apt.
  const mgr = managerForTrivyType(type) || pkgManager || null;
  const cmd = upgradeCmd(mgr, pkg);
  // Con gestor conocido, el fix ES el comando (copiable). Sin él, prosa sin línea.
  if (cmd) return { fix: cmd, command: cmd };
  const verTxt = ver ? ` a la versión ${ver}` : "";
  return {
    fix: `Actualiza ${pkg}${verTxt} con el gestor de paquetes de tu distribución.`,
    command: null,
  };
}

/** Paso de resolución de un paquete vulnerable en el host. El ecosistema sale del Type de Trivy;
 *  sin Type no se adivina: adivinando, un crate de Rust bajo /Cellar/ salía como brew upgrade. */
function getTrivyFixCommand(target, pkgName, fixedVersion, platform, pkgType = "", pkgManager = null, meta = {}) {
  if (!pkgName) return { fix: null, command: null };
  const pkg = pkgName.split("@")[0];
  const ver = fixedVersion || null;
  const type = String(pkgType || "").toLowerCase();
  const location = meta.location || target || null;

  // Sin PkgPath, Trivy leyó una anotación en un lockfile: no hay nada que actualizar en el equipo
  // y por tanto no puede haber comando. Caso real: los lockfiles de las colecciones de Ansible.
  if (meta.origin === "declared") {
    const donde = location ? ` (${location})` : "";
    return {
      fix: `${pkg} aparece anotado como dependencia en un fichero de bloqueo${donde}, ` +
           "no es software instalado en tu equipo: no hay nada que actualizar aquí. " +
           "Si ese fichero pertenece a un proyecto tuyo, actualiza la dependencia en el " +
           "proyecto y regenera el fichero de bloqueo; si viene empaquetado por otra " +
           "herramienta, ignóralo.",
      command: null,
    };
  }

  if (TRIVY_OS_TYPES.has(type)) {
    return ver
      ? osHostUpdateCmd(type, pkg, ver, pkgManager)   // ya devuelve { fix, command }
      : {
          fix: `No hay versión corregida disponible en el repositorio del sistema para ${pkg}. ` +
               `Vigila las actualizaciones del paquete (${type}) y aplica el parche cuando salga.`,
          command: null,
        };
  }

  if (TRIVY_LANG_CMD[type]) {
    const cmd = TRIVY_LANG_CMD[type](pkg, ver);
    if (type === "cargo") {
      // La nota va en línea aparte: `command` copia solo el comando.
      const fix = cmd + `\nSi ${ver ? "la versión " + ver : "la corrección"} es una versión mayor, ` +
             `ajusta la restricción de ${pkg} en Cargo.toml y vuelve a ejecutar cargo update.`;
      return { fix, command: cmd };
    }
    return { fix: cmd, command: cmd };
  }

  // python-pkg y node-pkg son instalaciones reales, no lockfiles. Quién manda lo dice la ruta:
  // bajo un prefijo del sistema, el gestor del SO.
  if (type === "python-pkg") {
    if (isSystemPath(location)) {
      const mgr = pkgManager || null;
      const cmd = upgradeCmd(mgr, pkg);
      if (cmd) return { fix: cmd, command: cmd };
      return {
        fix: `${pkg} está instalado en una ruta del sistema (${location}): lo gestiona el gestor ` +
             `de paquetes de tu distribución, no pip. Actualízalo con ${managerLabel(mgr)}. ` +
             "Un `pip install --upgrade` sobre esa ruta fallaría (entorno gestionado externamente).",
        command: null,
      };
    }
    const cmd = TRIVY_LANG_CMD.pip(pkg, ver);
    return { fix: cmd, command: cmd };
  }

  if (type === "node-pkg") {
    // Sin package.json en un ancestro no hay nada que npm update pueda resolver.
    if (hasAncestorFile(location, "package.json")) {
      const cmd = TRIVY_LANG_CMD.npm(pkg, ver);
      return { fix: cmd, command: cmd };
    }
    return {
      fix: `${pkg} está instalado en ${location || "una carpeta node_modules"} sin un package.json ` +
           "que lo declare: no pertenece a un proyecto que puedas actualizar con npm. " +
           "Actualiza la herramienta que lo trajo, o borra esa carpeta si ya no la usas.",
      command: null,
    };
  }

  if (TRIVY_LANG_MANUAL.has(type)) {
    return {
      fix: ver
        ? `Actualiza ${pkg} a la versión ${ver} en el fichero de construcción del proyecto (${type}) y reconstruye. Requiere intervención manual.`
        : `Actualiza ${pkg} a una versión sin la vulnerabilidad en el fichero de construcción del proyecto (${type}).`,
      command: null,
    };
  }

  // Binario Go: no hay gestor que lo actualice, se actualiza la herramienta que lo incluye.
  if (type === "gobinary" ||
      /^(github\.com|google\.golang\.org|golang\.org|gopkg\.in|go\.uber\.org|k8s\.io)\//i.test(pkgName)) {
    return {
      fix: `${pkg} es un módulo Go compilado dentro de una herramienta instalada en el sistema; ` +
           "no se actualiza con un gestor de paquetes. Actualiza la herramienta que lo incluye " +
           `con ${managerLabel(pkgManager)}, o espera a que publiquen una versión corregida.`,
      command: null,
    };
  }

  // Type no mapeado: prosa, nunca otro ecosistema.
  if (type) {
    return {
      fix: ver
        ? `Actualiza ${pkg} a la versión ${ver} con el gestor de paquetes de ${type}.`
        : `Actualiza ${pkg} a la última versión con el gestor de paquetes de ${type}.`,
      command: null,
    };
  }

  // Sin Type no se adivina: prosa.
  const verTxt = ver ? ` a la versión ${ver}` : "";
  const donde = target ? ` (detectado en ${target})` : "";
  return {
    fix: `Trivy no ha indicado a qué ecosistema pertenece ${pkg}${donde}, así que no se puede ` +
         `dar un comando seguro: el gestor correcto depende de cómo se instalara. ` +
         `Comprueba de dónde viene el paquete y actualízalo${verTxt} con su propio gestor ` +
         `(cargo para Rust, npm para Node, pip para Python, ${managerLabel(pkgManager)} para paquetes del sistema…).`,
    command: null,
  };
}

/** ¿Existe `filename` en la carpeta de `location` o en alguno de sus ancestros? */
function hasAncestorFile(location, filename) {
  if (!location) return false;
  let dir = path.dirname(String(location));
  for (let i = 0; i < 12 && dir && dir !== path.dirname(dir); i++) {
    try {
      if (fs.existsSync(path.join(dir, filename))) return true;
    } catch (_) { /* permisos: no bloquear la normalización */ }
    dir = path.dirname(dir);
  }
  return false;
}

/**
 * Convierte la salida JSON de `trivy fs` o `trivy image` a findings. Agrupa en dos capas: por
 * paquete (N CVEs → 1 finding) y por severidad (critical/high individuales, medium por target,
 * low/info en un resumen). Un escaneo de 30 imágenes puede dar 2000 CVEs y sin agrupar los
 * críticos quedan enterrados.
 */

/**
 * Pasos de resolución de un finding de imagen. La imagen es inmutable: ningún apt/dnf/apk sirve
 * aquí, se arregla con otro tag o reconstruyendo. Siempre prosa, sin comando único.
 */
function buildImageFix({ image, pkg, fixedVersion } = {}) {
  const img = image || "la imagen";
  const pkgFixed =
    pkg && fixedVersion
      ? `El paquete ${pkg} tiene corrección en la versión ${fixedVersion}. `
      : "";
  return (
    `Cambia a un tag más reciente de ${img} que ya incluya la corrección. ${pkgFixed}` +
    "Comprueba en el registro (Docker Hub / GHCR) qué tag la trae.\n" +
    "Si ningún tag la corrige aún, cambia a una imagen base más pequeña y mantenida " +
    "(p.ej. alpine o distroless en vez de debian): menos paquetes = menos superficie de ataque.\n" +
    "Si el mantenedor aún no ha publicado corrección, no hay fix disponible: documenta " +
    "el riesgo aceptado y vigila las actualizaciones del upstream.\n" +
    "Si es una imagen propia, reconstrúyela sobre una base actualizada (FROM al día) y vuelve a escanear."
  );
}

/** CVSS de una vulnerabilidad de Trivy: V3 sobre V2 y NVD como fuente preferida. */
function extractCvss(v) {
  const c = v && v.CVSS;
  if (!c || typeof c !== "object") return null;
  const preferred = ["nvd", "redhat", "ghsa"];
  const keys = [...preferred, ...Object.keys(c).filter((k) => !preferred.includes(k))];
  for (const field of ["V3Score", "V2Score"]) {
    for (const k of keys) {
      if (c[k] && typeof c[k][field] === "number") return c[k][field];
    }
  }
  return null;
}

/** Etiqueta legible de la URL del advisory, para saber a qué fuente lleva el enlace. */
function advisoryLabelFromUrl(url) {
  try {
    const host = new URL(url).hostname.replace(/^www\./, "");
    const MAP = {
      "security-tracker.debian.org": "Debian",
      "security.alpinelinux.org": "Alpine",
      "ubuntu.com": "Ubuntu",
      "access.redhat.com": "Red Hat",
      "nvd.nist.gov": "NVD",
      "github.com": "GitHub",
      "avd.aquasec.com": "Aqua",
    };
    return MAP[host] || host;
  } catch (e) {
    return "Advisory";
  }
}

/** Advisory fiable. Trivy fija PrimaryURL a avd.aquasec.com para todo CVE y esa página da 404
 *  en los recién asignados, así que se prefiere el tracker del ecosistema del DataSource. */
function bestAdvisoryUrl(v) {
  const id = ((v && v.VulnerabilityID) || "").toUpperCase();
  const ds = (((v && v.DataSource) || {}).Name || "").toLowerCase();

  if (/^CVE-\d{4}-\d+$/.test(id)) {
    if (ds.includes("debian")) return { url: `https://security-tracker.debian.org/tracker/${id}`, label: "Debian" };
    if (ds.includes("alpine")) return { url: `https://security.alpinelinux.org/vuln/${id}`, label: "Alpine" };
    if (ds.includes("ubuntu")) return { url: `https://ubuntu.com/security/${id}`, label: "Ubuntu" };
    if (ds.includes("red hat") || ds.includes("redhat")) return { url: `https://access.redhat.com/security/cve/${id}`, label: "Red Hat" };
    const puc = (v && v.PrimaryURL) || "";
    if (puc && !/avd\.aquasec\.com/i.test(puc)) return { url: puc, label: advisoryLabelFromUrl(puc) };
    return { url: `https://nvd.nist.gov/vuln/detail/${id}`, label: "NVD" };
  }

  const pu = (v && v.PrimaryURL) || "";
  if (pu && !/avd\.aquasec\.com/i.test(pu)) return { url: pu, label: advisoryLabelFromUrl(pu) };
  const ref = ((v && v.References) || []).find((r) => /^https?:\/\//i.test(r));
  return ref ? { url: ref, label: advisoryLabelFromUrl(ref) } : { url: null, label: null };
}

/** Añade al finding los metadatos que Trivy ya trae y createFinding no conserva. */
function attachImageMeta(f, meta) {
  if (meta.pkg)              f.pkg = String(meta.pkg);
  if (meta.installedVersion) f.installedVersion = String(meta.installedVersion);
  if (meta.fixedVersion)     f.fixedVersion = String(meta.fixedVersion);
  if (meta.cveId)            f.cveId = String(meta.cveId);
  if (typeof meta.cveCount === "number") f.cveCount = meta.cveCount;
  if (typeof meta.cvss === "number")     f.cvss = meta.cvss;
  if (meta.primaryUrl)       f.primaryUrl = String(meta.primaryUrl);
  if (meta.advisoryLabel)    f.advisoryLabel = String(meta.advisoryLabel);
  return f;
}

/** Findings a partir del JSON de Trivy. */
/**
 * Procedencia del paquete, con dos señales explícitas del JSON y ninguna heurística de rutas:
 * PkgPath presente ⇒ hay un fichero en disco, y Class === 'os-pkgs' ⇒ el paquete sale de la base
 * de datos del gestor, luego está instalado por definición. La segunda no sobra: en os-pkgs Trivy
 * no rellena PkgPath (0 de 169 en debian:12), y con solo la primera regla openssl salía
 * 'declared', fuera del riesgo global y con un fix que le decía al usuario que no tenía nada
 * instalado. Un chroot o un debootstrap bajo $HOME también da os-pkgs: se acepta, avisa de más.
 */
function originOf(result, v) {
  const fromOsDb = result && result.Class === "os-pkgs";
  return fromOsDb || v.PkgPath ? "installed" : "declared";
}

function fromTrivyJson(raw, idPrefix, category = "vulnerability", source = "trivy", opts = {}) {
  const platform   = opts.platform || process.platform;
  const pkgManager = opts.pkgManager || null;
  if (!raw || raw.skipped) return [];
  const context = idPrefix.startsWith("IMG") ? "image" : "host";

  const results = raw.Results || [];

  const seen = new Set();
  const allVulns = [];   // { v, target, sev }

  for (const result of results) {
    const target = result.Target || "unknown";
    // Ecosistema del Result; se propaga hasta getTrivyFixCommand para elegir el gestor.
    const type = result.Type || "";
    // Etiqueta de imagen del Result: agrupa los hallazgos cuando se escanean varias.
    const image = result.__image || "";

    // Dev dependencies de Homebrew Cellar: bajar un nivel de severidad
    const isDevDependency = (result.Target || "").includes("/Cellar/") &&
      ["phpmyadmin", "protobuf", "playwright", "python"].some((t) =>
        (result.Target || "").toLowerCase().includes(t));

    for (const v of (result.Vulnerabilities || [])) {
      // Clave: imagen + procedencia + CVE + paquete + versión. Sin la procedencia, el hallazgo
      // instalado se descartaba por haber visto antes el mismo CVE declarado en un lockfile.
      const originKey = originOf(result, v);
      const key = `${image}|${originKey}|${v.VulnerabilityID}:${v.PkgName}:${v.InstalledVersion}`;
      if (seen.has(key)) continue;
      seen.add(key);

      let sev = fromTrivy(v.Severity);
      if (isDevDependency && sev === "high")     sev = "medium";
      if (isDevDependency && sev === "critical") sev = "high";

      const origin   = originOf(result, v);
      const location = v.PkgPath || target || null;

      allVulns.push({ v, target, sev, image, type, origin, location });
    }
  }

  // Un paquete con N CVEs da un finding, con la severidad más alta del grupo.
  const pkgGroups = new Map();
  const medByTarget    = new Map();   // image|target → { image, target, vulns[] }
  const lowInfoByImage = new Map();   // image → { image, count, targets:Set }

  for (const item of allVulns) {
    const { v, target, sev, image, type, origin, location } = item;
    if (sev === "critical" || sev === "high") {
      // El mismo paquete en dos imágenes, o declarado e instalado, son grupos distintos: una sola
      // remediación no valdría para ambos.
      const pkgKey = `${image}|${origin}|${v.PkgName}:${v.InstalledVersion || ""}`;
      if (!pkgGroups.has(pkgKey)) {
        pkgGroups.set(pkgKey, { items: [], maxSev: sev, target, image, type, origin, location });
      }
      const grp = pkgGroups.get(pkgKey);
      grp.items.push(item);
      grp.maxSev = max(grp.maxSev, sev);
    } else if (sev === "medium") {
      // Agrupar medium por imagen (fallback al target si no hay imagen)
      const medKey = image || target;
      if (!medByTarget.has(medKey)) medByTarget.set(medKey, { image, target, vulns: [], origins: new Set() });
      medByTarget.get(medKey).vulns.push(v);
      medByTarget.get(medKey).origins.add(origin);
    } else {
      // low/info agrupados por imagen (fallback global cuando no hay imagen)
      const k = image || "";
      if (!lowInfoByImage.has(k)) {
        lowInfoByImage.set(k, { image, count: 0, targets: new Set(), origins: new Set() });
      }
      const e = lowInfoByImage.get(k);
      e.count++;
      e.targets.add(target);
      e.origins.add(origin);
    }
  }

  // Un resumen que mezcla declarados e instalados no tiene procedencia única: se etiqueta solo
  // si todos los ítems coinciden.
  const uniformOrigin = (origins) => (origins && origins.size === 1 ? [...origins][0] : null);

  const findings = [];
  let n = 1;

  for (const [, grp] of pkgGroups) {
    const { items, maxSev, target, image, type, origin, location } = grp;
    const first = items[0].v;
    const pkgLabel = `${first.PkgName}@${first.InstalledVersion || "?"}`;

    const fixedVersion = items.map((i) => i.v.FixedVersion).find(Boolean) || null;

    let title, evidence;

    if (items.length === 1) {
      title    = `${first.VulnerabilityID}: ${pkgLabel}`;
      evidence = `${first.VulnerabilityID} en ${first.PkgName} ${first.InstalledVersion || ""}. ${(first.Description || "").slice(0, 200)}`;
    } else {
      title = `${items.length} vulnerabilidades en ${pkgLabel}`;
      const MAX_IDS = 5;
      const ids     = items.slice(0, MAX_IDS).map((i) => i.v.VulnerabilityID);
      const rest    = items.length - MAX_IDS;
      const idList  = rest > 0 ? `${ids.join(", ")} y ${rest} más` : ids.join(", ");
      const desc    = (first.Description || "").slice(0, 150);
      evidence = desc ? `${idList}. ${desc}` : idList;
    }

    // Imagen inmutable: el fix es de imagen/tag. En host, comando real de actualización, y lo fija
    // quien lo genera, no un regex a posteriori.
    let fixText, fixCommand;
    if (context === "image") {
      fixText = buildImageFix({ image: image || target, pkg: first.PkgName, fixedVersion });
      fixCommand = null;   // una imagen nunca se arregla con un comando único
    } else if (origin === "declared") {
      // Anotación en un lockfile: no hay software que actualizar, exista o no FixedVersion.
      const r = getTrivyFixCommand(target, first.PkgName, fixedVersion, platform, type, pkgManager, { origin, location });
      fixText = r.fix;
      fixCommand = r.command;
    } else if (fixedVersion) {
      const r = getTrivyFixCommand(target, first.PkgName, fixedVersion, platform, type, pkgManager, { origin, location });
      fixText = r.fix;
      fixCommand = r.command;
    } else {
      fixText = `No hay versión corregida disponible aún para ${first.PkgName}. Monitorizar actualizaciones del paquete.`;
      fixCommand = null;
    }

    const f = createFinding({
      id:       `${idPrefix}-${String(n++).padStart(3, "0")}`,
      title,
      severity: maxSev,
      evidence,
      fix:      fixText,
      // command explícito: null ⇒ sin botón; string ⇒ botón «Copiar».
      command:  fixCommand,
      category,
      source,
      image: image || null,
      origin,
      location,
    });
    {
      const scores = items.map((i) => extractCvss(i.v)).filter((x) => typeof x === "number");
      const adv = bestAdvisoryUrl(first);
      attachImageMeta(f, {
        pkg:              first.PkgName,
        installedVersion: first.InstalledVersion,
        fixedVersion,
        cveId:            items.length === 1 ? first.VulnerabilityID : null,
        cveCount:         items.length,
        cvss:             scores.length ? Math.max(...scores) : null,
        primaryUrl:       adv.url,
        advisoryLabel:    adv.label,
      });
    }
    findings.push(f);
  }

  let medIdx = 1;
  for (const [, grp] of medByTarget) {
    const { image, target, vulns, origins } = grp;
    const label = image || target;
    const MAX_IDS = 5;
    const shownIds = vulns.slice(0, MAX_IDS).map((v) => v.VulnerabilityID);
    const remaining = vulns.length - MAX_IDS;
    const evidence = remaining > 0
      ? `${shownIds.join(", ")} y ${remaining} más`
      : shownIds.join(", ");

    const fMed = createFinding({
      id:       `${idPrefix}-MED-${String(medIdx++).padStart(3, "0")}`,
      title:    `${vulns.length} vulnerabilidades medium en ${label}`,
      severity: "medium",
      evidence,
      fix:      context === "image"
        ? buildImageFix({ image: label })
        : `Actualizar los paquetes afectados en ${label}`,
      // Resumen agrupado: prosa, sin botón.
      command:  null,
      category,
      source,
      image: image || null,
      // Solo si todos los paquetes del resumen comparten procedencia.
      origin: uniformOrigin(origins),
    });
    {
      const scores = vulns.map(extractCvss).filter((x) => typeof x === "number");
      attachImageMeta(fMed, { cveCount: vulns.length, cvss: scores.length ? Math.max(...scores) : null });
    }
    findings.push(fMed);
  }

  const multiLow = lowInfoByImage.size > 1;
  let lowIdx = 1;
  for (const [, grp] of lowInfoByImage) {
    const { image, count, targets, origins } = grp;
    const targetCount = targets.size;
    const where = image || `${targetCount} target${targetCount !== 1 ? "s" : ""}`;
    const fLow = createFinding({
      id:       multiLow ? `${idPrefix}-LOW-${String(lowIdx++).padStart(3, "0")}` : `${idPrefix}-LOW`,
      title:    `${count} vulnerabilidades low/info en ${where}`,
      severity: "low",
      evidence: image
        ? `${count} vulnerabilidades de severidad baja en ${image}`
        : `${count} vulnerabilidades de severidad baja distribuidas en ${targetCount} target${targetCount !== 1 ? "s" : ""}`,
      fix:      context === "image"
        ? buildImageFix({ image: where })
        : "Revisar y actualizar paquetes cuando sea posible",
      // Resumen low/info: prosa, sin botón.
      command:  null,
      category,
      source,
      image:    image || null,
      // Procedencia solo si es uniforme.
      origin: uniformOrigin(origins),
    });
    attachImageMeta(fLow, { cveCount: count });
    findings.push(fLow);
  }

  return findings;
}

/** Findings ya formateados por los módulos nativos. */
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

/** Pasos de resolución de un puerto abierto. El fix estático propone una sola acción fiable,
 *  parar el servicio: el cortafuegos filtra pero no cierra, y ese matiz lo aporta el LLM. */
function buildPortFix(p, platform, targetIsLocal, target) {
  // Target remoto: no se adjunta la guía por puerto de getFixForPort, redactada para el equipo
  // local. "systemctl disable nginx" no aplica a un router ni a una cámara.
  if (targetIsLocal === false) {
    const where = target ? `el dispositivo remoto ${target}` : "OTRO dispositivo de tu red";
    return (
      `Este puerto está abierto en ${where}, no en este equipo. Desde aquí no se puede cerrar: ` +
      "hay que acceder a ese dispositivo (su panel de administración o su configuración) y " +
      "detener allí el servicio que escucha, o restringir desde qué equipos se puede acceder.\n" +
      "LoCoAudit no puede generar comandos válidos para un equipo distinto del que ejecuta la " +
      "auditoría: su sistema operativo no se ha auditado."
    );
  }

  const sysSvc =
    getSystemService(p.process, platform) ||
    (p.service ? getSystemService(p.service, platform) : null);

  // Bind en loopback: no está expuesto, no se propone cerrar nada.
  if (p.localOnly === true) {
    const what = sysSvc ? `${sysSvc.label}. ${sysSvc.what}\n` : "";
    return (
      what +
      `Este servicio escucha solo en ${p.bind || "localhost"}: NO está expuesto a la red. ` +
      "Solo los programas de este mismo equipo pueden conectarse a él; desde otro equipo de tu red " +
      "no es accesible.\n" +
      "No hay nada que cerrar: se informa del puerto para que sepas qué está escuchando, no porque " +
      "sea un riesgo de exposición."
    );
  }

  // Servicio del propio SO: la vía soportada, no matarlo a lo bruto.
  if (sysSvc) {
    return (
      `${sysSvc.label}. ${sysSvc.what}\n` +
      "Si no lo necesitas, desactívalo por la vía que ofrece el propio sistema:\n" +
      `${sysSvc.soft}\n` +
      `Aviso: ${sysSvc.warn}`
    );
  }

  // Servicio de terceros o desconocido: parada condicional.
  const identify = platform === "win32"
    ? `netstat -ano | findstr :${p.port}`
    : `sudo lsof -i :${p.port}`;

  // Detener y limitar son cosas distintas: un bind-address 127.0.0.1 bajo "detén el servicio"
  // haría creer que el puerto se cierra. Orden: proceso real > demonio (SSH→sshd) > catálogo.
  const known = [p.process, p.service ? `${p.service}d` : null, p.service]
    .find((c) => c && getFixKind(c)) || null;
  const knownFix  = known ? getFixForProcess(known, platform) : null;
  const knownKind = known ? getFixKind(known) : null;
  const stopCmd   = knownKind === "stop" ? knownFix : null;
  const limitFix  = knownKind === "limit" ? knownFix : null;

  const genericStop = platform === "win32"
    ? "2) Con el PID que devuelve el comando anterior, identifica el servicio y deshabilítalo en " +
      "services.msc (Detener + Tipo de inicio: Deshabilitado). Si es una aplicación que instalaste " +
      "tú, ciérrala o desinstálala."
    : platform === "darwin"
      ? "2) Con el nombre del proceso (columna COMMAND) decide: si es una app que instalaste tú, " +
        "ciérrala o desinstálala; si es un servicio de compartición de macOS, desactívalo en " +
        "Ajustes del Sistema → General → Compartido. No uses kill: launchd relanza los servicios " +
        "y el puerto volvería a abrirse."
      : "2) Con el nombre del servicio (columna COMMAND), detenlo y deshabilítalo junto a su socket:\n" +
        "sudo systemctl disable --now <servicio>.service <servicio>.socket";

  const lines = [
    "Si NO necesitas este servicio, así lo detienes (y el puerto se cierra):",
    `1) Confirma qué proceso escucha en el puerto: ${identify}`,
    stopCmd ? `2) Detén y deshabilita el servicio:\n${stopCmd}` : genericStop,
  ];

  // Sin parar el .socket, systemd relanza el servicio con la siguiente conexión.
  if (platform === "linux" && lines.join("\n").includes(".socket")) {
    lines.push(
      "El .socket es imprescindible: con activación por socket, parar solo el .service no cierra " +
      "el puerto (systemd relanza el servicio en la siguiente conexión). Si systemd avisa de que " +
      "esa unidad .socket no existe, repite el comando solo con el .service."
    );
  }

  // La nota por puerto solo si no hubo fix por proceso: si no, se repite y choca con el epígrafe
  // de "si SÍ lo necesitas".
  if (!knownFix && p.fix) lines.push(`Sobre este servicio: ${p.fix}`);

  const keepAdvice = limitFix ||
    "configúralo para escuchar en 127.0.0.1 en vez de en todas las interfaces (*/0.0.0.0): " +
    "dejará de estar expuesto a la red sin perder el uso local.";
  lines.push(`Si SÍ lo necesitas: ${keepAdvice}`);

  return lines.join("\n");
}

/** Estado del cortafuegos como texto para la evidencia, no para el fix: el LLM necesita el dato
 *  real para no asumir ufw. */
function firewallEvidence(fw, isLocal) {
  if (!isLocal) return "";
  if (!fw || !fw.name) return " Cortafuegos del sistema: no se detectó ninguno instalado.";
  return ` Cortafuegos del sistema: ${fw.name} (${fw.active ? "activo" : "INACTIVO"}).`;
}

/** Ajustes según el bind detectado: loopback baja la severidad y lo dice en título y evidencia. */
function bindAdjustments(p) {
  if (p.localOnly === true) {
    return {
      severity: (p.severity === "info") ? "info" : "low",
      titleSuffix: " — solo accesible desde este equipo",
      evidenceExtra: ` Escucha solo en localhost (${p.bind}): no expuesto a la red.`,
    };
  }
  if (p.localOnly === false) {
    return {
      severity: null, // mantener la del catálogo
      titleSuffix: "",
      evidenceExtra: ` Escucha en ${p.bind}: accesible desde la red.`,
    };
  }
  return { severity: null, titleSuffix: "", evidenceExtra: "" };
}

/** Findings a partir de los puertos abiertos de nmap-wrapper. */
function fromNmap(raw, opts = {}) {
  if (!Array.isArray(raw)) return [];
  const isLocal = opts.targetIsLocal !== undefined ? opts.targetIsLocal : true;
  return raw
    .filter((p) => p.state === "open")
    .map((p, i) => {
      const service = p.service || "unknown";
      const isUnknownService = service === "unknown" || service === "tcpwrapped";
      const displayService = isUnknownService && p.process ? p.process : service;

      // Con service desconocido y proceso detectado, el proceso es el servicio.
      const title = p.process && !isUnknownService
        ? `Puerto abierto: ${p.port}/tcp (${displayService}) — usado por ${p.process}`
        : `Puerto abierto: ${p.port}/tcp (${displayService})`;

      let evidence = `Puerto ${p.port}/tcp abierto. Servicio: ${service}.`;
      if (p.version) evidence += ` Versión: ${p.version}.`;
      if (p.pid != null && p.process) evidence += ` Proceso: ${p.process} (PID ${p.pid}).`;
      if (p.extra) evidence += ` ${p.extra}`;

      const adj = bindAdjustments(p);
      evidence += adj.evidenceExtra;

      // El cortafuegos va a la evidencia, no al fix: es el dato con el que el LLM razona sin inventar.
      evidence += firewallEvidence(opts.firewall, isLocal);

      // Sin proceso, probar por nombre de servicio antes de caer a la guía genérica.
      const pForFix = (!p.process && p.service && getFixForProcess(p.service, process.platform))
        ? { ...p, process: p.service }
        : p;
      const fix = buildPortFix(pForFix, process.platform, isLocal, opts.target);

      // target e isLocalTarget viajan como campos, no dentro del texto del fix: el chat necesita el
      // dato estructurado para no proponer comandos de este equipo cuando el puerto está en otro.
      return createFinding({
        id:       `NET-PORT-${counter(i)}`,
        title:    title + adj.titleSuffix,
        severity: adj.severity || p.severity || "info",
        evidence,
        fix,
        category: "network",
        source:   "nmap",
        target:        opts.target || null,
        isLocalTarget: opts.targetIsLocal !== undefined ? opts.targetIsLocal : null,
      });
    });
}

/** Normaliza el raw de audit-host: cpuMemory, disk, swInventory, lynis y trivy. */
/** Sella el nodo de procedencia en los tres puntos de entrada, no en cada createFinding: tres
 *  líneas en vez de cuarenta. Respeta un scope que ya venga puesto. */
function sealScope(findings, scope) {
  for (const f of findings) if (f && !f.scope) f.scope = scope;
  return findings;
}

function normalizeHost(raw, opts = {}) {
  // opts puede ser string (legacy: source) u objeto { platform, pkgManager, source }
  const source = typeof opts === "string" ? opts : (opts.source || "native");
  const platform = typeof opts === "object" ? (opts.platform || process.platform) : process.platform;
  // Gestor real del equipo, detectado con pkg-manager.js. Ningún generador de fix lo asume.
  const pkgManager = typeof opts === "object" ? (opts.pkgManager || null) : null;

  // Compatibilidad: si raw tiene la forma del objeto compuesto de audit-host.js
  if (raw && typeof raw === "object" && !Array.isArray(raw)) {
    const findings = [];
    if (raw.cpuMemory) findings.push(...fromCpuMemory(raw.cpuMemory, platform));
    if (raw.disk) findings.push(...fromDisk(raw.disk));
    if (raw.swInventory) findings.push(...fromSwInventory(raw.swInventory, platform, pkgManager));
    if (raw.lynis) findings.push(...fromLynisRaw(raw.lynis, platform, pkgManager));
    if (raw.trivy) findings.push(...fromTrivyJson(raw.trivy, "HOST-CVE", "vulnerability", "trivy", { platform, pkgManager }));
    if (raw.securityEvents) findings.push(...fromSecurityEvents(raw.securityEvents, platform));
    return sealScope(findings, "host");
  }

  // Fallback: source explícito (para tests unitarios)
  if (source === "lynis") return sealScope(fromLynisRaw(raw, platform, pkgManager), "host");
  if (source === "trivy") {
    return sealScope(fromTrivyJson(raw, "HOST-CVE", "vulnerability", "trivy", { platform, pkgManager }), "host");
  }
  return sealScope(fromNative(Array.isArray(raw) ? raw : [], "native"), "host");
}

/** Findings de los puertos de nmap-wrapper + service-detect; array vacío ⇒ un finding info. */
function fromPortScanner(ports, opts = {}) {
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

  const isLocal = opts.targetIsLocal !== undefined ? opts.targetIsLocal : true;
  return ports.map((p, i) => {
    const idx = String(i + 1).padStart(3, "0");
    const service = p.service || "unknown";
    const isUnknownService = service === "unknown" || service === "tcpwrapped";
    const displayService = isUnknownService && p.process ? p.process : service;

    // Con service desconocido y proceso detectado, el proceso es el servicio.
    const title = p.process && !isUnknownService
      ? `Puerto abierto: ${p.port}/tcp (${displayService}) — usado por ${p.process}`
      : `Puerto abierto: ${p.port}/tcp (${displayService})`;

    let evidence = `Puerto ${p.port}/tcp abierto. Servicio: ${displayService}.`;
    if (p.pid != null && p.process) {
      evidence += ` Proceso: ${p.process} (PID ${p.pid}).`;
    }
    if (p.extra) {
      evidence += ` ${p.extra}`;
    }

    const adj = bindAdjustments(p);
    evidence += adj.evidenceExtra;

    // El cortafuegos va a la evidencia, no al fix estático.
    evidence += firewallEvidence(opts.firewall, isLocal);

    const fix = buildPortFix(p, process.platform, isLocal, opts.target);

    return createFinding({
      id:       `NET-PORT-${idx}`,
      title:    title + adj.titleSuffix,
      severity: adj.severity || p.severity || "low",
      evidence,
      fix,
      category: "network",
      source:   "native",
    });
  });
}

/** Normaliza el raw de audit-network. `firewall` va a la evidencia, no al fix; `target` y
 *  `targetIsLocal` se copian al finding para que el chat pueda nombrarlos. */
function normalizeNetwork(raw, source = "native", opts = {}) {
  if (source === "nmap") return sealScope(fromNmap(raw, opts), "network");
  return sealScope(fromPortScanner(Array.isArray(raw) ? raw : [], opts), "network");
}

/** Normaliza el raw de audit-image. */
function normalizeImage(raw, source = "docker") {
  if (source === "trivy") return sealScope(fromTrivyJson(raw, "IMG-CVE", "vulnerability", "trivy"), "image");
  return sealScope(fromNative(Array.isArray(raw) ? raw : [], source), "image");
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
  buildPortFix,
  // Expuestos para test-command-coverage.js, que recorre estas tablas reales.
  getTrivyFixCommand,
  isSystemPath,
  SYSTEM_PREFIXES,
  TRIVY_LANG_CMD,
  TRIVY_LANG_MANUAL,
  TRIVY_OS_TYPES,
};
