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

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { createFinding } = require("./finding-schema");
const { fromTrivy, max, MEMORY_THRESHOLDS, lynisGroup, lynisSeverity, SECURITY_EVENT_RULES } = require("./severity-map");
const { getFixForProcess, getFixKind, getSystemService, DANGEROUS_SERVICES } = require("./process-fix");
const { updateAllCmd, upgradeCmd, managerLabel, managerForTrivyType } = require("./pkg-manager");

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

// El hardening index de Lynis ya NO produce finding ni severidad.
//
// Era la única cifra del sistema que se convertía en hallazgo sin corresponder
// a ningún defecto concreto: un índice de 29 metía un "high" en el riesgo
// global que el usuario no podía arreglar, porque no señalaba nada que hacer —
// lo que hay que hacer ya está en los avisos y sugerencias, cada uno con su
// severidad. Ahora es una MÉTRICA de cabecera y viaja en
// msg.payload.scanMeta.lynis, que es lo que lee el gauge del dashboard.

// ── Normalizadores específicos por módulo ───────────────────────────────────

/**
 * Genera findings a partir del raw de cpu-memory.js.
 * @param {{ cpu: Object, memory: Object, platform: string }} raw
 * @param {string} [platform]  Sobrescribe raw.platform si se pasa explícitamente.
 * @returns {Finding[]}
 */
/**
 * Cómo inspeccionar procesos según el SO real.
 * `top`/`htop` no existen en Windows; el Administrador de tareas no existe en Unix.
 * @param {string} platform
 * @returns {string}
 */
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
        // Herramienta del SO real: top/htop no existen en Windows.
        fix: cpuSev !== "info" ? cpuInspectFix(plat) : null,
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
    // disk-storage.js entrega una entrada por SISTEMA DE FICHEROS. Cuando ese
    // filesystem se ve por varios montajes (subvolúmenes btrfs, datasets ZFS,
    // bind mounts) los demás se nombran en la evidencia: si no, un disco al 90 %
    // parecía afectar solo a "/" cuando en realidad /home y /var están dentro.
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

/**
 * Genera un finding informativo a partir del inventario de software.
 * No aplica severidad por ahora (se delega a Trivy para CVEs).
 * @param {Array<{name, version, source}>} pkgs
 * @returns {Finding[]}
 */
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

  // Detectar servicios peligrosos o innecesarios en el inventario
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

/**
 * Etiqueta en español del grupo de control de Lynis (prefijo del ID).
 *
 * Es la MISMA taxonomía que usa getLynisFixText() para elegir el paso de
 * resolución y que usa LYNIS_GROUP_TIER (lib/severity-map.js) para la
 * severidad: un solo vocabulario decide categoría, gravedad y remedio.
 *
 * Viaja en el finding como `subcategory` y el dashboard la pinta en la etiqueta
 * de cada tarjeta. Sin esto, el prefijo no llegaba al payload: todos los
 * hallazgos de Lynis caían en category "system" y el usuario veía treinta
 * tarjetas seguidas sin ningún criterio visible de agrupación.
 */
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

/**
 * Vocabulario CERRADO del campo 4 del .dat.
 *
 * El campo NO tiene una gramática garantizada. Medido sobre los dos fixtures
 * reales (macOS 1/18 relleno, CachyOS 4/32), aparece de tres formas:
 *
 *   'text:reboot'                                   ← convención <prefijo>:<token>
 *   'text:Use chmod to change file permissions'     ← convención, pero prosa detrás
 *   'Install a tool like rkhunter, chkrootkit…'     ← prosa suelta, SIN prefijo
 *   'Change sysctl value or disable test (skip-test=KRNL-6000:<sysctl-key>)'
 *                                                   ← prosa con dos puntos dentro
 *
 * O sea: el prefijo es una convención frecuente, no un formato. Solo el token
 * exacto tras un prefijo conocido se interpreta; todo lo demás se descarta.
 *
 * Por eso se mapean tokens EXACTOS y nada más: volcar la prosa en el paso de
 * resolución produciría instrucciones en inglés y sin contexto de plataforma,
 * justo lo que getLynisFixText() existe para evitar. Se amplía cuando aparezca
 * un token nuevo en un fixture, no por anticipado.
 */
const LYNIS_ACTION_TOKENS = {
  reboot: "reboot",
};

/**
 * Interpreta el campo 4 (tipo de solución).
 *
 * @param {string|null} solution
 * @returns {{ actionType?: string, primaryUrl?: string }}
 */
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
  return {};   // prosa libre → se ignora; manda getLynisFixText()
}

/**
 * Extrae una orden ejecutable del campo 3, si la hay.
 *
 * ── Por qué este patrón NO se amplía ─────────────────────────────────────────
 *
 * Solo reconoce la forma canónica con la que Lynis escribe una orden:
 *   Run '/usr/bin/systemd-analyze security SERVICE'    (BOOT-5264)
 *
 * Es deliberadamente estrecho, y es lo contrario de las heurísticas de ruta que
 * se quitaron del proyecto. El campo 3 contiene sobre todo datos que NO son
 * comandos —'/home', 'See screen output or log file'— y cualquier regla más
 * laxa (empieza por '/', contiene espacios, parece un binario) los convertiría
 * en botones «Copiar comando» que pegan basura inejecutable en la terminal del
 * usuario. Un comando mal detectado es peor que un comando no detectado: el
 * detalle sigue viéndose como evidencia en la tarjeta de todos modos.
 *
 * @param {string|null} detail
 * @returns {string|null}
 */
function commandFromDetail(detail) {
  const m = /^Run\s+'([^']+)'/.exec((detail || "").trim());
  return m ? m[1] : null;
}

/**
 * Clave estable de un hallazgo de Lynis: ID + descripción + detalle.
 *
 * El ID solo NO identifica un hallazgo. En ficheros reales AUTH-9286 aparece
 * dos veces con descripciones distintas (edad mínima y máxima de contraseña),
 * NETW-3200 cuatro veces, y FILE-6310 tres veces con la MISMA descripción,
 * distinguibles únicamente por el campo 3 (/home, /tmp, /var). Con el ID como
 * clave, todos ellos colapsaban en uno.
 *
 * Limitación conocida: una descripción con un valor incrustado ("Nameserver
 * 10.0.0.1 does not respond") cambia de hash si cambia ese valor. Es correcto
 * —es otro hallazgo—, pero rompería la continuidad entre ejecuciones si algún
 * día se guarda histórico; en ese momento habría que hashear solo ID + detalle.
 *
 * @param {{id: string, description: string, detail: string|null}} entry
 * @returns {string}  ID de finding: HOST-LYN-<CONTROL>-<hash>
 */
function lynisFindingId(entry) {
  const key = [entry.id, entry.description, entry.detail || ""].join("\u0000");
  const hash = crypto.createHash("sha1").update(key).digest("hex").slice(0, 6);
  return `HOST-LYN-${entry.id}-${hash}`;
}

/**
 * Texto de resolución de un control de Lynis, POR PLATAFORMA.
 *
 * Se aplica a TODOS los hallazgos de Lynis —avisos y sugerencias—, no solo a un
 * puñado de avisos como antes: era la única fuente de pasos adaptados al SO del
 * usuario y las sugerencias se quedaban sin ella, remitiendo a ejecutar
 * 'lynis show suggestions' en una terminal.
 *
 * Antes era una tabla de textos fijos con instrucciones de macOS ("Ajustes del
 * Sistema → …") que se emitían también en Linux, que es donde Lynis se ejecuta
 * casi siempre. Ahora cada prefijo define el paso de cada SO; si un aviso no
 * aplica a una plataforma se omite el paso concreto y se deja la guía genérica,
 * nunca los pasos de otro SO.
 *
 * @param {string} id          ID del aviso de Lynis (p.ej. "NETW-2704")
 * @param {string} platform    'darwin' | 'linux' | 'win32'
 * @param {string|null} [pkgManager]  Gestor real detectado (para PKGS)
 * @returns {{ fix: string, command: string|null }}
 *          `command` solo se rellena cuando el paso ES un comando puro y copiable
 *          (hoy: PKGS con gestor detectado). El resto es prosa → command null.
 */
// Excepciones POR CONTROL, consultadas antes que el prefijo.
//
// Un prefijo agrupa controles que no siempre comparten remedio: NETW cubre
// tanto los nameservers (2704, 2705) como los módulos de protocolo del kernel
// (3200), y el paso de DNS es directamente falso para los segundos. Mientras el
// texto se aplicaba solo a un puñado de avisos esto no se veía; ahora que cubre
// también las sugerencias, sí.
//
// Esta tabla es para los controles cuyo texto de prefijo sería ERRÓNEO, no para
// los que quedan genéricos: el genérico es correcto aunque sea poco concreto, y
// llenar esto de matices lo convertiría en el mapa por ID que precisamente no
// escala entre plataformas.
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

  // PKGS: el gestor real detectado da un comando ejecutable; sin él, prosa.
  // El comando va en 2ª línea y se expone en `command` para que el dashboard lo
  // ofrezca con botón «Copiar» — antes se perdía porque el extractor solo miraba
  // la primera línea (que aquí es prosa).
  if (prefix === "PKGS") {
    const cmd = updateAllCmd(pkgManager);
    return cmd
      ? { fix: `Actualizar los paquetes del sistema con ${managerLabel(pkgManager)}:\n${cmd}`, command: cmd }
      : { fix: "Actualizar los paquetes del sistema con el gestor de paquetes de tu distribución.", command: null };
  }

  const text = entry[plat] || entry.all;
  // Sin paso para esta plataforma → guía genérica, NUNCA los pasos de otro SO.
  return {
    fix: text || `Revisar la configuración del sistema relacionada con ${id} en tu sistema operativo.`,
    command: null,
  };
}

/**
 * Empareja avisos con sugerencias del mismo control.
 *
 * Un warning y una suggestion con el mismo ID y el mismo detalle NO son un
 * duplicado: son el problema y su remedio. Medido en un .dat real:
 *
 *   warning[]   =NETW-2704|Nameserver 10.0.0.1 does not respond|-|-|
 *   suggestion[]=NETW-2704|Check connection to this nameserver and make sure…|-|-|
 *
 * Encajan exactamente en el contrato de finding que ya existe: el aviso es
 * `evidence` (qué pasa) y la sugerencia es `fix` (qué hacer). Emitirlos por
 * separado daba dos tarjetas —una diciendo que el DNS falla y otra, más abajo,
 * diciendo que revises el DNS— y obligaba a meter el tipo en la clave para que
 * no colapsaran entre sí.
 *
 * Emparejamiento por orden de aparición dentro de cada clave: si hay dos avisos
 * y tres sugerencias del mismo control y detalle, se emparejan dos y la
 * sugerencia sobrante sale suelta. Ningún dato se descarta.
 *
 * @param {Array} warnings
 * @param {Array} suggestions
 * @returns {Array<{ type: 'warning'|'suggestion', entry: Object, remedy: Object|null }>}
 */
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

/**
 * Genera findings a partir del resultado de lynis.js.
 *
 * UN FINDING POR ENTRADA del .dat, no agregados. Antes se emitían como mucho
 * cinco avisos individuales y TODAS las sugerencias colapsaban en una sola
 * tarjeta que listaba diez códigos y remitía a ejecutar 'lynis show
 * suggestions' en una terminal: el contenido existía en payload.raw.lynis y se
 * perdía aquí. Para un usuario no experto eso era información nula, y para uno
 * experto era peor —le decía que usara Lynis en vez de LoCoAudit.
 *
 * El volumen que eso evitaba se controla ahora por SEVERIDAD, no escondiendo
 * hallazgos: las sugerencias son "info" salvo en el tramo de exposición directa
 * (ver LYNIS_GROUP_TIER en lib/severity-map.js), así que multiplicar los
 * findings no multiplica el contador de "requieren tu atención".
 *
 * El hardening index ya no sale por aquí: es una métrica de cabecera y viaja en
 * msg.payload.scanMeta.lynis (ver audit-host.js).
 *
 * @param {{ warnings: Array, suggestions: Array }} raw  Salida de lynis.js
 * @param {string} [platform]
 * @param {string|null} [pkgManager]
 * @returns {Finding[]}
 */
function fromLynisRaw(raw, platform, pkgManager) {
  if (!raw || raw.skipped) return [];

  const items = pairLynisEntries(raw.warnings || [], raw.suggestions || []);
  const findings = [];

  for (const { type, entry, remedy } of items) {
    const group = lynisGroup(entry.id);
    const lynFix = getLynisFixText(entry.id, platform, pkgManager);
    const solution = parseSolutionType(entry.solution);

    // Pasos de resolución, en orden de concreción:
    //   1. qué hay que conseguir (la sugerencia, si la hay)
    //   2. cómo se hace EN ESTE SO (getLynisFixText, siempre)
    //   3. la orden exacta, si Lynis la da en el campo 3
    // El campo 4 solo interviene con un token conocido ('text:reboot'), y lo
    // hace por delante: si hace falta reiniciar, lo demás no surte efecto hasta
    // que se reinicie.
    const steps = [];
    if (solution.actionType === "reboot") {
      steps.push("Reinicia el equipo para que el cambio surta efecto.");
    }
    if (remedy && remedy.description) steps.push(remedy.description);
    // El texto por prefijo se OMITE cuando el campo 4 ya da la acción exacta.
    // Es genérico por construcción (todo el prefijo comparte una frase), y
    // pegarlo detrás de una acción concreta produce justo el defecto que dio
    // origen a este trabajo: KRNL-5830 dice "hay que reiniciar" y el paso 2
    // mandaba a editar /etc/sysctl.conf, que no reinicia nada ni lo arregla.
    if (lynFix.fix && !solution.actionType) steps.push(lynFix.fix);

    // El campo 3 gana como comando cuando ES una orden: es específico de esta
    // instancia del control, mientras que el de getLynisFixText() es genérico
    // del prefijo. Como evidencia (el caso normal) no compite con nada: va a la
    // otra columna de la tarjeta.
    const detailCmd = commandFromDetail(entry.detail);
    if (detailCmd) steps.push(detailCmd);

    const evidenceParts = [entry.description];
    if (entry.detail && !detailCmd) evidenceParts.push(entry.detail);

    findings.push(
      createFinding({
        id: lynisFindingId(entry),
        // El título es la descripción legible. El código va de metadato: antes
        // encabezaba la tarjeta ("Lynis: NETW-2704 — …") y el usuario leía
        // primero un identificador que no significa nada para él.
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
        // Lynis no puntúa sus controles: el nivel lo pone LoCoAudit y la
        // tarjeta lo dice. Ver LYNIS_GROUP_TIER en lib/severity-map.js.
        severitySource: "locoaudit",
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

/**
 * Endurecimiento de SSH para el SO real del equipo.
 *
 * Antes era una constante que enumeraba los pasos de Linux Y de macOS a la vez,
 * así que la mitad del texto siempre sobraba (y en Windows sobraba entero).
 *
 * @param {string} platform  'darwin' | 'linux' | 'win32'
 * @returns {string}
 */
function sshHardenFix(platform) {
  const common =
    "Revisar /etc/ssh/sshd_config: PermitRootLogin no, y PasswordAuthentication no si usas claves.";
  if (platform === "darwin") {
    return `${common}\n` +
      "Si no usas el acceso remoto, desactívalo en Ajustes del Sistema → General → Compartido → Sesión remota.";
  }
  if (platform === "win32") {
    return "Revisar la configuración del Servidor OpenSSH (%ProgramData%\\ssh\\sshd_config). " +
      "Si no usas el acceso remoto por SSH, detén y deshabilita el servicio OpenSSH SSH Server en services.msc.";
  }
  return `${common}\n` +
    "Para limitar los intentos repetidos, considera fail2ban.";
}

const MAX_SEC_INDIVIDUAL = 10; // logins SSH individuales antes de agregar

/**
 * Findings de accesos SSH (correctos y fallidos) a partir de `ssh`.
 *
 * Vive fuera de las ramas por plataforma porque Windows también los produce
 * desde que se lee el canal OpenSSH/Operational: los mensajes los escribe
 * OpenSSH, con el mismo formato en los tres sistemas, así que el hallazgo debe
 * ser el mismo. Duplicar este bloque en la rama win32 habría sido el enésimo
 * caso de dos fuentes para el mismo dato.
 *
 * @param {{accepted: Array, failed: Array}} ssh
 * @param {{W: number, R: Object, sshHarden: string}} ctx
 * @returns {Array} findings
 */
function sshFindings(ssh, ctx) {
  const { W, R, sshHarden } = ctx;
  const findings = [];

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
        fix: sshHarden,
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

  // Fuentes parciales (p.ej. lastb sin permisos) → un finding info agregado.
  //
  // El canal Security se excluye cuando ya tiene su propio finding
  // (HOST-SEC-WIN-PERM, con explicación y pasos): si no, la misma fuente se
  // contaba dos veces, una aquí dentro de "N fuente(s) no disponibles" y otra
  // como hallazgo propio. Se filtra aquí, en el único punto que redacta la
  // lista, en vez de dejar de registrarla en partial[]: partial sigue siendo el
  // inventario completo, y lo necesita el motivo de HOST-SEC-SKIP.
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

  // Rama Windows: eventos 4624/4625/4672 del canal Security. Los accesos SSH
  // salen del canal OpenSSH/Operational y se tratan con el MISMO código que en
  // Linux/macOS: misma estructura de datos, mismos findings.
  if (raw.platform === "win32" || raw.windows) {
    const winSsh = raw.ssh || { accepted: [], failed: [] };
    return findings.concat(
      sshFindings(winSsh, { W, R, sshHarden }),
      fromSecurityEventsWin32(raw)
    );
  }

  const ssh = raw.ssh || { accepted: [], failed: [] };
  const sudo = raw.sudo || { ok: [], failed: [] };
  const sessions = Array.isArray(raw.sessions) ? raw.sessions : [];

  findings.push(...sshFindings(ssh, { W, R, sshHarden }));


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
// La elevación de privilegios (UAC/4688) NO se audita: Get-WinEvent solo pide
// 4624/4625/4672. Se emitía un aviso "no disponible en Windows" que no
// comprobaba nada — aparecía igual con la directiva activada — y cuyo fix
// (auditpol) no cambiaba nada de lo que el módulo lee. Se retiró: un hallazgo
// que no observa lo que dice observar es peor que no tenerlo.

// Misma regla que en audit-network: CERRAR y FILTRAR son acciones distintas y no
// se presentan mezcladas. Desactivar el Escritorio remoto cierra el acceso; una
// regla de cortafuegos solo lo filtra (el servicio sigue escuchando).
const RDP_HARDEN_FIX =
  "Si no reconoces estos accesos:\n" +
  "1) CERRARLO: desactiva el Escritorio remoto en Configuración → Sistema → Escritorio remoto. " +
  "El servicio deja de escuchar y el puerto 3389 se cierra.\n" +
  "2) Si SÍ necesitas el Escritorio remoto: exige autenticación a nivel de red (NLA), usa contraseñas " +
  "robustas en todas las cuentas y limita quién puede conectarse (Usuarios de escritorio remoto).\n" +
  "Una regla del Firewall de Windows Defender sobre el 3389 solo FILTRA el tráfico de red: el servicio " +
  "sigue activo y el puerto sigue abierto, así que no sustituye al paso 1.";

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

  // Sin NINGÚN evento relevante → finding info de comprobación. Los accesos SSH
  // cuentan: si el canal Security no se pudo leer pero OpenSSH sí dio intentos
  // fallidos, decir "sin eventos relevantes" sería falso.
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

/**
 * Prefijos que pertenecen al gestor de paquetes del sistema.
 *
 * Esta comprobación de ruta SÍ es legítima, a diferencia de adivinar el
 * ecosistema por el path: no infiere de dónde viene el paquete, verifica un
 * hecho del sistema de ficheros — si vive bajo un prefijo administrado por el
 * gestor del SO, lo instaló el gestor del SO, y es él quien lo actualiza.
 *
 * Importa por algo concreto: en Arch (y en toda distro con PEP 668), un
 * `pip install --upgrade` sobre un paquete de /usr/lib falla con
 * externally-managed-environment. Sugerir un comando que sabemos que va a
 * fallar es peor que no sugerir ninguno.
 */
const SYSTEM_PREFIXES = [
  "/usr/lib", "/usr/lib64", "/usr/local/lib", "/usr/share", "/opt",
  "/Library/", "/System/Library/",            // macOS
  "C:\\Program Files", "C:\\Windows",         // Windows
];

/**
 * ¿La ruta cuelga de un prefijo administrado por el gestor de paquetes del SO?
 * @param {string|null} location  PkgPath del hallazgo
 * @returns {boolean}
 */
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
  // Faltaban: en Arch el fix salía por el fallback y proponía apt.
  "arch", "archlinux", "gentoo",
]);

/**
 * Comando para actualizar un paquete del SO en el propio host (trivy fs).
 * El gestor depende de la distribución que Trivy identificó como Type.
 * @param {string} type  Type normalizado (debian/ubuntu/alpine/…)
 * @param {string} pkg
 * @param {string|null} ver
 * @returns {string}
 */
function osHostUpdateCmd(type, pkg, ver, pkgManager) {
  // 1º el Type de Trivy (identifica la distro del target escaneado); si no se
  // reconoce, el gestor REALMENTE detectado en el equipo. Nunca se asume apt.
  const mgr = managerForTrivyType(type) || pkgManager || null;
  const cmd = upgradeCmd(mgr, pkg, ver);
  // Con gestor conocido, el fix ES el comando (copiable). Sin él, prosa sin línea.
  if (cmd) return { fix: cmd, command: cmd };
  const verTxt = ver ? ` a la versión ${ver}` : "";
  return {
    fix: `Actualiza ${pkg}${verTxt} con el gestor de paquetes de tu distribución.`,
    command: null,
  };
}

/**
 * Genera el paso de resolución de un paquete vulnerable en el HOST (trivy fs).
 *
 * REGLA: el ecosistema se toma del campo `Type` que Trivy asigna a cada Result
 * (cargo/npm/pip/gomod/debian/alpine…). Es el único dato fiable. Si Trivy NO
 * trae Type, NO se adivina: se devuelve prosa. Adivinar producía fixes cruzados
 * — un crate de Rust bajo /Cellar/ salía como `brew upgrade`, y el fallback por
 * plataforma proponía `sudo apt` en una máquina con pacman.
 *
 * Solo contexto HOST: los findings de imagen los construye buildImageFix().
 *
 * @param {string} target             Target de Trivy (ruta escaneada).
 * @param {string} pkgName            Nombre del paquete vulnerable.
 * @param {string|null} fixedVersion  Versión que corrige (null si no hay).
 * @param {string} platform           process.platform del equipo auditado.
 * @param {string} [pkgType]          Campo Type de Trivy. Sin él → prosa.
 * @param {string|null} [pkgManager]  Gestor realmente detectado (pkg-manager.js).
 * @param {{origin?: string, location?: string}} [meta]  Procedencia (PkgPath).
 * @returns {{ fix: string|null, command: string|null }}
 *          `command` es la línea copiable (o null si el fix es prosa). El ramo que
 *          genera el comando es quien decide isCommand — NO un regex a posteriori.
 */
function getTrivyFixCommand(target, pkgName, fixedVersion, platform, pkgType = "", pkgManager = null, meta = {}) {
  if (!pkgName) return { fix: null, command: null };
  const pkg = pkgName.split("@")[0];
  const ver = fixedVersion || null;
  const type = String(pkgType || "").toLowerCase();
  const location = meta.location || target || null;

  // ── Dependencia DECLARADA en un fichero de bloqueo ──────────────────────────
  // Va antes que cualquier Type: sin PkgPath, Trivy leyó una ANOTACIÓN en un
  // lockfile, no un paquete instalado. No hay nada que actualizar en el equipo,
  // así que no puede haber comando (isCommand quedará en false). Este era el
  // caso de los Pipfile.lock/poetry.lock que pacman empaqueta dentro de las
  // colecciones de Ansible: hallazgos correctos y por completo inaccionables.
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

  // ── Paquete del sistema operativo ───────────────────────────────────────────
  if (TRIVY_OS_TYPES.has(type)) {
    return ver
      ? osHostUpdateCmd(type, pkg, ver, pkgManager)   // ya devuelve { fix, command }
      : {
          fix: `No hay versión corregida disponible en el repositorio del sistema para ${pkg}. ` +
               `Vigila las actualizaciones del paquete (${type}) y aplica el parche cuando salga.`,
          command: null,
        };
  }

  // ── Gestor de lenguaje con comando fiable ───────────────────────────────────
  if (TRIVY_LANG_CMD[type]) {
    const cmd = TRIVY_LANG_CMD[type](pkg, ver);
    if (type === "cargo") {
      // La nota va en línea aparte: `command` copia SOLO el comando, así el botón
      // «Copiar comando» nunca arrastra la explicación.
      const fix = cmd + `\nSi ${ver ? "la versión " + ver : "la corrección"} es una versión mayor, ` +
             `ajusta la restricción de ${pkg} en Cargo.toml y vuelve a ejecutar cargo update.`;
      return { fix, command: cmd };
    }
    return { fix: cmd, command: cmd };
  }

  // ── Paquete de lenguaje INSTALADO en disco (python-pkg / node-pkg) ──────────
  // Trivy usa estos Type para distribuciones reales (site-packages, node_modules),
  // no para lockfiles. El gestor correcto depende de QUIÉN lo instaló, y eso lo
  // dice la ruta: bajo un prefijo del sistema manda el gestor del SO.
  if (type === "python-pkg") {
    if (isSystemPath(location)) {
      const mgr = pkgManager || null;
      const cmd = upgradeCmd(mgr, pkg, ver);
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
    // Sin proyecto alrededor (package.json en un ancestro) no hay nada que
    // `npm update` pueda resolver: sería un comando que falla en el directorio.
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

  // ── Lenguaje reconocido sin comando fiable → prosa ──────────────────────────
  if (TRIVY_LANG_MANUAL.has(type)) {
    return {
      fix: ver
        ? `Actualiza ${pkg} a la versión ${ver} en el fichero de construcción del proyecto (${type}) y reconstruye. Requiere intervención manual.`
        : `Actualiza ${pkg} a una versión sin la vulnerabilidad en el fichero de construcción del proyecto (${type}).`,
      command: null,
    };
  }

  // ── Binario Go embebido (Type "gobinary" o path de módulo) ──────────────────
  // No hay gestor que actualice el binario: se actualiza la herramienta que lo
  // incluye. Cuál sea esa herramienta depende del equipo → prosa, sin comando.
  if (type === "gobinary" ||
      /^(github\.com|google\.golang\.org|golang\.org|gopkg\.in|go\.uber\.org|k8s\.io)\//i.test(pkgName)) {
    return {
      fix: `${pkg} es un módulo Go compilado dentro de una herramienta instalada en el sistema; ` +
           "no se actualiza con un gestor de paquetes. Actualiza la herramienta que lo incluye " +
           `con ${managerLabel(pkgManager)}, o espera a que publiquen una versión corregida.`,
      command: null,
    };
  }

  // ── Type presente pero no mapeado → prosa, NUNCA otro ecosistema ────────────
  if (type) {
    return {
      fix: ver
        ? `Actualiza ${pkg} a la versión ${ver} con el gestor de paquetes de ${type}.`
        : `Actualiza ${pkg} a la última versión con el gestor de paquetes de ${type}.`,
      command: null,
    };
  }

  // ── SIN Type: no se adivina. Prosa (isCommand quedará en false). ────────────
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

/**
 * ¿Existe `filename` en la carpeta de `location` o en alguno de sus ancestros?
 * Se usa para decidir si un paquete instalado pertenece a un proyecto real.
 *
 * @param {string|null} location
 * @param {string} filename
 * @returns {boolean}
 */
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
/**
 * Pasos de resolución para un finding de IMAGEN Docker.
 *
 * Una imagen es INMUTABLE: sus paquetes NO se actualizan tras construirla, así
 * que "actualizar los paquetes" (o cualquier apt/dnf/apk) es incorrecto aquí.
 * Las soluciones reales son a nivel de imagen/tag. Coherente con las reglas de
 * auditType=image del system prompt del LLM (lib/llm-client.js buildRulesBlock):
 * tag corregido → base más pequeña/mantenida → esperar parche → rebuild propio.
 *
 * Siempre prosa (isCommand=false): no hay un comando único que lo arregle.
 *
 * @param {Object} opts
 * @param {string}  opts.image          etiqueta de la imagen (repo:tag) o label
 * @param {string} [opts.pkg]           paquete afectado (si el finding es de 1 paquete)
 * @param {string} [opts.fixedVersion]  versión con el CVE corregido, si Trivy la reporta
 * @returns {string}
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

/**
 * Extrae la puntuación CVSS de una vulnerabilidad de Trivy. Trivy agrupa los
 * scores por fuente (nvd, redhat, ghsa...); se prefiere V3 sobre V2 y NVD como
 * fuente autoritativa, con fallback a cualquier otra. Devuelve el número o null.
 * @param {Object} v  vulnerabilidad cruda de Trivy
 * @returns {number|null}
 */
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

/** Etiqueta legible de una URL de advisory a partir de su host (para que el
 *  usuario sepa a qué fuente lleva el enlace: "Debian ↗", "GitHub ↗"...). */
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

/**
 * Devuelve { url, label } del advisory FIABLE de una vulnerabilidad de Trivy.
 *
 * Trivy fija `PrimaryURL = https://avd.aquasec.com/nvd/<cve>` para TODO ID CVE,
 * y esa página (Aqua VDB) da 404 en CVEs recién asignados. NVD y cve.org también
 * hacen "soft-404" ("CVE ID Not Found") mientras el CVE está RESERVED. La fuente
 * que SÍ tiene el dato es la del ecosistema que Trivy usó (campo DataSource), así
 * que el enlace se dirige AHÍ:
 *   - DataSource Debian  → security-tracker.debian.org/tracker/<CVE>
 *   - DataSource Alpine  → security.alpinelinux.org/vuln/<CVE>
 *   - DataSource Ubuntu  → ubuntu.com/security/<CVE>
 *   - DataSource Red Hat → access.redhat.com/security/cve/<CVE>
 *   - ID no-CVE (GHSA…)  → PrimaryURL (github) salvo que sea avd; si no, References.
 *   - CVE genérico sin ecosistema conocido → NVD (best-effort).
 *   - Nada fiable → { url:null } (el dashboard muestra "no disponible", sin link roto).
 *
 * @param {Object} v  vulnerabilidad cruda de Trivy
 * @returns {{ url: string|null, label: string|null }}
 */
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

/**
 * Adjunta a un finding de VULNERABILIDAD (Trivy: host o imagen) los metadatos
 * estructurados que la tarjeta del dashboard renderiza en su "tira de metadatos"
 * (paquete, versiones, CVSS, advisory). Son datos que Trivy ya trae en el raw
 * pero que createFinding no conserva. Solo afecta a findings HOST-CVE / IMG-CVE
 * (los únicos que pasan por fromTrivyJson); los nativos y de Lynis no lo usan.
 * @param {Object} f     finding devuelto por createFinding (se muta)
 * @param {Object} meta  { pkg, installedVersion, fixedVersion, cveId, cveCount, cvss, primaryUrl }
 * @returns {Object} el mismo finding
 */
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

/**
 * @param {Object} raw         Objeto JSON parseado de Trivy.
 * @param {string} idPrefix    "HOST-CVE" | "IMG-CVE"
 * @param {string} category    "vulnerability"
 * @param {string} source      "trivy"
 * @returns {Finding[]}
 */
/**
 * Procedencia de un paquete: ¿está INSTALADO en disco, o solo DECLARADO en un
 * fichero de dependencias?
 *
 * Dos señales explícitas del JSON de Trivy, ninguna heurística de rutas:
 *
 *   1. `PkgPath` presente ⇒ hay un fichero real en disco. Cubre los paquetes de
 *      lenguaje (site-packages, node_modules, jars).
 *   2. `Class === 'os-pkgs'` ⇒ el paquete sale de la base de datos del gestor
 *      del sistema (dpkg, rpm, apk). Está instalado por definición: una base de
 *      datos de paquetes instalados no puede contener una "declaración".
 *
 * La segunda señal NO es redundante. Trivy no rellena PkgPath en os-pkgs, ni en
 * rootfs ni en imágenes. Medido con trivy 0.72.0:
 *
 *   trivy rootfs sobre un árbol Debian 12 → 117 vulnerabilidades, 0 con PkgPath
 *   trivy image debian:12                 → 169 vulnerabilidades, 0 con PkgPath
 *
 * Con solo la regla de PkgPath, openssl y zlib1g instalados por dpkg salían
 * marcados 'declared'. Consecuencias, las dos graves: quedaban fuera del riesgo
 * global (ver isActionable() en lib/severity-map.js) y el paso de resolución les
 * decía al usuario que "no es software instalado en tu equipo: no hay nada que
 * actualizar aquí". Es exactamente lo contrario de la verdad, y sobre los
 * hallazgos MÁS accionables que produce la herramienta.
 *
 * ── Limitación conocida ─────────────────────────────────────────────────────
 * Un árbol de sistema ajeno dentro del ámbito escaneado (un chroot, un
 * debootstrap, un backup o una imagen desempaquetada bajo $HOME) también emite
 * Class 'os-pkgs'. Medido: `trivy fs` sobre ese árbol da una salida idéntica a
 * `trivy rootfs`. Esos paquetes se marcarán 'installed' y elevarán el riesgo
 * global.
 *
 * Se acepta a propósito:
 *   - La afirmación no es falsa: los paquetes de un debootstrap SÍ están
 *     instalados. Lo que cambia es si llegan a ejecutarse, y eso Trivy no lo
 *     distingue — no hay campo en el JSON que lo diga.
 *   - Es un falso positivo raro y conservador (avisa de más), frente al falso
 *     negativo anterior, que era sistemático y silenciaba lo más accionable.
 *   - Distinguirlo exigiría una heurística de rutas ("¿cuelga de /home?"), que
 *     es justo lo que se eliminó del proyecto (ver docs/fixes-inventory.md, la
 *     heurística /Cellar/ → brew).
 *   - `location` conserva el Target con la ruta, así que el dashboard muestra
 *     de dónde sale el hallazgo y el usuario puede juzgarlo.
 *
 * @param {{Class?: string}} result       Result de Trivy que contiene la vuln.
 * @param {{PkgPath?: string}} v          Vulnerability.
 * @returns {'installed'|'declared'}
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
      // Deduplicar por Imagen + procedencia + VulnerabilityID + PkgName + versión.
      // Incluir la imagen evita fusionar el mismo CVE entre imágenes distintas;
      // incluir la procedencia evita descartar el hallazgo INSTALADO por haber
      // visto antes el mismo CVE DECLARADO en un lockfile (o al revés): son dos
      // hechos distintos, con remediaciones distintas.
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

  // ── Paso 2: agrupar por paquete (PkgName:InstalledVersion) ─────────────────
  // Un paquete con N CVEs genera 1 finding. La severidad del grupo es la más alta.
  // pkgGroups: Map< "PkgName:InstalledVersion" → { items: [{v,target,sev}], maxSev, target } >
  const pkgGroups = new Map();
  const medByTarget    = new Map();   // image|target → { image, target, vulns[] }
  const lowInfoByImage = new Map();   // image → { image, count, targets:Set }

  for (const item of allVulns) {
    const { v, target, sev, image, type, origin, location } = item;
    if (sev === "critical" || sev === "high") {
      // Clave por imagen + procedencia + paquete: el mismo paquete en dos
      // imágenes son grupos distintos, y declarado vs instalado también —
      // fusionarlos daría un finding con una remediación que no vale para ambos.
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

  // Un resumen que mezcla paquetes declarados e instalados NO tiene una
  // procedencia única: se etiqueta solo si TODOS sus ítems coinciden. Nunca se
  // inventa un origin promediado.
  const uniformOrigin = (origins) => (origins && origins.size === 1 ? [...origins][0] : null);

  const findings = [];
  let n = 1;

  // ── Paso 3: emitir findings critical/high agrupados por paquete ────────────
  for (const [, grp] of pkgGroups) {
    const { items, maxSev, target, image, type, origin, location } = grp;
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

    // Imagen inmutable: el fix es a nivel de imagen/tag, nunca un gestor de
    // paquetes del host. Host: comando real de actualización del paquete.
    // El generador (getTrivyFixCommand) devuelve { fix, command }: quien SABE que
    // está produciendo "poetry update X" es quien fija command, no un regex después.
    let fixText, fixCommand;
    if (context === "image") {
      fixText = buildImageFix({ image: image || target, pkg: first.PkgName, fixedVersion });
      fixCommand = null;   // una imagen nunca se arregla con un comando único
    } else if (origin === "declared") {
      // Dependencia anotada en un lockfile: no hay software que actualizar, así
      // que tampoco importa si existe FixedVersion. El generador lo explica.
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
      // command explícito: string copiable o null. createFinding deriva isCommand
      // de aquí (no adivina por regex). null ⇒ sin botón; string ⇒ botón «Copiar».
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

  // ── Paso 4: medium → 1 finding resumen por imagen (o Target) ───────────────
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
      // Resumen agrupado: prosa, nunca un comando único → sin botón «Copiar».
      command:  null,
      category,
      source,
      image: image || null,
      // Solo si TODOS los paquetes del resumen comparten procedencia.
      origin: uniformOrigin(origins),
    });
    {
      const scores = vulns.map(extractCvss).filter((x) => typeof x === "number");
      attachImageMeta(fMed, { cveCount: vulns.length, cvss: scores.length ? Math.max(...scores) : null });
    }
    findings.push(fMed);
  }

  // ── Paso 5: low e info → 1 finding resumen por imagen (global si no hay imagen) ─
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
      // Resumen agrupado low/info: prosa, nunca un comando único → sin botón.
      command:  null,
      category,
      source,
      image:    image || null,
      // Idem: procedencia solo si es uniforme en todo el resumen.
      origin: uniformOrigin(origins),
    });
    attachImageMeta(fLow, { cveCount: count });
    findings.push(fLow);
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

// ── Fixes de puerto según bind, proceso y tipo de servicio ───────────────────

/**
 * Construye los pasos de resolución de un finding de puerto abierto.
 *
 * Decisión de diseño: el fix ESTÁTICO propone UNA sola acción fiable — cerrar
 * el puerto deteniendo el servicio que escucha. El cortafuegos NO aparece aquí:
 * depende de qué cortafuegos haya instalado, de si está activo, y filtrar no es
 * cerrar. Ese matiz lo aporta el LLM, que sí razona sobre el contexto concreto
 * (reglas de auditType=network en lib/llm-client.js::buildRulesBlock).
 *
 * Casos, en orden:
 *   1. Target remoto     → el arreglo es en el otro dispositivo, no en este equipo.
 *   2. Bind en loopback  → NO expuesto a la red: no se propone cerrar nada.
 *   3. Servicio del SO   → se explica qué es y se ofrece la vía soportada por el
 *                          sistema (un ajuste), nunca matarlo a lo bruto.
 *   4. Servicio de terceros → parada del servicio, SIEMPRE condicional
 *                          ("si NO lo necesitas"), con el .socket en Linux.
 *   5. Proceso desconocido → prosa: cómo identificarlo y qué hacer según el SO.
 *
 * @param {Object} p          Puerto enriquecido { port, service, process, fix, bind, localOnly }
 * @param {string} platform   process.platform
 * @param {boolean} targetIsLocal
 * @param {string} [target]   Host/IP escaneado, para nombrarlo en el caso remoto
 * @returns {string|null}
 */
function buildPortFix(p, platform, targetIsLocal, target) {
  // ── 1. Target remoto: este equipo no puede cerrar el puerto de otro ────────
  //
  // NO se adjunta la guía por-puerto de getFixForPort() (p.fix): está redactada
  // para el equipo que ejecuta la auditoría y trae comandos del SO LOCAL
  // ("sudo systemctl disable --now nginx" para el puerto 80 de un router). Sobre
  // un dispositivo remoto esos comandos no aplican —su SO es desconocido: puede
  // ser un router, una cámara o una impresora— y contradecían al propio texto que
  // los precede. Sin comandos: la acción es entrar en ese dispositivo.
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

  // ── 2. Bind solo-loopback: NO expuesto → no se propone cerrarlo ────────────
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

  // ── 3. Servicio del propio SO: vía soportada, no matarlo a lo bruto ────────
  if (sysSvc) {
    return (
      `${sysSvc.label}. ${sysSvc.what}\n` +
      "Si no lo necesitas, desactívalo por la vía que ofrece el propio sistema:\n" +
      `${sysSvc.soft}\n` +
      `Aviso: ${sysSvc.warn}`
    );
  }

  // ── 4/5. Servicio de terceros o desconocido: parada CONDICIONAL ────────────
  const identify = platform === "win32"
    ? `netstat -ano | findstr :${p.port}`
    : `sudo lsof -i :${p.port}`;

  // El fix conocido de un proceso puede ser de dos naturalezas: DETENER el
  // servicio o LIMITAR su exposición (rebind de una base de datos). Presentar un
  // "bind-address = 127.0.0.1" bajo "detén el servicio" haría creer que el
  // puerto se cierra — y no se cierra. Cada uno va a su epígrafe.
  // Orden de búsqueda: proceso real > nombre del demonio (SSH→sshd, Telnet→telnetd,
  // que es el que escucha) > nombre del servicio del catálogo.
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

  // El .socket es la trampa clásica de systemd: sin él, el servicio se relanza
  // con la siguiente conexión y el puerto nunca llega a cerrarse.
  if (platform === "linux" && lines.join("\n").includes(".socket")) {
    lines.push(
      "El .socket es imprescindible: con activación por socket, parar solo el .service no cierra " +
      "el puerto (systemd relanza el servicio en la siguiente conexión). Si systemd avisa de que " +
      "esa unidad .socket no existe, repite el comando solo con el .service."
    );
  }

  // Nota por-puerto (getFixForPort). Solo cuando no hubo fix por proceso/servicio:
  // si no, se repetiría lo mismo, y su redacción ("Desactiva Telnet...") chocaría
  // con el epígrafe de "si SÍ lo necesitas".
  if (!knownFix && p.fix) lines.push(`Sobre este servicio: ${p.fix}`);

  const keepAdvice = limitFix ||
    "configúralo para escuchar en 127.0.0.1 en vez de en todas las interfaces (*/0.0.0.0): " +
    "dejará de estar expuesto a la red sin perder el uso local.";
  lines.push(`Si SÍ lo necesitas: ${keepAdvice}`);

  return lines.join("\n");
}

/**
 * Estado real del cortafuegos, como texto para la EVIDENCIA (no para el fix).
 *
 * El fix estático ya no propone reglas de cortafuegos; el matiz lo da el LLM.
 * Para que pueda darlo sin inventar (ni asumir ufw), necesita el dato real:
 * qué cortafuegos hay y si está activo.
 *
 * @param {{name: string|null, active: boolean}|null} fw  Resultado de detectFirewall()
 * @param {boolean} isLocal  Solo se conoce el cortafuegos del equipo local
 * @returns {string}
 */
function firewallEvidence(fw, isLocal) {
  if (!isLocal) return "";
  if (!fw || !fw.name) return " Cortafuegos del sistema: no se detectó ninguno instalado.";
  return ` Cortafuegos del sistema: ${fw.name} (${fw.active ? "activo" : "INACTIVO"}).`;
}

/**
 * Ajustes comunes de un finding de puerto según el bind detectado.
 * Loopback-only → severidad rebajada y título/evidence lo dicen explícitamente.
 * @param {Object} p  Puerto enriquecido
 * @returns {{ severity: string|null, titleSuffix: string, evidenceExtra: string }}
 */
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

/**
 * Genera findings a partir del array de puertos abiertos de nmap-wrapper.
 * @param {Array<{port, protocol, state, service, version, severity?}>} raw
 * @param {{ firewall?: Object, targetIsLocal?: boolean, target?: string }} [opts]
 * @returns {Finding[]}
 */
function fromNmap(raw, opts = {}) {
  if (!Array.isArray(raw)) return [];
  const isLocal = opts.targetIsLocal !== undefined ? opts.targetIsLocal : true;
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

      // Bind detectado: rebaja severidad y lo hace explícito si es solo-local
      const adj = bindAdjustments(p);
      evidence += adj.evidenceExtra;

      // El cortafuegos NO entra en el fix estático (ver buildPortFix), pero SÍ en
      // la evidencia: es el dato real que el LLM necesita para razonar sobre filtrado
      // sin asumir un cortafuegos que quizá no exista o esté apagado.
      evidence += firewallEvidence(opts.firewall, isLocal);

      // Fix contextual: bind + proceso + tipo de servicio. Para nmap sin proceso,
      // intentar por nombre de servicio antes de caer a la guía genérica.
      const pForFix = (!p.process && p.service && getFixForProcess(p.service, process.platform))
        ? { ...p, process: p.service }
        : p;
      const fix = buildPortFix(pForFix, process.platform, isLocal, opts.target);

      // target/isLocalTarget viajan COMO CAMPOS, no solo dentro del texto de
      // `fix`: el chat con el LLM necesita el dato estructurado para no proponer
      // comandos de ESTE equipo cuando el puerto está en otro dispositivo.
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
/**
 * Sella el nodo de procedencia en cada finding.
 *
 * Se hace aquí, en los TRES puntos de entrada, y no en cada createFinding(): son
 * tres líneas en vez de cuarenta y es imposible olvidarse de un módulo nuevo.
 * `scope` decide si un hallazgo 'declared' eleva el riesgo global — ver
 * isActionable() en lib/severity-map.js.
 *
 * Respeta un scope ya puesto: si algún módulo lo fija a propósito, manda él.
 *
 * @param {Finding[]} findings
 * @param {'host'|'network'|'image'} scope
 * @returns {Finding[]}
 */
function sealScope(findings, scope) {
  for (const f of findings) if (f && !f.scope) f.scope = scope;
  return findings;
}

function normalizeHost(raw, opts = {}) {
  // opts puede ser string (legacy: source) u objeto { platform, pkgManager, source }
  const source = typeof opts === "string" ? opts : (opts.source || "native");
  const platform = typeof opts === "object" ? (opts.platform || process.platform) : process.platform;
  // Gestor de paquetes REAL del equipo (pacman/apt/dnf/zypper/brew/winget…), que
  // detecta el nodo con pkg-manager.js. Ningún generador de fix lo asume.
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

/**
 * Genera findings a partir del array de puertos de nmap-wrapper.js + service-detect.js.
 * Cada entrada tiene: { port, protocol, state, service, severity, fix, pid?, process?, extra? }
 * Si el array está vacío emite un único finding informativo.
 *
 * @param {Array} ports
 * @param {{ firewall?: Object, targetIsLocal?: boolean }} [opts]
 * @returns {Finding[]}
 */
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

    // Bind detectado: rebaja severidad y lo hace explícito si es solo-local
    const adj = bindAdjustments(p);
    evidence += adj.evidenceExtra;

    // El cortafuegos NO entra en el fix estático (ver buildPortFix); sí en la
    // evidencia, como dato real para el LLM.
    evidence += firewallEvidence(opts.firewall, isLocal);

    // Fix contextual: bind real, proceso detectado y tipo de servicio (del SO o de terceros).
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

/**
 * Normaliza raw data del nodo audit-network.
 * @param {Array|*} raw
 * @param {"native"|"nmap"} source
 * @param {{ firewall?: {name, active}, targetIsLocal?: boolean, target?: string }} [opts]
 *   firewall      → resultado de detectFirewall(). Va a la EVIDENCIA, no al fix:
 *                   el fix estático no propone reglas de cortafuegos (ver buildPortFix)
 *   targetIsLocal → false cuando se escanea otro dispositivo de la red
 *   target        → host/IP escaneado; se copia al finding para que el chat con
 *                   el LLM pueda nombrarlo sin reinferirlo
 * @returns {Finding[]}
 */
function normalizeNetwork(raw, source = "native", opts = {}) {
  if (source === "nmap") return sealScope(fromNmap(raw, opts), "network");
  return sealScope(fromPortScanner(Array.isArray(raw) ? raw : [], opts), "network");
}

/**
 * Normaliza raw data del nodo audit-image.
 * @param {*} raw
 * @param {"docker"|"trivy"} source
 * @returns {Finding[]}
 */
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
  // Expuestos para el diagnóstico de cobertura (test/manual/test-command-coverage.js):
  // el test recorre estas tablas REALES, así un gestor nuevo queda cubierto solo.
  getTrivyFixCommand,
  isSystemPath,
  SYSTEM_PREFIXES,
  TRIVY_LANG_CMD,
  TRIVY_LANG_MANUAL,
  TRIVY_OS_TYPES,
};
