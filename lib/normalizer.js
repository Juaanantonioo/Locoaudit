"use strict";

/** Convierte las salidas raw de los módulos al esquema Finding. */

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { createFinding } = require("./finding-schema");
const { fromTrivy, max, MEMORY_THRESHOLDS, lynisGroup, lynisSeverity, SECURITY_EVENT_RULES } = require("./severity-map");
const { getFixForProcess, getFixKind, getSystemService, DANGEROUS_SERVICES } = require("./process-fix");
const { updateAllCmd, upgradeCmd, installCmd, managerLabel, managerForTrivyType } = require("./pkg-manager");
const { correlateWindowsLogons } = require("./win-logons");
const { lynisText, lynisFix, lynisCoverage, lynisControlUrl, pickLynisDiscriminators } = require("./lynis-i18n");

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

/** Finding informativo con el inventario de software; los CVE los pone Trivy.
 *  `raw` llega en tres formas desde sw-inventory.js: el array de paquetes, un skip
 *  { skipped, kind, reason }, o un inventario parcial { packages, partial, partialSource,
 *  partialReason }. Un array vacío es un inventario vacío de verdad y no produce ningún finding:
 *  a partir de ahora "no había nada" y "no se pudo mirar" son estados distintos. */
function fromSwInventory(raw, platform, pkgManager) {
  if (!raw) return [];

  // La fuente no llegó a mirar: aviso explícito, mismo helper que HOST-LYN-SKIP y HOST-CVE-SKIP.
  if (raw.skipped) {
    return [skippedSourceFinding("sw-inventory", raw, platform, "HOST-SW")];
  }

  const isPartial = raw.partial === true;
  const pkgs = isPartial ? raw.packages : raw;
  if (!Array.isArray(pkgs)) return [];

  const findings = [];

  // Delante del recuento: la advertencia tiene que leerse antes que la cifra que matiza.
  // Sin sufijo -SKIP a propósito: aquí sí se inventarió, solo que de forma incompleta.
  if (isPartial) {
    findings.push(
      createFinding({
        id: "HOST-SW-PARTIAL",
        title: "Inventario de software incompleto: una de las fuentes no ha respondido",
        severity: "info",
        evidence:
          `La fuente \`${raw.partialSource}\` no ha respondido: ${raw.partialReason || "sin detalle"} ` +
          "El inventario que se muestra sale solo del resto de fuentes, así que puede faltar " +
          "software realmente instalado.",
        fix: swPartialFix(raw.partialSource),
        category: "system",
        source: "native",
        isCommand: false,
      })
    );
  }

  if (pkgs.length === 0) return findings;

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

/** Cómo se aplican las actualizaciones en este sistema. Texto, nunca comando: aplicarlas es una
 *  decisión del usuario y un `sudo pacman -Syu` copiable invita a ejecutarlo sin leer. */
function updateFixText(raw, platform, pkgManager) {
  const plat = platform || process.platform;
  if (plat === "darwin") {
    return "Abre Ajustes del Sistema → General → Actualización de software y aplica lo que haya " +
      "pendiente. Comprueba antes que tienes copia de seguridad si la actualización pide reiniciar.";
  }
  if (plat === "win32") {
    return "Abre Configuración → Windows Update y aplica lo que haya pendiente.";
  }
  const mgr = raw.manager || pkgManager || null;
  const label = mgr ? managerLabel(mgr) : "el gestor de paquetes de tu distribución";
  const cmd = mgr ? updateAllCmd(mgr) : null;
  return cmd
    ? `Actualiza el sistema con ${label}, revisando antes qué paquetes se van a tocar:\n${cmd}`
    : `Actualiza el sistema con ${label}.`;
}

/**
 * Un solo finding con el recuento y la lista, nunca uno por parche: un equipo con cuarenta
 * actualizaciones pendientes llenaría el panel y taparía todo lo demás.
 *
 * La severidad separa tres cosas distintas: hay pendientes marcadas como de seguridad (medium),
 * hay pendientes pero este sistema no dice cuáles lo son (low), y no hay ninguna (info). La
 * tercera es la única que puede afirmar que no hay nada que aplicar.
 */
function fromPendingUpdates(raw, platform, pkgManager) {
  if (!raw) return [];
  if (raw.skipped) {
    return [skippedSourceFinding("pending-updates", raw, platform, "HOST-UPD")];
  }

  const updates = Array.isArray(raw.updates) ? raw.updates : [];
  const total = typeof raw.total === "number" ? raw.total : updates.length;
  // 'full' clasifica todas, 'none' ninguna, 'partial' solo una parte (macOS: los datos de
  // protección sí, las del propio sistema no).
  const deteccion = raw.securityDetection || "none";
  const secCount = typeof raw.securityCount === "number" ? raw.securityCount : null;
  // Cuántas quedaron SIN CLASIFICAR. No es lo mismo que "no son de seguridad": el gestor no dio
  // señal ninguna sobre ellas. Se cuenta aparte y se dice, porque un recuento de seguridad que
  // las diera por seguras-que-no es el falso verde de siempre con otro nombre.
  const sinClasificar = typeof raw.unclassifiedCount === "number" ? raw.unclassifiedCount : 0;
  /**
   * Windows: hay actualizaciones YA INSTALADAS esperando un reinicio.
   *
   * true / false / null, y el tercero importa. `IsInstalled=0` no las devuelve —están instaladas,
   * solo que sin aplicar—, así que con cero pendientes el informe decía "Sistema al día" sobre un
   * equipo con una corrección de seguridad sin aplicar. Reproducido con KB5120708.
   *
   * `null` es "no se pudo leer el registro": no se afirma que no haya reinicio pendiente.
   */
  const reboot = raw.rebootPending === true ? true : raw.rebootPending === false ? false : null;

  let severity;
  // Una marcada como de seguridad sube a medium venga de donde venga: que la clasificación sea
  // parcial no hace menos cierta la que sí consta.
  // Un reinicio pendiente es trabajo real por hacer, aunque no haya nada que descargar: hasta
  // que se reinicie, la corrección instalada no está aplicada.
  if (total === 0 && reboot === true) severity = "medium";
  else if (total === 0) severity = "info";
  else if (secCount > 0) severity = "medium";
  else severity = "low";

  // El sufijo de sin clasificar va en el título y no solo en la evidencia: es la cifra que
  // impide leer "3 de seguridad" como "y las otras 12 no lo son".
  const sufijoSc = sinClasificar > 0 ? ` (${sinClasificar} sin clasificar)` : "";
  // El titular no puede afirmar más de lo que se ha comprobado. Con la lectura del registro
  // caída no se sabe si hay algo esperando un reinicio, así que "al día" sería una conclusión
  // sobre un dato que falta.
  const esWindows = (platform || raw.platform) === "win32";
  const title = total === 0 && reboot === true
    ? "Hay actualizaciones instaladas pendientes de reinicio"
    : total === 0 && reboot === null && esWindows
    ? "No hay actualizaciones pendientes de descargar (falta comprobar el reinicio)"
    : total === 0
    ? "Sistema al día: no hay actualizaciones pendientes"
    : secCount > 0
    ? `Actualizaciones pendientes: ${total}, de las cuales ${secCount} de seguridad${sufijoSc}`
    : `Actualizaciones pendientes: ${total}${sufijoSc}`;

  const plat = platform || raw.platform || process.platform;
  const partes = [];
  if (total === 0) {
    if (reboot === true) {
      // Va PRIMERO: es la parte que contradice el "no hay nada pendiente" que viene después, y
      // leerlo al revés deja al usuario con la conclusión equivocada.
      partes.push(
        "Este equipo tiene actualizaciones YA INSTALADAS que no se aplicarán hasta que reinicies. " +
        "Hasta entonces sigues ejecutando la versión anterior, con sus fallos sin corregir. " +
        "Reinicia el equipo cuando puedas."
      );
    }
    partes.push(`No hay actualizaciones pendientes de descargar según ${raw.source || "el gestor del sistema"}.`);
    // En Windows una respuesta vacía no es lo mismo que "al día": en un equipo gestionado por
    // WSUS o Intune, Windows Update solo ofrece lo que el servidor de la organización haya
    // aprobado. El aviso va siempre porque la consulta actual no distingue un equipo gestionado
    // de uno que pregunta a Microsoft directamente.
    if (plat === "win32") {
      partes.push(
        "Si este equipo lo gestiona tu organización (WSUS, Intune o similar), este resultado " +
        "depende de lo que el servidor haya publicado para él: puede haber actualizaciones que " +
        "todavía no se hayan aprobado."
      );
    }
  } else {
    const MAX = 15;
    const nombres = updates.slice(0, MAX).map((u) => {
      // La flecha es una comparación, así que necesita los dos extremos. softwareupdate y Windows
      // Update solo dicen qué hay disponible, nunca qué hay instalado: pintar "26.6.2 → 26.6.2"
      // sugería una comparación que nadie ha hecho. Sin versión instalada va el nombre a secas,
      // que en macOS ya incluye la versión dentro del propio Title.
      // El Title de macOS ya termina en la versión disponible ("macOS Tahoe 26.6.2"), así que se
      // recorta antes de añadirla: si no, sale dos veces cuando hay comparación que enseñar.
      const base = u.newVersion && String(u.name).endsWith(u.newVersion)
        ? String(u.name).slice(0, -u.newVersion.length).trim()
        : String(u.name);
      // Flecha solo con los dos extremos. Sin versión instalada se enseña la disponible a secas,
      // que es lo único que el gestor sabe.
      const ver = u.currentVersion && u.newVersion
        ? ` ${u.currentVersion} → ${u.newVersion}`
        : (u.newVersion ? ` ${u.newVersion}` : "");
      // Tres marcas, no dos: sin la tercera, una actualización sobre la que no se sabe nada se
      // presentaba igual que una de la que consta que no es de seguridad.
      const sec = u.security === true
        ? " [seguridad]"
        : u.security === null && deteccion === "full"
        ? " [sin clasificar]"
        : "";
      return `${base}${ver}${sec}`;
    });
    const resto = total - nombres.length;
    partes.push(
      `${total} actualizaciones pendientes según ${raw.source || "el gestor del sistema"}: ` +
      nombres.join(", ") + (resto > 0 ? `, y ${resto} más.` : ".")
    );

    // Nunca "no hay de seguridad" cuando lo que pasa es que no se sabe: son cosas distintas y
    // colapsarlas produce exactamente el falso verde que este campo existe para evitar.
    if (deteccion === "none") {
      partes.push(
        "Este sistema no indica cuáles de estas actualizaciones son de seguridad, así que conviene " +
        "revisarlas todas. Que no aparezca ninguna marcada NO significa que no las haya."
      );
      // Puntero, no deducción: dónde está el dato que aquí no se puede obtener. Sin URL por
      // distribución, que envejece y varía; el boletín de cada una es el sitio correcto.
      if (plat === "linux") {
        partes.push(
          "Ese detalle sí lo publica tu distribución: consúltalo en su boletín de seguridad o en " +
          "las notas de publicación de cada paquete."
        );
      }
    } else if (deteccion === "partial") {
      // Las dos mitades, y ninguna se calla: lo que sí consta y lo que no se puede saber.
      partes.push(
        (secCount > 0
          ? `${secCount} están marcadas como de seguridad: son los datos de protección de macOS ` +
            "(XProtect, MRT, Gatekeeper). "
          : "Ninguna de las pendientes es una actualización de datos de protección de macOS " +
            "(XProtect, MRT, Gatekeeper). ") +
        "Las actualizaciones del propio sistema no se pueden clasificar: softwareupdate no indica " +
        "si incluyen correcciones de seguridad, así que conviene revisarlas igualmente. " +
        // Puntero, no deducción: el dato existe, solo que no por esta vía. Apple lo publica en
        // Ajustes y en sus notas de seguridad, y ahí es donde hay que mirarlo.
        "Ese detalle sí lo publica Apple: puedes verlo en Ajustes del Sistema → General → " +
        "Actualización de software, o en sus notas de seguridad (support.apple.com/100100)."
      );
    } else if (secCount === 0 && sinClasificar === 0) {
      partes.push("Ninguna de las pendientes está marcada como de seguridad.");
    } else if (raw.securityCountIsPatches) {
      partes.push(
        `${secCount} parches de seguridad pendientes. El recuento es de parches, que no se ` +
        "corresponden uno a uno con los paquetes de la lista."
      );
    }
  }

  // Reinicio pendiente con la lista NO vacía: el aviso va igual, porque son dos cosas distintas
  // (lo que falta por instalar y lo que falta por aplicar) y arreglar una no arregla la otra.
  if (reboot === true && total > 0) {
    partes.push(
      "Además, hay actualizaciones ya instaladas que no se aplicarán hasta que reinicies el equipo."
    );
  }
  // No se pudo mirar. Se dice, en vez de callarlo: "no lo sé" no es "no hay".
  if (reboot === null && (plat === "win32" || raw.platform === "win32")) {
    partes.push(
      "No se ha podido comprobar si hay actualizaciones instaladas esperando un reinicio, así que " +
      "este resultado no lo incluye."
    );
  }

  // Las que el gestor no supo clasificar. Va después del resto para que no se lea como una
  // corrección de lo anterior: es información adicional sobre las mismas actualizaciones.
  if (sinClasificar > 0) {
    partes.push(
      (sinClasificar === 1
        ? "1 de estas actualizaciones ha llegado sin categoría ni severidad, así que LoCoAudit " +
          "no ha podido determinar si es de seguridad. NO está contada entre las "
        : `${sinClasificar} de estas actualizaciones han llegado sin categoría ni severidad, así ` +
          "que LoCoAudit no ha podido determinar si son de seguridad. NO están contadas entre las ") +
      `${secCount == null ? 0 : secCount} de seguridad, y tampoco se dan por descartadas: ` +
      (sinClasificar === 1 ? "revísala también." : "revísalas también.")
    );
  }

  // Camino de respaldo de pacman: la lista sale de la base local, que puede estar vieja.
  if (raw.staleDb) {
    const dias = typeof raw.dbAgeDays === "number" ? raw.dbAgeDays : null;
    partes.push(
      "La lista se ha obtenido comparando con la base de datos local de pacman" +
      (dias != null ? `, sincronizada por última vez hace ${dias} día(s)` : "") +
      ": puede estar incompleta. LoCoAudit no sincroniza la base porque `pacman -Sy` modificaría " +
      "el sistema auditado. Instala `pacman-contrib` para que use `checkupdates`."
    );
  }

  return [
    createFinding({
      id: "HOST-UPD-001",
      title,
      severity,
      evidence: partes.join(" "),
      // Sin actualizaciones no hay pasos que dar, y un texto de relleno bajo "Pasos de Resolución"
      // sería ruido. La evidencia se ve igual: desde que la columna izquierda tiene su propia
      // guarda (`v-if="f.evidence"`), un fix nulo ya no la esconde.
      fix: total === 0 ? null : updateFixText(raw, platform, pkgManager),
      // Aplicar actualizaciones no se ofrece como comando copiable en ningún caso.
      command: null,
      isCommand: false,
      category: "system",
      source: "native",
    }),
  ];
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
  return {};   // prosa libre: manda la tabla por control de lib/lynis-i18n.js
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

/**
 * Kinds que significan "aquí no aplica", no "ha fallado".
 *
 * Son límites ESTRUCTURALES: la comprobación no se puede hacer en este sistema y no se va a poder
 * hacer reintentando, instalando algo ni arreglando nada. Redactarlos como fallo —"no se ha
 * podido analizar"— manda al usuario a buscar una solución que no existe, y ensucia el informe
 * con avisos que parecen deuda pendiente.
 *
 *   'unsupported'      Lynis en Windows sin WSL · gestor de paquetes que LoCoAudit no sabe leer
 *   'os-unsupported'   Trivy no reconoce la familia del SO (macOS, Windows)
 *   'nothing-to-scan'  no hay ninguna imagen que analizar: no falta nada, es que no hay
 *
 * Fuera quedan a propósito 'disabled' (decisión del usuario, ya tiene su propio camino) y todos
 * los de fallo real ('error', 'timeout', 'not-installed', 'output-too-large'…). 'not-installed'
 * NO entra: una herramienta que falta SÍ se puede instalar.
 *
 * Lista única. La leen skippedSourceFinding() y audit-host.js para el estado del módulo; el
 * dashboard no la repite, recibe el flag ya sellado en el finding.
 */
// 'not-applicable' y 'no-version' se suman por NSE: un puerto que no es TLS o un servicio que no
// anuncia versión son el alcance real del método, no un hueco que se cierre reintentando.
// 'source-unavailable' NO entra a propósito: ahí sí falta un dato que debería estar, y merece
// ámbar.
const SKIP_KINDS_NO_APLICA = new Set([
  "unsupported", "os-unsupported", "nothing-to-scan", "not-applicable", "no-version",
]);

/** ¿Este kind es un límite del sistema en vez de un fallo? */
function esNoAplica(kind) {
  return SKIP_KINDS_NO_APLICA.has(String(kind || ""));
}

/**
 * Aviso de que una fuente no llegó a mirar. Sin él, un Lynis o un Trivy omitidos son
 * indistinguibles de un sistema limpio para todo el que solo vea `findings[]`: el chat, el
 * informe exportado. El estado estructurado sigue viajando en scanMeta, que es lo que lee el
 * dashboard; esto es la mitad legible. Severidad info: no se pudo comprobar no es un riesgo, y
 * summarize() deja lo informativo fuera del riesgo global.
 */
function skippedSourceFinding(tool, raw, platform, idPrefix = "", context = "host", category = "vulnerability") {
  // El reason llega ya cerrado con su punto, y por eso las plantillas de abajo no lo añaden: si
  // no, el de sw-inventory —que es una frase entera— cerraba la evidencia con "instalado..".
  // Sin tocar las cadenas de cada módulo: la puntuación es de quien las une, no de quien las
  // escribe. Una elipsis final se respeta entera y no recibe punto: "se cortó...", no "...".
  const reason = String(raw.reason || "sin detalle").trim().replace(/(?<!\.\.)\.?$/, ".");
  const kind = raw.kind || null;
  // Un límite del sistema no se redacta como un fallo: cambia el título y el flag que lo separa
  // del resto en el dashboard.
  const noAplica = esNoAplica(kind);
  // Tres registros distintos para tres situaciones distintas. "No se ha podido" solo vale para el
  // fallo real: sobre un módulo que el usuario apagó suena a avería, y sobre un límite de la
  // plataforma manda a buscar una solución que no existe.
  const apagado = kind === "disabled";

  if (tool === "lynis") {
    return createFinding({
      id: "HOST-LYN-SKIP",
      title: noAplica
        ? "Hardening del sistema: no aplica en este sistema"
        : apagado
        ? "Hardening del sistema: desactivado en el nodo"
        : "Hardening del sistema: no se ha podido comprobar",
      severity: "info",
      evidence:
        `No se han evaluado los controles de hardening del sistema: ${reason} ` +
        "La ausencia de hallazgos no significa que la configuración sea correcta, significa que " +
        "no se ha comprobado.",
      fix: lynisSkipFix(kind, platform),
      category: "hardening",
      source: "lynis",
      isCommand: false,
      // El hecho, no el sufijo del id: es lo que el dashboard usa para separar
      // "cero porque está limpio" de "cero porque no se pudo mirar".
      skipped: true,
      // Y el porqué, que separa "lo apagaste tú" de "se intentó y falló".
      kind,
      notApplicable: noAplica,
    });
  }

  if (tool === "sw-inventory") {
    return createFinding({
      id: `${idPrefix}-SKIP`,
      title: noAplica
        ? "Software instalado: no aplica en este sistema"
        : apagado
        ? "Software instalado: desactivado en el nodo"
        : "Software instalado: no se ha podido inventariar",
      severity: "info",
      evidence:
        `No se ha podido obtener la lista de software instalado: ${reason} ` +
        'Una lista vacía aquí significa "no se ha podido mirar", no "no hay nada instalado".',
      fix: swSkipFix(kind, platform),
      category: "system",
      source: "native",
      isCommand: false,
      // El hecho, no el sufijo del id: es lo que el dashboard usa para separar
      // "cero porque está limpio" de "cero porque no se pudo mirar".
      skipped: true,
      // Y el porqué, que separa "lo apagaste tú" de "se intentó y falló".
      kind,
      notApplicable: noAplica,
    });
  }

  if (tool === "pending-updates") {
    return createFinding({
      id: `${idPrefix}-SKIP`,
      title: noAplica
        ? "Actualizaciones pendientes: no aplica en este sistema"
        : apagado
        ? "Actualizaciones pendientes: desactivado en el nodo"
        : "Actualizaciones pendientes: no se han podido consultar",
      severity: "info",
      evidence:
        `No se ha podido comprobar si hay actualizaciones pendientes: ${reason} ` +
        "Que no aparezca ninguna aquí NO significa que el sistema esté al día.",
      fix: updatesSkipFix(kind, platform),
      category: "system",
      source: "native",
      isCommand: false,
      // El hecho, no el sufijo del id: es lo que el dashboard usa para separar
      // "cero porque está limpio" de "cero porque no se pudo mirar".
      skipped: true,
      // Y el porqué, que separa "lo apagaste tú" de "se intentó y falló".
      kind,
      notApplicable: noAplica,
    });
  }

  const what = context === "image"
    ? "las vulnerabilidades de la imagen"
    : "las vulnerabilidades del software instalado";
  return createFinding({
    id: `${idPrefix}-SKIP`,
    title: noAplica
      ? (context === "image"
          ? "Vulnerabilidades de la imagen: no aplica en este caso"
          : "Vulnerabilidades del software instalado: no aplica en este sistema")
      : apagado
      ? (context === "image"
          ? "Vulnerabilidades de la imagen: desactivado en el nodo"
          : "Vulnerabilidades del software instalado: desactivado en el nodo")
      : (context === "image"
          ? "Vulnerabilidades de la imagen: no se han podido analizar"
          : "Vulnerabilidades del software instalado: no se han podido analizar"),
    severity: "info",
    evidence:
      `No se han analizado ${what}: ${reason} Cero CVE aquí significa "sin analizar", ` +
      'no "sin vulnerabilidades".',
    fix: trivySkipFix(kind, context),
    category,
    source: "trivy",
    isCommand: false,
    // El hecho, no el sufijo del id: es lo que el dashboard usa para separar
    // "cero porque está limpio" de "cero porque no se pudo mirar".
    skipped: true,
    // Y el porqué, que separa "lo apagaste tú" de "se intentó y falló".
    kind,
    notApplicable: noAplica,
  });
}

/** Qué hacer con un Lynis omitido, según por qué se omitió. */
function lynisSkipFix(kind, platform) {
  // Apagado por el usuario: no es un fallo y no hay nada que arreglar. El texto lo dice
  // así para que la tarjeta no se lea como un problema del equipo.
  if (kind === "disabled") {
    return "Lo has desactivado tú en las opciones del nodo audit-host. Vuelve a marcarlo si " +
      "quieres que la próxima auditoría incluya el hardening del sistema.";
  }
  if (kind === "unsupported") {
    return platform === "win32"
      ? "Lynis no tiene versión para Windows nativo. Para auditar el hardening de este equipo, " +
        "instala WSL y ejecuta LoCoAudit dentro de la distribución de WSL."
      : "Esta plataforma no puede ejecutar Lynis. Es un límite conocido, no un fallo de la auditoría.";
  }
  if (kind === "not-installed") {
    return "Instala Lynis (https://cisofy.com/lynis/) y vuelve a lanzar la auditoría, o desactiva " +
      "el módulo en las opciones del nodo para no volver a verlo.";
  }
  return "Revisa el motivo del aviso: hasta que se resuelva, el hardening del sistema queda sin auditar.";
}

/** Qué hacer con un Trivy omitido, según por qué se omitió. */
function trivySkipFix(kind, context) {
  // Apagado por el usuario: no es un fallo y no hay nada que arreglar. El texto lo dice
  // así para que la tarjeta no se lea como un problema del equipo.
  if (kind === "disabled") {
    return context === "image"
      ? "Lo has desactivado tú en las opciones del nodo audit-image. Vuelve a marcarlo si quieres " +
        "que la próxima auditoría analice las vulnerabilidades de las imágenes."
      : "Lo has desactivado tú en las opciones del nodo audit-host. Vuelve a marcarlo si quieres " +
        "que la próxima auditoría analice tu carpeta personal.";
  }
  if (kind === "unsupported") {
    return "Es un límite conocido de la herramienta en esta plataforma o con este gestor de " +
      "paquetes, no un fallo de la auditoría. El resto de módulos sí se ha ejecutado.";
  }
  if (kind === "not-installed") {
    return "Instala Trivy (https://trivy.dev/) y vuelve a lanzar la auditoría, o desactiva el " +
      "módulo en las opciones del nodo para no volver a verlo.";
  }
  return context === "image"
    ? "Revisa el motivo del aviso: hasta que se resuelva, la imagen queda sin analizar."
    : "Revisa el motivo del aviso: hasta que se resuelva, el software instalado queda sin analizar.";
}

/** Qué hacer con un inventario de software omitido, según por qué se omitió. */
function swSkipFix(kind, platform) {
  if (kind === "unsupported") {
    return "El inventario de software de LoCoAudit todavía solo sabe leer dpkg y rpm, y este " +
      "sistema usa otro gestor de paquetes. No es un fallo de tu equipo ni le falta nada: es un " +
      "límite de LoCoAudit. El resto de módulos de la auditoría no se ve afectado.";
  }
  if (kind === "not-installed") {
    return platform === "win32"
      ? "Windows 11 24H2 y posteriores ya no incluyen `wmic`, que es la fuente del inventario en " +
        "Windows. El resto de la auditoría no se ve afectado."
      : "Falta la herramienta que lista los paquetes en este sistema. Instálala y vuelve a lanzar " +
        "la auditoría, o desactiva el módulo en las opciones del nodo para no volver a verlo.";
  }
  if (kind === "timeout") {
    return "El inventario no terminó dentro del límite de tiempo. Vuelve a lanzar la auditoría con " +
      "el equipo menos cargado, o desactiva el módulo en las opciones del nodo.";
  }
  return "Revisa el motivo del aviso: hasta que se resuelva, el software instalado queda sin " +
    "inventariar.";
}

/** Qué hacer con una consulta de actualizaciones omitida, según por qué se omitió. */
function updatesSkipFix(kind, platform) {
  if (kind === "unsupported") {
    return "Es un límite de LoCoAudit, no un fallo de tu equipo: el resto de módulos de la " +
      "auditoría no se ve afectado. Comprueba las actualizaciones por el medio habitual de tu " +
      "sistema.";
  }
  if (kind === "not-installed") {
    return platform === "win32"
      ? "Sin PowerShell no hay forma nativa de consultar Windows Update. Revisa las " +
        "actualizaciones en Configuración → Windows Update."
      : "Falta la herramienta que lista las actualizaciones en este sistema. Revísalas por el " +
        "medio habitual de tu distribución.";
  }
  if (kind === "timeout") {
    return "La consulta tardó más de lo permitido. Vuelve a lanzar la auditoría con el equipo " +
      "menos cargado, o desactiva el módulo en las opciones del nodo.";
  }
  return "Revisa el motivo del aviso: hasta que se resuelva, no se sabe si el sistema tiene " +
    "actualizaciones pendientes.";
}

/** Qué hacer con la fuente de macOS que no respondió. La otra sí, así que hay inventario. */
function swPartialFix(source) {
  return source === "brew"
    ? "Comprueba a mano que Homebrew responde: brew list --versions\n" +
      "Hasta entonces el inventario solo incluye las aplicaciones que ve system_profiler."
    : "Comprueba a mano que system_profiler responde: system_profiler SPApplicationsDataType\n" +
      "Hasta entonces el inventario solo incluye los paquetes de Homebrew.";
}

/** Un finding por entrada del .dat. Antes las sugerencias colapsaban en una tarjeta que
 *  remitía a 'lynis show suggestions'; el volumen se controla por severidad, no ocultando. */
function fromLynisRaw(raw, platform, pkgManager) {
  if (!raw) return [];
  if (raw.skipped) return [skippedSourceFinding("lynis", raw, platform)];

  const items = pairLynisEntries(raw.warnings || [], raw.suggestions || []);
  const findings = [];

  /**
   * Cuántas veces sale cada control EN ESTE informe.
   *
   * Hace falta porque la traducción se indexa por ID, y un mismo control puede emitir varias
   * sugerencias distintas: AUTH-9286 sale dos veces, una por la edad mínima de la contraseña y
   * otra por la máxima, y FILE-6310 una vez por cada punto de montaje. Con una sola entrada en
   * el diccionario, las dos tarjetas salían con el mismo título y parecían duplicadas.
   *
   * Solo se desambigua lo que se repite: en el caso normal —un control, una tarjeta— el título
   * se queda limpio, que es de lo que se trataba al traducirlo.
   */
  const vecesPorControl = new Map();
  for (const { entry } of items) {
    vecesPorControl.set(entry.id, (vecesPorControl.get(entry.id) || 0) + 1);
  }

  /**
   * El discriminador se elige POR GRUPO, no por entrada: el criterio es que los títulos queden
   * distintos, y un candidato que da el mismo valor en dos entradas no distingue nada.
   * pickLynisDiscriminators() baja de nivel —token entrecomillado, mínima/máxima, ruta, campo 3,
   * y por último la frase original— hasta dar con uno único en todas.
   *
   * Antes se usaba `entry.detail || entry.description`, y en Debian AUTH-9286 no trae detail:
   * el título acababa con la frase entera de Lynis en inglés metida entre paréntesis.
   */
  const discPorControl = new Map();
  for (const [id, veces] of vecesPorControl) {
    if (veces < 2) continue;
    const delControl = items.filter((it) => it.entry.id === id).map((it) => it.entry);
    const elegidos = pickLynisDiscriminators(delControl);
    if (elegidos) {
      const porEntrada = new Map();
      delControl.forEach((e, i) => porEntrada.set(e, elegidos[i]));
      discPorControl.set(id, porEntrada);
    }
  }

  for (const { type, entry, remedy } of items) {
    const group = lynisGroup(entry.id);
    // Por ID COMPLETO, desde lib/lynis-i18n.js. La tabla por PREFIJO que había aquí daba la
    // solución del área temática y no la del problema: "revisar los servicios de arranque" para
    // un GRUB sin contraseña, `apt upgrade` para "no tienes herramienta de auditoría". Se ha
    // eliminado, no degradado a respaldo: un respaldo plausible pero equivocado ocupa el sitio
    // de la recomendación real y nadie lo mira dos veces.
    const lynFix = lynisFix(entry.id, platform, pkgManager, installCmd);
    const solution = parseSolutionType(entry.solution);

    // Orden del fix: qué conseguir (la sugerencia), cómo se hace en este SO, y la orden exacta
    // si Lynis la da. Un token conocido del campo 4 ('text:reboot') va por delante de todo.
    const steps = [];
    // `noAction` manda sobre todo lo demás: si el control no admite acción, no hay pasos que dar
    // y cualquiera que se añadiera sería una contradicción con el propio dato. Pasaba con
    // NETW-2704: la tabla decía "no admite acción" y el remedio emparejado le montaba igualmente
    // un bloque de "Pasos de Resolución".
    if (!lynFix.noAction) {
      if (solution.actionType === "reboot") {
        steps.push("Reinicia el equipo para que el cambio surta efecto.");
      }
      // El remedio de Lynis NO entra aquí: viene en inglés y el bloque de resolución es texto
      // nuestro y en castellano. Se conserva en la evidencia, etiquetado como lo que es.
      if (lynFix.fix && !solution.actionType) steps.push(lynFix.fix);

      // El campo 3 sí es de esta instancia concreta del control, y es una orden ejecutable
      // literal cuando tiene la forma canónica `Run '…'`.
      const cmdDetalle = commandFromDetail(entry.detail);
      if (cmdDetalle) steps.push(cmdDetalle);
    }
    const detailCmd = commandFromDetail(entry.detail);

    // El texto de Lynis viene en inglés. Se traduce por ID DE CONTROL contra la tabla estática
    // de lib/lynis-i18n.js —los IDs son estables entre versiones, el texto no— y nunca con el
    // LLM: es opcional y no determinista, y dos ejecuciones darían informes distintos sobre los
    // mismos datos. Sin entrada en la tabla sale el original en inglés, marcado.
    const traduccion = lynisText(entry.id, entry.description);

    // Lo que distingue una instancia de otra: el detalle si lo hay (FILE-6310 trae el punto de
    // montaje), y si no, la descripción original de Lynis (AUTH-9286 distingue "minimum" de
    // "maximum" solo ahí). Sin esto, dos tarjetas del mismo control eran indistinguibles.
    const repetido = traduccion.translated && (vecesPorControl.get(entry.id) || 0) > 1;
    const disc = repetido ? (discPorControl.get(entry.id) || new Map()).get(entry) : null;
    // El último recurso es la frase original en inglés: si toca usarla, se dice, en vez de
    // colarla como si fuera texto nuestro.
    const matiz = disc ? (disc.translated ? disc.text : `en inglés: ${disc.text}`) : "";
    const titulo = matiz ? `${traduccion.text} (${matiz})` : traduccion.text;

    const evidenceParts = [traduccion.text];
    // El original solo se repite cuando SÍ se ha traducido: si no, sería la misma frase dos
    // veces. Cuando no hay traducción, la nota dice por qué está en inglés.
    if (traduccion.translated && entry.description && entry.description !== traduccion.text) {
      evidenceParts.push(`Texto original de Lynis: ${entry.description}`);
    } else if (!traduccion.translated) {
      evidenceParts.push(
        "Este control todavía no está traducido en LoCoAudit, así que se muestra el texto " +
        `original de Lynis (${entry.id}).`
      );
    }
    if (entry.detail && !detailCmd) evidenceParts.push(entry.detail);
    // El remedio que Lynis empareja con el aviso. Va a la EVIDENCIA y no al fix: llega en inglés
    // y sin traducir, y el bloque de "Pasos de Resolución" es texto de LoCoAudit. Aquí no se
    // pierde —es información del propio Lynis— pero queda claro de quién es.
    if (remedy && remedy.description) {
      evidenceParts.push(`Sugerencia original de Lynis: ${remedy.description}`);
    }

    findings.push(
      createFinding({
        id: lynisFindingId(entry),
        // El título es la descripción; el código va de metadato (antes encabezaba la tarjeta).
        title: titulo,
        severity: lynisSeverity(entry.id, type),
        evidence: evidenceParts.join(" · "),
        // null cuando no hay ningún paso REAL que dar. Antes nunca era null: getLynisFixText()
        // devolvía "Revisar la configuración del sistema relacionada con <ID>", que es repetir
        // el identificador disfrazado de recomendación.
        fix: steps.length ? steps.join("\n") : null,
        command: lynFix.noAction ? null : (detailCmd || lynFix.command || null),
        category: "system",
        source: "lynis",
        control: entry.id,
        controlGroup: group,
        subcategory: LYNIS_GROUP_LABELS[group] || LYNIS_GROUP_FALLBACK,
        detail: detailCmd ? null : entry.detail,
        lynisType: type,
        actionType: solution.actionType || null,
        // La ficha oficial del control. El campo existía y llegaba siempre vacío en los
        // hallazgos de Lynis: el .dat solo trae URL en unos pocos. Cuando no hay paso concreto,
        // esto es lo único útil y honesto que se le puede ofrecer al usuario.
        primaryUrl: solution.primaryUrl || lynisControlUrl(entry.id),
        advisoryLabel: solution.primaryUrl ? null : `Control ${entry.id} de Lynis`,
        // El control no admite acción (Lynis informa de lo que él no pudo mirar, o de algo que
        // no es un defecto). Distinto de "no tenemos el paso escrito", y el dashboard lo dice
        // distinto: afirmar "no requiere acción" sobre un GRUB sin contraseña sería falso.
        noAction: lynFix.noAction,
        // Lynis no puntúa: el nivel lo pone LoCoAudit (LYNIS_GROUP_TIER en severity-map).
        severitySource: "locoaudit",
        // false ⇒ el título está en inglés. El dashboard lo marca; sin esto no habría forma de
        // distinguir un control sin traducir de uno cuya traducción coincide con el original.
        translated: traduccion.translated,
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
// Las dos vías son EXCLUYENTES, no dos pasos de una secuencia: la numeración "1)/2)" de antes
// decía lo contrario. Van con el marcador "## " de rama, que el dashboard de host convierte en
// subtítulo. Empieza por salto de línea A PROPÓSITO: hay llamantes que lo concatenan detrás de
// una frase con un espacio (HOST-SEC-WIN-RDP-*), y "## " solo abre rama si abre la línea.
const RDP_HARDEN_FIX =
  "\n## Si no necesitas el Escritorio remoto\n" +
  "Desactívalo en Configuración → Sistema → Escritorio remoto. El servicio deja de escuchar y el " +
  "puerto 3389 se cierra.\n" +
  "## Si SÍ necesitas el Escritorio remoto\n" +
  "Exige autenticación a nivel de red (NLA).\n" +
  "Usa contraseñas robustas en todas las cuentas.\n" +
  "Limita quién puede conectarse (Usuarios de escritorio remoto).\n" +
  "Una regla del Firewall de Windows Defender sobre el 3389 solo FILTRA el tráfico de red: el servicio " +
  "sigue activo y el puerto sigue abierto, así que no sustituye a desactivar el Escritorio remoto.";

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
      fix: `En este equipo no hay nada que actualizar: ${pkg} no está instalado, solo aparece ` +
           `anotado como dependencia dentro de un fichero de bloqueo${donde}.\n` +
           "En el proyecto al que pertenece ese fichero sí puede haber trabajo: si el proyecto es " +
           `tuyo, actualiza ahí la dependencia ${pkg} y regenera el fichero de bloqueo. Si el ` +
           "fichero lo trae empaquetado otra herramienta, ignóralo.",
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
 *
 * Escrito en la gramática que parsean los tres dashboards: "## " abre una rama, "> " es una nota
 * y el resto es un paso. Los cuatro "Si …" que había eran ramas EXCLUYENTES escritas como una
 * lista corrida, y el panel las numeraba como pasos consecutivos: se hacía cuatro cosas cuando
 * hay que hacer una.
 */
function buildImageFix({ image, pkg, fixedVersion } = {}) {
  const img = image || "la imagen";
  const intro =
    pkg && fixedVersion
      ? [`El paquete ${pkg} tiene corrección en la versión ${fixedVersion}.`]
      : [];
  return [
    ...intro,
    "## Si hay un tag ya corregido",
    `Cambia a un tag más reciente de ${img} que ya incluya la corrección.`,
    "Comprueba en el registro (Docker Hub / GHCR) qué tag la trae.",
    "## Si ningún tag la corrige todavía",
    "Cambia a una imagen base más pequeña y mantenida (p. ej. alpine o distroless en vez de debian):",
    "menos paquetes = menos superficie de ataque.",
    "## Si la imagen es propia",
    "Reconstrúyela sobre una base actualizada (FROM al día) y vuelve a escanear.",
    "> Si el mantenedor aún no ha publicado corrección no hay fix disponible: documenta el riesgo aceptado y vigila las actualizaciones del upstream.",
  ].join("\n");
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

/** Advisory de Vulners. Los CVE se llevan al NVD, no al espejo de Vulners. */
function bestNetworkAdvisoryUrl(id, sourceUrl) {
  const value = String(id || "").toUpperCase();
  if (/^CVE-\d{4}-\d+$/.test(value)) {
    return { url: `https://nvd.nist.gov/vuln/detail/${value}`, label: "NVD" };
  }
  return bestAdvisoryUrl({ VulnerabilityID: value, PrimaryURL: sourceUrl || "" });
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

/**
 * Finding agregado: N vulnerabilidades que el usuario NO puede accionar, en una sola tarjeta.
 *
 * Existe factorizado porque hay dos casos con la misma forma y el mismo razonamiento, y escribir
 * el patrón dos veces garantizaba que se separasen:
 *
 *   HOST-OS-CVE-UNFIXED  · paquetes del sistema sin corrección publicada por la distribución.
 *   HOST-CVE-DECLARED    · versiones anotadas en ficheros de dependencias de terceros.
 *
 * Y una tercera, que no es un finding: el resumen de las comprobaciones que no se hicieron
 * (buildSkippedChecksSummary), que viaja en scanMeta. Por eso la composición del texto está
 * extraída en buildAggregateText(): las tres dicen "N cosas, y esto es lo que significan", y
 * escribirlo tres veces era garantizar que acabaran diciéndolo de tres maneras distintas.
 *
 * En las dos que sí son finding, la severidad es `info` y NO hay campo `fix`. En LoCoAudit la severidad mide urgencia
 * de ACCIÓN: marcarlas por su severidad nominal llenaría la cabecera de riesgo con cosas que el
 * usuario no puede tocar y le haría ignorar también lo que sí puede. Y tampoco se ocultan: miles
 * de tarjetas es ilegible, cero es mentira, y una que las cuenta es lo honesto.
 */
function buildAggregateText({ count, noun, evidenceHead, body }) {
  return {
    title: `${count} ${noun}`,
    evidence: [evidenceHead, ...body].join("\n\n"),
  };
}

function buildAggregateFinding({ id, count, noun, evidenceHead, body, source, origin }) {
  const texto = buildAggregateText({ count, noun, evidenceHead, body });
  return createFinding({
    id,
    title: texto.title,
    severity: "info",
    evidence: texto.evidence,
    // Sin `fix` a propósito: no hay ninguna acción que ofrecer, y una casilla de solución
    // genérica ("mantente al día") convertiría esto en una tarea pendiente que no lo es.
    fix: null,
    category: "system",
    source,
    origin,
    // Lo que separa esta tarjeta de un informativo normal ("tu disco está al 42 %"): resume
    // muchos hallazgos, no describe un hecho del equipo. El dashboard lo necesita para no
    // contarla entre los datos de estado.
    aggregate: true,
  });
}

/** Cuenta ficheros distintos, para poder decir "en M ficheros" sin inventarse la cifra. */
function _contarFicheros(items) {
  const ficheros = new Set();
  for (const it of items) {
    const f = it.location || it.target;
    if (f) ficheros.add(f);
  }
  return ficheros.size;
}

/**
 * HOST-CVE-DECLARED: todas las declaradas del host, en un solo finding.
 *
 * `trivy fs` sobre el HOME sigue ejecutándose igual y el JSON exportado conserva el detalle
 * completo: lo único que cambia es el renderizado. Enumerarlas llenaba el dashboard de tarjetas
 * sobre versiones anotadas en lockfiles de programas de terceros, que no describen software en
 * ejecución y no tienen ninguna acción asociada.
 */
function buildDeclaredAggregate(declared) {
  const n = declared.length;
  const nFicheros = _contarFicheros(declared);
  const conFix = declared.filter((x) => x.v && x.v.FixedVersion).length;

  const ficheros = nFicheros === 1 ? "1 fichero de dependencias" : `${nFicheros} ficheros de dependencias`;
  // La cifra de "corregibles" se da porque el JSON la tiene y alguien la buscará; se dice en la
  // misma frase que la aclaración de que no hay nada que actualizar aquí, para que no se lea
  // como una lista de tareas.
  const fix = conFix === 0
    ? "Ninguna de ellas tiene una versión corregida anotada."
    : conFix === n
    ? "Todas tienen una versión corregida anotada en el propio fichero."
    : `${conFix} de ellas tienen una versión corregida anotada en el propio fichero.`;

  return buildAggregateFinding({
    id: "HOST-CVE-DECLARED",
    count: n,
    noun: n === 1 ? "vulnerabilidad declarada en ficheros de dependencias"
                  : "vulnerabilidades declaradas en ficheros de dependencias",
    evidenceHead:
      `Encontradas en ${ficheros} (\`yarn.lock\`, \`pom.xml\`, \`bun.lock\`…) dentro de tu carpeta ` +
      "personal, pertenecientes a programas de terceros. Describen versiones anotadas en esos " +
      "ficheros, no software que se esté ejecutando en tu equipo. No hay ningún paquete de tu " +
      "sistema que puedas actualizar para resolverlas.",
    body: [
      // La cifra de corregibles va junto a la aclaración de que aquí no hay nada que actualizar:
      // suelta, se leería como una lista de tareas, que es justo lo contrario de lo que es.
      `${fix} Esa versión corregida es la que el fichero declara, no un paquete instalado en tu equipo.`,
      "Se informan por transparencia, no como tarea pendiente.",
      "El detalle completo está en la exportación JSON.",
    ],
    source: "trivy",
    // La procedencia se conserva: es lo que hace que isActionable() lo deje fuera del riesgo
    // global aunque alguna de las agregadas fuese 'critical'.
    origin: "declared",
  });
}

/**
 * Resumen de las comprobaciones que NO se hicieron, para el panel de Alcance.
 *
 * Tercera aplicación del patrón de HOST-CVE-DECLARED y HOST-OS-CVE-UNFIXED, y por el mismo
 * motivo: el nivel de agregación estaba mal. Cada comprobación caída era un hallazgo informativo
 * suelto dentro de "Sistema & Actualizaciones", mezclado con hallazgos reales sobre el equipo. El
 * usuario los leía como cuatro problemas más, cuando son una sola cosa —"esto es lo que no se ha
 * mirado"— y su sitio natural es junto al alcance del análisis, no en la lista de hallazgos.
 *
 * NO es un finding, a diferencia de las otras dos: los `*-SKIP` individuales SE SIGUEN EMITIENDO
 * con `skipped: true`. Eso es deliberado y tiene dos razones:
 *   1. La exportación JSON conserva el detalle íntegro de cada módulo, con su motivo y su kind.
 *   2. `failedCheckFindings` del dashboard —el que decide si la tarjeta va en ámbar— sigue
 *      teniendo su fuente. Si desaparecieran, ese estado se quedaría sin datos.
 * Lo que cambia es solo el renderizado: el dashboard los saca de la lista de hallazgos y enseña
 * este bloque.
 *
 * Se DERIVA de esos mismos findings, nunca de una lista paralela: dos recuentos de comprobaciones
 * caídas divergirían en cuanto alguien tocase uno de los dos.
 *
 * Devuelve null si no hay ninguna: sin nada que contar no hay bloque que enseñar.
 */
function buildSkippedChecksSummary(findings) {
  const omitidas = (findings || []).filter((f) => f && f.skipped === true);
  if (!omitidas.length) return null;

  // Tres motivos distintos, tres frases distintas. Fundirlos es lo que hacía que un módulo
  // apagado a propósito se leyera igual que uno que falló.
  const apagadas = omitidas.filter((f) => f.kind === "disabled");
  const noAplican = omitidas.filter((f) => f.notApplicable === true);
  const fallidas = omitidas.filter((f) => f.kind !== "disabled" && f.notApplicable !== true);

  const trozos = [];
  if (fallidas.length) {
    trozos.push(fallidas.length === 1
      ? "1 se intentó y no pudo completarse"
      : `${fallidas.length} se intentaron y no pudieron completarse`);
  }
  if (noAplican.length) {
    trozos.push(noAplican.length === 1
      ? "1 no aplica en este sistema"
      : `${noAplican.length} no aplican en este sistema`);
  }
  if (apagadas.length) {
    trozos.push(apagadas.length === 1
      ? "1 la desactivaste tú"
      : `${apagadas.length} las desactivaste tú`);
  }

  const texto = buildAggregateText({
    count: omitidas.length,
    noun: omitidas.length === 1 ? "comprobación no realizada" : "comprobaciones no realizadas",
    evidenceHead: `De las que no se han hecho: ${trozos.join(", ")}.`,
    body: [
      // Lo único que importa de verdad: solo las fallidas dejan un agujero. Las otras dos son
      // alcance conocido, no deuda.
      fallidas.length
        ? "Las que no pudieron completarse dejan un hueco en el informe: que no aparezcan " +
          "hallazgos de esa parte no significa que esté limpia, significa que nadie la ha mirado."
        : "Ninguna ha fallado: lo que falta es alcance conocido, no un hueco en el informe.",
      "El detalle de cada una, con su motivo exacto, está en la exportación JSON.",
    ],
  });

  return {
    ...texto,
    total: omitidas.length,
    failed: fallidas.length,
    notApplicable: noAplican.length,
    disabled: apagadas.length,
    // Una línea por módulo, ya redactada: el dashboard pinta, no decide. `title` viene del propio
    // finding, así que no hay una segunda tabla de etiquetas que mantener sincronizada.
    items: omitidas.map((f) => ({
      id: f.id,
      title: f.title,
      reason: f.evidence,
      kind: f.kind || null,
      estado: f.kind === "disabled"
        ? "disabled"
        : f.notApplicable === true
        ? "not-applicable"
        : "failed",
    })),
  };
}

/** Etiqueta legible del sistema: "debian 13.6", o solo la familia si Trivy no dio la versión. */
function osLabel(os) {
  if (!os || !os.family) return "el sistema";
  return os.name ? `${os.family} ${os.name}` : String(os.family);
}

/** Reparto por severidad en el orden en que se lee, con las palabras del usuario y no las de
 *  Trivy: "72 críticas, 736 altas…". Las claves ausentes no se nombran. */
function severityPhrase(bySeverity) {
  const LABEL = {
    CRITICAL: ["crítica", "críticas"],
    HIGH:     ["alta", "altas"],
    MEDIUM:   ["media", "medias"],
    LOW:      ["baja", "bajas"],
    UNKNOWN:  ["sin clasificar", "sin clasificar"],
  };
  const parts = [];
  for (const key of ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]) {
    const n = bySeverity && bySeverity[key];
    if (!n) continue;
    const [one, many] = LABEL[key];
    parts.push(`${n} ${n === 1 ? one : many}`);
  }
  return parts.length ? parts.join(", ") : "sin desglose disponible";
}

/**
 * Findings de los paquetes del SISTEMA (lib/trivy-rootfs.js).
 *
 * Dos salidas y no una, porque son dos situaciones distintas para quien lee el informe:
 *
 *  - CON corrección publicada → un finding POR PAQUETE (HOST-OS-PKG-<paquete>). La acción del
 *    usuario es actualizar un paquete, así que cinco CVE corregidos en la misma versión son una
 *    sola orden. Agrupar por CVE daría cinco tarjetas idénticas para un solo `apt install`.
 *
 *  - SIN corrección publicada → UN ÚNICO finding agregado (HOST-OS-CVE-UNFIXED), severidad info.
 *    En LoCoAudit la severidad mide urgencia de ACCIÓN, y aquí no hay ninguna acción posible: no
 *    existe actualización que las resuelva. Marcarlas 'critical' llenaría la cabecera de riesgo
 *    con algo que el usuario no puede tocar y le haría ignorar también lo que sí puede. Tampoco
 *    se ocultan: 4078 tarjetas es ilegible, cero es mentira, y una que las cuenta es lo honesto.
 */
function fromTrivyRootfs(raw, platform, pkgManager) {
  if (!raw) return [];
  if (raw.skipped) return [skippedRootfsFinding(raw, platform)];

  const findings = [];
  const label = osLabel(raw.os);
  const pkgNum = raw.pkgNum != null ? raw.pkgNum : null;

  // El id lleva el nombre del paquete para que sobreviva entre ejecuciones, pero el nombre solo
  // no siempre es único: el mismo paquete puede estar instalado en dos versiones (multiarch), y
  // groupFixableByPackage las separa correctamente en dos grupos. Sin esto los dos findings
  // saldrían con el mismo id y el dashboard mostraría uno pisando al otro.
  const repetidos = new Set();
  const vistos = new Set();
  for (const grp of raw.fixable || []) {
    if (vistos.has(grp.pkg)) repetidos.add(grp.pkg);
    vistos.add(grp.pkg);
  }

  // Un finding por paquete actualizable.
  for (const grp of raw.fixable || []) {
    const n = grp.cves.length;
    const version = grp.installedVersion || "sin versión";
    const cmd = upgradeCmd(pkgManager, grp.pkg);

    // Los CVE con su severidad, como evidencia: el usuario tiene que poder buscarlos.
    const MAX_LIST = 12;
    const listed = grp.cves.slice(0, MAX_LIST)
      .map((c) => `${c.id} (${c.severity.toLowerCase()})`).join(", ");
    const rest = n - MAX_LIST;
    const cveList = rest > 0 ? `${listed} y ${rest} más` : listed;

    findings.push(createFinding({
      // Por nombre de paquete y no por un contador: el id sobrevive entre ejecuciones y el chat
      // puede referirse al mismo hallazgo aunque cambie el número de CVE. La versión se añade
      // SOLO cuando ese nombre aparece más de una vez, para no ensuciar el caso normal.
      id: repetidos.has(grp.pkg)
        ? `HOST-OS-PKG-${grp.pkg}@${grp.installedVersion || "sin-version"}`
        : `HOST-OS-PKG-${grp.pkg}`,
      title: `${grp.pkg} ${version} — ${n} ${n === 1 ? "vulnerabilidad corregida" : "vulnerabilidades corregidas"} en ${grp.fixedVersion}`,
      // La MÁXIMA del grupo: la urgencia la marca la peor, no la media.
      severity: fromTrivy(grp.maxSeverity),
      evidence:
        `Paquete del sistema ${grp.pkg} ${version} en ${label}. ` +
        `Tu distribución ya publicó la versión ${grp.fixedVersion}, que corrige ${cveList}.`,
      fix: cmd
        ? `${cmd}\nActualiza ${grp.pkg} a ${grp.fixedVersion} o posterior.`
        : `Actualiza ${grp.pkg} a ${grp.fixedVersion} o posterior con ${managerLabel(pkgManager)}.`,
      command: cmd,
      category: "system",
      source: "trivy",
      // Instalado de verdad, leído de la base de datos del gestor: no es una anotación en un
      // lockfile. Sin esto isActionable() lo dejaría fuera del riesgo global.
      origin: "installed",
    }));
  }

  // Un único finding para todo lo que no tiene corrección.
  const unfixed = raw.unfixed || { total: 0, bySeverity: {} };
  if (unfixed.total > 0) {
    const desglose = severityPhrase(unfixed.bySeverity);
    const paquetes = pkgNum != null ? `${pkgNum} paquetes analizados` : "paquetes del sistema analizados";

    // Misma factoría que HOST-CVE-DECLARED: dos casos, un patrón. Escribirlo dos veces era
    // garantizar que con el tiempo dijeran cosas distintas sobre la misma idea.
    findings.push(buildAggregateFinding({
      id: "HOST-OS-CVE-UNFIXED",
      count: unfixed.total,
      noun: "vulnerabilidades conocidas sin corrección disponible",
      evidenceHead: `${label} · ${paquetes}. Reparto por severidad: ${desglose}.`,
      body: [
        "Estas vulnerabilidades están documentadas en los paquetes de tu sistema, pero tu " +
        "distribución no ha publicado ninguna corrección para ellas. No existe ninguna " +
        "actualización que las resuelva: no hay nada que puedas hacer y no es un descuido tuyo.",
        "Las distribuciones revisan cada vulnerabilidad y muchas quedan clasificadas como de " +
        "impacto despreciable en la versión estable, por cómo están compilados y configurados " +
        "los paquetes. Además, las severidades mostradas proceden en parte de bases de datos " +
        "genéricas y no reflejan necesariamente la valoración de tu distribución, que suele ser " +
        "menor.",
        "Se listan para que sepas que existen, no como tarea pendiente.",
      ],
      source: "trivy",
      origin: "installed",
    }));
  }

  return findings;
}

/**
 * Paquetes del sistema no analizados. Mismo `skipped: true` que skippedSourceFinding(), pero con
 * texto propio: 'os-unsupported' es un límite conocido de la plataforma y el resto de kinds no.
 */
function skippedRootfsFinding(raw, platform) {
  const reason = String(raw.reason || "sin detalle").trim().replace(/(?<!\.\.)\.?$/, ".");
  const kind = raw.kind || null;

  let fix;
  // Apagado por el usuario: no es un fallo y no hay nada que arreglar. El texto lo dice
  // así para que la tarjeta no se lea como un problema del equipo.
  if (kind === "disabled") {
    fix = "Lo has desactivado tú en las opciones del nodo audit-host. Vuelve a marcarlo si quieres " +
          "que la próxima auditoría incluya los paquetes del sistema operativo.";
  } else if (kind === "os-unsupported") {
    fix = platform === "darwin"
      ? "macOS no tiene un gestor de paquetes de sistema que Trivy sepa leer, así que este " +
        "análisis no aplica en este equipo. Las actualizaciones de seguridad del sistema las " +
        "gestiona Apple: revísalas en Ajustes del Sistema → General → Actualización de software."
      : platform === "win32"
      ? "Trivy no analiza los paquetes de sistema de Windows, así que este análisis no aplica en " +
        "este equipo. Mantén el sistema al día con Windows Update."
      : "Trivy no ha reconocido la distribución de este equipo y no sabe leer su base de datos " +
        "de paquetes. Mantén el sistema al día con tu gestor habitual.";
  } else if (kind === "output-too-large") {
    fix = "La salida de Trivy se cortó por tamaño y el resultado parcial se ha descartado a " +
          "propósito. Vuelve a lanzar la auditoría; si se repite, es un fallo de LoCoAudit.";
  } else if (kind === "timeout") {
    fix = "El análisis de los paquetes del sistema no terminó a tiempo. Ejecuta `trivy rootfs /` " +
          "a mano para ver dónde se detiene, o desactiva el módulo en las opciones del nodo.";
  } else {
    fix = "Comprueba que Trivy funciona ejecutando `trivy rootfs /` a mano, o desactiva el " +
          "análisis de paquetes del sistema en las opciones del nodo audit-host.";
  }

  return createFinding({
    id: "HOST-OS-CVE-SKIP",
    title: esNoAplica(kind)
      ? "Vulnerabilidades de los paquetes del sistema: no aplica en este sistema"
      : kind === "disabled"
      ? "Vulnerabilidades de los paquetes del sistema: desactivado en el nodo"
      : "Vulnerabilidades de los paquetes del sistema: no se han podido analizar",
    severity: "info",
    evidence: esNoAplica(kind)
      ? `Esta comprobación no aplica en este sistema: ${reason} ` +
        "No es un fallo ni algo que puedas arreglar: Trivy no cubre los paquetes de sistema de " +
        "esta plataforma. Cero vulnerabilidades del sistema aquí significa \"fuera de alcance\", " +
        'no "sin vulnerabilidades".'
      : `No se han analizado las vulnerabilidades de los paquetes del sistema operativo: ${reason} ` +
        'Cero vulnerabilidades del sistema aquí significa "sin analizar", no "sin vulnerabilidades".',
    fix,
    category: "system",
    source: "trivy",
    isCommand: false,
    skipped: true,
    kind,
    notApplicable: esNoAplica(kind),
  });
}

function fromTrivyJson(raw, idPrefix, category = "vulnerability", source = "trivy", opts = {}) {
  const platform   = opts.platform || process.platform;
  const pkgManager = opts.pkgManager || null;
  if (!raw) return [];
  const context = idPrefix.startsWith("IMG") ? "image" : "host";
  if (raw.skipped) {
    // En imagen, un `failed` con entradas ya sale como un IMG-SCAN-ERR por imagen desde el nodo:
    // el aviso general sobraría y contaría dos veces el mismo fallo.
    if (context === "image" && Array.isArray(raw.failed) && raw.failed.length) return [];
    return [skippedSourceFinding("trivy", raw, platform, idPrefix, context, category)];
  }

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

  /**
   * Las DECLARADAS se colapsan en un solo finding, y salen de aquí antes de repartirse por los
   * cubos de severidad. Por qué antes y no filtrando los findings ya construidos: `medByTarget` y
   * `lowInfoByImage` agrupan varias vulnerabilidades en un resumen y le ponen `origin` solo si
   * TODAS coinciden (uniformOrigin); en cuanto un resumen mezcla declaradas e instaladas, su
   * `origin` queda a null. Filtrar por `origin === "declared"` a posteriori dejaría fuera esos
   * resúmenes, que seguirían enumerados y —peor— contando como accionables sin serlo. Aquí cada
   * vulnerabilidad tiene todavía su procedencia concreta y el recuento sale exacto.
   *
   * Solo en host, y por un flag EXPLÍCITO del llamante: audit-image usa este mismo
   * fromTrivyJson() y ahí las declaradas son el contenido del informe, no ruido de fondo. El
   * dashboard de imagen conserva su detalle intacto.
   */
  const declared = opts.collapseDeclared ? allVulns.filter((x) => x.origin === "declared") : [];
  const restantes = opts.collapseDeclared ? allVulns.filter((x) => x.origin !== "declared") : allVulns;

  // Un paquete con N CVEs da un finding, con la severidad más alta del grupo.
  const pkgGroups = new Map();
  const medByTarget    = new Map();   // image|target → { image, target, vulns[] }
  const lowInfoByImage = new Map();   // image → { image, count, targets:Set }

  for (const item of restantes) {
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

  // El agregado de las declaradas, si las hubo. Va al final para que salga después de lo que sí
  // requiere acción: es contexto, no tarea.
  if (declared.length) findings.push(buildDeclaredAggregate(declared));

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

/**
 * Un comando empotrado detrás de dos puntos, tal y como lo escribe el catálogo de
 * lib/process-fix.js: "Solo si no imprimes desde este equipo: sudo systemctl disable …",
 * a veces entre paréntesis. Ese catálogo NO se edita desde aquí, así que el troceo se hace
 * al construir el fix.
 *
 * La condición es EXACTA y comprobable sobre todo el catálogo —dos puntos, espacio y una
 * línea que empieza por `sudo`—, no la lista de verbos que se retiró del dashboard: una
 * frase que solo menciona un comando de pasada no se convierte en un botón de copiar.
 */
const CMD_TRAS_DOSPUNTOS = /^(\(?.*?):\s+(sudo\s.+?)\)?$/;

/** Trocea un texto del catálogo en líneas de la gramática de `fix` (paso / "$ " comando). */
function lineasDeCatalogo(texto) {
  const out = [];
  for (const bruta of String(texto || "").split("\n")) {
    const linea = bruta.trim();
    if (!linea) continue;
    const m = CMD_TRAS_DOSPUNTOS.exec(linea);
    if (m) {
      out.push(`${m[1].replace(/^\(/, "").trim()}:`);
      out.push(`$ ${m[2]}`);
    } else if (/^sudo\s/.test(linea)) {
      out.push(`$ ${linea}`);
    } else {
      out.push(linea);
    }
  }
  return out;
}

/** Pasos de resolución de un puerto abierto. El fix estático propone una sola acción fiable,
 *  parar el servicio: el cortafuegos filtra pero no cierra, y ese matiz lo aporta el LLM.
 *
 *  Gramática de salida (la misma que lee el dashboard): "## " abre rama, "$ " es el comando
 *  del paso anterior, "> " es una nota que no se numera, y lo anterior a la primera "## " es
 *  un párrafo introductorio. */
function buildPortFix(p, platform, targetIsLocal, target) {
  // Target remoto: no se adjunta la guía por puerto de getFixForPort, redactada para el equipo
  // local. "systemctl disable nginx" no aplica a un router ni a una cámara.
  if (targetIsLocal === false) {
    const where = target ? `el dispositivo remoto ${target}` : "OTRO dispositivo de tu red";
    // Dos notas, no dos pasos: aquí no hay nada que ejecutar. Sin ninguna "## " el parser
    // numeraría dos párrafos que nadie tiene que "hacer" en orden.
    return (
      `> Este puerto está abierto en ${where}, no en este equipo. Desde aquí no se puede cerrar: ` +
      "hay que acceder a ese dispositivo (su panel de administración o su configuración) y " +
      "detener allí el servicio que escucha, o restringir desde qué equipos se puede acceder.\n" +
      "> LoCoAudit no puede generar comandos válidos para un equipo distinto del que ejecuta la " +
      "auditoría: su sistema operativo no se ha auditado."
    );
  }

  const sysSvc =
    getSystemService(p.process, platform) ||
    (p.service ? getSystemService(p.service, platform) : null);

  // Bind en loopback: no está expuesto, no se propone cerrar nada. Todo son notas por el
  // mismo motivo que la rama remota: no hay una sola acción que dar.
  if (p.localOnly === true) {
    const what = sysSvc ? `> ${sysSvc.label}. ${sysSvc.what}\n` : "";
    return (
      what +
      `> Este servicio escucha solo en ${p.bind || "localhost"}: NO está expuesto a la red. ` +
      "Solo los programas de este mismo equipo pueden conectarse a él; desde otro equipo de tu red " +
      "no es accesible.\n" +
      "> No hay nada que cerrar: se informa del puerto para que sepas qué está escuchando, no porque " +
      "sea un riesgo de exposición."
    );
  }

  // Servicio del propio SO: la vía soportada, no matarlo a lo bruto. Qué es el servicio va de
  // intro —describe, no pide nada— y el aviso, de nota al pie de la rama.
  if (sysSvc) {
    return [
      `${sysSvc.label}. ${sysSvc.what}`,
      "## Si no lo necesitas, desactívalo por la vía que ofrece el propio sistema",
      ...lineasDeCatalogo(sysSvc.soft),
      `> ${sysSvc.warn}`,
    ].join("\n");
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

  // Sin "1)/2)": el orden lo pone la lista del dashboard. Numerarlo aquí además producía dos
  // numeraciones superpuestas en cuanto la rama tenía más de un paso.
  const genericStop = platform === "win32"
    ? ["Con el PID que devuelve el comando anterior, identifica el servicio y deshabilítalo en " +
       "services.msc (Detener + Tipo de inicio: Deshabilitado). Si es una aplicación que instalaste " +
       "tú, ciérrala o desinstálala."]
    : platform === "darwin"
      ? ["Con el nombre del proceso (columna COMMAND) decide: si es una app que instalaste tú, " +
         "ciérrala o desinstálala; si es un servicio de compartición de macOS, desactívalo en " +
         "Ajustes del Sistema → General → Compartido. No uses kill: launchd relanza los servicios " +
         "y el puerto volvería a abrirse."]
      : ["Con el nombre del servicio (columna COMMAND), detenlo y deshabilítalo junto a su socket:",
         "$ sudo systemctl disable --now <servicio>.service <servicio>.socket"];

  // El comando del catálogo puede traer prosa detrás de un salto de línea (el FTP de macOS):
  // la primera línea es el comando y el resto, una nota. Solo se marca como comando si empieza
  // por `sudo`; en Windows el "comando" del catálogo es una instrucción de services.msc.
  const stopLines = [];
  if (stopCmd) {
    const trozos = String(stopCmd).split("\n").map((l) => l.trim()).filter(Boolean);
    stopLines.push("Detén y deshabilita el servicio:");
    stopLines.push(/^sudo\s/.test(trozos[0]) ? `$ ${trozos[0]}` : trozos[0]);
    trozos.slice(1).forEach((l) => stopLines.push(`> ${l}`));
  }

  const lines = [
    "## Si no lo necesitas",
    "Confirma qué proceso escucha en el puerto:",
    `$ ${identify}`,
    ...(stopLines.length ? stopLines : genericStop),
    "> Al detener el servicio, el puerto se cierra.",
  ];

  // Sin parar el .socket, systemd relanza el servicio con la siguiente conexión.
  if (platform === "linux" && lines.join("\n").includes(".socket")) {
    lines.push(
      "> El .socket es imprescindible: con activación por socket, parar solo el .service no cierra " +
      "el puerto (systemd relanza el servicio en la siguiente conexión). Si systemd avisa de que " +
      "esa unidad .socket no existe, repite el comando solo con el .service."
    );
  }

  const keepAdvice = limitFix ||
    "Configúralo para escuchar en 127.0.0.1 en vez de en todas las interfaces (*/0.0.0.0): " +
    "dejará de estar expuesto a la red sin perder el uso local.";
  lines.push("## Si lo necesitas");
  lines.push(...lineasDeCatalogo(keepAdvice));

  // La guía por puerto solo si no hubo fix por proceso: si no, se repite y choca con la rama
  // de "si lo necesitas". Llega YA en la gramática, con sus propias "## ", así que se concatena
  // como ramas hermanas: envolverla en "Sobre este servicio: …" la habría metido dentro de una
  // rama ajena y las ramas no anidan.
  if (!knownFix && p.fix) lines.push(String(p.fix).trim());

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
        port: p.port,
        protocol: p.protocol || "tcp",
        service: p.service || null,
        version: p.version || null,
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
    if (raw.pendingUpdates) findings.push(...fromPendingUpdates(raw.pendingUpdates, platform, pkgManager));
    if (raw.lynis) findings.push(...fromLynisRaw(raw.lynis, platform, pkgManager));
    // collapseDeclared solo aquí: es el flag explícito que separa host de imagen. normalizeImage
    // NO lo pasa, y por eso el dashboard de imagen conserva el detalle por CVE.
    if (raw.trivy) findings.push(...fromTrivyJson(raw.trivy, "HOST-CVE", "vulnerability", "trivy", { platform, pkgManager, collapseDeclared: true }));
    // Paquetes del SISTEMA, de lib/trivy-rootfs.js. Aparte de raw.trivy a propósito: son otra
    // pregunta, con otra fuente y otro contrato, y mezclarlas es lo que se acaba de deshacer.
    if (raw.trivyRootfs) findings.push(...fromTrivyRootfs(raw.trivyRootfs, platform, pkgManager));
    if (raw.securityEvents) findings.push(...fromSecurityEvents(raw.securityEvents, platform));
    return sealScope(findings, "host");
  }

  // Fallback: source explícito (para tests unitarios)
  if (source === "lynis") return sealScope(fromLynisRaw(raw, platform, pkgManager), "host");
  if (source === "trivy") {
    return sealScope(fromTrivyJson(raw, "HOST-CVE", "vulnerability", "trivy", { platform, pkgManager, collapseDeclared: true }), "host");
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

/**
 * PROCEDENCIA DE LOS CVE DE VULNERS. Va en TODOS los NET-VULN-*, sin excepción y sin acortar.
 *
 * No es una nota legal ni una coletilla defensiva: sin ella el hallazgo afirma más de lo que la
 * fuente sabe. Cuatro cosas que el dato NO dice, y que quien lo lee da por supuestas:
 *
 *  1. La versión la ANUNCIA el servicio. Nadie ha comprobado contra el objetivo que el fallo
 *     esté ahí: se ha buscado en una base de datos por número de versión.
 *  2. Debian, Ubuntu y RHEL corrigen fallos MANTENIENDO el número de versión (backporting). Un
 *     OpenSSH 8.9 parcheado sigue diciendo 8.9 y aparecerá aquí con todos sus CVE. Esto es un
 *     límite conocido del método, no un fallo que se pueda arreglar desde el nodo: para
 *     descartarlo hay que mirar el changelog del paquete en el equipo.
 *  3. La nota de vulners puede no coincidir con la del NVD para el mismo CVE, y la escala de
 *     LoCoAudit se aplica sobre la de vulners.
 *  4. Un CVE del CLIENTE de un programa puede aparecer atribuido a su SERVIDOR, porque la
 *     consulta se hace por producto y versión, no por rol. Ocurre de verdad y puede producir un
 *     crítico que al mirarlo no lo era.
 *
 * Un hallazgo de estos sin este texto es un hallazgo mal presentado.
 */
const PROCEDENCIA_VULNERS =
  "La versión la anuncia el propio servicio y NO se ha verificado contra " +
  "el objetivo; muchas distribuciones (Debian, Ubuntu, RHEL) corrigen fallos sin cambiar el " +
  "número de versión, así que un servicio ya parcheado puede aparecer aquí igualmente; la " +
  "puntuación es la que da vulners.com y puede diferir de la del NVD para el mismo CVE; y como " +
  "la consulta se hace por producto y versión, un fallo que solo afecta al cliente puede " +
  "aparecer atribuido a su servidor. Confirma cada CVE contra el changelog del paquete antes de " +
  "darlo por bueno.";

/** Los CVE de un grupo, en texto, con su nota. Se listan TODOS: el recorte a los N peores fue lo
 *  que hizo falta corregir en Trivy cuando el usuario no encontraba el CVE que le habían citado. */
function _listarCves(cves) {
  return cves
    .map((c) => `${c.id} (${c.cvss != null ? c.cvss.toFixed(1) : "sin nota"}${c.isExploit ? ", con exploit público" : ""})`)
    .join(", ");
}

/**
 * NET-VULN-*: un finding por PUERTO y CPE, no uno por CVE.
 *
 * Un OpenSSH cualquiera trae once CVE: once tarjetas para una sola acción —actualizar— entierran
 * el resto del informe y no añaden ni una decisión. La severidad del grupo es la del peor CVE, y
 * los once viajan enteros en `vulnerabilities`, que es lo que pinta la tabla del hallazgo: la
 * evidencia dice cuántos son y cuánto puntúa el peor, sin repetir la lista en prosa.
 *
 * NO se usa buildAggregateFinding() pese a ser "un finding que resume muchos": esa función fija
 * severity 'info' y category 'system' porque nació para lo que el usuario no puede accionar, y
 * aquí sí hay acción y sí hay riesgo. Forzar el encaje habría aplanado a 'info' un crítico.
 *
 * Y LO QUE NO HACE: no toca la severidad del NET-PORT-* correspondiente. El puerto vale lo que
 * dice PORT_CATALOG; heredar la severidad de sus CVE convertiría "SSH abierto" en crítico por un
 * fallo que quizá ni está.
 */
function fromNseVulns(ports, opts = {}) {
  const findings = [];
  let i = 0;

  for (const p of ports) {
    const resumen = p && p.nseSummary;
    if (!resumen || !resumen.vulns || !resumen.vulns.length) continue;

    for (const grupo of resumen.vulns) {
      const nombre = [p.service, p.version].filter(Boolean).join(" ") || `puerto ${p.port}`;
      // "OpenSSH 10.3" → "OpenSSH": lo accionable es el producto; la versión ya va en la ficha.
      // Sin banner de versión se cae al nombre del servicio, que es lo que había antes.
      const producto =
        (p.version && String(p.version).replace(/\s+v?\d[\w.\-+]*$/, "").trim()) ||
        p.service || "el servicio";
      const exploitTxt = grupo.exploits
        ? ` ${grupo.exploits} de los registros devueltos son exploits públicos.`
        : "";
      const vulnerabilities = grupo.cves.map((cve) => {
        const advisory = bestNetworkAdvisoryUrl(cve.id, cve.sourceUrl);
        return {
          id: cve.id,
          kind: "cve",
          cvss: cve.cvss,
          severity: cve.severity,
          isExploit: cve.isExploit,
          url: advisory.url,
          label: advisory.label,
        };
      });

      findings.push(createFinding({
        id:       `NET-VULN-${counter(i++)}`,
        title:    `${grupo.cves.length} ${grupo.cves.length === 1 ? "CVE conocido" : "CVE conocidos"} en ${nombre} (puerto ${p.port}/tcp)`,
        severity: grupo.severity,
        // Frase, no volcado: los CVE uno a uno los pinta la tabla del hallazgo desde
        // `vulnerabilities`, y repetirlos aquí obligaba a leer la misma lista dos veces.
        // Que vulners no describa cada CVE se dice explícitamente: sin esa frase, una tabla
        // de identificadores sin texto se lee como un dato que falta por cargar.
        evidence:
          `El servicio del puerto ${p.port}/tcp se identifica como ${grupo.cpe || nombre}. ` +
          `vulners.com devuelve ${grupo.cves.length} CVE para la versión anunciada` +
          `${grupo.maxCvss != null ? `, y el más grave puntúa ${grupo.maxCvss.toFixed(1)}` : ""}.` +
          `${exploitTxt} vulners no aporta una descripción por CVE: de cada uno se conoce su ` +
          "identificador, su puntuación y si tiene exploit público. " +
          PROCEDENCIA_VULNERS,
        // Sin comando: el gestor de paquetes correcto depende del equipo auditado, que puede no
        // ser este. Proponer un `apt upgrade` contra la máquina de otro sería un fix falso.
        fix:
          `Actualiza ${producto} del equipo ${opts.target || "auditado"} a la versión que ` +
          "publique su sistema.\n" +
          "Si ya está al día, comprueba en el changelog del paquete si los CVE listados están " +
          "corregidos por backport.",
        category: "network",
        source:   "nmap",
        target:        opts.target || null,
        isLocalTarget: opts.targetIsLocal !== undefined ? opts.targetIsLocal : null,
        port: p.port,
        protocol: p.protocol || "tcp",
        service: p.service || null,
        version: p.version || null,
        cpe: grupo.cpe || null,
        vulnerabilities,
        provenance: PROCEDENCIA_VULNERS,
      }));
    }
  }
  return findings;
}

/**
 * NET-TLS-*: la nota de ssl-enum-ciphers.
 *
 * La severidad sale de la tabla A-F del catálogo, que llega hasta 'high'. Ver allí por qué esta
 * escala y la de SSH no son la misma: en TLS el grado F incluye SSLv2/SSLv3, NULL y export, que
 * se explotan del lado servidor sin que el cliente colabore (mecanismo de DROWN).
 *
 * Una nota que no esté en la tabla —'unknown' incluida— no produce hallazgo de riesgo: produce
 * una omisión, porque significa que el script no llegó a concluir.
 */
function fromNseTls(ports, opts = {}) {
  const findings = [];
  let i = 0;

  for (const p of ports) {
    const tls = p && p.nseSummary && p.nseSummary.tls;
    if (!tls || !tls.severity) continue;

    const peores = tls.weak.slice(0, 8).map((w) => `${w.name} (${w.grade})`).join(", ");
    let evidence =
      `El servicio TLS del puerto ${p.port}/tcp obtiene la nota ${tls.grade} de nmap ` +
      `(escala A-F, donde A es la configuración actual y F incluye SSLv2, SSLv3, suites NULL y ` +
      `de exportación). Protocolos aceptados: ${tls.protocols.join(", ") || "no consta"}.`;
    if (tls.weak.length) {
      evidence += ` Suites por debajo de A: ${tls.weak.length}` +
                  `${peores ? ` — ${peores}${tls.weak.length > 8 ? ", …" : ""}` : ""}.`;
    }
    if (tls.cert) {
      const partes = [];
      if (tls.cert.issuer)   partes.push(`emitido por ${tls.cert.issuer}`);
      if (tls.cert.sigAlgo)  partes.push(`firma ${tls.cert.sigAlgo}`);
      if (tls.cert.notAfter) partes.push(`válido hasta ${tls.cert.notAfter}`);
      if (partes.length) evidence += ` Certificado: ${partes.join(", ")}.`;
    }
    // La frase literal del catálogo: sin ella, "ofrece" se lee como "usa".
    evidence += ` Matiz importante: ${p.nseSummary.offeredText}`;

    findings.push(createFinding({
      id:       `NET-TLS-${counter(i++)}`,
      title:    `Configuración TLS con nota ${tls.grade} en el puerto ${p.port}/tcp`,
      severity: tls.severity,
      evidence,
      fix:
        "Revisa la configuración TLS del servicio y deja solo TLS 1.2 y 1.3 con suites que " +
        "nmap califique con A; retira SSLv2, SSLv3 y cualquier suite RC4, 3DES, NULL o de " +
        "exportación.",
      category: "network",
      source:   "nmap",
      target:        opts.target || null,
      isLocalTarget: opts.targetIsLocal !== undefined ? opts.targetIsLocal : null,
      port: p.port,
      protocol: p.protocol || "tcp",
      service: p.service || null,
      version: p.version || null,
    }));
  }
  return findings;
}

/**
 * NET-SVC-*: los algoritmos que ofrece un SSH.
 *
 * Techo 'medium' a propósito (ver nse-catalog.js): en SSH el hash de intercambio cubre los
 * KEXINIT, así que no hay degradación forzada desde la red y el riesgo exige un cliente que
 * elija el algoritmo débil. El criterio es si el riesgo depende de un tercero, no la antigüedad.
 *
 * Sin nada débil el hallazgo se emite igual, como inventario informativo: "esto es lo que ofrece
 * tu SSH" es un dato de auditoría, y su ausencia se leería como que no se miró.
 */
function fromNseSvc(ports, opts = {}) {
  const findings = [];
  let i = 0;

  for (const p of ports) {
    const ssh = p && p.nseSummary && p.nseSummary.ssh;
    if (!ssh) continue;

    const inventario = ssh.groups.map((g) => `${g.label}: ${g.count}`).join(", ");
    let evidence = `El servicio SSH del puerto ${p.port}/tcp ofrece ${ssh.total} algoritmos ` +
                   `(${inventario}).`;

    if (ssh.weak.length) {
      const porNivel = { medium: [], low: [] };
      for (const w of ssh.weak) (porNivel[w.severity] || []).push(`${w.name} [${w.group}]`);
      if (porNivel.medium.length) evidence += ` Rotos o desaconsejados sin discusión: ${porNivel.medium.join(", ")}.`;
      if (porNivel.low.length)    evidence += ` Débiles, no rotos: ${porNivel.low.join(", ")}.`;
    } else {
      evidence += " Ninguno figura en la lista de algoritmos débiles de LoCoAudit; eso no " +
                  "significa que todos sean recomendables, solo que este catálogo no se " +
                  "pronuncia sobre ellos.";
    }
    evidence += ` Matiz importante: ${p.nseSummary.offeredText}`;

    findings.push(createFinding({
      id:       `NET-SVC-${counter(i++)}`,
      title: ssh.weak.length
        ? `SSH ofrece ${ssh.weak.length} ${ssh.weak.length === 1 ? "algoritmo débil" : "algoritmos débiles"} en el puerto ${p.port}/tcp`
        : `Algoritmos SSH ofrecidos en el puerto ${p.port}/tcp`,
      severity: ssh.severity,
      evidence,
      fix: ssh.weak.length
        ? "En el servidor SSH, deja fuera los algoritmos listados: en OpenSSH se hace con las " +
          "directivas KexAlgorithms, Ciphers, MACs y HostKeyAlgorithms de sshd_config, " +
          "declarando solo los que quieres admitir. Reinicia el servicio y vuelve a auditar."
        : null,
      category: "network",
      source:   "nmap",
      target:        opts.target || null,
      isLocalTarget: opts.targetIsLocal !== undefined ? opts.targetIsLocal : null,
      port: p.port,
      protocol: p.protocol || "tcp",
      service: p.service || null,
      version: p.version || null,
    }));
  }
  return findings;
}

/**
 * Lo que NO se llegó a comprobar, agrupado por motivo.
 *
 * Aquí vive la mitad que el proyecto se juega: un puerto con versión al que no se le pudo
 * preguntar por CVE NO es un puerto limpio, y tiene que decirlo en findings[] —que es lo que ven
 * el chat y el informe descargado—, no solo en scanMeta.
 *
 * Se agrupa por motivo y no por puerto porque son avisos de cobertura, no hallazgos: cinco
 * tarjetas iguales cambiando el número de puerto esconden las que sí piden algo.
 *
 * `notApplicable` distingue el límite del hueco, y esa distinción decide el color en el panel:
 *   no-version, not-applicable  → el alcance real. No se arregla reintentando. Sin ámbar.
 *   source-unavailable, script-missing, nse-unavailable → huecos de ESTA ejecución. Ámbar.
 */
function fromNseOmissions(ports, opts = {}) {
  const meta = opts.nse || {};
  const findings = [];
  let i = 0;

  const push = ({ kind, title, evidence, fix = null, notApplicable = false }) => {
    findings.push(createFinding({
      id:    `NET-NSE-SKIP-${counter(i++)}`,
      title,
      // 'info': no se pudo comprobar NO es un riesgo, y summarize() deja lo informativo fuera
      // del riesgo global. Lo que lo hace visible es `skipped` + `kind`, no la severidad.
      severity: "info",
      evidence,
      fix,
      category: "network",
      source:   "nmap",
      skipped:  true,
      kind,
      notApplicable,
      target:        opts.target || null,
      isLocalTarget: opts.targetIsLocal !== undefined ? opts.targetIsLocal : null,
      port: null,
    }));
  };

  if (!meta.enabled) {
    push({
      kind: "nse-disabled",
      title: "Análisis de vulnerabilidades y configuración de servicios no realizado",
      evidence:
        "El escaneo detectó qué puertos están abiertos, pero NO comprobó si los servicios que " +
        "escuchan tienen vulnerabilidades conocidas ni cómo están configurados: el análisis con " +
        "scripts NSE está desactivado en este nodo. La ausencia de vulnerabilidades en este " +
        "informe significa que no se buscaron, no que no las haya.",
      fix: "Activa «Analizar vulnerabilidades y configuración de servicios» en la configuración " +
           "del nodo de red y repite la auditoría.",
    });
    return findings;
  }

  if (meta.availability && meta.availability.checked === false) {
    push({
      kind: "nse-unavailable",
      title: "No se pudo comprobar qué scripts de análisis están instalados",
      evidence:
        `No se pudo obtener la lista de scripts NSE disponibles en este nmap: ${
          meta.availability.reason || "sin detalle"}. Por precaución el escaneo se lanzó sin ` +
        "ellos, así que no se analizaron ni vulnerabilidades ni configuración de servicios.",
    });
  }

  for (const nombre of (meta.availability && meta.availability.missing) || []) {
    push({
      kind: "script-missing",
      title: `El script de análisis '${nombre}' no está instalado`,
      evidence:
        `Este nmap no tiene el script '${nombre}', así que se quitó del comando para no abortar ` +
        "el escaneo entero. Lo que ese script comprueba no se ha comprobado en ningún puerto.",
      fix: "Instala la colección completa de scripts NSE de tu distribución (en Debian y Ubuntu, " +
           "el paquete `nmap` completo en lugar de `nmap-common`) y repite la auditoría.",
    });
  }

  // ssl-enum-ciphers corrió y no concluyó: devuelve nota fuera de la tabla A-F ('unknown'
  // cuando no pudo completar el diálogo TLS). No es una nota buena ni mala: es un hueco.
  const tlsMudo = ports.filter((p) => {
    const t = p.nseSummary && p.nseSummary.tls;
    return t && !t.severity;
  });
  if (tlsMudo.length) {
    push({
      kind: "tls-inconclusive",
      title: `Configuración TLS sin evaluar en ${tlsMudo.length} ${tlsMudo.length === 1 ? "puerto" : "puertos"}`,
      evidence:
        "El análisis de cifrado TLS se lanzó contra estos puertos pero no devolvió una nota " +
        `interpretable (${tlsMudo.map((p) => `${p.port}/tcp${p.nseSummary.tls.grade ? `: ${p.nseSummary.tls.grade}` : ""}`).join(", ")}), ` +
        "normalmente porque no llegó a completar el diálogo TLS. NO se ha comprobado si aceptan " +
        "protocolos o suites obsoletos.",
      fix: "Repite la auditoría; si vuelve a ocurrir, comprueba a mano la configuración del " +
           "servicio con `openssl s_client -connect equipo:puerto`.",
    });
  }

  // Por estado de puerto. El orden importa: primero el hueco, que es el que hay que ver.
  const sinFuente  = ports.filter((p) => p.nseSummary && p.nseSummary.vulnState === "source-unavailable");
  const sinVersion = ports.filter((p) => p.nseSummary && p.nseSummary.vulnState === "no-version");

  if (sinFuente.length) {
    const lista = sinFuente.map((p) => `${p.port}/tcp (${p.version || p.service || "sin identificar"})`).join(", ");
    push({
      kind: "source-unavailable",
      title: `${sinFuente.length} ${sinFuente.length === 1 ? "puerto" : "puertos"} con versión sin comprobar frente a la base de CVE`,
      evidence:
        `Estos servicios anunciaron versión pero no consta que la base de datos de CVE ` +
        `respondiera, así que NO se puede afirmar que estén libres de vulnerabilidades ` +
        `conocidas: ${lista}. ${(meta.canary && meta.canary.detail) || ""}`.trim(),
      fix: "Repite la auditoría cuando el equipo tenga salida a internet; si el problema " +
           "persiste, comprueba si un proxy o un cortafuegos bloquea vulners.com.",
    });
  }

  if (sinVersion.length) {
    const lista = sinVersion.map((p) => `${p.port}/tcp (${p.service || "desconocido"})`).join(", ");
    push({
      kind: "no-version",
      // Límite real del método, no fallo: sin versión no hay nada que consultar.
      notApplicable: true,
      title: `${sinVersion.length} ${sinVersion.length === 1 ? "puerto abierto" : "puertos abiertos"} sin versión identificable`,
      evidence:
        `Estos servicios no anunciaron versión, así que no había nada que consultar en la base ` +
        `de datos de CVE: ${lista}. No es un fallo del análisis: un servicio puede ocultar su ` +
        "versión a propósito, y eso no dice nada sobre si es vulnerable.",
    });
  }

  return findings;
}

/** Todo lo que aporta NSE, en el orden en que conviene leerlo. Solo puertos abiertos: es sobre
 *  los que se lanzaron los scripts, y es el mismo filtro que aplica fromNmap. */
function fromNse(ports, opts = {}) {
  const lista = (Array.isArray(ports) ? ports : []).filter((p) => p && p.state === "open");
  return [
    ...fromNseVulns(lista, opts),
    ...fromNseTls(lista, opts),
    ...fromNseSvc(lista, opts),
    ...fromNseOmissions(lista, opts),
  ];
}

/** Normaliza el raw de audit-network. `firewall` va a la evidencia, no al fix; `target` y
 *  `targetIsLocal` se copian al finding para que el chat pueda nombrarlos. */
function normalizeNetwork(raw, source = "native", opts = {}) {
  if (source === "nmap") {
    // Los puertos primero y lo de NSE después: el panel se lee de arriba abajo, y lo primero
    // que se busca es qué está abierto. `opts.nse` solo llega cuando el nodo lo activó; sin él
    // esto devuelve exactamente lo de siempre.
    const findings = fromNmap(raw, opts);
    if (opts.nse) findings.push(...fromNse(raw, opts));
    return sealScope(findings, "network");
  }
  return sealScope(fromPortScanner(Array.isArray(raw) ? raw : [], opts), "network");
}

/** Normaliza el raw de audit-image. */
function normalizeImage(raw, source = "docker") {
  if (source === "trivy") return sealScope(fromTrivyJson(raw, "IMG-CVE", "vulnerability", "trivy"), "image");
  return sealScope(fromNative(Array.isArray(raw) ? raw : [], source), "image");
}

module.exports = {
  normalizeHost,
  buildSkippedChecksSummary,
  lynisCoverage,
  SKIP_KINDS_NO_APLICA,
  esNoAplica,
  normalizeNetwork,
  normalizeImage,
  // Subfunciones expuestas para tests unitarios
  fromCpuMemory,
  fromDisk,
  fromSwInventory,
  fromPendingUpdates,
  fromLynisRaw,
  fromSecurityEvents,
  fromSecurityEventsWin32,
  fromTrivyJson,
  fromNmap,
  fromNse,
  fromNseVulns,
  bestAdvisoryUrl,
  advisoryLabelFromUrl,
  bestNetworkAdvisoryUrl,
  fromNseTls,
  fromNseSvc,
  fromNseOmissions,
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
