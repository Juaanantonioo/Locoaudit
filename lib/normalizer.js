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
const { classifyHostPath, classifyImagePath, misconfSeverity } = require("./secret-context");

function safe(val, fallback = "—") {
  return val != null ? String(val) : fallback;
}

function counter(n) {
  return String(n + 1).padStart(3, "0");
}

/** Severidad según el porcentaje de uso de disco. */
// Umbrales domésticos: un disco al 68 % no es un riesgo.
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
  if (raw.skipped) return [nativeSkipFinding("HOST-CPU-SKIP", "Procesador y memoria", raw, "cpu")];
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
      // macOS reporta la RAM al 95-99 % por la gestión unificada: informativo.
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

/** Comprobación nativa que no se pudo hacer (el módulo lanzó): info, pero contada como no realizada. */
function nativeSkipFinding(id, label, raw, category) {
  const kind = raw.kind || "error";
  return createFinding({
    id,
    title: `${label}: no se ha podido comprobar`,
    severity: "info",
    evidence: `${String(raw.reason || "sin detalle").trim().replace(/(?<!\.\.)\.?$/, ".")} ` +
      "Que no aparezca ningún aviso aquí no significa que esté bien, significa que no se ha mirado.",
    fix: "Revisa el motivo del aviso y vuelve a lanzar la auditoría.",
    category,
    source: "native",
    isCommand: false,
    skipped: true,
    kind,
    notApplicable: esNoAplica(kind),
  });
}

/** Findings a partir de las particiones de disk-storage.js. */
function fromDisk(partitions) {
  if (partitions && partitions.skipped) return [nativeSkipFinding("HOST-DISK-SKIP", "Almacenamiento", partitions, "disk")];
  if (!Array.isArray(partitions)) return [];
  return partitions.map((p, i) => {
    const sev = diskSeverity(p.usedPercent);
    // Los demás montajes del mismo sistema de ficheros van en la evidencia.
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

/** Finding informativo con el inventario de software (los CVE los pone Trivy).
 *  `raw` es un array de paquetes, un skip { skipped, kind, reason } o un inventario parcial. */
function fromSwInventory(raw, platform, pkgManager) {
  if (!raw) return [];

  // La fuente no llegó a mirar: aviso explícito, igual que HOST-LYN-SKIP y HOST-CVE-SKIP.
  if (raw.skipped) {
    return [skippedSourceFinding("sw-inventory", raw, platform, "HOST-SW")];
  }

  const isPartial = raw.partial === true;
  const pkgs = isPartial ? raw.packages : raw;
  if (!Array.isArray(pkgs)) return [];

  const findings = [];

  // Va antes del recuento; sin sufijo -SKIP porque sí se inventarió, aunque de forma incompleta.
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

/** Cómo se aplican las actualizaciones. Texto y nunca comando: aplicarlas lo decide el usuario. */
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

/** Un finding con los parches pendientes: medium si alguno es de seguridad, low si hay
 *  pendientes sin clasificar, info si no hay ninguno. */
function fromPendingUpdates(raw, platform, pkgManager) {
  if (!raw) return [];
  if (raw.skipped) {
    return [skippedSourceFinding("pending-updates", raw, platform, "HOST-UPD")];
  }

  const updates = Array.isArray(raw.updates) ? raw.updates : [];
  const total = typeof raw.total === "number" ? raw.total : updates.length;
  // 'full' clasifica todas, 'none' ninguna, 'partial' solo una parte (macOS).
  const deteccion = raw.securityDetection || "none";
  const secCount = typeof raw.securityCount === "number" ? raw.securityCount : null;
  // Sin clasificar no es lo mismo que "no son de seguridad": se cuenta y se dice aparte.
  const sinClasificar = typeof raw.unclassifiedCount === "number" ? raw.unclassifiedCount : 0;
  // Windows: reinicio pendiente (true/false/null); null es que no se pudo leer el registro.
  const reboot = raw.rebootPending === true ? true : raw.rebootPending === false ? false : null;

  let severity;
  // Una de seguridad sube a medium aunque la clasificación sea parcial, y un reinicio
  // pendiente también: la corrección instalada no está aplicada hasta reiniciar.
  if (total === 0 && reboot === true) severity = "medium";
  else if (total === 0) severity = "info";
  else if (secCount > 0) severity = "medium";
  else severity = "low";

  // Las sin clasificar van en el título para no leer el resto como "no son de seguridad".
  const sufijoSc = sinClasificar > 0 ? ` (${sinClasificar} sin clasificar)` : "";
  // Sin poder leer el registro no se puede afirmar "al día".
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
      // Va primero porque contradice el "no hay nada pendiente" que viene después.
      partes.push(
        "Este equipo tiene actualizaciones YA INSTALADAS que no se aplicarán hasta que reinicies. " +
        "Hasta entonces sigues ejecutando la versión anterior, con sus fallos sin corregir. " +
        "Reinicia el equipo cuando puedas."
      );
    }
    partes.push(`No hay actualizaciones pendientes de descargar según ${raw.source || "el gestor del sistema"}.`);
    // En un Windows gestionado (WSUS, Intune) una lista vacía no significa "al día", y la
    // consulta no distingue un equipo gestionado de uno que no lo está.
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
      // El Title de macOS ya termina en la versión disponible: se recorta antes de añadirla.
      const base = u.newVersion && String(u.name).endsWith(u.newVersion)
        ? String(u.name).slice(0, -u.newVersion.length).trim()
        : String(u.name);
      // Flecha solo con las dos versiones; si falta la instalada, solo la disponible.
      const ver = u.currentVersion && u.newVersion
        ? ` ${u.currentVersion} → ${u.newVersion}`
        : (u.newVersion ? ` ${u.newVersion}` : "");
      // Tres marcas: de seguridad, no de seguridad y desconocido.
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

    // No saber no es lo mismo que "no hay de seguridad".
    if (deteccion === "none") {
      partes.push(
        "Este sistema no indica cuáles de estas actualizaciones son de seguridad, así que conviene " +
        "revisarlas todas. Que no aparezca ninguna marcada NO significa que no las haya."
      );
      // Se indica dónde está el dato, sin URL por distribución porque envejece.
      if (plat === "linux") {
        partes.push(
          "Ese detalle sí lo publica tu distribución: consúltalo en su boletín de seguridad o en " +
          "las notas de publicación de cada paquete."
        );
      }
    } else if (deteccion === "partial") {
      // Lo que consta y lo que no se puede saber.
      partes.push(
        (secCount > 0
          ? `${secCount} están marcadas como de seguridad: son los datos de protección de macOS ` +
            "(XProtect, MRT, Gatekeeper). "
          : "Ninguna de las pendientes es una actualización de datos de protección de macOS " +
            "(XProtect, MRT, Gatekeeper). ") +
        "Las actualizaciones del propio sistema no se pueden clasificar: softwareupdate no indica " +
        "si incluyen correcciones de seguridad, así que conviene revisarlas igualmente. " +
        // Apple publica ese detalle en Ajustes y en sus notas de seguridad.
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

  // Instalar lo pendiente y aplicar lo instalado son cosas distintas: el aviso va igual.
  if (reboot === true && total > 0) {
    partes.push(
      "Además, hay actualizaciones ya instaladas que no se aplicarán hasta que reinicies el equipo."
    );
  }
  // No se pudo mirar: "no lo sé" no es "no hay".
  if (reboot === null && (plat === "win32" || raw.platform === "win32")) {
    partes.push(
      "No se ha podido comprobar si hay actualizaciones instaladas esperando un reinicio, así que " +
      "este resultado no lo incluye."
    );
  }

  // Va al final para que no se lea como una corrección de lo anterior.
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
      // Sin actualizaciones no hay pasos que dar.
      fix: total === 0 ? null : updateFixText(raw, platform, pkgManager),
      // Aplicar actualizaciones nunca se ofrece como comando copiable.
      command: null,
      isCommand: false,
      category: "system",
      source: "native",
    }),
  ];
}

/** Etiqueta en español del prefijo del control; viaja como `subcategory` y agrupa las tarjetas. */
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

/** Vocabulario cerrado del campo 4: solo se interpreta el token exacto, la prosa se descarta. */
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

/** Orden del campo 3, solo con la forma `Run '…'`: el campo trae sobre todo datos ('/home'). */
function commandFromDetail(detail) {
  const m = /^Run\s+'([^']+)'/.exec((detail || "").trim());
  return m ? m[1] : null;
}

/** Clave estable: ID + descripción + detalle. Un mismo ID puede salir varias veces en el .dat. */
function lynisFindingId(entry) {
  const key = [entry.id, entry.description, entry.detail || ""].join("\u0000");
  const hash = crypto.createHash("sha1").update(key).digest("hex").slice(0, 6);
  return `HOST-LYN-${entry.id}-${hash}`;
}

/** Empareja aviso y sugerencia del mismo control y detalle (problema y remedio), por orden de aparición. */
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

/** Kinds que significan "aquí no aplica" y no "ha fallado": no se arreglan reintentando.
 *  'not-installed' no está porque una herramienta que falta sí se instala. */
const SKIP_KINDS_NO_APLICA = new Set([
  "unsupported", "os-unsupported", "nothing-to-scan", "not-applicable", "no-version",
]);

/** ¿Este kind es un límite del sistema en vez de un fallo? */
function esNoAplica(kind) {
  return SKIP_KINDS_NO_APLICA.has(String(kind || ""));
}

/** Aviso info de que una fuente no llegó a mirar, para que no parezca un sistema limpio. */
function skippedSourceFinding(tool, raw, platform, idPrefix = "", context = "host", category = "vulnerability") {
  // El reason llega con su punto y aquí se cierra si falta; una elipsis final se respeta.
  const reason = String(raw.reason || "sin detalle").trim().replace(/(?<!\.\.)\.?$/, ".");
  const kind = raw.kind || null;
  // Un límite del sistema no se redacta como un fallo.
  const noAplica = esNoAplica(kind);
  // Fallo, apagado por el usuario y límite de la plataforma se redactan distinto.
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
      // Separa "limpio" de "no se pudo mirar" sin depender del sufijo del id.
      skipped: true,
      // Separa "lo apagaste tú" de "se intentó y falló".
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
      // Separa "limpio" de "no se pudo mirar" sin depender del sufijo del id.
      skipped: true,
      // Separa "lo apagaste tú" de "se intentó y falló".
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
      // Separa "limpio" de "no se pudo mirar" sin depender del sufijo del id.
      skipped: true,
      // Separa "lo apagaste tú" de "se intentó y falló".
      kind,
      notApplicable: noAplica,
    });
  }

  if (tool === "trivy-secrets") {
    return createFinding({
      id: `${idPrefix}-SKIP`,
      title: noAplica
        ? "Secretos y configuraciones en ficheros: no aplica en este sistema"
        : apagado
        ? "Secretos y configuraciones en ficheros: desactivado en el nodo"
        : "Secretos y configuraciones en ficheros: no se han podido analizar",
      severity: "info",
      evidence:
        `No se ha buscado si hay contraseñas, claves o configuraciones inseguras en tus ficheros: ${reason} ` +
        'Que no aparezca ninguna aquí significa "sin analizar", no "sin secretos".',
      fix: apagado
        ? "Lo has desactivado tú en las opciones del nodo audit-host. Vuelve a marcarlo si quieres que la próxima " +
          "auditoría busque secretos y configuraciones inseguras en tu carpeta personal."
        : trivySkipFix(kind, context),
      category,
      source: "trivy",
      isCommand: false,
      skipped: true,
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
    // Separa "limpio" de "no se pudo mirar" sin depender del sufijo del id.
    skipped: true,
    // Separa "lo apagaste tú" de "se intentó y falló".
    kind,
    notApplicable: noAplica,
  });
}

/** Qué hacer con un Lynis omitido, según por qué se omitió. */
function lynisSkipFix(kind, platform) {
  // Apagado por el usuario: no es un fallo y no hay nada que arreglar.
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
  // Apagado por el usuario: no es un fallo y no hay nada que arreglar.
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

/** Un finding por entrada del .dat; el volumen se controla con la severidad, no ocultando. */
function fromLynisRaw(raw, platform, pkgManager) {
  if (!raw) return [];
  if (raw.skipped) return [skippedSourceFinding("lynis", raw, platform)];

  const items = pairLynisEntries(raw.warnings || [], raw.suggestions || []);
  const findings = [];

  // Veces que sale cada control: solo se desambigua el título de los repetidos.
  const vecesPorControl = new Map();
  for (const { entry } of items) {
    vecesPorControl.set(entry.id, (vecesPorControl.get(entry.id) || 0) + 1);
  }

  // El discriminador se elige por grupo con pickLynisDiscriminators().
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
    // Por ID completo, desde lib/lynis-i18n.js.
    const lynFix = lynisFix(entry.id, platform, pkgManager, installCmd);
    const solution = parseSolutionType(entry.solution);

    // Orden del fix: token del campo 4, paso de este SO y orden exacta de Lynis si la da.
    const steps = [];
    // Si el control no admite acción no se añade ningún paso.
    if (!lynFix.noAction) {
      if (solution.actionType === "reboot") {
        steps.push("Reinicia el equipo para que el cambio surta efecto.");
      }
      // El remedio de Lynis viene en inglés: va a la evidencia, no aquí.
      if (lynFix.fix && !solution.actionType) steps.push(lynFix.fix);

      // El campo 3 es de esta instancia y, con la forma `Run '…'`, una orden literal.
      const cmdDetalle = commandFromDetail(entry.detail);
      if (cmdDetalle) steps.push(cmdDetalle);
    }
    const detailCmd = commandFromDetail(entry.detail);

    // Traducción por ID contra la tabla estática, nunca con el LLM: el informe debe ser reproducible.
    const traduccion = lynisText(entry.id, entry.description);

    // Matiz para distinguir instancias del mismo control (punto de montaje, minimum/maximum).
    const repetido = traduccion.translated && (vecesPorControl.get(entry.id) || 0) > 1;
    const disc = repetido ? (discPorControl.get(entry.id) || new Map()).get(entry) : null;
    // Si el matiz es la frase original en inglés, se dice.
    const matiz = disc ? (disc.translated ? disc.text : `en inglés: ${disc.text}`) : "";
    const titulo = matiz ? `${traduccion.text} (${matiz})` : traduccion.text;

    const evidenceParts = [traduccion.text];
    // El original solo se repite si se ha traducido; si no, sería la misma frase dos veces.
    if (traduccion.translated && entry.description && entry.description !== traduccion.text) {
      evidenceParts.push(`Texto original de Lynis: ${entry.description}`);
    } else if (!traduccion.translated) {
      evidenceParts.push(
        "Este control todavía no está traducido en LoCoAudit, así que se muestra el texto " +
        `original de Lynis (${entry.id}).`
      );
    }
    if (entry.detail && !detailCmd) evidenceParts.push(entry.detail);
    // El remedio emparejado va a la evidencia, etiquetado: llega en inglés y sin traducir.
    if (remedy && remedy.description) {
      evidenceParts.push(`Sugerencia original de Lynis: ${remedy.description}`);
    }

    findings.push(
      createFinding({
        id: lynisFindingId(entry),
        // El título es la descripción; el código va como metadato.
        title: titulo,
        severity: lynisSeverity(entry.id, type),
        evidence: evidenceParts.join(" · "),
        // null cuando no hay ningún paso real que dar.
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
        // Ficha oficial del control: el .dat solo trae URL en unos pocos.
        primaryUrl: solution.primaryUrl || lynisControlUrl(entry.id),
        advisoryLabel: solution.primaryUrl ? null : `Control ${entry.id} de Lynis`,
        // No admite acción, que no es lo mismo que no tener el paso escrito.
        noAction: lynFix.noAction,
        // Lynis no puntúa: el nivel lo pone LoCoAudit.
        severitySource: "locoaudit",
        // false: el título está en inglés y el dashboard lo marca.
        translated: traduccion.translated,
      })
    );
  }

  return findings;
}

// security-events cuenta quién entró, cuándo y desde dónde. Los fixes nunca bloquean usuarios ni IPs.

/** Rutas de OpenSSH por plataforma. En Windows los administradores usan administrators_authorized_keys. */
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

// Consejo único para cuenta administradora, compartido por el acceso SSH y el 4672 suelto.
const ADMIN_ACCOUNT_FIX =
  "Comprueba que reconoces este acceso. El aviso NO dice que se ejecutara nada con permisos " +
  "elevados: dice que la cuenta con la que se entró es una cuenta de administrador, así que " +
  "quien tenga sus credenciales puede hacer cambios en todo el equipo.\n" +
  "Para el uso remoto del día a día, entra con una cuenta normal y reserva la de administrador " +
  "para cuando de verdad haga falta. Revisa también qué cuentas pueden conectarse en remoto y " +
  "quita de esa lista las que no lo necesiten.";

const MAX_SEC_INDIVIDUAL = 10; // logins SSH individuales antes de agregar

/** ¿El acceso SSH se hizo con una identidad privilegiada? root en Unix, o un 4672 correlacionado en Windows. */
function privilegedSshIdentity(access, ctx) {
  if (access && access.user === "root") return { kind: "root", events: [] };
  const events = typeof ctx.winPrivileged === "function" ? ctx.winPrivileged(access) || [] : [];
  return events.length > 0 ? { kind: "admin-group", events } : null;
}

/** Título según cómo se cumplió el predicado: "root" no existe en Windows. */
function privilegedSshTitle(kind) {
  return kind === "root"
    ? "Acceso SSH como root detectado"
    : "Acceso SSH con una cuenta que tiene privilegios de administrador";
}

/** Por qué el acceso se clasificó como privilegiado; en Windows, con el evento y su LogonId. */
function privilegedSshNote(identity) {
  if (!identity || identity.kind !== "admin-group") return "";
  const ids = [...new Set(identity.events.map((e) => e.logonId).filter(Boolean))];
  return (
    " · Evento 4672" + (ids.length ? ` (LogonId ${ids.join(", ")})` : "") +
    ": Windows registra que la cuenta pertenece al grupo Administradores"
  );
}

/** Findings de accesos SSH. Común a los tres sistemas: OpenSSH escribe igual en todos. */
function sshFindings(ssh, ctx) {
  const { W, R, sshHarden, sshReview } = ctx;
  const findings = [];

  // Identidad privilegiada: high individual. El resto, info con tope MAX_SEC_INDIVIDUAL y un agregado.
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

  // Fuentes no disponibles: info, pero marcado como comprobación no realizada.
  if (raw.skipped) {
    const kind = raw.kind || "error";
    findings.push(
      createFinding({
        id: "HOST-EVT-SKIP",
        title: kind === "no-permission"
          ? "Eventos de seguridad: sin permisos para leer los logs"
          : "Eventos de seguridad: fuentes de log no disponibles",
        severity: "info",
        evidence: `${String(raw.reason || "sin detalle").trim()}. ` +
          "Que no aparezcan eventos aquí no significa que no los haya, significa que no se han podido leer.",
        fix:
          "Comprobar el acceso a los logs del sistema: en Linux, journalctl o /var/log/auth.log legible " +
          "(añadir el usuario al grupo adm/systemd-journal si es necesario); en macOS, el comando `log`; " +
          "en Windows, PowerShell disponible y la cuenta en el grupo «Lectores del registro de eventos» " +
          "(«Event Log Readers»), que da lectura del canal Security sin elevar. " +
          "Ejecutar Node-RED con un usuario con permisos de lectura sobre los logs, no con privilegios elevados.",
        category: "system-logs",
        source: "security-events",
        isCommand: false,
        skipped: true,
        kind,
        notApplicable: esNoAplica(kind),
      })
    );
    return findings;
  }

  // El canal Security se excluye si ya tiene su propio finding, para no contarlo dos veces.
  const securityDenied = !!(raw.windows && raw.windows.securityLogDenied);
  const partialSources = (Array.isArray(raw.partial) ? raw.partial : []).filter(
    (p) => !(securityDenied && p.source === "Get-WinEvent(Security)")
  );
  if (partialSources.length > 0) {
    findings.push(
      createFinding({
        id: "HOST-EVT-SRC",
        title: `Eventos de seguridad: ${partialSources.length} fuente(s) no disponibles`,
        severity: "info",
        evidence: partialSources.map((p) => `${p.source}: ${p.reason}`).join(" · "),
        fix: "La auditoría se completó con las fuentes restantes. Para cobertura completa, revisar permisos de lectura de logs.",
        category: "system-logs",
        source: "security-events",
      })
    );
  }

  // Windows: 4624/4625/4672 del canal Security. SSH llega por OpenSSH/Operational, como en Unix.
  if (raw.platform === "win32" || raw.windows) {
    const winSsh = raw.ssh || { accepted: [], failed: [] };
    // La correlación se calcula una vez y se pasa a las dos mitades para no duplicar findings.
    const corr = correlateWindowsLogons(raw);
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
        id: "HOST-EVT-INF",
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

// Rama Windows: 4624 tipo 10/3 ≈ login SSH, 4625 ≈ fallidos, 4672 remoto ≈ root, RDP ≈ sesión remota.

// La elevación (UAC/4688) no se audita.

// Desactivar el Escritorio remoto cierra el acceso; el cortafuegos solo lo filtra. Ramas excluyentes,
// y empieza por salto de línea porque "## " solo abre rama al inicio de línea.
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

// SID de "Event Log Readers": estable entre idiomas, a diferencia del nombre del grupo.
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

/** Findings del canal Security (4624/4625/4672). Se descarta lo que ya cuenta un finding de SSH. */
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
        // Sin pedir Node-RED como administrador: el grupo de lectores del registro basta.
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

  // Locales: solo recuento, y solo si hubo remotos.
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

  // 4672: remoto, high individual; local, agregado. Indica que la cuenta es administradora, no que la sesión esté elevada.
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

  // Los accesos SSH cuentan aunque el canal Security no se pueda leer.
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
        id: "HOST-EVT-INF",
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

// El ecosistema sale del campo Type de cada Result, nunca de la ruta: adivinar da gestores cruzados.

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

/** Gestores que actualizan dentro del rango declarado: con un salto de versión mayor no actualizan.
 *  `yarn upgrade` es de Yarn 1; en Yarn 2+ es `yarn up`. */
const RANGE_MANIFEST = {
  cargo: "Cargo.toml", npm: "package.json", pnpm: "package.json", yarn: "package.json",
  poetry: "pyproject.toml", bundler: "Gemfile", gemspec: "el .gemspec", composer: "composer.json",
};
function rangeNote(type, pkg, ver) {
  const manifest = RANGE_MANIFEST[type];
  if (!manifest) return null;
  const cual = ver ? `la versión ${ver}` : "la versión corregida";
  const extra = type === "yarn" ? " Con Yarn 2 o posterior, la orden es yarn up." : "";
  return `Actualiza dentro del rango que declara ${manifest}: si ${cual} queda fuera de ese rango, ` +
         `ajusta la versión de ${pkg} en ${manifest} y vuelve a ejecutarla.${extra}`;
}

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

/** Prefijos administrados por el gestor del SO (en Arch, pip --upgrade sobre /usr/lib falla por PEP 668). */
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
  // Sin estos, en Arch se acababa proponiendo apt.
  "arch", "archlinux", "gentoo",
]);

/** Comando para actualizar un paquete del SO en el host; el gestor sale del Type. */
function osHostUpdateCmd(type, pkg, ver, pkgManager) {
  // Primero el Type de Trivy y si no el gestor del equipo. Nunca se asume apt.
  const mgr = managerForTrivyType(type) || pkgManager || null;
  const cmd = upgradeCmd(mgr, pkg);
  // Con gestor conocido, el fix es el propio comando.
  if (cmd) return { fix: cmd, command: cmd };
  const verTxt = ver ? ` a la versión ${ver}` : "";
  return {
    fix: `Actualiza ${pkg}${verTxt} con el gestor de paquetes de tu distribución.`,
    command: null,
  };
}

/** Paso de resolución de un paquete vulnerable en el host. Sin Type no se adivina el ecosistema. */
function getTrivyFixCommand(target, pkgName, fixedVersion, platform, pkgType = "", pkgManager = null, meta = {}) {
  if (!pkgName) return { fix: null, command: null };
  const pkg = pkgName.split("@")[0];
  const ver = fixedVersion || null;
  const type = String(pkgType || "").toLowerCase();
  const location = meta.location || target || null;

  // Sin PkgPath, Trivy leyó un lockfile: no hay nada que actualizar en el equipo.
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
    // La nota va en línea aparte: `command` copia solo el comando.
    const nota = rangeNote(type, pkg, ver);
    return { fix: nota ? `${cmd}\n${nota}` : cmd, command: cmd };
  }

  // python-pkg y node-pkg son instalaciones reales; bajo un prefijo del sistema manda el gestor del SO.
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
      return { fix: `${cmd}\n${rangeNote("npm", pkg, ver)}`, command: cmd };
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

/** JSON de `trivy fs` o `trivy image` a findings, agrupados por paquete (N CVE → 1 finding) y por severidad. */

/** Pasos de resolución de un finding de imagen: la imagen es inmutable, se cambia el tag o se reconstruye.
 *  "## " abre una rama y "> " es una nota. */
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
    "Valora una imagen base más pequeña y mantenida, como una variante slim, alpine o distroless:",
    "menos paquetes = menos superficie de ataque.",
    "## Si la imagen es propia",
    "Reconstrúyela sobre una base actualizada (FROM al día) y vuelve a escanear.",
    "Si el paquete es una dependencia de tu aplicación (npm, pip, Maven…), actualízala en el proyecto antes de reconstruir.",
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

/** Advisory fiable: la PrimaryURL de avd.aquasec.com da 404 en CVE recientes, se prefiere el tracker del DataSource. */
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
/** Procedencia del paquete: con PkgPath, fichero en disco; con Class 'os-pkgs', instalado por el gestor. */
function originOf(result, v) {
  const fromOsDb = result && result.Class === "os-pkgs";
  return fromOsDb || v.PkgPath ? "installed" : "declared";
}

/** Finding agregado de vulnerabilidades no accionables: info y sin `fix`, pero visibles. */
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
    // Sin `fix`: no hay acción que ofrecer.
    fix: null,
    category: "system",
    source,
    origin,
    // Resume muchos hallazgos, no describe un dato del equipo.
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

/** HOST-CVE-DECLARED: todas las versiones declaradas en lockfiles del host en un solo finding. */
function buildDeclaredAggregate(declared) {
  const n = declared.length;
  const nFicheros = _contarFicheros(declared);
  const conFix = declared.filter((x) => x.v && x.v.FixedVersion).length;

  const ficheros = nFicheros === 1 ? "1 fichero de dependencias" : `${nFicheros} ficheros de dependencias`;
  // La cifra de corregibles va junto a la aclaración para que no se lea como una lista de tareas.
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
      `${fix} Esa versión corregida es la que el fichero declara, no un paquete instalado en tu equipo.`,
      "Se informan por transparencia, no como tarea pendiente.",
      "El detalle completo está en la exportación JSON.",
    ],
    source: "trivy",
    // Con origin 'declared', isActionable() lo deja fuera del riesgo global.
    origin: "declared",
  });
}

/** Resumen de las comprobaciones omitidas para el panel de Alcance, derivado de los `*-SKIP`. null si no hay. */
function buildSkippedChecksSummary(findings) {
  const omitidas = (findings || []).filter((f) => f && f.skipped === true);
  if (!omitidas.length) return null;

  // Apagada, no aplica y fallida se cuentan por separado.
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
      // Solo las fallidas dejan un hueco; las otras son alcance conocido.
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
    // Una línea por módulo, con el título del propio finding.
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

/** Reparto por severidad en castellano: "72 críticas, 736 altas…". Las claves ausentes no se nombran. */
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

/** Paquetes del sistema (lib/trivy-rootfs.js): un finding por paquete con corrección y uno
 *  agregado (HOST-OS-CVE-UNFIXED) para los que no la tienen. */
function fromTrivyRootfs(raw, platform, pkgManager) {
  if (!raw) return [];
  if (raw.skipped) return [skippedRootfsFinding(raw, platform)];

  const findings = [];
  const label = osLabel(raw.os);
  const pkgNum = raw.pkgNum != null ? raw.pkgNum : null;

  // Un paquete puede estar en dos versiones (multiarch): entonces la versión entra en el id para no repetirlo.
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
      // Id por nombre de paquete para que se mantenga entre ejecuciones.
      id: repetidos.has(grp.pkg)
        ? `HOST-OS-PKG-${grp.pkg}@${grp.installedVersion || "sin-version"}`
        : `HOST-OS-PKG-${grp.pkg}`,
      title: `${grp.pkg} ${version} — ${n} ${n === 1 ? "vulnerabilidad corregida" : "vulnerabilidades corregidas"} en ${grp.fixedVersion}`,
      // La máxima del grupo: la urgencia la marca la peor.
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
      // Leído de la base de datos del gestor: cuenta para el riesgo global.
      origin: "installed",
    }));
  }

  // Un único finding para todo lo que no tiene corrección.
  const unfixed = raw.unfixed || { total: 0, bySeverity: {} };
  if (unfixed.total > 0) {
    const desglose = severityPhrase(unfixed.bySeverity);
    const paquetes = pkgNum != null ? `${pkgNum} paquetes analizados` : "paquetes del sistema analizados";

    // Misma factoría que HOST-CVE-DECLARED.
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

/** Paquetes del sistema no analizados, con texto propio: 'os-unsupported' es un límite de la plataforma. */
function skippedRootfsFinding(raw, platform) {
  const reason = String(raw.reason || "sin detalle").trim().replace(/(?<!\.\.)\.?$/, ".");
  const kind = raw.kind || null;

  let fix;
  // Apagado por el usuario: no es un fallo y no hay nada que arreglar.
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
    // En imagen cada fallo ya sale como IMG-SCAN-ERR desde el nodo; no se cuenta dos veces.
    if (context === "image" && Array.isArray(raw.failed) && raw.failed.length) return [];
    return [skippedSourceFinding("trivy", raw, platform, idPrefix, context, category)];
  }

  // Campos externos que acaban en el fix: un salto de línea fabricaría un "$ orden" copiable.
  const oneLine = (s) => (typeof s === "string" ? s.replace(/[\x00-\x1f\x7f\u2028\u2029]+/g, " ") : s);
  const VULN_ID_FIELDS = ["VulnerabilityID", "PkgName", "PkgID", "PkgPath", "InstalledVersion", "FixedVersion"];
  const results = (raw.Results || []).map((r) => ({
    ...r,
    Target: oneLine(r.Target),
    __image: oneLine(r.__image),
    Vulnerabilities: (r.Vulnerabilities || []).map((v) => {
      const c = { ...v };
      for (const k of VULN_ID_FIELDS) c[k] = oneLine(c[k]);
      return c;
    }),
  }));

  const seen = new Set();
  const allVulns = [];   // { v, target, sev }

  for (const result of results) {
    const target = result.Target || "unknown";
    // Ecosistema del Result; se propaga hasta getTrivyFixCommand para elegir el gestor.
    const type = result.Type || "";
    // Etiqueta de imagen del Result: agrupa los hallazgos cuando se escanean varias.
    const image = result.__image || "";

    // Dependencias de desarrollo de Homebrew Cellar: bajan un nivel de severidad.
    const isDevDependency = (result.Target || "").includes("/Cellar/") &&
      ["phpmyadmin", "protobuf", "playwright", "python"].some((t) =>
        (result.Target || "").toLowerCase().includes(t));

    for (const v of (result.Vulnerabilities || [])) {
      // La procedencia entra en la clave para no descartar el instalado si antes salió el declarado.
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

  // Las declaradas se colapsan antes de repartir por severidad, porque los resúmenes mezclados
  // pierden el `origin`. Solo en host: en audit-image son el contenido del informe.
  const declared = opts.collapseDeclared ? allVulns.filter((x) => x.origin === "declared") : [];
  const restantes = opts.collapseDeclared ? allVulns.filter((x) => x.origin !== "declared") : allVulns;

  // Un paquete con N CVEs da un finding, con la severidad más alta del grupo.
  const pkgGroups = new Map();
  const medByTarget    = new Map();   // image|target → { image, target, vulns[] }
  const lowInfoByImage = new Map();   // image → { image, count, targets:Set }

  for (const item of restantes) {
    const { v, target, sev, image, type, origin, location } = item;
    if (sev === "critical" || sev === "high") {
      // El mismo paquete en dos imágenes, o declarado e instalado, son grupos distintos.
      const pkgKey = `${image}|${origin}|${v.PkgName}:${v.InstalledVersion || ""}`;
      if (!pkgGroups.has(pkgKey)) {
        pkgGroups.set(pkgKey, { items: [], maxSev: sev, target, image, type, origin, location });
      }
      const grp = pkgGroups.get(pkgKey);
      grp.items.push(item);
      grp.maxSev = max(grp.maxSev, sev);
    } else if (sev === "medium") {
      // Medium agrupado por imagen, o por target si no hay imagen.
      const medKey = image || target;
      if (!medByTarget.has(medKey)) medByTarget.set(medKey, { image, target, vulns: [], origins: new Set() });
      medByTarget.get(medKey).vulns.push(v);
      medByTarget.get(medKey).origins.add(origin);
    } else {
      // Low/info agrupados por imagen, o globales si no hay imagen.
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

  // Un resumen solo lleva procedencia si todos sus ítems coinciden.
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

    // En imagen, el fix es de tag; en host, el comando real que fija quien lo genera.
    let fixText, fixCommand;
    if (context === "image") {
      fixText = buildImageFix({ image: image || target, pkg: first.PkgName, fixedVersion });
      fixCommand = null;   // una imagen nunca se arregla con un comando único
    } else if (origin === "declared") {
      // En un lockfile no hay software que actualizar, haya o no FixedVersion.
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
      // null: sin botón; string: botón «Copiar».
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

  // El agregado de las declaradas va al final: es contexto, no tarea.
  if (declared.length) findings.push(buildDeclaredAggregate(declared));

  // Carpetas del home donde Trivy falló: un hueco, no un "sin vulnerabilidades".
  const caidas = context === "host" && raw.scan && raw.scan.children
    ? (raw.scan.children.skipped || []).filter((c) => c.kind === "error")
    : [];
  if (caidas.length) {
    const nombres = caidas.slice(0, 5).map((c) => `~/${oneLine(c.name)}`).join(", ");
    findings.push(createFinding({
      id: `${idPrefix}-PARTIAL`,
      title: caidas.length === 1
        ? "Vulnerabilidades del home: 1 carpeta sin analizar"
        : `Vulnerabilidades del home: ${caidas.length} carpetas sin analizar`,
      severity: "info",
      evidence:
        `Trivy no pudo terminar en ${nombres}${caidas.length > 5 ? " y otras" : ""}. ` +
        "Que no haya CVE de esas carpetas no significa que estén limpias, significa que no se han analizado.",
      fix: "Si es una unidad de red o de la nube, indica en el nodo una carpeta concreta a auditar.\n" +
           "Si el motivo es el tiempo, vuelve a lanzar la auditoría: la segunda pasada suele ser más rápida.",
      command: null,
      category,
      source,
      isCommand: false,
      skipped: true,
      kind: "error",
    }));
  }

  return findings;
}

/* ── Secretos y configuraciones inseguras (Trivy) ───────────────────────────────────────── */

/** Fichas en castellano de los controles de Dockerfile más habituales; el resto sale con el texto de Trivy. */
const TRIVY_MISCONF_ES = {
  "DS-0001": {
    title: "La imagen base usa la etiqueta :latest",
    fix: "Fija una versión concreta de la imagen base en la instrucción FROM, por ejemplo ubuntu:24.04.\n" +
         "> Con :latest cada construcción puede partir de una base distinta y un fallo nuevo entra sin que nadie lo note.",
  },
  "DS-0002": {
    title: "La imagen se ejecuta como root",
    fix: "Crea un usuario sin privilegios en el Dockerfile y declara USER antes del CMD.\n" +
         "Reconstruye la imagen.\n" +
         "> El usuario tiene que existir dentro de la imagen: un USER que no está creado hace fallar el arranque.",
  },
  "DS-0004": {
    title: "La imagen expone el puerto 22 de SSH",
    fix: "Quita la línea EXPOSE 22 del Dockerfile.\n" +
         "Para entrar en un contenedor usa docker exec en lugar de un servidor SSH dentro de él.",
  },
  "DS-0009": {
    title: "WORKDIR usa una ruta relativa",
    fix: "Usa una ruta absoluta en WORKDIR, por ejemplo WORKDIR /app.",
  },
  "DS-0010": {
    title: "Una instrucción RUN usa sudo",
    fix: "Quita sudo de las instrucciones RUN y pon los pasos que necesitan root antes de la instrucción USER.",
  },
  "DS-0013": {
    title: "Se cambia de directorio con RUN cd",
    fix: "Cambia de directorio con la instrucción WORKDIR en lugar de RUN cd.",
  },
  "DS-0015": {
    title: "Falta yum clean all tras instalar paquetes",
    fix: "Añade yum clean all al final de la instrucción RUN que instala con yum, para no dejar su caché dentro de la imagen.",
  },
  "DS-0017": {
    title: "La actualización del índice de paquetes va en una instrucción aparte",
    fix: "Une la actualización del índice y la instalación en una sola instrucción RUN, por ejemplo apt-get update && apt-get install -y paquete.\n" +
         "> Separadas, la capa de la actualización sale de la caché y se instalan versiones antiguas de los paquetes.",
  },
  "DS-0021": {
    title: "apt-get se usa sin la opción -y",
    fix: "Añade -y a apt-get install para que la construcción no se quede esperando una confirmación.",
  },
  "DS-0022": {
    title: "Se usa MAINTAINER, que está obsoleto",
    fix: "Sustituye MAINTAINER por una etiqueta, por ejemplo LABEL maintainer=\"tu nombre\".",
  },
  "DS-0025": {
    title: "apk add se usa sin --no-cache",
    fix: "Añade --no-cache a apk add para no dejar el índice de paquetes dentro de la imagen.",
  },
  "DS-0026": {
    title: "La imagen no define HEALTHCHECK",
    fix: "Añade una instrucción HEALTHCHECK que compruebe que el servicio responde, para que Docker detecte un contenedor colgado.",
  },
  "DS-0029": {
    title: "apt-get se usa sin --no-install-recommends",
    fix: "Añade --no-install-recommends a apt-get install para no instalar paquetes que la imagen no necesita.\n" +
         "> Cada paquete de más es superficie de ataque y vulnerabilidades que mantener.",
  },
  "DS-0031": {
    title: "Hay secretos en variables de entorno, argumentos de construcción o ficheros copiados",
    fix: "Revoca o cambia la credencial en el servicio que la emitió: la que va en la imagen ya debe darse por expuesta.\n" +
         "Para la construcción usa montajes de secretos (RUN --mount=type=secret) y para la ejecución, Docker secrets o un volumen.\n" +
         "Reconstruye la imagen sin el secreto.\n" +
         "> Un valor puesto con ENV o ARG queda en el historial de la imagen aunque se borre en una capa posterior.",
  },
};

/** Ficha de un control de configuración: la nuestra si existe, la de Trivy si no. */
function misconfSheet(m) {
  const es = TRIVY_MISCONF_ES[m.ID];
  if (es) return { title: es.title, fix: es.fix };
  const res = (m.Resolution || "").trim();
  return {
    title: m.Title || m.ID || "Configuración insegura",
    fix: res
      ? `Recomendación de Trivy, en inglés: ${res}\n> La ficha enlazada explica el control y cómo corregirlo.`
      : "Consulta la ficha enlazada: explica el control y cómo corregirlo.",
  };
}

/** Nombre en castellano de las reglas de secretos conocidas; el resto, con su título. */
const TRIVY_SECRET_ES = {
  "private-key": "Clave privada",
  "github-pat": "Token personal de GitHub",
  "github-oauth": "Token OAuth de GitHub",
  "gitlab-pat": "Token personal de GitLab",
  "jwt-token": "Token JWT",
  "openai-project-api-key": "Clave de API de OpenAI",
  "azure-storage-account-key": "Clave de cuenta de almacenamiento de Azure",
  "gcp-service-account": "Cuenta de servicio de Google Cloud",
  "sendgrid-api-token": "Token de API de SendGrid",
  "maven-settings-password": "Contraseña en settings.xml de Maven",
  "maven-settings-passphrase": "Frase de paso en settings.xml de Maven",
  "symfony-default-secret": "Secreto por defecto de Symfony",
};

/** Trivy enmascara `Match` con asteriscos; si alguna versión no lo hiciera, no se enseña nada. */
function maskedMatch(sec) {
  const m = String(sec.Match || "").replace(/[\x00-\x1f\x7f]+/g, " ").trim();
  if (!m || !m.includes("*")) return null;
  return m.length > 120 ? m.slice(0, 117) + "..." : m;
}

const SECRET_FIX_HOST =
  "Comprueba si el valor es una credencial real y si sigue en uso.\n" +
  "Si lo es, revócala o cámbiala en el servicio que la emitió: la que hay en el fichero ya debe darse por expuesta.\n" +
  "Quita el valor del fichero y guárdalo en un gestor de contraseñas o de secretos.\n" +
  "> Si el fichero está en un repositorio Git, borrarlo ahora no lo quita del historial.";

const KEY_FIX_HOST =
  "Comprueba si la clave sigue en uso y en qué servidores está autorizada.\n" +
  "Si la necesitas, muévela a la carpeta .ssh de tu usuario y protégela con una frase de paso.\n" +
  "Si ya no la usas, bórrala y retírala de los servidores donde estaba autorizada.";

const SECRET_FIX_IMAGE =
  "Revoca o cambia la credencial en el servicio que la emitió: cualquiera que descargue la imagen puede leerla.\n" +
  "Reconstruye la imagen sin ese fichero y pasa el secreto al arrancar el contenedor, con Docker secrets o un volumen.\n" +
  "> Borrar el fichero en una capa posterior no lo elimina: sigue en la capa donde se añadió.";

const HOST_KEYS_FIX_IMAGE =
  "Quita las claves de servidor SSH de la imagen y haz que cada contenedor genere las suyas al arrancar.\n" +
  "> Si van grabadas en la imagen, todos los contenedores que salen de ella comparten la misma identidad y quien tenga la imagen puede suplantarlos.";

const STORE_FIX =
  "No hace falta moverlos: es donde cada aplicación guarda tu sesión o tus claves.\n" +
  "Comprueba que solo tu usuario puede leerlos y que el disco del equipo está cifrado.\n" +
  "Si dejaste de usar alguna de esas aplicaciones, cierra la sesión en ella para que el token deje de valer.";

const NOISE_FIX =
  "No hace falta hacer nada: son credenciales de ejemplo que traen esos programas o conjuntos de pruebas, o patrones " +
  "que Trivy reconoce dentro de código empaquetado.\n" +
  "Si reconoces alguno como tuyo, trátalo como un secreto expuesto: revócalo y sácalo de ahí.";

/** Etiqueta "~/…" de una ruta relativa al home. */
const tilde = (rel) => (rel.startsWith("/") ? rel : `~/${rel}`);

/** Carpeta que agrupa el ruido: las dos primeras piezas de la ruta. */
function noiseBucket(rel) {
  const segs = rel.split("/").filter(Boolean);
  return tilde(segs.slice(0, Math.min(2, segs.length - 1) || 1).join("/"));
}

/** "~/a (3), ~/b (1) y 2 carpetas más". */
function bucketList(map, max = 6) {
  const items = [...map.entries()].sort((a, b) => b[1] - a[1]);
  const shown = items.slice(0, max).map(([k, n]) => `${k} (${n})`);
  const rest = items.length - max;
  return rest > 0 ? `${shown.join(", ")} y ${rest} carpeta${rest > 1 ? "s" : ""} más` : shown.join(", ");
}

/** Ruta de un Result: absoluta si se conoce la raíz del escaneo. */
function trivyResultPath(result) {
  const target = String(result.Target || "");
  return result.__root && !path.isAbsolute(target) ? path.join(result.__root, target) : target;
}

/** Secretos y configuraciones inseguras de un informe de Trivy. La severidad depende de dónde está
 *  el fichero (lib/secret-context.js). Nunca se copian `Code` ni `CauseMetadata`: van sin enmascarar. */
function fromTrivySecretsMisconfig(raw, opts = {}) {
  if (!raw || raw.skipped) return [];
  const context = opts.context === "image" ? "image" : "host";
  const pre = context === "image" ? "IMG" : "HOST";
  const home = opts.home || (raw.scan && raw.scan.mode === "fs-by-children" ? raw.scan.target : null);
  const oneLine = (x) => (typeof x === "string" ? x.replace(/[\x00-\x1f\x7f\u2028\u2029]+/g, " ").trim() : x);

  const findings = [];
  const seen = new Set();
  let nSec = 1;
  let nMis = 1;
  const nextSec = () => `${pre}-SEC-${String(nSec++).padStart(3, "0")}`;
  const nextMis = () => `${pre}-MIS-${String(nMis++).padStart(3, "0")}`;

  // Lo que no se enseña uno a uno, para resumirlo al final.
  const stores = [];                         // { where, titulo }
  const noise = new Map();                   // carpeta → n   (host)
  let noiseMis = 0;
  const imgNoise = new Map();                // imagen → n    (imagen)
  const misByImage = new Map();              // imagen → [{ m, sev }]

  for (const r of raw.Results || []) {
    const image = oneLine(r.__image || "") || null;
    const abs = trivyResultPath(r);
    const ctxHost = context === "host" ? classifyHostPath(abs, home) : null;
    const ctxImg = context === "image" ? classifyImagePath(abs) : null;
    const where = oneLine(context === "image" ? String(r.Target || "") : tilde(ctxHost.rel));

    for (const sec of r.Secrets || []) {
      const key = `${image}|${where}|${sec.RuleID}|${sec.StartLine}`;
      if (seen.has(key)) continue;
      seen.add(key);
      const titulo = TRIVY_SECRET_ES[sec.RuleID] || oneLine(sec.Title || sec.RuleID || "Secreto");
      const esClave = sec.RuleID === "private-key";

      if (context === "host" && ctxHost.kind === "store") { stores.push({ where, titulo }); continue; }
      if (context === "host" && ctxHost.kind !== "user") {
        const b = noiseBucket(ctxHost.rel);
        noise.set(b, (noise.get(b) || 0) + 1);
        continue;
      }
      if (context === "image" && ctxImg.kind !== "user") {
        imgNoise.set(image || where, (imgNoise.get(image || where) || 0) + 1);
        continue;
      }

      const linea = Number.isInteger(sec.StartLine) && sec.StartLine > 0 ? `, línea ${sec.StartLine}` : "";
      const valor = esClave ? null : maskedMatch(sec);
      let severity = fromTrivy(sec.Severity);
      let fix = context === "image" ? SECRET_FIX_IMAGE : SECRET_FIX_HOST;
      let nota = "";

      if (context === "host" && esClave) {
        severity = ctxHost.synced ? "high" : "medium";
        fix = KEY_FIX_HOST;
        nota = ctxHost.synced
          ? " La carpeta se sincroniza con un servicio en la nube, así que la clave también está fuera de este equipo."
          : " No está en la carpeta .ssh de tu usuario, que es donde deben guardarse las claves.";
      } else if (context === "host" && ctxHost.synced) {
        nota = " La carpeta se sincroniza con un servicio en la nube, así que el valor también está fuera de este equipo.";
      } else if (context === "image" && esClave && /^\/?etc\/ssh\/ssh_host_/.test(ctxImg.rel)) {
        fix = HOST_KEYS_FIX_IMAGE;
        nota = " Es una clave de servidor SSH grabada en la imagen.";
      } else if (context === "image") {
        nota = " El fichero va dentro de la imagen.";
      }

      const title = context === "host" && esClave
        ? (ctxHost.synced ? `Clave privada en una carpeta sincronizada: ${where}` : `Clave privada fuera de su almacén: ${where}`)
        : context === "host" && ctxHost.synced
        ? `Secreto en una carpeta sincronizada: ${titulo} en ${where}`
        : context === "image" && esClave && /^\/?etc\/ssh\/ssh_host_/.test(ctxImg.rel)
        ? `Clave de servidor SSH grabada en la imagen: ${where}`
        : `Secreto expuesto: ${titulo} en ${where}`;

      findings.push(createFinding({
        id: nextSec(),
        title,
        severity,
        evidence: `Trivy ha detectado «${titulo}» en ${where}${linea}` + (valor ? `: ${valor}.` : ".") + nota,
        fix,
        command: null,
        category: "secret",
        source: "trivy",
        image,
        location: where,
        // En claves privadas del host, la severidad es de LoCoAudit.
        severitySource: (context === "host" && esClave) ? "locoaudit" : null,
      }));
    }

    const fallidos = (r.Misconfigurations || []).filter((m) => String(m.Status || "FAIL").toUpperCase() === "FAIL");
    if (!fallidos.length) continue;

    if (context === "image") {
      const k = image || where;
      if (!misByImage.has(k)) misByImage.set(k, { image, where, items: [] });
      for (const m of fallidos) {
        const mk = `${k}|${m.ID}`;
        if (seen.has(mk)) continue;
        seen.add(mk);
        misByImage.get(k).items.push({ m, sev: misconfSeverity(m.ID, m.Severity) || fromTrivy(m.Severity) });
      }
      continue;
    }

    // Equipo: los ficheros de terceros no son proyectos del usuario.
    if (ctxHost.kind !== "user") { noiseMis++; continue; }
    findings.push(hostMisconfFinding(nextMis(), where, fallidos, r.Type, oneLine));
  }

  // Imagen: un hallazgo por imagen, y los secretos en ENV/ARG (DS-0031) aparte.
  for (const [, grp] of misByImage) {
    const secretos = grp.items.filter((x) => x.m.ID === "DS-0031");
    const resto = grp.items.filter((x) => x.m.ID !== "DS-0031");
    for (const { m, sev } of secretos) {
      const sheet = misconfSheet(m);
      findings.push(createFinding({
        id: nextMis(),
        title: `${sheet.title} (${m.ID})`,
        severity: sev,
        evidence: m.Message
          ? `Trivy lo ha detectado en la configuración de la imagen. Su detalle, en inglés: ${oneLine(m.Message)}`
          : "Trivy lo ha detectado en la configuración de la imagen.",
        fix: sheet.fix,
        command: null,
        category: "misconfig",
        source: "trivy",
        image: grp.image,
        location: grp.where,
        primaryUrl: m.PrimaryURL || null,
      }));
    }
    if (!resto.length) continue;
    const orden = ["critical", "high", "medium", "low", "info"];
    resto.sort((a, b) => orden.indexOf(a.sev) - orden.indexOf(b.sev));
    const maxSev = resto[0].sev;
    const lista = resto.map(({ m, sev }) => `${misconfSheet(m).title} (${m.ID}, ${SEV_ES[sev]})`);
    findings.push(createFinding({
      id: nextMis(),
      title: resto.length === 1
        ? `${misconfSheet(resto[0].m).title} (${resto[0].m.ID})`
        : `${misconfSheet(resto[0].m).title} y ${resto.length - 1} mala${resto.length > 2 ? "s" : ""} práctica${resto.length > 2 ? "s" : ""} más`,
      severity: maxSev,
      evidence: `Trivy ha revisado cómo está construida la imagen y señala: ${lista.join("; ")}. ` +
        "La severidad es la de LoCoAudit: separa lo que expone algo, como ejecutarse como root, de las " +
        "buenas prácticas de construcción que no abren ninguna vía de ataque.",
      fix: resto.map(({ m }) => misconfSheet(m).fix.split("\n")[0]).join("\n"),
      command: null,
      category: "misconfig",
      source: "trivy",
      image: grp.image,
      location: grp.where,
      primaryUrl: resto.length === 1 ? (resto[0].m.PrimaryURL || null) : null,
      severitySource: "locoaudit",
    }));
  }

  if (stores.length) {
    // Varios tokens en un mismo fichero de sesión se agrupan por fichero.
    const porFichero = new Map();
    for (const x of stores) {
      if (!porFichero.has(x.where)) porFichero.set(x.where, new Map());
      const t = porFichero.get(x.where);
      t.set(x.titulo, (t.get(x.titulo) || 0) + 1);
    }
    const ficheros = [...porFichero.entries()];
    const lista = ficheros.slice(0, 8).map(([w, t]) =>
      `${w} (${[...t.entries()].map(([k, n]) => (n > 1 ? `${n} × ${k}` : k)).join(", ")})`);
    findings.push(createFinding({
      id: nextSec(),
      title: ficheros.length === 1
        ? `Credencial guardada por su aplicación: ${ficheros[0][0]}`
        : `${ficheros.length} ficheros de credenciales guardados por sus aplicaciones`,
      severity: "info",
      evidence: `Trivy ha encontrado claves y tokens en los ficheros donde las aplicaciones guardan tu sesión: ` +
        `${lista.join(", ")}${ficheros.length > 8 ? ` y ${ficheros.length - 8} más` : ""}. ` +
        "Que estén ahí es lo normal: así es como cada programa recuerda que has iniciado sesión.",
      fix: STORE_FIX,
      command: null,
      category: "secret",
      source: "trivy",
    }));
  }

  const nNoise = [...noise.values()].reduce((a, b) => a + b, 0);
  if (nNoise || noiseMis) {
    const partes = [];
    if (nNoise) partes.push(`${nNoise} posible${nNoise > 1 ? "s" : ""} secreto${nNoise > 1 ? "s" : ""} en ${bucketList(noise)}`);
    if (noiseMis) partes.push(`${noiseMis} fichero${noiseMis > 1 ? "s" : ""} de configuración de terceros con controles sin cumplir`);
    findings.push(createFinding({
      id: nextSec(),
      title: nNoise
        ? `${nNoise} posible${nNoise > 1 ? "s" : ""} secreto${nNoise > 1 ? "s" : ""} en software de terceros o datos de prueba`
        : `${noiseMis} configuración${noiseMis > 1 ? "es" : ""} de software de terceros`,
      severity: "info",
      evidence: `Trivy ha señalado ${partes.join(", y ")}. Son extensiones, dependencias, programas descargados ` +
        "o conjuntos de pruebas de seguridad, no ficheros tuyos, y no cuentan en el riesgo del equipo.",
      fix: NOISE_FIX,
      command: null,
      category: "secret",
      source: "trivy",
    }));
  }

  for (const [img, n] of imgNoise) {
    findings.push(createFinding({
      id: nextSec(),
      title: `${n} posible${n > 1 ? "s" : ""} secreto${n > 1 ? "s" : ""} en tests o dependencias de la imagen`,
      severity: "info",
      evidence: `Trivy ha señalado ${n} valor${n > 1 ? "es" : ""} con forma de credencial en ficheros de test o en ` +
        "dependencias que trae la imagen. Suelen ser datos de ejemplo de esos paquetes.",
      fix: NOISE_FIX,
      command: null,
      category: "secret",
      source: "trivy",
      image: img,
    }));
  }

  // Carpetas donde la pasada falló (tiempo agotado, sin permisos): un hueco, no un "limpio".
  const caidas = context === "host" && raw.scan && raw.scan.children
    ? (raw.scan.children.skipped || []).filter((c) => c.kind === "error")
    : [];
  if (caidas.length) {
    const nombres = caidas.slice(0, 5).map((c) => tilde(oneLine(c.name))).join(", ");
    findings.push(createFinding({
      id: `${pre}-SEC-PARTIAL`,
      title: caidas.length === 1
        ? "Búsqueda de secretos: 1 carpeta sin revisar"
        : `Búsqueda de secretos: ${caidas.length} carpetas sin revisar`,
      severity: "info",
      evidence:
        `La búsqueda de secretos y configuraciones no pudo terminar en ${nombres}${caidas.length > 5 ? " y otras" : ""}. ` +
        "Que no haya hallazgos de esas carpetas no significa que estén limpias, significa que no se han revisado.",
      fix: "Si es una unidad de red o de la nube, indica en el nodo una carpeta concreta a auditar.\n" +
           "Si el motivo es el tiempo, vuelve a lanzar la auditoría: la segunda pasada suele ser más rápida.",
      command: null,
      category: "secret",
      source: "trivy",
    }));
  }

  return findings;
}

const SEV_ES = { critical: "crítico", high: "alto", medium: "medio", low: "bajo", info: "informativo" };

/** Un informativo por fichero de proyecto, con sus controles fallidos dentro. */
function hostMisconfFinding(id, where, fallidos, type, oneLine) {
  const porSev = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  const sevOf = (m) => misconfSeverity(m.ID, m.Severity) || fromTrivy(m.Severity);
  for (const m of fallidos) porSev[sevOf(m)]++;
  const resumen = ["critical", "high", "medium", "low"]
    .filter((k) => porSev[k])
    .map((k) => `${porSev[k]} ${SEV_ES[k]}${porSev[k] > 1 ? "s" : ""}`)
    .join(", ");
  const MAX = 8;
  const lista = fallidos.slice(0, MAX).map((m) => `${misconfSheet(m).title} (${m.ID})`);
  const resto = fallidos.length - MAX;
  const tipo = oneLine(type || "configuración");
  return createFinding({
    id,
    title: fallidos.length > 1
      ? `${fallidos.length} configuraciones mejorables en ${where}`
      : `1 configuración mejorable en ${where}`,
    severity: "info",
    evidence:
      `Trivy ha revisado este fichero de tipo ${tipo} y ha encontrado ${fallidos.length} control${fallidos.length > 1 ? "es" : ""} ` +
      `sin cumplir${resumen ? ` (${resumen})` : ""}: ${lista.join("; ")}${resto > 0 ? ` y ${resto} más` : ""}. ` +
      "Es un fichero de un proyecto tuyo: no cambia el riesgo de este equipo, pero sí el de las imágenes o los despliegues que se construyan con él.",
    fix: fallidos.slice(0, MAX).map((m) => misconfSheet(m).fix.split("\n")[0]).join("\n"),
    command: null,
    category: "misconfig",
    source: "trivy",
    location: where,
  });
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

/** Comando detrás de dos puntos, como lo escribe lib/process-fix.js: ": sudo …". */
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

/** Pasos de resolución de un puerto abierto: la única acción fiable es parar el servicio.
 *  "## " abre rama, "$ " es comando y "> " una nota. */
function buildPortFix(p, platform, targetIsLocal, target, pkgManager) {
  // Target remoto: la guía por puerto está pensada para este equipo, no para otro.
  if (targetIsLocal === false) {
    const where = target ? `el dispositivo remoto ${target}` : "OTRO dispositivo de tu red";
    // Solo notas: aquí no hay nada que ejecutar en orden.
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

  // Bind en loopback: no está expuesto, así que solo notas.
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

  // Servicio del propio SO: se desactiva por la vía soportada, no matando el proceso.
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

  // Orden de preferencia del nombre: proceso real, demonio (SSH→sshd) y catálogo.
  const known = [p.process, p.service ? `${p.service}d` : null, p.service]
    .find((c) => c && getFixKind(c)) || null;
  const knownFix  = known ? getFixForProcess(known, platform, pkgManager || null) : null;
  const knownKind = known ? getFixKind(known) : null;
  const stopCmd   = knownKind === "stop" ? knownFix : null;
  const limitFix  = knownKind === "limit" ? knownFix : null;

  // Sin numerar: la numeración la pone el dashboard.
  const genericStop = platform === "win32"
    ? ["Con el PID que devuelve el comando anterior, identifica el servicio y deshabilítalo en " +
       "services.msc (Detener + Tipo de inicio: Deshabilitado). Si es una aplicación que instalaste " +
       "tú, ciérrala o desinstálala."]
    : platform === "darwin"
      ? ["Con el nombre del proceso (columna COMMAND) decide: si es una app que instalaste tú, " +
         "ciérrala o desinstálala; si es un servicio de compartición de macOS, desactívalo en " +
         "Ajustes del Sistema → General → Compartido. No uses kill: launchd relanza los servicios " +
         "y el puerto volvería a abrirse."]
      : ["Con el nombre del servicio (columna COMMAND), detenlo y deshabilítalo junto a su socket, si lo tiene:",
         "$ sudo systemctl disable --now <servicio>.service && { sudo systemctl disable --now <servicio>.socket 2>/dev/null || true; }"];

  // Del comando del catálogo, la primera línea es la orden (si empieza por `sudo`) y el resto, nota.
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
      "> La orden desactiva también la unidad .socket si el servicio la tiene: con activación por " +
      "socket, parar solo el .service no cierra el puerto, porque systemd relanza el servicio en la " +
      "siguiente conexión."
    );
  }

  const keepAdvice = limitFix ||
    "Configúralo para escuchar en 127.0.0.1 en vez de en todas las interfaces (*/0.0.0.0): " +
    "dejará de estar expuesto a la red sin perder el uso local.";
  lines.push("## Si lo necesitas");
  lines.push(...lineasDeCatalogo(keepAdvice));

  // La guía por puerto solo si no hubo fix por proceso; ya trae sus "## " y va como ramas hermanas.
  if (!knownFix && p.fix) lines.push(String(p.fix).trim());

  return lines.join("\n");
}

/** Estado del cortafuegos para la evidencia, para que el LLM no asuma ufw. */
function firewallEvidence(fw, isLocal) {
  if (!isLocal) return "";
  // active null: la consulta falló, así que no se sabe si está encendido.
  if (fw && fw.active === null) {
    return fw.name
      ? ` Cortafuegos del sistema: ${fw.name} (no se pudo comprobar su estado).`
      : " Cortafuegos del sistema: no se pudo comprobar si hay alguno ni su estado.";
  }
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

      // El cortafuegos va a la evidencia, no al fix.
      evidence += firewallEvidence(opts.firewall, isLocal);

      // Sin proceso, probar por nombre de servicio antes de caer a la guía genérica.
      const pForFix = (!p.process && p.service && getFixForProcess(p.service, process.platform))
        ? { ...p, process: p.service }
        : p;
      const fix = buildPortFix(pForFix, process.platform, isLocal, opts.target, opts.pkgManager);

      // target e isLocalTarget van como campos para no proponer comandos locales a un equipo remoto.
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

/** Sella el scope en los puntos de entrada; respeta uno que ya venga puesto. */
function sealScope(findings, scope) {
  for (const f of findings) if (f && !f.scope) f.scope = scope;
  return findings;
}

function normalizeHost(raw, opts = {}) {
  // opts puede ser string (source, forma antigua) u objeto { platform, pkgManager, source }.
  const source = typeof opts === "string" ? opts : (opts.source || "native");
  const platform = typeof opts === "object" ? (opts.platform || process.platform) : process.platform;
  // Gestor real del equipo; ningún generador de fix lo asume.
  const pkgManager = typeof opts === "object" ? (opts.pkgManager || null) : null;

  // Forma habitual: el objeto compuesto de audit-host.js.
  if (raw && typeof raw === "object" && !Array.isArray(raw)) {
    const findings = [];
    if (raw.cpuMemory) findings.push(...fromCpuMemory(raw.cpuMemory, platform));
    if (raw.disk) findings.push(...fromDisk(raw.disk));
    if (raw.swInventory) findings.push(...fromSwInventory(raw.swInventory, platform, pkgManager));
    if (raw.pendingUpdates) findings.push(...fromPendingUpdates(raw.pendingUpdates, platform, pkgManager));
    if (raw.lynis) findings.push(...fromLynisRaw(raw.lynis, platform, pkgManager));
    // collapseDeclared solo en host: en imagen se conserva el detalle por CVE.
    if (raw.trivy) findings.push(...fromTrivyJson(raw.trivy, "HOST-CVE", "vulnerability", "trivy", { platform, pkgManager, collapseDeclared: true }));
    // Paquetes del sistema (lib/trivy-rootfs.js), con su propia fuente y contrato.
    if (raw.trivyRootfs) findings.push(...fromTrivyRootfs(raw.trivyRootfs, platform, pkgManager));
    // Secretos y configuraciones del home: otra pasada de Trivy.
    if (raw.trivySecrets) {
      findings.push(...(raw.trivySecrets.skipped
        ? [skippedSourceFinding("trivy-secrets", raw.trivySecrets, platform, "HOST-SEC", "host", "secret")]
        : fromTrivySecretsMisconfig(raw.trivySecrets, { context: "host" })));
    }
    if (raw.securityEvents) findings.push(...fromSecurityEvents(raw.securityEvents, platform));
    return sealScope(findings, "host");
  }

  // Source explícito, para tests.
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

    const fix = buildPortFix(p, process.platform, isLocal, opts.target, opts.pkgManager);

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

/** Procedencia de los CVE de Vulners: la versión la anuncia el servicio, hay backporting y la nota
 *  puede no coincidir con el NVD. */
const PROCEDENCIA_VULNERS =
  "La versión la anuncia el propio servicio y NO se ha verificado contra " +
  "el objetivo; muchas distribuciones (Debian, Ubuntu, RHEL) corrigen fallos sin cambiar el " +
  "número de versión, así que un servicio ya parcheado puede aparecer aquí igualmente; la " +
  "puntuación es la que da vulners.com y puede diferir de la del NVD para el mismo CVE; y como " +
  "la consulta se hace por producto y versión, un fallo que solo afecta al cliente puede " +
  "aparecer atribuido a su servidor. Confirma cada CVE contra el changelog del paquete antes de " +
  "darlo por bueno.";

/** NET-VULN-*: un finding por puerto y CPE, con la severidad del peor CVE y todos en `vulnerabilities`. */
function fromNseVulns(ports, opts = {}) {
  const findings = [];
  let i = 0;

  for (const p of ports) {
    const resumen = p && p.nseSummary;
    if (!resumen || !resumen.vulns || !resumen.vulns.length) continue;

    for (const grupo of resumen.vulns) {
      const nombre = [p.service, p.version].filter(Boolean).join(" ") || `puerto ${p.port}`;
      // "OpenSSH 10.3" → "OpenSSH"; sin banner de versión, el nombre del servicio.
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
        // Los CVE uno a uno los pinta la tabla desde `vulnerabilities`; aquí solo la frase.
        evidence:
          `El servicio del puerto ${p.port}/tcp se identifica como ${grupo.cpe || nombre}. ` +
          `vulners.com devuelve ${grupo.cves.length} CVE para la versión anunciada` +
          `${grupo.maxCvss != null ? `, y el más grave puntúa ${grupo.maxCvss.toFixed(1)}` : ""}.` +
          `${exploitTxt} vulners no aporta una descripción por CVE: de cada uno se conoce su ` +
          "identificador, su puntuación y si tiene exploit público. " +
          PROCEDENCIA_VULNERS,
        // Sin comando: el gestor depende del equipo auditado, que puede no ser este.
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

/** NET-TLS-*: la nota de ssl-enum-ciphers según la tabla A-F; una nota fuera de la tabla es una omisión. */
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

/** NET-SVC-*: algoritmos que ofrece un SSH, con techo 'medium'. Sin nada débil sale como informativo. */
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

/** Lo que no se llegó a comprobar, agrupado por motivo. no-version y not-applicable son alcance;
 *  source-unavailable, script-missing y nse-unavailable son huecos (ámbar). */
function fromNseOmissions(ports, opts = {}) {
  const meta = opts.nse || {};
  const findings = [];
  let i = 0;

  const push = ({ kind, title, evidence, fix = null, notApplicable = false }) => {
    findings.push(createFinding({
      id:    `NET-NSE-SKIP-${counter(i++)}`,
      title,
      // 'info': no comprobar no es un riesgo; lo hacen visible `skipped` y `kind`.
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
      // En Debian y Ubuntu los scripts NSE vienen en `nmap-common`; los cinco están desde Nmap 7.80.
      fix: "Actualiza Nmap: los cinco scripts que usa LoCoAudit vienen incluidos en Nmap 7.80 y " +
           "posteriores (comprueba tu versión con `nmap --version`). Si tu distribución trae una " +
           "versión anterior, instala la de nmap.org y repite la auditoría.",
    });
  }

  // ssl-enum-ciphers corrió sin concluir (nota fuera de la tabla, p. ej. 'unknown'): es un hueco.
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

  // Por estado de puerto; primero el hueco.
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

/** Todo lo que aporta NSE, en orden de lectura. Solo puertos abiertos, igual que fromNmap. */
function fromNse(ports, opts = {}) {
  const lista = (Array.isArray(ports) ? ports : []).filter((p) => p && p.state === "open");
  return [
    ...fromNseVulns(lista, opts),
    ...fromNseTls(lista, opts),
    ...fromNseSvc(lista, opts),
    ...fromNseOmissions(lista, opts),
  ];
}

/** Normaliza el raw de audit-network. `firewall` va a la evidencia; `target` y `targetIsLocal` al finding. */
function normalizeNetwork(raw, source = "native", opts = {}) {
  if (source === "nmap") {
    // Primero los puertos y después NSE, que solo llega si el nodo lo activó.
    const findings = fromNmap(raw, opts);
    if (opts.nse) findings.push(...fromNse(raw, opts));
    return sealScope(findings, "network");
  }
  return sealScope(fromPortScanner(Array.isArray(raw) ? raw : [], opts), "network");
}

/** Normaliza el raw de audit-image. */
function normalizeImage(raw, source = "docker") {
  if (source === "trivy") {
    return sealScope([
      ...fromTrivyJson(raw, "IMG-CVE", "vulnerability", "trivy"),
      ...fromTrivySecretsMisconfig(raw, { context: "image" }),
    ], "image");
  }
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
  // Subfunciones expuestas para tests
  fromCpuMemory,
  fromDisk,
  fromSwInventory,
  fromPendingUpdates,
  fromLynisRaw,
  fromSecurityEvents,
  fromSecurityEventsWin32,
  fromTrivyJson,
  fromTrivySecretsMisconfig,
  TRIVY_MISCONF_ES,
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
