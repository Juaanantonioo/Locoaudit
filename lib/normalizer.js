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

const { createFinding } = require("./finding-schema");
const { fromTrivy, fromLynis, max, MEMORY_THRESHOLDS, LYNIS_PERSONAL_SEVERITY } = require("./severity-map");
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
function getTrivyFixCommand(target, pkgName, fixedVersion, platform, context = "host") {
  if (!pkgName) return null;
  const t = target || "";
  const pkg = pkgName.split("@")[0];
  const ver = fixedVersion || null;

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
  if (!fix || typeof fix !== "string") return false;
  const commandPatterns = [
    /^brew\s/i,
    /^sudo\s/i,
    /^npm\s/i,
    /^yarn\s/i,
    /^pip\s/i,
    /^composer\s/i,
    /^go\s/i,
    /^apt\s/i,
    /^dnf\s/i,
    /^yum\s/i,
    /^winget\s/i,
    /^choco\s/i,
    /^lsof\s/i,
    /^nslookup\s/i,
    /^kill\s/i,
    /^systemctl\s/i,
    /^launchctl\s/i,
    /^netsh\s/i,
    /^net\s+stop\s/i,
  ];
  return commandPatterns.some((p) => p.test(fix.trim()));
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

    // Dev dependencies de Homebrew Cellar: bajar un nivel de severidad
    const isDevDependency = (result.Target || "").includes("/Cellar/") &&
      ["phpmyadmin", "protobuf", "playwright", "python"].some((t) =>
        (result.Target || "").toLowerCase().includes(t));

    for (const v of (result.Vulnerabilities || [])) {
      // Deduplicar por VulnerabilityID + PkgName + InstalledVersion
      const key = `${v.VulnerabilityID}:${v.PkgName}:${v.InstalledVersion}`;
      if (seen.has(key)) continue;
      seen.add(key);

      let sev = fromTrivy(v.Severity);
      if (isDevDependency && sev === "high")     sev = "medium";
      if (isDevDependency && sev === "critical") sev = "high";

      allVulns.push({ v, target, sev });
    }
  }

  // ── Paso 2: agrupar por paquete (PkgName:InstalledVersion) ─────────────────
  // Un paquete con N CVEs genera 1 finding. La severidad del grupo es la más alta.
  // pkgGroups: Map< "PkgName:InstalledVersion" → { items: [{v,target,sev}], maxSev, target } >
  const pkgGroups = new Map();
  const medByTarget = new Map();   // target → v[]
  const lowInfoAll  = { count: 0, targets: new Set() };

  for (const item of allVulns) {
    const { v, target, sev } = item;
    if (sev === "critical" || sev === "high") {
      const pkgKey = `${v.PkgName}:${v.InstalledVersion || ""}`;
      if (!pkgGroups.has(pkgKey)) {
        pkgGroups.set(pkgKey, { items: [], maxSev: sev, target });
      }
      const grp = pkgGroups.get(pkgKey);
      grp.items.push(item);
      grp.maxSev = max(grp.maxSev, sev);
    } else if (sev === "medium") {
      if (!medByTarget.has(target)) medByTarget.set(target, []);
      medByTarget.get(target).push(v);
    } else {
      lowInfoAll.count++;
      lowInfoAll.targets.add(target);
    }
  }

  const findings = [];
  let n = 1;

  // ── Paso 3: emitir findings critical/high agrupados por paquete ────────────
  for (const [, grp] of pkgGroups) {
    const { items, maxSev, target } = grp;
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

    findings.push(
      createFinding({
        id:       `${idPrefix}-${String(n++).padStart(3, "0")}`,
        title,
        severity: maxSev,
        evidence,
        fix:      fixedVersion
          ? getTrivyFixCommand(target, first.PkgName, fixedVersion, process.platform, context)
          : `No hay versión corregida disponible aún para ${first.PkgName}. Monitorizar actualizaciones del paquete.`,
        category,
        source,
      })
    );
  }

  // ── Paso 4: medium → 1 finding resumen por Target ──────────────────────────
  let medIdx = 1;
  for (const [target, vulns] of medByTarget) {
    const MAX_IDS = 5;
    const shownIds = vulns.slice(0, MAX_IDS).map((v) => v.VulnerabilityID);
    const remaining = vulns.length - MAX_IDS;
    const evidence = remaining > 0
      ? `${shownIds.join(", ")} y ${remaining} más`
      : shownIds.join(", ");

    findings.push(
      createFinding({
        id:       `${idPrefix}-MED-${String(medIdx++).padStart(3, "0")}`,
        title:    `${vulns.length} vulnerabilidades medium en ${target}`,
        severity: "medium",
        evidence,
        fix:      `Actualizar los paquetes afectados en ${target}`,
        category,
        source,
      })
    );
  }

  // ── Paso 5: low e info → 1 único finding resumen global ────────────────────
  if (lowInfoAll.count > 0) {
    const targetCount = lowInfoAll.targets.size;
    findings.push(
      createFinding({
        id:       `${idPrefix}-LOW`,
        title:    `${lowInfoAll.count} vulnerabilidades low/info en ${targetCount} target${targetCount !== 1 ? "s" : ""}`,
        severity: "low",
        evidence: `${lowInfoAll.count} vulnerabilidades de severidad baja distribuidas en ${targetCount} target${targetCount !== 1 ? "s" : ""}`,
        fix:      "Revisar y actualizar paquetes cuando sea posible",
        category,
        source,
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
  fromTrivyJson,
  fromNmap,
  fromNative,
  // Utilitaria: detecta si un fix es comando ejecutable directamente
  isExecutableCommand,
};
