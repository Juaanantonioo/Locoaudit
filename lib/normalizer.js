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
const { fromTrivy, fromLynis, MEMORY_THRESHOLDS, LYNIS_PERSONAL_SEVERITY } = require("./severity-map");

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
function diskSeverity(pct) {
  if (pct >= 90) return "critical";
  if (pct >= 75) return "high";
  if (pct >= 60) return "medium";
  return "info";
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
  return [
    createFinding({
      id: "HOST-SW-001",
      title: `Software instalado: ${pkgs.length} paquetes`,
      severity: "info",
      evidence: `${pkgs.length} paquetes encontrados. Fuentes: ${[...new Set(pkgs.map((p) => p.source))].join(", ")}`,
      fix: null,
      category: "system",
      source: "native",
    }),
  ];
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
    const controlId = (w.id || "").toLowerCase();

    findings.push(
      createFinding({
        id: `HOST-LYN-${String(i + 1).padStart(3, "0")}`,
        title,
        severity: LYNIS_PERSONAL_SEVERITY[w.id] ?? "low",
        evidence: w.description || w.id || "sin descripción",
        fix: controlId
          ? `https://cisofy.com/lynis/controls/${controlId}/`
          : "Consultar la base de conocimiento de Lynis para este control.",
        category: "system",
        source: "lynis",
      })
    );
  }

  // 3. Warnings adicionales → 1 finding resumen de severidad "medium"
  if (extraWarnings.length > 0) {
    const extraIds = extraWarnings.map((w) => w.id || "UNKNOWN").join(", ");
    findings.push(
      createFinding({
        id: "HOST-LYN-WARN-EXTRA",
        title: `Lynis: ${extraWarnings.length} advertencias adicionales`,
        severity: "medium",
        evidence: extraIds,
        fix: "Ejecutar 'lynis show warnings' para ver el detalle completo.",
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
 * Convierte la salida JSON de `trivy fs` o `trivy image` a findings.
 * Estructura estándar de Trivy: { Results: [{ Target, Vulnerabilities: [...] }] }
 *
 * @param {Object} raw         Objeto JSON parseado de Trivy.
 * @param {string} idPrefix    "HOST-CVE" | "IMG-CVE"
 * @param {string} category    "vulnerability"
 * @param {string} source      "trivy"
 * @returns {Finding[]}
 */
function fromTrivyJson(raw, idPrefix, category = "vulnerability", source = "trivy") {
  if (!raw || raw.skipped) return [];
  const findings = [];
  const results = raw.Results || [];
  let n = 1;

  for (const result of results) {
    for (const v of (result.Vulnerabilities || [])) {
      const sev = fromTrivy(v.Severity);
      findings.push(
        createFinding({
          id: `${idPrefix}-${String(n++).padStart(3, "0")}`,
          title: `${v.VulnerabilityID}: ${v.PkgName}@${v.InstalledVersion || "?"}`,
          severity: sev,
          evidence: `${v.VulnerabilityID} en ${v.PkgName} ${v.InstalledVersion || ""}. ${(v.Description || "").slice(0, 200)}`,
          fix: v.FixedVersion ? `Actualizar ${v.PkgName} a ${v.FixedVersion}` : null,
          category,
          source,
        })
      );
    }
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
      const portStr = `${p.port}/${p.protocol || "tcp"}`;
      const svc = p.service
        ? ` (${p.service}${p.version ? " " + p.version : ""})`
        : "";
      return createFinding({
        id: `NET-PORT-${counter(i)}`,
        title: `Puerto abierto: ${portStr}${svc}`,
        severity: p.severity || "info",
        evidence: `Puerto ${portStr} en estado open${svc}`,
        fix: p.fix || null,
        category: "network",
        source: "nmap",
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
 * Normaliza raw data del nodo audit-network.
 * @param {*} raw
 * @param {"native"|"nmap"} source
 * @returns {Finding[]}
 */
function normalizeNetwork(raw, source = "native") {
  if (source === "nmap") return fromNmap(raw);
  return fromNative(Array.isArray(raw) ? raw : [], "native");
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
};
