"use strict";

/** Vulnerabilidades de los paquetes del sistema con `trivy rootfs` (`trivy fs` solo ve lockfiles).
 *  Fallos como { skipped, kind, reason }; que Trivy esté instalado lo comprueba audit-host. */

const { execToFile, execCommand } = require("./executor");

// rootfs recorre el sistema entero: con un timeout corto el JSON parcial parecía un escaneo limpio.
const ROOTFS_TIMEOUT_MS = 600000;

// Sistemas virtuales y estado volátil; /var/lib/docker son capas de imágenes, que audita audit-image.
const ROOTFS_SKIP_DIRS = ["/proc", "/sys", "/dev", "/run", "/var/lib/docker"];

/** Versión de Trivy, guardada con el resultado para diagnosticar cambios en su salida. */
async function trivyVersion() {
  try {
    const out = await execCommand("trivy --version", 5000);
    const m = out.match(/Version:\s*(\S+)/i);
    return m ? m[1] : (out.split("\n")[0] || "").trim() || null;
  } catch (_) {
    return null;
  }
}

/** Severidad de Trivy en mayúsculas. UNKNOWN se conserva: pasarlo a LOW inventaría una valoración. */
function trivySeverity(v) {
  const s = String((v && v.Severity) || "UNKNOWN").trim().toUpperCase();
  return s || "UNKNOWN";
}

const SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"];

/** La peor de las dos; UNKNOWN nunca gana. */
function worstSeverity(a, b) {
  const ia = SEVERITY_ORDER.indexOf(a);
  const ib = SEVERITY_ORDER.indexOf(b);
  return (ia === -1 ? 99 : ia) <= (ib === -1 ? 99 : ib) ? a : b;
}

/** Reparto por severidad, en el orden en que se enseña y sin claves a cero. */
function severityBreakdown(vulns) {
  const counts = {};
  for (const v of vulns) {
    const s = trivySeverity(v);
    counts[s] = (counts[s] || 0) + 1;
  }
  const out = {};
  for (const s of SEVERITY_ORDER) if (counts[s]) out[s] = counts[s];
  return out;
}

/** Compara dos FixedVersion del mismo paquete por sus tramos numéricos. No es un comparador dpkg completo;
 *  si no sabe, devuelve 0 y el llamante conserva la que tenía. */
function compareVersions(a, b) {
  if (!a) return -1;
  if (!b) return 1;
  const na = String(a).match(/\d+/g) || [];
  const nb = String(b).match(/\d+/g) || [];
  for (let i = 0; i < Math.max(na.length, nb.length); i++) {
    const x = parseInt(na[i] || "0", 10);
    const y = parseInt(nb[i] || "0", 10);
    if (x !== y) return x > y ? 1 : -1;
  }
  return 0;
}

/** Agrupa las vulnerabilidades corregibles por paquete (la acción es actualizar el paquete, no cada CVE).
 *  La clave incluye la versión instalada para separar casos multiarch. */
function groupFixableByPackage(vulns) {
  const groups = new Map();

  for (const v of vulns) {
    const pkg = v.PkgName || "desconocido";
    const installed = v.InstalledVersion || "";
    const key = `${pkg} ${installed}`;

    if (!groups.has(key)) {
      groups.set(key, {
        pkg,
        installedVersion: installed || null,
        fixedVersion: v.FixedVersion,
        maxSeverity: trivySeverity(v),
        cves: [],
      });
    }

    const g = groups.get(key);
    // La urgencia la marca la peor del grupo.
    g.maxSeverity = worstSeverity(g.maxSeverity, trivySeverity(v));
    // La versión a instalar es la que corrige todos los CVE del grupo.
    if (compareVersions(v.FixedVersion, g.fixedVersion) > 0) g.fixedVersion = v.FixedVersion;
    g.cves.push({
      id: v.VulnerabilityID || "sin identificador",
      severity: trivySeverity(v),
      title: v.Title || null,
    });
  }

  // Las más urgentes primero: es el orden en el que hay que atenderlas.
  return [...groups.values()].sort(
    (a, b) => SEVERITY_ORDER.indexOf(a.maxSeverity) - SEVERITY_ORDER.indexOf(b.maxSeverity)
  );
}

/** Paquetes del informe cuando Trivy no da PackageCount: se cuentan los suyos, sin duplicar. */
function countPackages(report) {
  const seen = new Set();
  for (const result of report.Results || []) {
    for (const p of result.Packages || []) {
      seen.add(`${p.Name} ${p.Version || ""} ${p.Arch || ""}`);
    }
  }
  return seen.size || null;
}

/** Ejecuta el escaneo y devuelve los datos particionados, o { skipped, kind, reason }. Los findings los hace normalizer.js. */
async function runTrivyRootfs() {
  const started = Date.now();

  const cmd = (file) =>
    "trivy rootfs --scanners vuln --pkg-types os --quiet " +
    `--skip-dirs ${ROOTFS_SKIP_DIRS.join(",")} ` +
    `-f json -o "${file}" /`;

  // A fichero y no por stdout: la salida pasa de 20 MB y no cabe en maxBuffer.
  const report = await execToFile(cmd, ROOTFS_TIMEOUT_MS, { prefix: "lcaudit-trivy-rootfs-" });

  const durationMs = Date.now() - started;
  if (report.skipped) return { ...report, durationMs };

  // Sin familia de SO, Trivy no ha leído paquetes: no es lo mismo que "0 vulnerabilidades".
  const osMeta = report && report.Metadata && report.Metadata.OS;
  if (!osMeta || !osMeta.Family) {
    return {
      skipped: true,
      kind: "os-unsupported",
      reason: "Trivy no ha detectado la familia del sistema operativo",
      durationMs,
    };
  }

  // Cifra del propio informe; no se cuadra con la de dpkg en sw-inventory.
  const pkgNum =
    report.Metadata && typeof report.Metadata.PackageCount === "number"
      ? report.Metadata.PackageCount
      : countPackages(report);

  const vulns = [];
  for (const result of report.Results || []) {
    // Por si se cuela un resultado que no es de paquetes del SO.
    if (result.Class && result.Class !== "os-pkgs") continue;
    for (const v of result.Vulnerabilities || []) vulns.push(v);
  }

  const fixable = vulns.filter((v) => v.FixedVersion);
  const unfixed = vulns.filter((v) => !v.FixedVersion);

  return {
    os: {
      family: osMeta.Family,
      name: osMeta.Name || null,
      eosl: osMeta.EOSL === true,
    },
    pkgNum,
    trivyVersion: await trivyVersion(),
    total: vulns.length,
    fixable: groupFixableByPackage(fixable),
    fixableVulnCount: fixable.length,
    unfixed: {
      total: unfixed.length,
      bySeverity: severityBreakdown(unfixed),
    },
    scan: {
      mode: "rootfs",
      target: "/",
      skipDirs: ROOTFS_SKIP_DIRS,
      durationMs,
    },
    durationMs,
  };
}

/** Estado del análisis de paquetes del sistema para el bloque de Alcance. Función pura; la frase la pone el dashboard. */
function systemPackagesSupport(platform, result, opts = {}) {
  // Desactivado: en Linux se podía hacer y no se hizo; fuera de Linux no aplica.
  if (!opts.enabled) return platform === "linux" ? "supported-not-run" : "not-applicable";

  if (!result) return "failed";

  if (result.skipped) {
    // Trivy no reconoció el sistema: en Linux es un gestor que no sabe leer.
    if (result.kind === "os-unsupported") {
      return platform === "linux" ? "unsupported-manager" : "not-applicable";
    }
    return "failed";
  }

  return "scanned";
}

module.exports = {
  runTrivyRootfs,
  systemPackagesSupport,
  groupFixableByPackage,
  severityBreakdown,
  compareVersions,
  worstSeverity,
  ROOTFS_SKIP_DIRS,
  ROOTFS_TIMEOUT_MS,
};
