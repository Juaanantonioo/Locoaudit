"use strict";

/**
 * Vulnerabilidades de los paquetes del SISTEMA anfitrión, con `trivy rootfs`. Va aparte de trivy-fs.js porque `trivy fs`
 * sobre el HOME solo ve lockfiles (`origin: 'declared'`) y no la base de paquetes del SO.
 * Mismo contrato de fallo que trivy-fs.js y lynis.js: { skipped, kind, reason }, y se decide por `kind`.
 * Que Trivy esté instalado lo comprueba el despacho de audit-host, no este módulo.
 */

const { execToFile, execCommand } = require("./executor");

// rootfs recorre el sistema entero. Con el timeout corto de `fs` se cortaba a mitad y el JSON
// parcial se leía como un escaneo limpio.
const ROOTFS_TIMEOUT_MS = 600000;

/**
 * Directorios que no son paquetes del sistema y sí son un problema si se recorren: /proc y /sys
 * son sistemas de ficheros virtuales del kernel, /dev son nodos de dispositivo, /run es estado
 * volátil, y /var/lib/docker son las capas de las imágenes, que audita audit-image y no este nodo.
 */
const ROOTFS_SKIP_DIRS = ["/proc", "/sys", "/dev", "/run", "/var/lib/docker"];

/** Se guarda con el resultado: si la forma de la salida cambia, dice si fue Trivy o nosotros. */
async function trivyVersion() {
  try {
    const out = await execCommand("trivy --version", 5000);
    const m = out.match(/Version:\s*(\S+)/i);
    return m ? m[1] : (out.split("\n")[0] || "").trim() || null;
  } catch (_) {
    return null;
  }
}

/** Severidad tal cual la da Trivy, en mayúsculas. UNKNOWN es un valor real suyo y se conserva:
 *  colapsarlo en LOW inventaría una valoración que nadie ha hecho. */
function trivySeverity(v) {
  const s = String((v && v.Severity) || "UNKNOWN").trim().toUpperCase();
  return s || "UNKNOWN";
}

const SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"];

/** La peor de las dos, con UNKNOWN al final: no se sabe qué es, así que no manda sobre nada. */
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

/**
 * Compara dos versiones de paquete por sus tramos numéricos. No es un comparador de versiones de
 * Debian completo (epoch, el operador ~ y el resto de reglas de dpkg no caben aquí) y no pretende
 * serlo: solo decide cuál de dos FixedVersion del MISMO paquete es la mayor. Ante algo que no sabe
 * comparar devuelve 0 y el llamante se queda con la que ya tenía, que es la respuesta segura.
 */
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

/**
 * Agrupa las vulnerabilidades CON corrección POR PAQUETE y no por CVE: la acción es actualizar un paquete, y cinco CVE
 * corregidos en la misma versión son una sola orden. La clave lleva la versión instalada, porque dos versiones del mismo
 * nombre (multiarch) no se arreglan con la misma orden.
 */
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
    // Pero la versión que hay que instalar es la que cubre a TODAS: quedarse con la primera
    // dejaría CVE del grupo sin corregir después de actualizar, y la tarjeta diría lo contrario.
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

/**
 * Ejecuta el escaneo y devuelve los datos ya particionados, o { skipped, kind, reason }.
 * No construye findings: eso es de lib/normalizer.js, igual que con todos los demás módulos.
 */
async function runTrivyRootfs() {
  const started = Date.now();

  const cmd = (file) =>
    "trivy rootfs --scanners vuln --pkg-types os --quiet " +
    `--skip-dirs ${ROOTFS_SKIP_DIRS.join(",")} ` +
    `-f json -o "${file}" /`;

  // A fichero y no por stdout: en una Debian 13 normal esta salida son 24 MB de JSON, y exec()
  // mata el proceso al pasarse de maxBuffer y entrega un trozo cortado que parece salida válida.
  const report = await execToFile(cmd, ROOTFS_TIMEOUT_MS, { prefix: "lcaudit-trivy-rootfs-" });

  const durationMs = Date.now() - started;
  if (report.skipped) return { ...report, durationMs };

  // Guarda de plataforma: la da el INFORME, no una lista de gestores nuestra.
  // Sin esto, macOS y Windows caerían en el bucle de abajo, no encontrarían nada, y el informe
  // diría "0 vulnerabilidades del sistema" sobre unos paquetes que Trivy ni siquiera sabe leer.
  // Cero por no haber mirado y cero por estar limpio no se pueden renderizar igual.
  // Por el informe y no por una lista de distros o de gestores: esa lista envejece con cada
  // versión de Trivy y le decía que no a distribuciones que sí sabía analizar.
  const osMeta = report && report.Metadata && report.Metadata.OS;
  if (!osMeta || !osMeta.Family) {
    return {
      skipped: true,
      kind: "os-unsupported",
      reason: "Trivy no ha detectado la familia del sistema operativo",
      durationMs,
    };
  }

  // Los paquetes analizados salen del propio informe. Es la única cifra que Trivy respalda; la
  // que da dpkg en sw-inventory es otra medida de otra fuente y no se intenta cuadrar con esta.
  const pkgNum =
    report.Metadata && typeof report.Metadata.PackageCount === "number"
      ? report.Metadata.PackageCount
      : countPackages(report);

  const vulns = [];
  for (const result of report.Results || []) {
    // --pkg-types os ya lo acota, pero un Results de otra clase aquí sería un dato de otra
    // pregunta colándose en esta.
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

/**
 * Estado del análisis de paquetes del sistema, para el bloque de Alcance. Pura (plataforma y resultado por parámetro, para
 * testear las tres plataformas desde una máquina). Devuelve un hecho y no prosa: la frase la escribe el dashboard.
 */
function systemPackagesSupport(platform, result, opts = {}) {
  // Desactivado: no hay informe del que derivar nada, así que solo queda la plataforma. En Linux
  // el análisis sí era posible y no se hizo ('supported-not-run'); fuera de Linux nunca lo fue.
  if (!opts.enabled) return platform === "linux" ? "supported-not-run" : "not-applicable";

  if (!result) return "failed";

  if (result.skipped) {
    // Trivy miró y no reconoció el sistema: en Linux eso es un gestor que no sabe leer, y fuera
    // de Linux, que esa plataforma no tiene paquetes de sistema que Trivy cubra.
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
