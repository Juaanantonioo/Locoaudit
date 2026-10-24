"use strict";

/**
 * test-trivy-separation.js — La carpeta personal y los paquetes del sistema son dos auditorías independientes.
 * Fija que trivy-fs no sepa nada de los paquetes del sistema (extremo a extremo: test-audit-host-payload.js, 5 y 6).
 * Uso: node test/manual/test-trivy-separation.js
 */

const trivyFs = require("../../nodes/audit-host/modules/trivy-fs");
const trivyRootfs = require("../../lib/trivy-rootfs");

let failed = 0;
let passed = 0;

function ok(cond, label, detail) {
  if (cond) { passed++; console.log(`  ✓ ${label}`); }
  else { failed++; console.log(`  ✗ ${label}`); if (detail) console.log(`      ${detail}`); }
}

console.log("\n── 1 · trivy-fs ya no sabe nada de los paquetes del sistema ──────\n");

// Si alguno de estos vuelve, es que el acoplamiento ha vuelto con él.
for (const nombre of ["mergeScans", "runTrivyRootfs", "systemPackagesSupport", "TRIVY_OS_MANAGERS"]) {
  ok(trivyFs[nombre] === undefined,
     `trivy-fs NO exporta ${nombre}`,
     `sigue exportando ${nombre}: el escaneo del sistema ha vuelto a colarse en el módulo de la carpeta`);
}

ok(typeof trivyFs.runTrivyFs === "function", "trivy-fs sigue exportando runTrivyFs");
ok(typeof trivyRootfs.runTrivyRootfs === "function", "trivy-rootfs exporta runTrivyRootfs");
ok(typeof trivyRootfs.systemPackagesSupport === "function",
   "systemPackagesSupport vive ahora junto al módulo cuyo resultado interpreta");

// Se mira el fichero entero, no solo los exports.
const fs = require("fs");
const path = require("path");
const fuente = fs.readFileSync(
  path.join(__dirname, "../../nodes/audit-host/modules/trivy-fs.js"), "utf8");
const codigo = fuente.split("\n")
  .filter((l) => !/^\s*(\*|\/\/|\/\*)/.test(l))   // los comentarios sí pueden citarlo
  .join("\n");

ok(!/trivy\s+rootfs/.test(codigo),
   "el código de trivy-fs no invoca `trivy rootfs` por ningún camino");
ok(!/\bsystemPackages\b/.test(codigo),
   "el código de trivy-fs no lee ninguna opción `systemPackages`");

console.log("\n── 2 · Los dos objetivos son fijos y distintos ───────────────────\n");

// El del sistema es siempre "/"; el campo del nodo solo acota la carpeta personal.
ok(trivyRootfs.ROOTFS_SKIP_DIRS.includes("/proc") &&
   trivyRootfs.ROOTFS_SKIP_DIRS.includes("/sys") &&
   trivyRootfs.ROOTFS_SKIP_DIRS.includes("/dev"),
   "el rootfs excluye los sistemas de ficheros virtuales del kernel",
   JSON.stringify(trivyRootfs.ROOTFS_SKIP_DIRS));

ok(!trivyRootfs.ROOTFS_SKIP_DIRS.some((d) => trivyFs.DEFAULT_SKIP_DIRS.includes(d)),
   "las exclusiones de los dos módulos no se solapan: son ámbitos distintos");

// El objetivo de la carpeta sí lo elige el usuario, y sigue haciéndolo.
const conConfig = trivyFs.resolveScanTarget("~/proyectos");
ok(conConfig.resolvedFrom === "config" && conConfig.target.endsWith("proyectos"),
   "resolveScanTarget sigue respetando el campo del nodo",
   JSON.stringify(conConfig));

const sinConfig = trivyFs.resolveScanTarget("");
ok(sinConfig.resolvedFrom !== "config" && sinConfig.target,
   "y sin campo cae en el home, no en /", JSON.stringify(sinConfig));
ok(sinConfig.target !== "/",
   "el escaneo de la carpeta NUNCA apunta a / por omisión: ese era el bug original");

console.log("\n── 3 · Un módulo caído no arrastra al otro ───────────────────────\n");

// El intérprete del estado del sistema no mira nada del escaneo de la carpeta.
const homeRoto = { skipped: true, kind: "error", reason: "no se pudo leer el home: EACCES" };
const sistemaOk = { os: { family: "debian", name: "13.6" }, pkgNum: 2056, unfixed: { total: 4078 } };

ok(trivyRootfs.systemPackagesSupport("linux", sistemaOk, { enabled: true }) === "scanned",
   "el sistema sale 'scanned' aunque el escaneo de la carpeta haya fallado");

// Y al revés: el resultado de la carpeta no se toma por el del sistema.
ok(trivyRootfs.systemPackagesSupport("linux", homeRoto, { enabled: true }) === "failed",
   "un resultado fallido nunca se lee como análisis conseguido");

console.log("\n── 4 · Agrupar lo corregible: por PAQUETE, no por CVE ────────────\n");

// Cinco CVE corregidos en la misma versión dan una sola orden.
const vulns = [
  { PkgName: "openssl", InstalledVersion: "3.0.11-1", FixedVersion: "3.0.14-1", Severity: "MEDIUM", VulnerabilityID: "CVE-1" },
  { PkgName: "openssl", InstalledVersion: "3.0.11-1", FixedVersion: "3.0.15-1", Severity: "CRITICAL", VulnerabilityID: "CVE-2" },
  { PkgName: "openssl", InstalledVersion: "3.0.11-1", FixedVersion: "3.0.12-1", Severity: "LOW", VulnerabilityID: "CVE-3" },
  { PkgName: "curl",    InstalledVersion: "8.5.0-1",  FixedVersion: "8.6.0-1",  Severity: "HIGH", VulnerabilityID: "CVE-4" },
];
const grupos = trivyRootfs.groupFixableByPackage(vulns);

ok(grupos.length === 2, "3 CVE de openssl + 1 de curl → 2 grupos", `obtenidos ${grupos.length}`);

const openssl = grupos.find((g) => g.pkg === "openssl");
ok(openssl && openssl.cves.length === 3, "el grupo de openssl conserva sus 3 CVE como evidencia");
ok(openssl && openssl.maxSeverity === "CRITICAL",
   "la severidad del grupo es la MÁXIMA: la urgencia la marca la peor", openssl && openssl.maxSeverity);
// Se toma la FixedVersion que corrige todos los CVE, no la primera.
ok(openssl && openssl.fixedVersion === "3.0.15-1",
   "la versión propuesta es la que cubre a TODOS los CVE del grupo, no la primera",
   openssl && openssl.fixedVersion);

// El orden importa: lo más urgente primero.
ok(grupos[0].pkg === "openssl", "los grupos salen ordenados por severidad descendente");

// Un mismo paquete en dos versiones instaladas no se arregla con la misma orden.
const dosVersiones = trivyRootfs.groupFixableByPackage([
  { PkgName: "libfoo", InstalledVersion: "1.0", FixedVersion: "1.1", Severity: "HIGH", VulnerabilityID: "CVE-A" },
  { PkgName: "libfoo", InstalledVersion: "2.0", FixedVersion: "2.1", Severity: "HIGH", VulnerabilityID: "CVE-B" },
]);
ok(dosVersiones.length === 2,
   "el mismo paquete en dos versiones instaladas son dos grupos", `obtenidos ${dosVersiones.length}`);

console.log("\n── 5 · Los ids no colisionan ─────────────────────────────────────\n");

// El id lleva el nombre del paquete y se desambigua si hay dos versiones instaladas.
const { normalizeHost } = require("../../lib/normalizer");
const conRepetido = normalizeHost({
  trivyRootfs: {
    os: { family: "debian", name: "13.6" }, pkgNum: 2056, total: 3,
    fixable: [
      { pkg: "openssl", installedVersion: "3.0.11-1", fixedVersion: "3.0.15-1", maxSeverity: "CRITICAL", cves: [{ id: "CVE-1", severity: "CRITICAL" }] },
      { pkg: "libfoo",  installedVersion: "1.0", fixedVersion: "1.1", maxSeverity: "HIGH", cves: [{ id: "CVE-A", severity: "HIGH" }] },
      { pkg: "libfoo",  installedVersion: "2.0", fixedVersion: "2.1", maxSeverity: "HIGH", cves: [{ id: "CVE-B", severity: "HIGH" }] },
    ],
    fixableVulnCount: 3, unfixed: { total: 0, bySeverity: {} },
  },
}, { platform: "linux", pkgManager: "apt" });

const ids = conRepetido.map((f) => f.id);
ok(new Set(ids).size === ids.length, "ningún id repetido", JSON.stringify(ids));
ok(ids.includes("HOST-OS-PKG-openssl"),
   "el paquete que aparece una vez conserva el id limpio, sin versión", JSON.stringify(ids));
ok(ids.filter((i) => i.startsWith("HOST-OS-PKG-libfoo")).length === 2,
   "el que aparece dos veces se desambigua con la versión instalada", JSON.stringify(ids));

// Lo corregible sí es accionable: eleva el riesgo global y trae comando.
const { summarize } = require("../../lib/severity-map");
const resumen = summarize(conRepetido);
ok(resumen.maxSeverity === "critical",
   "un paquete del sistema con corrección disponible SÍ eleva el riesgo global", resumen.maxSeverity);
ok(resumen.actionable.total === 3, "los 3 cuentan como accionables", String(resumen.actionable.total));
ok(conRepetido.every((f) => f.command && f.command.includes("apt")),
   "cada uno trae su comando de actualización del gestor real");

console.log("\n── 6 · UNKNOWN es un valor real y no se colapsa ──────────────────\n");

// UNKNOWN de Trivy no se convierte en LOW.
const reparto = trivyRootfs.severityBreakdown([
  { Severity: "CRITICAL" }, { Severity: "LOW" }, { Severity: "UNKNOWN" }, { Severity: "UNKNOWN" }, {},
]);
ok(reparto.UNKNOWN === 3, "los que no traen Severity cuentan como UNKNOWN", JSON.stringify(reparto));
ok(reparto.MEDIUM === undefined, "las severidades sin casos NO aparecen con un cero", JSON.stringify(reparto));
ok(Object.keys(reparto)[0] === "CRITICAL", "el reparto sale en orden de severidad", JSON.stringify(reparto));

// UNKNOWN va al final: no se sabe qué es, así que no puede mandar sobre nada.
ok(trivyRootfs.worstSeverity("UNKNOWN", "LOW") === "LOW",
   "UNKNOWN no gana a LOW al calcular la severidad de un grupo");
ok(trivyRootfs.worstSeverity("CRITICAL", "UNKNOWN") === "CRITICAL", "y CRITICAL sí gana a UNKNOWN");

console.log(`\n${passed} pasados · ${failed} fallidos\n`);
process.exit(failed > 0 ? 1 : 0);
