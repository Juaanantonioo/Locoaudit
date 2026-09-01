"use strict";

/**
 * test-trivy-separation.js — La carpeta personal y los paquetes del sistema son
 * DOS auditorías independientes.
 *
 * Historia, porque explica qué protege cada assert:
 *
 *  1. Al principio el interruptor hacía `if (opts.systemPackages) return
 *     runTrivyRootfs();`, y ese `return` iba ANTES de resolver el objetivo. Un
 *     usuario de Debian que marcaba "Analizar paquetes del sistema" (a) dejaba
 *     de auditar su carpeta personal por completo y (b) anulaba en silencio el
 *     campo "Carpeta a auditar". El dashboard decía "se han analizado TAMBIÉN
 *     los paquetes del sistema" con "Carpeta: /".
 *
 *  2. Se arregló con mergeScans(), que sumaba los `Results` de los dos escaneos
 *     en un solo objeto y colgaba el estado del sistema de `scan.system`. Eso
 *     quitó la pérdida de datos, pero dejó dos preguntas distintas compartiendo
 *     un array: el bloque de alcance tenía que reconstruir a posteriori de cuál
 *     de los dos venía cada cifra, y `origin` era la única pista.
 *
 *  3. Ahora son dos módulos con dos entradas del despacho y dos huecos en `raw`.
 *     mergeScans() ya no existe porque no hay nada que fusionar.
 *
 * Este fichero fija el paso 3 a nivel de MÓDULO: que trivy-fs no vuelva a saber
 * nada de los paquetes del sistema. La prueba de extremo a extremo —que las dos
 * mitades llegan al payload y ninguna anula a la otra— vive en
 * test-audit-host-payload.js, secciones 5 y 6.
 *
 * Uso:
 *   node test/manual/test-trivy-separation.js
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

// El fichero, no solo los exports: una función privada acoplada haría el mismo
// daño sin aparecer en module.exports.
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

// El del sistema es siempre "/" y no lo elige el usuario: el campo del nodo
// acota la CARPETA PERSONAL, y confundirlos fue el bug original.
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

// Ya no hay ningún código que combine los dos resultados, así que la
// independencia es estructural. Lo que sí se puede comprobar aquí es que el
// intérprete del estado del sistema no mira NADA del escaneo de la carpeta.
const homeRoto = { skipped: true, kind: "error", reason: "no se pudo leer el home: EACCES" };
const sistemaOk = { os: { family: "debian", name: "13.6" }, pkgNum: 2056, unfixed: { total: 4078 } };

ok(trivyRootfs.systemPackagesSupport("linux", sistemaOk, { enabled: true }) === "scanned",
   "el sistema sale 'scanned' aunque el escaneo de la carpeta haya fallado");

// Y al revés: el resultado de la carpeta no puede colarse como si fuera el del
// sistema. Un skipped del home tiene kinds ('error') que aquí significan otra cosa.
ok(trivyRootfs.systemPackagesSupport("linux", homeRoto, { enabled: true }) === "failed",
   "un resultado fallido nunca se lee como análisis conseguido");

console.log("\n── 4 · Agrupar lo corregible: por PAQUETE, no por CVE ────────────\n");

// Cinco CVE corregidos en la misma versión son UNA orden para el usuario, no
// cinco tarjetas idénticas.
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
// Quedarse con la primera FixedVersion dejaría CVE-2 sin corregir después de
// actualizar, y la tarjeta afirmaría lo contrario.
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

// El id lleva el NOMBRE del paquete para sobrevivir entre ejecuciones, pero el
// nombre solo no es único: el mismo paquete puede estar instalado en dos
// versiones. Sin desambiguar, los dos findings salían con el mismo id y el
// dashboard mostraba uno pisando al otro.
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

// Y lo corregible SÍ es accionable: sale de la base de datos del gestor, no de
// un lockfile, así que eleva el riesgo global y trae comando.
const { summarize } = require("../../lib/severity-map");
const resumen = summarize(conRepetido);
ok(resumen.maxSeverity === "critical",
   "un paquete del sistema con corrección disponible SÍ eleva el riesgo global", resumen.maxSeverity);
ok(resumen.actionable.total === 3, "los 3 cuentan como accionables", String(resumen.actionable.total));
ok(conRepetido.every((f) => f.command && f.command.includes("apt")),
   "cada uno trae su comando de actualización del gestor real");

console.log("\n── 6 · UNKNOWN es un valor real y no se colapsa ──────────────────\n");

// Trivy usa UNKNOWN de verdad (94 casos en la Debian 13.6 de referencia).
// Convertirlo en LOW inventaría una valoración que nadie ha hecho.
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
