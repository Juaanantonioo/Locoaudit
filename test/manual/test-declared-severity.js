"use strict";

/**
 * test-declared-severity.js — Los hallazgos 'declared' de host no elevan el riesgo.
 * Un lockfile de un programa de terceros no describe el equipo; en imágenes Docker, en cambio, sí elevan.
 * Uso: node test/manual/test-declared-severity.js (sin framework; sale con 1 si falla)
 */

const path = require("path");
const { resumir, esAccionable } = require("../../lib/severity-map");
const { normalizarHost, normalizarImagen } = require("../../lib/normalizer");

let failed = 0;
let passed = 0;

function ok(cond, label, detail) {
  if (cond) {
    passed++;
    console.log(`  ✓ ${label}`);
  } else {
    failed++;
    console.log(`  ✗ ${label}`);
    if (detail) console.log(`      ${detail}`);
  }
}

/** Finding mínimo con la forma que produce el normalizador. */
function f(over) {
  return Object.assign(
    { id: "X-001", title: "t", severity: "high", evidence: "e", category: "vulnerability" },
    over
  );
}

console.log("\n── 1 · Riesgo global: quién lo eleva y quién no ──────────────────\n");

const casos = [
  {
    label: "host + declared + high → NO eleva",
    findings: [f({ scope: "host", origin: "declared", severity: "high" })],
    maxSeverity: "info",
    actionable: 0,
    informative: 1,
  },
  {
    label: "host + installed + high → SÍ eleva",
    findings: [f({ scope: "host", origin: "installed", severity: "high" })],
    maxSeverity: "high",
    actionable: 1,
    informative: 0,
  },
  {
    label: "IMAGEN + declared + critical → SÍ eleva (os-pkgs sin PkgPath)",
    findings: [f({ id: "IMG-CVE-001", scope: "image", origin: "declared", severity: "critical" })],
    maxSeverity: "critical",
    actionable: 1,
    informative: 0,
  },
  {
    label: "IMAGEN + installed + high → SÍ eleva",
    findings: [f({ id: "IMG-CVE-002", scope: "image", origin: "installed", severity: "high" })],
    maxSeverity: "high",
    actionable: 1,
    informative: 0,
  },
  {
    label: "host mixto: 1 installed medium + 20 declared critical → medium",
    findings: [
      f({ scope: "host", origin: "installed", severity: "medium" }),
      ...Array.from({ length: 20 }, (_, i) =>
        f({ id: `HOST-CVE-${i}`, scope: "host", origin: "declared", severity: "critical" })
      ),
    ],
    maxSeverity: "medium",
    actionable: 1,
    informative: 20,
  },
  {
    label: "legacy sin scope ni origin + high → SÍ eleva (compatibilidad)",
    findings: [f({ severity: "high" })],
    maxSeverity: "high",
    actionable: 1,
    informative: 0,
  },
  {
    label: "legacy sin scope pero con origin declared → NO eleva (se trata como host)",
    findings: [f({ origin: "declared", severity: "critical" })],
    maxSeverity: "info",
    actionable: 0,
    informative: 1,
  },
  {
    label: "performance critical → NO eleva (precedente que ya existía)",
    findings: [f({ scope: "host", category: "performance", severity: "critical" })],
    maxSeverity: "info",
    actionable: 0,
    informative: 1,
  },
  {
    label: "severity info → informativo por definición",
    findings: [f({ scope: "host", severity: "info" })],
    maxSeverity: "info",
    actionable: 0,
    informative: 1,
  },
];

for (const c of casos) {
  const s = resumir(c.findings);
  ok(
    s.maxSeverity === c.maxSeverity &&
      s.actionable.total === c.actionable &&
      s.informative.total === c.informative,
    c.label,
    `esperado maxSeverity=${c.maxSeverity} act=${c.actionable} inf=${c.informative} · ` +
      `obtenido maxSeverity=${s.maxSeverity} act=${s.actionable.total} inf=${s.informative.total}`
  );
}

console.log("\n── 2 · Contraste declared host vs declared imagen ────────────────\n");

// Mismo CVE, misma severidad, misma marca 'declared'. Solo cambia el scope.
const mismoCve = {
  id: "CVE-2026-4800", title: "lodash@4.17.23", severity: "critical",
  evidence: "CVSS 9.8", category: "vulnerability", origin: "declared",
  location: "plugins/discord/bun.lock",
};

const enHost   = resumir([Object.assign({}, mismoCve, { scope: "host" })]);
const enImagen = resumir([Object.assign({}, mismoCve, { scope: "image" })]);

console.log("  hallazgo idéntico (declared · critical · CVSS 9.8), solo cambia scope:");
console.log(`    scope=host   → maxSeverity ${enHost.maxSeverity.padEnd(8)} ` +
            `actionable ${enHost.actionable.total}  informative ${enHost.informative.total}`);
console.log(`    scope=image  → maxSeverity ${enImagen.maxSeverity.padEnd(8)} ` +
            `actionable ${enImagen.actionable.total}  informative ${enImagen.informative.total}`);
console.log("");

ok(enHost.maxSeverity === "info",       "en host   el riesgo global NO sube");
ok(enImagen.maxSeverity === "critical", "en imagen el riesgo global SÍ sube");
ok(esAccionable(Object.assign({}, mismoCve, { scope: "image" })) === true,
   "esAccionable() coincide con summarize() en imagen");
ok(esAccionable(Object.assign({}, mismoCve, { scope: "host" })) === false,
   "esAccionable() coincide con summarize() en host");

console.log("\n── 3 · counts NO cambia: los 96 se siguen contando ───────────────\n");

// La segmentación es de presentación: ningún hallazgo desaparece del total.
const noventaYSeis = Array.from({ length: 96 }, (_, i) =>
  f({ id: `HOST-CVE-${i}`, scope: "host", origin: "declared", severity: i < 9 ? "critical" : "high" })
);
const s96 = resumir(noventaYSeis);
const total = Object.values(s96.counts).reduce((a, b) => a + b, 0);

ok(total === 96, "counts sigue sumando 96", `obtenido ${total}`);
ok(s96.counts.critical === 9, "counts.critical conserva los 9 críticos originales");
ok(s96.actionable.counts.critical === 0, "actionable.counts.critical es 0");
ok(s96.informative.total === 96, "los 96 caen en informative");
ok(s96.actionable.total + s96.informative.total === 96,
   "actionable + informative == total (sin dobles conteos ni huecos)");

console.log("\n── 4 · Clasificación por Class: os-pkgs vs lang-pkgs ─────────────\n");

// Trivy no rellena PkgPath en paquetes del SO; aun así deben salir 'installed' (ver origenDe()).
function trivyResult({ cls, type, pkg, pkgPath = null, sev = "CRITICAL", target = "/ (debian 12.5)" }) {
  return {
    Results: [{
      Target: target, Class: cls, Type: type,
      Vulnerabilities: [{
        VulnerabilityID: "CVE-2026-9999", PkgName: pkg, PkgPath: pkgPath,
        InstalledVersion: "1.0.0", FixedVersion: "1.0.1", Severity: sev,
      }],
    }],
  };
}

const osPkgHost = normalizarHost(
  { trivy: trivyResult({ cls: "os-pkgs", type: "debian", pkg: "openssl" }) },
  { platform: "linux", pkgManager: "apt" }
);
const langPkgHost = normalizarHost(
  { trivy: trivyResult({ cls: "lang-pkgs", type: "npm", pkg: "lodash", target: "proyecto/yarn.lock" }) },
  { platform: "linux", pkgManager: "apt" }
);
const osPkgImage = normalizarImagen(trivyResult({ cls: "os-pkgs", type: "debian", pkg: "openssl" }), "trivy");

const sOsHost = resumir(osPkgHost);
const sLangHost = resumir(langPkgHost);
const sOsImage = resumir(osPkgImage);

console.log("  misma ausencia de PkgPath, distinto Class:");
console.log(`    host  · os-pkgs   → origin ${String(osPkgHost[0].origin).padEnd(9)} maxSeverity ${sOsHost.maxSeverity.padEnd(8)} actionable ${sOsHost.actionable.total}`);
console.log(`    host  · lang-pkgs → origin ${String(langPkgHost[0].origin).padEnd(9)} maxSeverity ${sLangHost.maxSeverity.padEnd(8)} actionable ${sLangHost.actionable.total}`);
console.log(`    image · os-pkgs   → origin ${String(osPkgImage[0].origin).padEnd(9)} maxSeverity ${sOsImage.maxSeverity.padEnd(8)} actionable ${sOsImage.actionable.total}`);
console.log("");

ok(osPkgHost[0].origin === "installed", "host · os-pkgs sin PkgPath → origin 'installed'", osPkgHost[0].origin);
ok(sOsHost.maxSeverity === "critical", "host · os-pkgs SÍ eleva el riesgo global", sOsHost.maxSeverity);
ok(sOsHost.actionable.total === 1, "host · os-pkgs cuenta como accionable");
ok(langPkgHost[0].origin === "declared", "host · lang-pkgs sin PkgPath → origin 'declared'", langPkgHost[0].origin);
ok(sLangHost.maxSeverity === "info", "host · lang-pkgs NO eleva el riesgo global", sLangHost.maxSeverity);
ok(osPkgImage[0].origin === "installed", "image · os-pkgs → origin 'installed'", osPkgImage[0].origin);
ok(sOsImage.maxSeverity === "critical", "image · os-pkgs sigue elevando", sOsImage.maxSeverity);

// PkgPath sigue mandando para los paquetes de lenguaje instalados en disco.
const langInstalled = normalizarHost(
  { trivy: trivyResult({ cls: "lang-pkgs", type: "node-pkg", pkg: "minimist",
                         pkgPath: "/home/u/proyecto/node_modules/minimist/index.js" }) },
  { platform: "linux", pkgManager: "apt" }
);
ok(langInstalled[0].origin === "installed", "host · lang-pkgs CON PkgPath → sigue siendo 'installed'");

console.log("\n── 5 · Salida REAL de trivy rootfs (fixture medido) ──────────────\n");

// Fixture: recorte real de `trivy rootfs` sobre Debian 12.
const rootfsRaw = require(path.join(__dirname, "../fixtures/trivy/rootfs-debian.json"));
const rootfsFindings = normalizarHost({ trivy: rootfsRaw }, { platform: "linux", pkgManager: "apt" });
const sRootfs = resumir(rootfsFindings);
const conPkgPath = rootfsRaw.Results[0].Vulnerabilities.filter((v) => v.PkgPath).length;

console.log(`  vulnerabilidades en el fixture: ${rootfsRaw.Results[0].Vulnerabilities.length} · con PkgPath: ${conPkgPath}`);
console.log(`  findings: ${rootfsFindings.length} · maxSeverity: ${sRootfs.maxSeverity} · actionable: ${sRootfs.actionable.total}`);
rootfsFindings.forEach((f) => console.log(`    ${f.id} | ${f.severity.padEnd(8)} | ${f.origin} | ${String(f.command)}`));
console.log("");

ok(conPkgPath === 0, "el fixture reproduce la ausencia total de PkgPath en os-pkgs");
ok(rootfsFindings.every((f) => f.origin === "installed"), "los paquetes de dpkg salen todos 'installed'");
ok(sRootfs.maxSeverity === "critical", "maxSeverity critical (openssl, libssl3, zlib1g)", sRootfs.maxSeverity);
ok(sRootfs.actionable.total === rootfsFindings.length, "todos son accionables");
ok(sRootfs.informative.total === 0, "ninguno cae en informativos");

const cmdOpenssl = rootfsFindings.find((f) => /openssl@/.test(f.title));
ok(cmdOpenssl && cmdOpenssl.command === "sudo apt update && sudo apt install --only-upgrade openssl",
   "openssl genera el comando de apt, no la prosa de lockfile",
   cmdOpenssl && cmdOpenssl.command);
ok(rootfsFindings.every((f) => !/fichero de bloqueo/.test(f.fix || "")),
   "ningún paso de resolución dice ya 'anotado en un fichero de bloqueo'");

console.log("\n── 6 · Las declaradas del HOST se colapsan en una sola tarjeta ───\n");

// Datos sintéticos: las declaradas de host se colapsan en resúmenes (el JSON conserva el detalle).
const mkRes = (target, vulns) => ({ Target: target, Class: "lang-pkgs", Type: "npm", Vulnerabilities: vulns });
const mkVuln = (id, pkg, sev, fixed) => ({
  VulnerabilityID: id, PkgName: pkg, InstalledVersion: "1.0.0", Severity: sev,
  ...(fixed ? { FixedVersion: fixed } : {}),
});

// Siete declaradas en tres ficheros, repartidas por los tres cubos de severidad.
const declaradoRaw = {
  Results: [
    mkRes("proyectos/api/package-lock.json", [
      mkVuln("CVE-D1", "lodash", "CRITICAL", "4.17.21"),
      mkVuln("CVE-D2", "axios", "HIGH"),
      mkVuln("CVE-D3", "minimist", "MEDIUM", "1.2.6"),
    ]),
    mkRes("proyectos/web/yarn.lock", [
      mkVuln("CVE-D4", "tar", "MEDIUM"),
      mkVuln("CVE-D5", "glob", "LOW", "7.2.0"),
    ]),
    mkRes("proyectos/api/pom.xml", [
      mkVuln("CVE-D6", "log4j", "CRITICAL", "2.17.1"),
      mkVuln("CVE-D7", "jackson", "LOW"),
    ]),
  ],
  scan: { mode: "fs", target: "/home/ana" },
};

const colapsado = normalizarHost({ trivy: declaradoRaw }, { platform: "linux", pkgManager: "apt" });
const agg = colapsado.filter((f) => f.id === "HOST-CVE-DECLARED");

console.log(`  7 declaradas en 3 ficheros → ${colapsado.length} finding(s): ${JSON.stringify(colapsado.map((f) => f.id))}`);

ok(colapsado.length === 1, "las 7 se colapsan en UN solo finding", JSON.stringify(colapsado.map((f) => f.id)));
ok(agg.length === 1, "ese finding es HOST-CVE-DECLARED");
ok(agg[0].severity === "info", "severidad info: no hay ninguna acción posible", agg[0].severity);
ok(agg[0].fix === null, "sin campo fix");
ok(agg[0].aggregate === true, "marcado como agregado en el DATO, no por el prefijo del id");
ok(agg[0].origin === "declared", "conserva la procedencia, que es lo que lo deja fuera del riesgo");
ok(agg[0].title.startsWith("7 "), "el título lleva el total real", agg[0].title);
ok(agg[0].evidence.includes("3 ficheros"), "la evidencia cuenta los ficheros afectados", agg[0].evidence.slice(0, 80));
ok(/4 de ellas tienen una versión corregida/.test(agg[0].evidence),
   "y cuántas traen FixedVersion (4 de 7)", agg[0].evidence);
ok(agg[0].evidence.includes("exportación JSON"),
   "cierra remitiendo al JSON, donde el detalle SÍ está completo");

const sColapsado = resumir(colapsado);
ok(sColapsado.actionable.total === 0, "ninguna cuenta como accionable", String(sColapsado.actionable.total));
ok(sColapsado.maxSeverity === "info", "y no elevan el riesgo global", sColapsado.maxSeverity);

// Ningún CVE suelto sobrevive en el dashboard de host.
ok(!colapsado.some((f) => /^HOST-CVE-(\d|MED|LOW)/.test(f.id)),
   "no queda ningún HOST-CVE-NNN / -MED / -LOW suelto",
   JSON.stringify(colapsado.map((f) => f.id)));

console.log("\n── 7 · La IMAGEN conserva su detalle intacto ─────────────────────\n");

// En audit-image no se colapsa: normalizarImagen no pasa collapseDeclared.
const declaradasEnImagen = normalizarImagen(declaradoRaw, "trivy");
console.log(`  mismo JSON por normalizarImagen → ${declaradasEnImagen.length} findings: ${JSON.stringify(declaradasEnImagen.map((f) => f.id))}`);

ok(declaradasEnImagen.length > 1, "la imagen sigue enumerando", String(declaradasEnImagen.length));
ok(!declaradasEnImagen.some((f) => f.aggregate), "y no aparece ningún agregado");
ok(!declaradasEnImagen.some((f) => f.id === "HOST-CVE-DECLARED"), "ni el HOST-CVE-DECLARED del host");

// Mezcla instaladas + declaradas: solo se colapsan las segundas.
const mixtoRaw = {
  Results: [
    mkRes("proyectos/api/yarn.lock", [mkVuln("CVE-M1", "lodash", "HIGH", "4.17.21")]),
    { Target: "/ (debian 12)", Class: "os-pkgs", Type: "debian",
      Vulnerabilities: [mkVuln("CVE-M2", "openssl", "CRITICAL", "3.0.14")] },
  ],
  scan: { mode: "fs", target: "/home/ana" },
};
const mixto = normalizarHost({ trivy: mixtoRaw }, { platform: "linux", pkgManager: "apt" });
console.log(`  mezcla instalada+declarada → ${JSON.stringify(mixto.map((f) => f.id))}`);
ok(mixto.some((f) => f.id === "HOST-CVE-DECLARED"), "la declarada se colapsa");
ok(mixto.some((f) => f.origin === "installed" && !f.aggregate),
   "y la INSTALADA sigue enumerada, con su comando");
ok(resumir(mixto).actionable.total === 1,
   "solo la instalada cuenta como accionable", String(resumir(mixto).actionable.total));

console.log(`\n${passed} pasados · ${failed} fallidos\n`);
process.exit(failed > 0 ? 1 : 0);
