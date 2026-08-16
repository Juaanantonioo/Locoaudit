"use strict";

/**
 * test-declared-severity.js — Los hallazgos 'declared' de host no elevan el riesgo.
 *
 * Fija el arreglo del segundo falso positivo de la herramienta (el primero fue el
 * tick verde sobre un host inexistente, ver test-host-state.js):
 *
 *   Trivy leía ficheros de bloqueo (yarn.lock, bun.lock, pom.xml) empaquetados
 *   dentro de programas de terceros y los presentaba con su CVSS. Medido en
 *   macOS: 96 hallazgos, 96 de ellos 'declared', y el resumen decía RIESGO
 *   CRÍTICO por un yarn.lock de una extensión de VS Code de 2019. El usuario no
 *   tenía absolutamente nada que hacer.
 *
 * El CVSS de esos hallazgos describe la vulnerabilidad si la ejecutaras, no el
 * estado del equipo. Fuera del riesgo global.
 *
 * EL CONTRASTE ES LA MITAD DEL TEST: en una imagen Docker la misma marca
 * 'declared' significa lo contrario. Los CVEs de paquetes del SO llegan SIN
 * PkgPath (medido con trivy 0.72.0 sobre debian:12 → 0 de 169 traen PkgPath),
 * así que la regla `PkgPath ? installed : declared` de normalizer.js los marca
 * 'declared' aunque estén instalados dentro de la imagen. Ahí SÍ elevan.
 *
 * Uso:
 *   node test/manual/test-declared-severity.js
 *
 * Sin framework, como el resto de test/manual/*.js. Sale con código 1 si falla.
 */

const path = require("path");
const { summarize, isActionable } = require("../../lib/severity-map");
const { normalizeHost, normalizeImage } = require("../../lib/normalizer");

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
  const s = summarize(c.findings);
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

const enHost   = summarize([Object.assign({}, mismoCve, { scope: "host" })]);
const enImagen = summarize([Object.assign({}, mismoCve, { scope: "image" })]);

console.log("  hallazgo idéntico (declared · critical · CVSS 9.8), solo cambia scope:");
console.log(`    scope=host   → maxSeverity ${enHost.maxSeverity.padEnd(8)} ` +
            `actionable ${enHost.actionable.total}  informative ${enHost.informative.total}`);
console.log(`    scope=image  → maxSeverity ${enImagen.maxSeverity.padEnd(8)} ` +
            `actionable ${enImagen.actionable.total}  informative ${enImagen.informative.total}`);
console.log("");

ok(enHost.maxSeverity === "info",       "en host   el riesgo global NO sube");
ok(enImagen.maxSeverity === "critical", "en imagen el riesgo global SÍ sube");
ok(isActionable(Object.assign({}, mismoCve, { scope: "image" })) === true,
   "isActionable() coincide con summarize() en imagen");
ok(isActionable(Object.assign({}, mismoCve, { scope: "host" })) === false,
   "isActionable() coincide con summarize() en host");

console.log("\n── 3 · counts NO cambia: los 96 se siguen contando ───────────────\n");

// La segmentación es de presentación: ningún hallazgo desaparece del total.
const noventaYSeis = Array.from({ length: 96 }, (_, i) =>
  f({ id: `HOST-CVE-${i}`, scope: "host", origin: "declared", severity: i < 9 ? "critical" : "high" })
);
const s96 = summarize(noventaYSeis);
const total = Object.values(s96.counts).reduce((a, b) => a + b, 0);

ok(total === 96, "counts sigue sumando 96", `obtenido ${total}`);
ok(s96.counts.critical === 9, "counts.critical conserva los 9 críticos originales");
ok(s96.actionable.counts.critical === 0, "actionable.counts.critical es 0");
ok(s96.informative.total === 96, "los 96 caen en informative");
ok(s96.actionable.total + s96.informative.total === 96,
   "actionable + informative == total (sin dobles conteos ni huecos)");

console.log("\n── 4 · Clasificación por Class: os-pkgs vs lang-pkgs ─────────────\n");

// Trivy NO rellena PkgPath en paquetes del SO. Medido con trivy 0.72.0:
//   trivy rootfs sobre un árbol Debian 12 → 117 vulnerabilidades, 0 con PkgPath
//   trivy image  debian:12                → 169 vulnerabilidades, 0 con PkgPath
// Con la regla `PkgPath ? installed : declared` a secas, openssl instalado por
// dpkg salía 'declared', quedaba fuera del riesgo global Y el paso de resolución
// le decía al usuario que "no es software instalado en tu equipo". Ver originOf()
// en lib/normalizer.js.
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

const osPkgHost = normalizeHost(
  { trivy: trivyResult({ cls: "os-pkgs", type: "debian", pkg: "openssl" }) },
  { platform: "linux", pkgManager: "apt" }
);
const langPkgHost = normalizeHost(
  { trivy: trivyResult({ cls: "lang-pkgs", type: "npm", pkg: "lodash", target: "proyecto/yarn.lock" }) },
  { platform: "linux", pkgManager: "apt" }
);
const osPkgImage = normalizeImage(trivyResult({ cls: "os-pkgs", type: "debian", pkg: "openssl" }), "trivy");

const sOsHost = summarize(osPkgHost);
const sLangHost = summarize(langPkgHost);
const sOsImage = summarize(osPkgImage);

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
const langInstalled = normalizeHost(
  { trivy: trivyResult({ cls: "lang-pkgs", type: "node-pkg", pkg: "minimist",
                         pkgPath: "/home/u/proyecto/node_modules/minimist/index.js" }) },
  { platform: "linux", pkgManager: "apt" }
);
ok(langInstalled[0].origin === "installed", "host · lang-pkgs CON PkgPath → sigue siendo 'installed'");

console.log("\n── 5 · Salida REAL de trivy rootfs (fixture medido) ──────────────\n");

// test/fixtures/trivy/rootfs-debian.json: recorte de una ejecución real de
// `trivy rootfs` 0.72.0 sobre un árbol Debian 12 (openssl, libssl3, curl, zlib1g).
const rootfsRaw = require(path.join(__dirname, "../fixtures/trivy/rootfs-debian.json"));
const rootfsFindings = normalizeHost({ trivy: rootfsRaw }, { platform: "linux", pkgManager: "apt" });
const sRootfs = summarize(rootfsFindings);
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

console.log(`\n${passed} pasados · ${failed} fallidos\n`);
process.exit(failed > 0 ? 1 : 0);
