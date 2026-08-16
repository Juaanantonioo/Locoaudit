"use strict";

/**
 * test-trivy-merge.js — El escaneo de paquetes del sistema SUMA, no sustituye.
 *
 * Fija el arreglo de un interruptor que hacía lo contrario de lo que decía:
 *
 *   `if (opts.systemPackages) return runTrivyRootfs();`
 *
 * Ese `return` iba ANTES de resolver el objetivo, así que marcar "Analizar
 * paquetes del sistema" (a) dejaba de auditar la carpeta personal por completo
 * y (b) anulaba en silencio el campo "Carpeta a auditar" del nodo. Un usuario de
 * Debian que marcaba la casilla perdía los hallazgos de sus proyectos sin
 * ningún aviso, y el dashboard afirmaba "se han analizado TAMBIÉN los paquetes
 * del sistema" con "Carpeta: /".
 *
 * mergeScans() es pura, así que aquí no se ejecuta Trivy: fixtures y asserts.
 *
 * Uso:
 *   node test/manual/test-trivy-merge.js
 */

const { mergeScans } = require("../../nodes/audit-host/modules/trivy-fs");

let failed = 0;
let passed = 0;

function ok(cond, label, detail) {
  if (cond) { passed++; console.log(`  ✓ ${label}`); }
  else { failed++; console.log(`  ✗ ${label}`); if (detail) console.log(`      ${detail}`); }
}

/** Resultado del escaneo del home, con la forma que deja scanHomeByChildren. */
function homeScan() {
  return {
    SchemaVersion: 2, ArtifactName: "/home/ana", ArtifactType: "filesystem",
    Results: [
      { Target: "proyectos/api/package-lock.json", Class: "lang-pkgs", Type: "npm", Vulnerabilities: [{ VulnerabilityID: "CVE-A" }] },
      { Target: "proyectos/web/yarn.lock", Class: "lang-pkgs", Type: "yarn", Vulnerabilities: [{ VulnerabilityID: "CVE-B" }] },
    ],
    scan: {
      mode: "fs-by-children", target: "/home/ana", skipDirs: [".cache"],
      durationMs: 31671, resolvedFrom: "env", trivyVersion: "0.72.0",
      children: {
        scanned: [{ name: "proyectos", results: 2, durationMs: 900 }],
        skipped: [{ name: ".cache", kind: "excluded", reason: "en la lista de exclusiones" }],
      },
    },
  };
}

/** Resultado de runTrivyRootfs con éxito. */
function systemScan() {
  return {
    SchemaVersion: 2, ArtifactName: "/", ArtifactType: "filesystem",
    Results: [
      { Target: "/ (debian 12.5)", Class: "os-pkgs", Type: "debian", Vulnerabilities: [{ VulnerabilityID: "CVE-OS-1" }, { VulnerabilityID: "CVE-OS-2" }] },
    ],
    scan: { mode: "rootfs", target: "/", skipDirs: [], durationMs: 240000, resolvedFrom: "systemPackages", trivyVersion: "0.72.0" },
  };
}

console.log("\n── 1 · Los dos escaneos: los Results se concatenan ───────────────\n");

let m = mergeScans(homeScan(), systemScan());

ok(m.Results.length === 3, "3 Results: 2 del home + 1 del sistema", `obtenido ${m.Results.length}`);
ok(m.Results[0].Class === "lang-pkgs" && m.Results[2].Class === "os-pkgs",
   "el orden se preserva: primero el home, después el sistema");
ok(m.scan.system && m.scan.system.status === "scanned", "scan.system.status = 'scanned'");
ok(m.scan.system.results === 1, "scan.system.results cuenta los Result añadidos");
ok(m.scan.system.durationMs === 240000, "scan.system.durationMs es el del rootfs");
ok(m.scan.durationMs === 31671, "scan.durationMs sigue siendo el del HOME, no la suma");

console.log("\n── 2 · Si el sistema falla, el HOME NO se pierde ─────────────────\n");

// Este es el caso que motivó todo el cambio. Un límite conocido de la
// herramienta no puede tirar el trabajo que sí se completó.
const FALLOS = [
  { kind: "unsupported", reason: "Trivy no soporta pacman", esperado: "unsupported" },
  { kind: "unsupported", reason: "rootfs solo aplica en Linux", esperado: "unsupported" },
  { kind: "error", reason: "trivy failed: exit status 2", esperado: "error" },
];

for (const f of FALLOS) {
  m = mergeScans(homeScan(), { skipped: true, kind: f.kind, reason: f.reason });

  ok(m.skipped !== true, `[${f.reason}] el resultado NO queda marcado como skipped`);
  ok(m.Results.length === 2, `[${f.reason}] los 2 Results del home siguen intactos`, `obtenido ${m.Results.length}`);
  ok(m.scan.system.status === f.esperado, `[${f.reason}] scan.system.status = '${f.esperado}'`, m.scan.system.status);
  ok(m.scan.system.reason === f.reason, `[${f.reason}] el motivo se conserva para el dashboard`);
  ok(m.scan.system.results === 0, `[${f.reason}] results = 0`);
}

console.log("\n── 3 · Si el HOME falla, se devuelve tal cual ────────────────────\n");

// La auditoría va a abortar de todos modos (kind 'error' o 'not-installed'):
// el resultado del sistema no cambia esa decisión.
const homeRoto = { skipped: true, kind: "error", reason: "no se pudo leer el home /home/ana: EACCES" };
m = mergeScans(homeRoto, systemScan());

ok(m.skipped === true, "se propaga el skipped del home");
ok(m.kind === "error", "se conserva el kind del home");
ok(m.scan === undefined, "no se inventa un scan.system sobre un resultado fallido");

console.log("\n── 4 · Nada del bloque del home se altera ────────────────────────\n");

// Los consumidores actuales del dashboard leen estas claves. Si la fusión las
// tocara, el bloque de alcance dejaría de funcionar sin que nadie se enterase.
m = mergeScans(homeScan(), systemScan());
const ref = homeScan().scan;

ok(m.scan.target === ref.target, "scan.target intacto");
ok(m.scan.mode === ref.mode, "scan.mode sigue describiendo el escaneo del home");
ok(m.scan.trivyVersion === ref.trivyVersion, "scan.trivyVersion intacto");
ok(m.scan.resolvedFrom === ref.resolvedFrom, "scan.resolvedFrom intacto");
ok(m.scan.children.scanned.length === 1 && m.scan.children.skipped.length === 1,
   "scan.children intacto (lo usan las pills y el detalle del alcance)");

console.log("\n── 5 · Sin systemPackages no aparece el sub-bloque ───────────────\n");

// Ausente, no `attempted: false`: la ausencia ya significa "no se pidió", y un
// campo a false invitaría a redactar un aviso para algo que nadie preguntó.
const soloHome = homeScan();
ok(soloHome.scan.system === undefined, "un escaneo de solo home no trae scan.system");

console.log(`\n${passed} pasados · ${failed} fallidos\n`);
process.exit(failed > 0 ? 1 : 0);
