"use strict";

/**
 * test-system-pkg-scope.js — Alcance del análisis de paquetes del sistema.
 *
 * El hecho que el dashboard convierte en una frase: ¿se han analizado los
 * paquetes del sistema de este equipo, y si no, por qué no?
 *
 * En CachyOS la respuesta es NO (Trivy no tiene analizador para pacman) y hasta
 * ahora no aparecía en ningún sitio: el usuario veía sus hallazgos y concluía
 * que su equipo estaba cubierto. Ausencia de datos presentada como resultado.
 *
 * systemPackagesSupport() es PURA y recibe plataforma y gestor por parámetro,
 * así que esta matriz cubre las tres plataformas desde una sola máquina — no
 * hace falta un Arch ni un Windows para fijar el comportamiento.
 *
 * Uso:
 *   node test/manual/test-system-pkg-scope.js
 */

const {
  systemPackagesSupport,
  TRIVY_OS_MANAGERS,
} = require("../../nodes/audit-host/modules/trivy-fs");

let failed = 0;
let passed = 0;

function ok(cond, label, detail) {
  if (cond) { passed++; console.log(`  ✓ ${label}`); }
  else { failed++; console.log(`  ✗ ${label}`); if (detail) console.log(`      ${detail}`); }
}

// Sub-bloque parsed.scan.system que deja mergeScans(): es lo que se inspecciona
// ahora, y no el resultado entero. Desde que los dos escaneos se suman, que
// falle el del sistema ya no marca todo como skipped — el del home sigue ahí.
const SYS_FALLO = { attempted: true, status: "unsupported", reason: "Trivy no soporta pacman", results: 0 };
const SYS_OK    = { attempted: true, status: "scanned", reason: null, results: 1 };

console.log("\n── Matriz plataforma × gestor × interruptor ──────────────────────\n");

const MATRIZ = [
  // plataforma, gestor,   enabled, systemScan, estado esperado,        nota
  ["linux",  "pacman",  false, null,      "unsupported-manager", "CachyOS/Arch, interruptor apagado"],
  ["linux",  "pacman",  true,  SYS_FALLO, "unsupported-manager", "CachyOS/Arch, interruptor encendido"],
  ["linux",  "emerge",  false, null,      "unsupported-manager", "Gentoo: mismo límite que pacman"],
  ["linux",  null,      false, null,      "unsupported-manager", "gestor no identificado"],
  ["linux",  "apt",     false, null,      "supported-not-run",   "Debian/Ubuntu, sin activar"],
  ["linux",  "dnf",     false, null,      "supported-not-run",   "Fedora/RHEL, sin activar"],
  ["linux",  "apk",     false, null,      "supported-not-run",   "Alpine, sin activar"],
  ["linux",  "zypper",  false, null,      "supported-not-run",   "openSUSE, sin activar"],
  ["linux",  "apt",     true,  SYS_OK,    "scanned",             "Debian/Ubuntu, analizado"],
  ["linux",  "dnf",     true,  SYS_FALLO, "failed",              "activado pero el escaneo falló"],
  ["darwin", "brew",    true,  null,      "not-applicable",      "macOS: Homebrew no es gestor de sistema"],
  ["darwin", null,      false, null,      "not-applicable",      "macOS sin Homebrew"],
  ["win32",  "winget",  true,  null,      "not-applicable",      "Windows"],
  ["win32",  "choco",   false, null,      "not-applicable",      "Windows con Chocolatey"],
];

for (const [platform, mgr, enabled, systemScan, esperado, nota] of MATRIZ) {
  const got = systemPackagesSupport(platform, mgr, { enabled, systemScan });
  const etiqueta = `${platform.padEnd(7)} ${String(mgr).padEnd(7)} ` +
                   `${enabled ? "on " : "off"} → ${esperado.padEnd(20)} (${nota})`;
  ok(got === esperado, etiqueta, `obtenido "${got}"`);
}

console.log("\n── Coherencia de la lista de gestores soportados ─────────────────\n");

ok(!TRIVY_OS_MANAGERS.includes("pacman"), "pacman NO está en la lista de soportados");
ok(!TRIVY_OS_MANAGERS.includes("emerge"), "emerge NO está en la lista de soportados");
ok(!TRIVY_OS_MANAGERS.includes("brew"),   "brew NO está: instala software del usuario, no del sistema");
ok(TRIVY_OS_MANAGERS.includes("apt") && TRIVY_OS_MANAGERS.includes("dnf"),
   "apt y dnf sí están");

// El gate es por gestor, no por nombre de distribución: una lista de distros
// envejece y sería una segunda fuente de verdad sobre el mismo hecho.
const derivadasArch = ["CachyOS", "Manjaro", "EndeavourOS", "Garuda", "Artix"];
const todasIgual = derivadasArch.every(
  () => systemPackagesSupport("linux", "pacman", { enabled: true }) === "unsupported-manager"
);
ok(todasIgual, `las ${derivadasArch.length} derivadas de Arch dan el mismo estado sin listarlas`);

console.log("\n── Estados que el dashboard debe saber redactar ──────────────────\n");

const ESTADOS = ["scanned", "supported-not-run", "unsupported-manager", "not-applicable", "failed"];
const producidos = new Set(
  MATRIZ.map(([p, m, e, r]) => systemPackagesSupport(p, m, { enabled: e, systemScan: r }))
);
for (const est of ESTADOS) {
  ok(producidos.has(est), `la matriz cubre el estado "${est}"`);
}

console.log(`\n${passed} pasados · ${failed} fallidos\n`);
process.exit(failed > 0 ? 1 : 0);
