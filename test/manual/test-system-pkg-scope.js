"use strict";

/**
 * test-system-pkg-scope.js — Alcance del análisis de paquetes del sistema: ¿se analizaron, y si no, por qué?
 * El veredicto sale de `.Metadata.OS.Family` del informe de Trivy, no de una lista propia de gestores.
 * soportePaquetesSistema() es pura y recibe la plataforma, así que cubre las tres desde una máquina.
 * Uso: node test/manual/test-system-pkg-scope.js
 */

const { soportePaquetesSistema, versionSinAvisos } = require("../../lib/trivy-rootfs");

let failed = 0;
let passed = 0;

function ok(cond, label, detail) {
  if (cond) { passed++; console.log(`  ✓ ${label}`); }
  else { failed++; console.log(`  ✗ ${label}`); if (detail) console.log(`      ${detail}`); }
}

// Resultados posibles de ejecutarTrivyRootfs(); "SO no reconocido" se cuenta según la plataforma.
const NO_OS   = { skipped: true, kind: "os-unsupported", reason: "Trivy no ha detectado la familia del sistema operativo" };
const FALLO   = { skipped: true, kind: "error", reason: "trivy failed: exit status 2" };
const CORTADO = { skipped: true, kind: "output-too-large", reason: "la salida no cupo en el búfer" };
const SIN_BIN = { skipped: true, kind: "not-installed", reason: "Trivy no está instalado" };
const OK      = { os: { family: "debian", name: "13.6" }, pkgNum: 2056, unfixed: { total: 4078 } };

console.log("\n── Matriz plataforma × resultado × interruptor ───────────────────\n");

const MATRIZ = [
  // plataforma, enabled, resultado, estado esperado,       nota
  ["linux",  false, null,    "supported-not-run",   "Linux, interruptor apagado: no se pidió"],
  ["linux",  true,  OK,      "scanned",             "Debian/Ubuntu, analizado"],
  ["linux",  true,  NO_OS,   "unsupported-manager", "Arch y derivadas: Trivy no reconoce pacman"],
  ["linux",  true,  FALLO,   "failed",              "activado pero el escaneo falló"],
  ["linux",  true,  CORTADO, "failed",              "la salida se cortó: NO es un análisis limpio"],
  ["linux",  true,  SIN_BIN, "failed",              "Trivy no instalado"],
  ["linux",  true,  null,    "failed",              "el módulo no devolvió nada (un throw tragado)"],
  ["darwin", true,  NO_OS,   "not-applicable",      "macOS: Homebrew no es gestor de sistema"],
  ["darwin", false, null,    "not-applicable",      "macOS, interruptor apagado"],
  ["darwin", true,  FALLO,   "failed",              "macOS: un fallo real sigue siendo un fallo"],
  ["win32",  true,  NO_OS,   "not-applicable",      "Windows"],
  ["win32",  false, null,    "not-applicable",      "Windows, interruptor apagado"],
];

for (const [platform, enabled, result, esperado, nota] of MATRIZ) {
  const got = soportePaquetesSistema(platform, result, { enabled });
  const etiqueta = `${platform.padEnd(7)} ${enabled ? "on " : "off"} ` +
                   `${String(result && result.kind || (result ? "ok" : "—")).padEnd(17)} ` +
                   `→ ${esperado.padEnd(20)} (${nota})`;
  ok(got === esperado, etiqueta, `obtenido "${got}"`);
}

console.log("\n── El veredicto NO depende del gestor de paquetes ────────────────\n");

// El mismo resultado de Trivy da el mismo estado con cualquier gestor; `manager` solo redacta.
const GESTORES = ["apt", "dnf", "yum", "zypper", "apk", "pacman", "emerge", "xbps", null];
const todosScanned = GESTORES.every(
  () => soportePaquetesSistema("linux", OK, { enabled: true, manager: "pacman" }) === "scanned"
);
ok(todosScanned,
   `un informe con OS.Family da 'scanned' con cualquiera de los ${GESTORES.length} gestores`);

// Un gestor conocido no convierte en 'scanned' un informe sin familia de SO.
ok(soportePaquetesSistema("linux", NO_OS, { enabled: true }) === "unsupported-manager",
   "un informe SIN OS.Family no puede salir como analizado, aunque el gestor fuese apt");

// Las derivadas de Arch, sin listarlas en ninguna parte.
const derivadasArch = ["CachyOS", "Manjaro", "EndeavourOS", "Garuda", "Artix"];
const todasIgual = derivadasArch.every(
  () => soportePaquetesSistema("linux", NO_OS, { enabled: true }) === "unsupported-manager"
);
ok(todasIgual, `las ${derivadasArch.length} derivadas de Arch dan el mismo estado sin listarlas`);

console.log("\n── Un fallo NUNCA se cuenta como análisis limpio ─────────────────\n");

// Fallo de la herramienta ≠ dato negativo: ningún kind de fallo acaba en 'scanned'.
for (const r of [FALLO, CORTADO, SIN_BIN, NO_OS]) {
  for (const plat of ["linux", "darwin", "win32"]) {
    const got = soportePaquetesSistema(plat, r, { enabled: true });
    ok(got !== "scanned", `${plat.padEnd(7)} + kind '${r.kind}' → "${got}", nunca 'scanned'`);
  }
}

console.log("\n── Derivadas de Debian y Ubuntu: versión sin avisos en Trivy ─────\n");

// Trivy lee /etc/debian_version: en Kali da "kali-rolling" y en Mint "trixie/sid", sin avisos en su base de datos.
const VERSIONES = [
  // familia, versión que lee Trivy, ¿tiene avisos?, nota
  ["debian", "13.1",         true,  "Debian 13"],
  ["debian", "12",           true,  "Debian 12 sin versión menor"],
  ["debian", "kali-rolling", false, "Kali Linux"],
  ["debian", "trixie/sid",   false, "Linux Mint, Pop!_OS y otras derivadas de Ubuntu"],
  ["debian", "forky/sid",    false, "Debian testing"],
  ["debian", "",             false, "sin versión"],
  ["ubuntu", "24.04",        true,  "Ubuntu 24.04"],
  ["ubuntu", "noble",        false, "nombre en clave en lugar de número"],
  ["alpine", "3.20.3",       true,  "otras familias no se tocan"],
  ["redhat", "9.4",          true,  "otras familias no se tocan"],
];
for (const [family, name, conAvisos, nota] of VERSIONES) {
  const motivo = versionSinAvisos({ Family: family, Name: name });
  let esperado;
  let texto;
  if (conAvisos) {
    esperado = motivo === null;
    texto = "se analiza";
  } else {
    esperado = typeof motivo === "string" && motivo.length > 0;
    texto = "no se da por analizado";
  }
  ok(esperado, `${family} «${name}» → ${texto} (${nota})`, `motivo: ${motivo}`);
}

const KALI = { skipped: true, kind: "os-unsupported", reason: versionSinAvisos({ Family: "debian", Name: "kali-rolling" }),
               os: { family: "debian", name: "kali-rolling" } };
ok(soportePaquetesSistema("linux", KALI, { enabled: true }) === "unsupported-manager",
   "Kali con Trivy ejecutado → 'unsupported-manager', nunca 'scanned'");
ok(/kali-rolling/.test(KALI.reason) && /cero/.test(KALI.reason),
   "el motivo dice qué versión leyó Trivy y que un cero no vale");

console.log("\n── Estados que el dashboard debe saber redactar ──────────────────\n");

const ESTADOS = ["scanned", "supported-not-run", "unsupported-manager", "not-applicable", "failed"];
const producidos = new Set(
  MATRIZ.map(([p, e, r]) => soportePaquetesSistema(p, r, { enabled: e }))
);
for (const est of ESTADOS) {
  ok(producidos.has(est), `la matriz cubre el estado "${est}"`);
}

console.log(`\n${passed} pasados · ${failed} fallidos\n`);
process.exit(failed > 0 ? 1 : 0);
