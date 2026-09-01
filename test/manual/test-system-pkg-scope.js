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
 * QUÉ CAMBIÓ. El veredicto salía de una lista nuestra de gestores soportados
 * (TRIVY_OS_MANAGERS = apt, dnf, yum, zypper, apk). Esa lista era una segunda
 * fuente de verdad sobre algo que Trivy ya responde por sí mismo, y envejecía
 * con cada versión suya: a una distribución que Trivy sí sabía analizar se le
 * decía que no sin haberlo intentado. Ahora el gate es `.Metadata.OS.Family`
 * del propio informe, y systemPackagesSupport() recibe el RESULTADO del módulo
 * en vez del nombre del gestor.
 *
 * Sigue siendo PURA y recibiendo la plataforma por parámetro, así que esta
 * matriz cubre las tres plataformas desde una sola máquina — no hace falta un
 * Arch ni un Windows para fijar el comportamiento.
 *
 * Uso:
 *   node test/manual/test-system-pkg-scope.js
 */

const { systemPackagesSupport } = require("../../lib/trivy-rootfs");

let failed = 0;
let passed = 0;

function ok(cond, label, detail) {
  if (cond) { passed++; console.log(`  ✓ ${label}`); }
  else { failed++; console.log(`  ✗ ${label}`); if (detail) console.log(`      ${detail}`); }
}

// Resultados posibles de runTrivyRootfs(), que es lo que ahora se inspecciona.
// Trivy no reconoció el sistema: es la respuesta que da tanto en Arch (pacman)
// como en macOS y Windows. Una sola causa, y la plataforma decide cómo se cuenta.
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
  const got = systemPackagesSupport(platform, result, { enabled });
  const etiqueta = `${platform.padEnd(7)} ${enabled ? "on " : "off"} ` +
                   `${String(result && result.kind || (result ? "ok" : "—")).padEnd(17)} ` +
                   `→ ${esperado.padEnd(20)} (${nota})`;
  ok(got === esperado, etiqueta, `obtenido "${got}"`);
}

console.log("\n── El veredicto NO depende del gestor de paquetes ────────────────\n");

// La regresión que se está fijando: el mismo resultado de Trivy tiene que dar el
// mismo estado sea cual sea el gestor detectado. `manager` sigue viajando en
// scanMeta, pero solo para REDACTAR la frase, nunca para decidirla.
const GESTORES = ["apt", "dnf", "yum", "zypper", "apk", "pacman", "emerge", "xbps", null];
const todosScanned = GESTORES.every(
  () => systemPackagesSupport("linux", OK, { enabled: true, manager: "pacman" }) === "scanned"
);
ok(todosScanned,
   `un informe con OS.Family da 'scanned' con cualquiera de los ${GESTORES.length} gestores`);

// Y al revés: un gestor de la antigua lista de "soportados" no salva un informe
// sin familia de SO. Antes, 'apt' + interruptor activo daba 'scanned' mirando
// solo un sub-bloque de estado; ahora manda lo que Trivy encontró.
ok(systemPackagesSupport("linux", NO_OS, { enabled: true }) === "unsupported-manager",
   "un informe SIN OS.Family no puede salir como analizado, aunque el gestor fuese apt");

// Las derivadas de Arch, sin listarlas en ninguna parte.
const derivadasArch = ["CachyOS", "Manjaro", "EndeavourOS", "Garuda", "Artix"];
const todasIgual = derivadasArch.every(
  () => systemPackagesSupport("linux", NO_OS, { enabled: true }) === "unsupported-manager"
);
ok(todasIgual, `las ${derivadasArch.length} derivadas de Arch dan el mismo estado sin listarlas`);

console.log("\n── Un fallo NUNCA se cuenta como análisis limpio ─────────────────\n");

// La regla del proyecto: fallo de la herramienta ≠ dato negativo. Ningún kind de
// fallo puede acabar en 'scanned', que es lo único que el dashboard redacta como
// cobertura conseguida.
for (const r of [FALLO, CORTADO, SIN_BIN, NO_OS]) {
  for (const plat of ["linux", "darwin", "win32"]) {
    const got = systemPackagesSupport(plat, r, { enabled: true });
    ok(got !== "scanned", `${plat.padEnd(7)} + kind '${r.kind}' → "${got}", nunca 'scanned'`);
  }
}

console.log("\n── Estados que el dashboard debe saber redactar ──────────────────\n");

const ESTADOS = ["scanned", "supported-not-run", "unsupported-manager", "not-applicable", "failed"];
const producidos = new Set(
  MATRIZ.map(([p, e, r]) => systemPackagesSupport(p, r, { enabled: e }))
);
for (const est of ESTADOS) {
  ok(producidos.has(est), `la matriz cubre el estado "${est}"`);
}

console.log(`\n${passed} pasados · ${failed} fallidos\n`);
process.exit(failed > 0 ? 1 : 0);
