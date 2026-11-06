"use strict";

/**
 * test-windows-powershell.js — Discos e inventario de Windows leídos con PowerShell.
 *
 *   A) leerDiscosWindows: array, objeto suelto, Size nulo y JSON roto (lanza).
 *   B) leerProgramasWindows: array, objeto suelto, sin versión y duplicados HKLM/HKCU.
 *   C) Orquestación en win32 con existeComando / ejecutarPowerShell sustituidos: skips de sw-inventory y excepciones de disco.
 * Uso: node test/manual/test-windows-powershell.js
 */

const { leerDiscosWindows, WINDOWS_DISK_PS_SCRIPT } = require("../../nodes/audit-host/modules/disk-storage");
const { leerProgramasWindows, WINDOWS_SW_PS_SCRIPT } = require("../../nodes/audit-host/modules/sw-inventory");

let failed = 0;
let passed = 0;

function ok(cond, label, detail) {
  if (cond) { passed++; console.log(`  ✓ ${label}`); }
  else { failed++; console.log(`  ✗ ${label}`); if (detail) console.log(`      ${detail}`); }
}

function lanza(fn) {
  try { fn(); return false; } catch (_) { return true; }
}

const GiB = 1024 * 1024 * 1024;

console.log("\n── A · leerDiscosWindows ─────────────────────────────────────────\n");

{
  const json = JSON.stringify([
    { DeviceID: "C:", FreeSpace: 100 * GiB, Size: 400 * GiB },
    { DeviceID: "D:", FreeSpace: null, Size: null },          // lector óptico
    { DeviceID: "E:", FreeSpace: 0, Size: 0 },
  ]);
  const r = leerDiscosWindows(json);
  ok(r.length === 1, "array: solo queda la unidad con tamaño", JSON.stringify(r));
  const c = r[0] || {};
  ok(c.mount === "C:" && c.device === "C:" && Array.isArray(c.mounts) && c.mounts[0] === "C:",
     "array: mount, mounts y device son la letra", JSON.stringify(c));
  ok(c.fsType === null, "array: fsType es null");
  ok(c.totalGB === 400 && c.freeGB === 100 && c.usedGB === 300 && c.usedPercent === 75,
     "array: cifras en GB y porcentaje correctos", JSON.stringify(c));
}

{
  const r = leerDiscosWindows(JSON.stringify({ DeviceID: "C:", FreeSpace: 50 * GiB, Size: 100 * GiB }));
  ok(r.length === 1 && r[0].usedPercent === 50, "objeto suelto: se normaliza a una lista", JSON.stringify(r));
}

{
  const r = leerDiscosWindows(JSON.stringify([{ DeviceID: "D:", FreeSpace: null, Size: null }]));
  ok(Array.isArray(r) && r.length === 0, "Size null: la unidad se descarta", JSON.stringify(r));
}

ok(lanza(() => leerDiscosWindows("esto no es json")), "JSON roto: lanza, no devuelve []");
ok(lanza(() => leerDiscosWindows("")), "salida vacía: lanza, no devuelve []");
ok(/Win32_LogicalDisk/.test(WINDOWS_DISK_PS_SCRIPT) && /ConvertTo-Json -Compress/.test(WINDOWS_DISK_PS_SCRIPT),
   "el script de discos usa Win32_LogicalDisk y ConvertTo-Json -Compress");

console.log("\n── B · leerProgramasWindows ──────────────────────────────────────\n");

{
  const r = leerProgramasWindows(JSON.stringify([
    { name: "Zeta", version: "2.0" },
    { name: "Alfa", version: "1.0" },
  ]));
  ok(r.length === 2 && r[0].name === "Alfa" && r[1].name === "Zeta", "array: ordenado por nombre", JSON.stringify(r));
  ok(r.every((p) => p.source === "registry"), "array: source es 'registry'");
}

{
  const r = leerProgramasWindows(JSON.stringify({ name: "Solo", version: "3.1" }));
  ok(r.length === 1 && r[0].name === "Solo" && r[0].version === "3.1", "objeto suelto: se normaliza a una lista",
     JSON.stringify(r));
}

{
  const r = leerProgramasWindows(JSON.stringify([
    { name: "SinVersion", version: "" },
    { name: "VersionNula", version: null },
    { name: "", version: "1.0" },
  ]));
  ok(r.length === 2 && r.every((p) => p.version === "unknown"),
     "sin versión → 'unknown'; sin nombre → fuera", JSON.stringify(r));
}

{
  const r = leerProgramasWindows(JSON.stringify([
    { name: "7-Zip 23.01 (x64)", version: "23.01" },
    { name: "7-zip 23.01 (x64)", version: "23.01" },   // la misma entrada en HKCU
    { name: "Git", version: "2.45.0" },
  ]));
  ok(r.length === 2, "duplicados HKLM/HKCU: una entrada por programa", JSON.stringify(r));
}

ok(lanza(() => leerProgramasWindows("{roto")), "JSON roto: lanza (el llamante lo convierte en skip)");
for (const rama of [
  "HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*",
  "HKLM:\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*",
  "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*",
]) {
  ok(WINDOWS_SW_PS_SCRIPT.includes(rama), `el script lee ${rama}`);
}
ok(/-ErrorAction SilentlyContinue/.test(WINDOWS_SW_PS_SCRIPT),
   "una rama del registro que no existe no es error (-ErrorAction SilentlyContinue)");

console.log("\n── C · Orquestación en win32 (executor sustituido) ───────────────\n");

// Dobles: se instalan en el executor y se vuelven a requerir los módulos, que lo desestructuran al cargar.
const executor = require("../../lib/executor");
const execReal = { existeComando: executor.existeComando, ejecutarPowerShell: executor.ejecutarPowerShell };
let disponibles = new Set();                 // qué shells "existen"
let respuesta = async () => "";              // (shell, script, timeout, opts) → stdout o rechazo
const llamadas = [];
executor.existeComando = async (cmd) => disponibles.has(cmd);
executor.ejecutarPowerShell = async (shell, script, timeoutMs, opts) => {
  llamadas.push({ shell, script, timeoutMs, opts });
  return respuesta(shell, script, timeoutMs, opts);
};

const RUTA_DISK = require.resolve("../../nodes/audit-host/modules/disk-storage");
const RUTA_SW = require.resolve("../../nodes/audit-host/modules/sw-inventory");
delete require.cache[RUTA_DISK];
delete require.cache[RUTA_SW];
const diskW = require(RUTA_DISK);
const swW = require(RUTA_SW);

const platformReal = Object.getOwnPropertyDescriptor(process, "platform");

function errorExec(msg, extra) {
  return Object.assign(new Error(msg), { stdout: "", stderr: "", code: 1 }, extra || {});
}

async function lanzaAsync(fn) {
  try { await fn(); return null; } catch (e) { return e; }
}

async function orquestacion() {
  Object.defineProperty(process, "platform", { value: "win32", configurable: true });
  try {
    // ── sw-inventory ──
    disponibles = new Set();
    let r = await swW.inventarioSoftware();
    ok(r && r.skipped && r.kind === "not-installed" && /PowerShell/.test(r.reason),
       "sw: sin powershell ni pwsh → skip not-installed", JSON.stringify(r));

    disponibles = new Set(["pwsh"]);
    llamadas.length = 0;
    respuesta = async () => JSON.stringify([{ name: "Git", version: "2.45.0" }]);
    r = await swW.inventarioSoftware();
    ok(llamadas.length === 1 && llamadas[0].shell === "pwsh", "sw: solo pwsh → se usa pwsh",
       JSON.stringify(llamadas.map((l) => l.shell)));
    ok(llamadas[0] && llamadas[0].opts && llamadas[0].opts.prefix === "lcaudit-swinv-",
       "sw: prefijo lcaudit-swinv-");
    ok(Array.isArray(r) && r.length === 1 && r[0].source === "registry", "sw: source === 'registry'",
       JSON.stringify(r));

    disponibles = new Set(["powershell", "pwsh"]);
    llamadas.length = 0;
    r = await swW.inventarioSoftware();
    ok(llamadas[0] && llamadas[0].shell === "powershell", "sw: con los dos → se prefiere powershell");

    respuesta = async () => "[]";
    r = await swW.inventarioSoftware();
    ok(!Array.isArray(r) && r.skipped && r.kind === "error", "sw: salida [] → skip error, nunca []",
       JSON.stringify(r));

    respuesta = async () => "esto no es json";
    r = await swW.inventarioSoftware();
    ok(r && r.skipped && r.kind === "error", "sw: salida no JSON → skip error", JSON.stringify(r));

    respuesta = async () => { throw errorExec("Acceso denegado"); };
    r = await swW.inventarioSoftware();
    ok(r && r.skipped && r.kind === "error" && /Acceso denegado/.test(r.reason),
       "sw: ejecución que rechaza → skip error con el motivo", JSON.stringify(r));

    respuesta = async () => { throw errorExec("timeout", { killed: true, signal: "SIGTERM" }); };
    r = await swW.inventarioSoftware();
    ok(r && r.skipped && r.kind === "timeout", "sw: rechazo con killed=true → skip timeout", JSON.stringify(r));

    respuesta = async () => "\uFEFF\r\n" + JSON.stringify([{ name: "7-Zip", version: "23.01" }]) + "\r\n";
    r = await swW.inventarioSoftware();
    ok(Array.isArray(r) && r.length === 1 && r[0].name === "7-Zip" && r[0].source === "registry",
       "sw: salida con BOM y \\r\\n iniciales se parsea", JSON.stringify(r));

    // ── disk-storage ──
    disponibles = new Set();
    let e = await lanzaAsync(() => diskW.infoDisco());
    ok(e instanceof Error && /PowerShell/.test(e.message), "disco: sin PowerShell → infoDisco lanza",
       e ? e.message : "no lanzó");

    disponibles = new Set(["powershell"]);
    respuesta = async () => { throw errorExec("Get-CimInstance reventó"); };
    e = await lanzaAsync(() => diskW.infoDisco());
    ok(e instanceof Error && /Get-CimInstance reventó/.test(e.message), "disco: ejecución que rechaza → lanza",
       e ? e.message : "no lanzó");

    respuesta = async () => "basura";
    e = await lanzaAsync(() => diskW.infoDisco());
    ok(e instanceof Error && /JSON/.test(e.message), "disco: salida no JSON → lanza", e ? e.message : "no lanzó");

    llamadas.length = 0;
    respuesta = async () => JSON.stringify([
      { DeviceID: "C:", FreeSpace: 100 * GiB, Size: 400 * GiB },
      { DeviceID: "D:", FreeSpace: null, Size: null },
    ]);
    const d = await diskW.infoDisco();
    const claves = ["mount", "mounts", "device", "fsType", "totalGB", "usedGB", "freeGB", "usedPercent"];
    ok(Array.isArray(d) && d.length === 1 && JSON.stringify(Object.keys(d[0])) === JSON.stringify(claves),
       "disco: salida válida → misma forma que antes", JSON.stringify(d));
    ok(d[0] && d[0].mount === "C:" && d[0].fsType === null && d[0].usedPercent === 75,
       "disco: valores de C: correctos", JSON.stringify(d[0]));
    ok(llamadas[0] && llamadas[0].shell === "powershell" && llamadas[0].opts.prefix === "lcaudit-disk-",
       "disco: usa powershell con prefijo lcaudit-disk-");
  } finally {
    Object.defineProperty(process, "platform", platformReal);
    executor.existeComando = execReal.existeComando;
    executor.ejecutarPowerShell = execReal.ejecutarPowerShell;
    delete require.cache[RUTA_DISK];
    delete require.cache[RUTA_SW];
  }
}

orquestacion()
  .catch((e) => ok(false, "D: la orquestación lanzó", e && e.stack ? e.stack.split("\n").slice(0, 2).join(" ") : String(e)))
  .then(() => {
    ok(process.platform === platformReal.value, "process.platform restaurado");
    console.log(`\n${passed} pasados · ${failed} fallidos\n`);
    process.exit(failed > 0 ? 1 : 0);
  });
