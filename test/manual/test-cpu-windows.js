"use strict";

/**
 * test-cpu-windows.js — En Windows os.loadavg() siempre da [0, 0, 0]: cpu-memory mide el uso con dos
 * lecturas de os.cpus() y el normalizador no puede convertir un fallo de medida en un 0.
 * Sin esperas reales: os.cpus se sustituye y la espera se inyecta.
 * Uso: node test/manual/test-cpu-windows.js
 */

const os = require("os");
const path = require("path");

let failed = 0, passed = 0;
function ok(cond, label, detail) {
  if (cond) { passed++; console.log(`  ✓ ${label}`); }
  else { failed++; console.log(`  ✗ ${label}`); if (detail) console.log(`      ${detail}`); }
}

const ROOT = path.join(__dirname, "../..");
const { ejecutarModuloSistema, calcularUsoCpu, MUESTRA_CPU_MS } = require(path.join(ROOT, "nodes/audit-host/modules/cpu-memory"));
const { desdeCpuMemoria } = require(path.join(ROOT, "lib/normalizer"));

const nucleo = (user, nice, sys, idle, irq) => ({ model: "CPU de prueba", speed: 2000, times: { user, nice, sys, idle, irq } });

function conPlataforma(plat, fn) {
  const real = Object.getOwnPropertyDescriptor(process, "platform");
  Object.defineProperty(process, "platform", { value: plat, configurable: true });
  return Promise.resolve().then(fn).finally(() => Object.defineProperty(process, "platform", real));
}

/** os.cpus devuelve las lecturas en orden; la última se repite. */
function conCpus(lecturas, fn) {
  const real = os.cpus;
  let i = 0;
  os.cpus = () => lecturas[Math.min(i++, lecturas.length - 1)];
  return Promise.resolve().then(fn).finally(() => { os.cpus = real; });
}

(async () => {
  console.log("\n── 1 · calcularUsoCpu ─────\n");
  {
    // 2 núcleos: Δtotal = 1000 + 1000, Δidle = 750 + 250 → 50 %.
    const antes = [nucleo(100, 0, 50, 1000, 0), nucleo(200, 0, 100, 2000, 0)];
    const despues = [nucleo(300, 0, 100, 1750, 0), nucleo(700, 0, 350, 2250, 0)];
    ok(calcularUsoCpu(antes, despues) === 50, "deltas normales → 50 %", calcularUsoCpu(antes, despues));
    // Δtotal = 600 + 17 + 50 + 333 = 1000 (irq no suma), Δidle = 333 → 66,7 % → 67.
    ok(calcularUsoCpu([nucleo(0, 0, 0, 0, 0)], [nucleo(600, 17, 50, 333, 7)]) === 67, "redondeo a entero → 67 %");
    // En Windows sys ya incluye las interrupciones: irq no puede cambiar el resultado.
    const conIrq = calcularUsoCpu([nucleo(100, 0, 50, 1000, 40)], [nucleo(300, 0, 100, 1750, 540)]);
    const sinIrq = calcularUsoCpu([nucleo(100, 0, 50, 1000, 0)], [nucleo(300, 0, 100, 1750, 0)]);
    // Δtotal = 200 + 50 + 750 = 1000, Δidle = 750 → 25 %; con irq en el total saldría 1 − 750/1500 → 50 %.
    ok(conIrq === 25 && sinIrq === 25, "irq distinto de 0 no altera el uso (25 % con y sin irq)", JSON.stringify([conIrq, sinIrq]));
    ok(calcularUsoCpu([nucleo(0, 0, 0, 0, 0)], [nucleo(0, 0, 0, 1000, 0)]) === 0, "todo idle → 0 % (medido, no inventado)");
    ok(calcularUsoCpu(antes, antes) === null, "delta total 0 → null, no 0");
    ok(calcularUsoCpu([], []) === null, "sin núcleos → null");
    ok(calcularUsoCpu(antes, [despues[0]]) === null, "distinto número de núcleos → null");
    ok(calcularUsoCpu(antes, [despues[0], { model: "x" }]) === null, "núcleo sin times → null");
    ok(calcularUsoCpu(antes, [despues[0], nucleo(700, 0, 350, NaN, 0)]) === null, "campo no numérico → null");
    ok(calcularUsoCpu(despues, antes) === null, "contadores que retroceden → null");
    ok(calcularUsoCpu(null, despues) === null && calcularUsoCpu(antes, undefined) === null, "entrada que no es array → null");
  }

  console.log("\n── 2 · ejecutarModuloSistema ─────\n");
  const antes = [nucleo(100, 0, 50, 1000, 0), nucleo(200, 0, 100, 2000, 0)];
  const despues = [nucleo(300, 0, 100, 1750, 0), nucleo(700, 0, 350, 2250, 0)];

  await conPlataforma("win32", () => conCpus([antes, despues], async () => {
    const esperas = [];
    const r = await ejecutarModuloSistema({ esperar: async (ms) => { esperas.push(ms); } });
    ok(r.cpu.loadAvg === null, "win32: loadAvg null (no el [0,0,0] de os.loadavg)", JSON.stringify(r.cpu.loadAvg));
    ok(r.cpu.usagePercent === 50, "win32: usagePercent medido entre las dos lecturas", r.cpu.usagePercent);
    ok(r.cpu.usageSampleMs === 1000 && MUESTRA_CPU_MS === 1000, "win32: usageSampleMs 1000");
    ok(esperas.length === 1 && esperas[0] === 1000, "win32: una sola espera de 1000 ms entre lecturas", JSON.stringify(esperas));
    ok(r.cpu.cores === 2 && r.cpu.model === "CPU de prueba" && r.platform === "win32", "win32: modelo, núcleos y plataforma de la primera lectura");
    ok(r.memory && r.memory.totalBytes > 0, "win32: la memoria se sigue leyendo");
  }));

  await conPlataforma("win32", () => conCpus([antes, antes], async () => {
    const r = await ejecutarModuloSistema({ esperar: async () => {} });
    ok(r.cpu.usagePercent === null && r.cpu.loadAvg === null, "win32 sin tiempo de CPU entre lecturas → usagePercent null", JSON.stringify(r.cpu));
  }));

  await conPlataforma("linux", () => conCpus([antes, despues], async () => {
    let esperado = false;
    const r = await ejecutarModuloSistema({ esperar: async () => { esperado = true; } });
    ok(Array.isArray(r.cpu.loadAvg) && r.cpu.loadAvg.length === 3, "linux: loadAvg sigue siendo el array de os.loadavg", JSON.stringify(r.cpu.loadAvg));
    ok(!("usagePercent" in r.cpu) && !("usageSampleMs" in r.cpu), "linux: sin usagePercent ni usageSampleMs", JSON.stringify(r.cpu));
    ok(!esperado, "linux: no espera ninguna muestra");
  }));

  await conPlataforma("darwin", () => conCpus([antes], async () => {
    const r = await ejecutarModuloSistema({ esperar: async () => { throw new Error("no debería esperar"); } });
    ok(Array.isArray(r.cpu.loadAvg) && !("usagePercent" in r.cpu), "darwin: igual que linux");
  }));

  console.log("\n── 3 · normalizer: desdeCpuMemoria ─────\n");
  const mem = { totalGiB: 16, usedGiB: 4, freeRatio: 0.75 };
  {
    const f = desdeCpuMemoria({ cpu: { model: "X", cores: 8, loadAvg: null, usagePercent: 97, usageSampleMs: 1000 }, memory: mem, platform: "win32" }, "win32")
      .find((x) => x.id === "HOST-CPU-001");
    ok(f && f.severity === "info", "win32 con usagePercent alto → severidad info (muestra puntual)", f && f.severity);
    ok(f && f.evidence === "Modelo: X, Cores: 8, Uso de CPU: 97 % (medido durante 1 s antes de la auditoría)",
       "win32 con usagePercent → evidencia con el % medido", f && f.evidence);
    ok(f && !/Load avg/.test(f.evidence), "win32 con usagePercent → sin load avg en la evidencia");
  }
  {
    const f = desdeCpuMemoria({ cpu: { model: "X", cores: 8, loadAvg: null, usagePercent: null, usageSampleMs: 1000 }, memory: mem, platform: "win32" }, "win32")
      .find((x) => x.id === "HOST-CPU-001");
    ok(f && !/0\.00/.test(f.evidence) && !/\b0 %/.test(f.evidence), "win32 sin datos → la evidencia no dice 0", f && f.evidence);
    ok(f && /no se pudo medir/.test(f.evidence), "win32 sin datos → la evidencia dice que no se pudo medir", f && f.evidence);
    ok(f && !/N\/A \(Windows\)/.test(f.evidence), "sin el literal N/A (Windows)");
  }
  {
    const f = desdeCpuMemoria({ cpu: { model: "X", cores: 4, loadAvg: [6.4, 3.2, 1.6] }, memory: mem, platform: "linux" }, "linux")
      .find((x) => x.id === "HOST-CPU-001");
    ok(f && f.severity === "high" && f.evidence === "Modelo: X, Cores: 4, Load avg: 1m: 6.40, 5m: 3.20, 15m: 1.60",
       "linux: severidad por carga y evidencia como antes", f && JSON.stringify([f.severity, f.evidence]));
  }

  console.log(`\n${passed} pasados · ${failed} fallidos`);
  process.exit(failed ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });
