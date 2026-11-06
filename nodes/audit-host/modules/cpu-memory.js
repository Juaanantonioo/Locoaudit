"use strict";

const os = require("os");
const { aMiB, aGiB } = require("../../../lib/utils");

// Ventana de muestreo del uso de CPU en Windows.
const MUESTRA_CPU_MS = 1000;

function esperarMs(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Uso de CPU entre dos lecturas de os.cpus(): 1 - Δidle / Δ(user+nice+sys+idle), en % entero.
 * null si los datos no cuadran o no ha pasado tiempo de CPU: nunca un 0 inventado.
 */
function calcularUsoCpu(antes, despues) {
    if (!Array.isArray(antes) || !Array.isArray(despues)) return null;
    if (antes.length === 0 || antes.length !== despues.length) return null;
    let idle = 0;
    let total = 0;
    for (let i = 0; i < antes.length; i++) {
        const a = antes[i] && antes[i].times;
        const d = despues[i] && despues[i].times;
        if (!a || !d) return null;
        // Sin irq: en Windows sys ya incluye las interrupciones y el total es Kernel + User, con el idle
        // dentro del Kernel (https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getsystemtimes).
        for (const campo of ["user", "nice", "sys", "idle"]) {
            const delta = d[campo] - a[campo];
            if (!Number.isFinite(delta) || delta < 0) return null;
            total += delta;
            if (campo === "idle") idle += delta;
        }
    }
    if (total <= 0) return null;
    return Math.min(100, Math.max(0, Math.round((1 - idle / total) * 100)));
}

/**
 * CPU, memoria y plataforma, todo de os/process: nada externo que pueda faltar.
 * `opciones.esperar` sustituye la espera de la muestra (tests).
 */
async function ejecutarModuloSistema(opciones = {}) {
    const esperar = opciones.esperar || esperarMs;
    const cpus = os.cpus() || [];
    const totalMem = os.totalmem();
    const freeMem = os.freemem();
    const usedMem = totalMem - freeMem;
    let freeRatio;
    if (totalMem > 0) {
      freeRatio = freeMem / totalMem;
    } else {
      freeRatio = null;
    }

    const cpu = {
        model: cpus[0]?.model || "unknown",
        cores: cpus.length,
    };
    if (process.platform === "win32") {
      // En Windows os.loadavg() siempre da [0, 0, 0] (doc. de Node): se mide el uso real con dos lecturas.
      cpu.loadAvg = null;
      await esperar(MUESTRA_CPU_MS);
      cpu.usagePercent = calcularUsoCpu(cpus, os.cpus() || []);
      cpu.usageSampleMs = MUESTRA_CPU_MS;
    } else if (typeof os.loadavg === "function") {
      cpu.loadAvg = os.loadavg();
    } else {
      cpu.loadAvg = null;
    }

    return {
        cpu,
        memory: {
            totalBytes: totalMem,
            freeBytes: freeMem,
            usedBytes: usedMem,
            totalGiB: aGiB(totalMem),
            freeMiB: aMiB(freeMem),
            usedGiB: aGiB(usedMem),
            freeRatio,
        },
        platform: process.platform,
    };
}

module.exports = { ejecutarModuloSistema, calcularUsoCpu, MUESTRA_CPU_MS };
