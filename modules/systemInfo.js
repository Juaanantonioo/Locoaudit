"use strict";

const os = require("os");
const { bytesToMiB, bytesToGiB } = require("../core/helpers");

/**
 * Recoge información del sistema: CPU, memoria, OS.
 */
function runSystemModule() {
    const cpus = os.cpus() || [];
    const totalMem = os.totalmem();
    const freeMem = os.freemem();
    const usedMem = totalMem - freeMem;
    const freeRatio = totalMem > 0 ? freeMem / totalMem : null;

    return {
        cpu: {
            model: cpus[0]?.model || "unknown",
            cores: cpus.length,
            loadAvg: typeof os.loadavg === "function" ? os.loadavg() : null,
        },
        memory: {
            totalBytes: totalMem,
            freeBytes: freeMem,
            usedBytes: usedMem,
            totalGiB: bytesToGiB(totalMem),
            freeMiB: bytesToMiB(freeMem),
            usedGiB: bytesToGiB(usedMem),
            freeRatio,
        },
    };
}

module.exports = { runSystemModule };
