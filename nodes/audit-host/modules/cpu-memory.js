"use strict";

const os = require("os");
const { aMiB, aGiB } = require("../../../lib/utils");

/** CPU, memoria y plataforma, todo de os/process: nada externo que pueda faltar. */
function ejecutarModuloSistema() {
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

    let cargaMedia;
    if (typeof os.loadavg === "function") {
      cargaMedia = os.loadavg();
    } else {
      cargaMedia = null;
    }

    return {
        cpu: {
            model: cpus[0]?.model || "unknown",
            cores: cpus.length,
            loadAvg: cargaMedia,
        },
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

module.exports = { ejecutarModuloSistema };
