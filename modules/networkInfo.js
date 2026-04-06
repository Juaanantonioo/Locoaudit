"use strict";

const os = require("os");

/**
 * Recoge información de las interfaces de red del equipo.
 */
function runNetworkModule() {
    const ifaces = os.networkInterfaces ? os.networkInterfaces() : {};
    const externalIPv4 = {};

    for (const [name, addrs] of Object.entries(ifaces || {})) {
        const v4 = (addrs || []).filter(
            (a) => a.family === "IPv4" && a.internal === false
        );
        if (v4.length > 0) {
            externalIPv4[name] = v4.map((a) => ({
                address: a.address,
                cidr: a.cidr,
                mac: a.mac,
            }));
        }
    }

    let primaryIPv4 = null;
    for (const name of Object.keys(externalIPv4)) {
        const addr = externalIPv4[name]?.[0]?.address;
        if (addr) {
            primaryIPv4 = addr;
            break;
        }
    }

    return { primaryIPv4, externalIPv4 };
}

module.exports = { runNetworkModule };
