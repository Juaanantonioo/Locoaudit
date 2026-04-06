"use strict";

const { which, execFilePromise, isLocalTarget } = require("../core/helpers");

const DEFAULT_PORTS = [
    22, 53, 80, 443, 445, 1880, 3389, 5900, 8080, 3306, 5432, 6379, 27017,
];

// ── Parser de output grepable de Nmap ───────────────────────────────────────

function parseNmapGrepable(output) {
    const openPorts = [];
    const lines = output.split("\n");

    for (const line of lines) {
        const idx = line.indexOf("Ports:");
        if (idx === -1) continue;

        const portsPart = line.slice(idx + "Ports:".length).trim();
        const entries = portsPart.split(",");

        for (const e of entries) {
            const part = e.trim();
            const bits = part.split("/");
            const port = parseInt(bits[0], 10);
            const state = bits[1];
            const proto = bits[2];
            const service = bits[4] || null;

            if (!Number.isNaN(port) && state === "open") {
                openPorts.push({ port, protocol: proto || "tcp", service });
            }
        }
    }

    return openPorts;
}

// ── Descubrimiento de hosts en red (ping scan) ─────────────────────────────

function parseNmapPingScan(output) {
    const hosts = [];
    const lines = output.split("\n");

    for (const line of lines) {
        // Formato grepable: Host: 192.168.1.1 (hostname) Status: Up
        const match = line.match(/^Host:\s+(\S+)\s+\(([^)]*)\)\s+Status:\s+Up/i);
        if (match) {
            hosts.push({
                ip: match[1],
                hostname: match[2] || null,
            });
        }
    }

    return hosts;
}

async function runHostDiscovery(cidr) {
    const nmapPath = which("nmap");
    if (!nmapPath) {
        return {
            mode: "nmap-discovery",
            available: false,
            cidr,
            hosts: [],
            note: "nmap no está instalado o no está en PATH",
        };
    }

    const args = ["-sn", "-oG", "-", cidr];

    try {
        const { stdout } = await execFilePromise(nmapPath, args, {
            timeout: 60000,
        });
        const hosts = parseNmapPingScan(stdout);

        return {
            mode: "nmap-discovery",
            available: true,
            cidr,
            hosts,
            totalFound: hosts.length,
        };
    } catch (err) {
        return {
            mode: "nmap-discovery",
            available: true,
            cidr,
            hosts: [],
            error: err.message,
        };
    }
}

// ── Escaneo de puertos ─────────────────────────────────────────────────────

async function runPortsNmap(target, portsToTest, serviceDetect) {
    const nmapPath = which("nmap");
    if (!nmapPath) {
        return {
            mode: "nmap",
            target,
            available: false,
            portsTested: portsToTest,
            openPorts: [],
            note: "nmap no está instalado o no está en PATH",
        };
    }

    const args = ["-Pn", "-sT"];
    if (serviceDetect) args.push("-sV");
    args.push(
        "--host-timeout",
        "20s",
        "-p",
        portsToTest.join(","),
        "-oG",
        "-",
        target
    );

    const { stdout } = await execFilePromise(nmapPath, args, { timeout: 30000 });
    const openPorts = parseNmapGrepable(stdout);

    return {
        mode: "nmap",
        target,
        available: true,
        portsTested: portsToTest,
        openPorts,
        serviceDetect: !!serviceDetect,
    };
}

// ── Findings de puertos ────────────────────────────────────────────────────

function addPortFindings(findings, portsReport, network) {
    if (!portsReport) return;

    if (portsReport.mode === "nmap" && portsReport.available === false) {
        findings.push({
            id: "NMAP_NOT_AVAILABLE",
            severity: "LOW",
            category: "ports",
            scope: "host",
            title: "Nmap no disponible",
            evidence: { target: portsReport.target },
            recommendation:
                "Instalar nmap y volver a ejecutar para un escaneo de puertos más completo.",
        });
        return;
    }

    const open = portsReport.openPorts || [];
    if (open.length === 0) {
        findings.push({
            id: "NO_OPEN_PORTS_DETECTED",
            severity: "INFO",
            category: "ports",
            scope: "host",
            title: `No se detectaron puertos abiertos en el objetivo (${portsReport.target})`,
            evidence: {
                target: portsReport.target,
                portsTested: portsReport.portsTested || DEFAULT_PORTS,
            },
            recommendation: "Sin acción requerida.",
        });
        return;
    }

    findings.push({
        id: "OPEN_PORTS_DETECTED",
        severity: "INFO",
        category: "ports",
        scope: "host",
        title: `Puertos abiertos detectados en ${portsReport.target}`,
        evidence: { target: portsReport.target, openPorts: open },
        recommendation:
            "Revisar que los servicios expuestos sean necesarios y estén restringidos.",
    });

    const openSet = new Set(open.map((p) => p.port));
    const local = isLocalTarget(portsReport.target);
    const isLanTarget =
        !local &&
        network?.primaryIPv4 &&
        portsReport.target === network.primaryIPv4;

    const sensitiveHigh = new Set([3389, 445, 5900, 3306, 5432, 6379, 27017]);
    const sensitiveMed = new Set([22, 8080, 1880]);

    const openSensitiveHigh = open
        .filter((p) => sensitiveHigh.has(p.port))
        .map((p) => p.port);
    const openSensitiveMed = open
        .filter((p) => sensitiveMed.has(p.port))
        .map((p) => p.port);

    let severity = local ? "INFO" : isLanTarget ? "MEDIUM" : "LOW";
    if (!local) {
        if (openSensitiveHigh.length > 0) severity = "HIGH";
        else if (openSensitiveMed.length > 0) severity = "MEDIUM";
    }

    const scope = local ? "localhost" : isLanTarget ? "lan" : "non-localhost";
    const title =
        scope === "localhost"
            ? `Servicios expuestos solo en localhost (${portsReport.target})`
            : scope === "lan"
                ? `Servicios expuestos en red local (LAN) (${portsReport.target})`
                : `Servicios expuestos fuera de localhost (${portsReport.target})`;

    const recommendation =
        scope === "localhost"
            ? "Riesgo reducido al estar accesible solo desde el propio equipo. Mantener restringido a localhost si es posible."
            : severity === "HIGH"
                ? "Riesgo alto por exposición de servicios sensibles. Restringir acceso (firewall/VPN), cerrar puertos no necesarios, limitar binding e imponer autenticación."
                : "Restringir la exposición (firewall/VPN), limitar el binding a interfaces necesarias y habilitar autenticación.";

    findings.push({
        id: "EXPOSURE_CONTEXT",
        severity,
        category: "ports",
        scope: "host",
        title,
        evidence: {
            target: portsReport.target,
            primaryIPv4: network?.primaryIPv4 || null,
            openPorts: open,
            scope,
            sensitivePorts: { high: openSensitiveHigh, medium: openSensitiveMed },
        },
        recommendation,
    });

    if (openSet.has(1880)) {
        const local1880 = isLocalTarget(portsReport.target);
        findings.push({
            id: "NODE_RED_PORT_1880_OPEN",
            severity: local1880 ? "LOW" : "MEDIUM",
            category: "ports",
            scope: "host",
            title: local1880
                ? `Node-RED accesible en localhost (${portsReport.target}:1880)`
                : `Node-RED expuesto en red (${portsReport.target}:1880)`,
            evidence: {
                target: portsReport.target,
                port: 1880,
                primaryIPv4: network?.primaryIPv4 || null,
            },
            recommendation: local1880
                ? "Riesgo bajo si solo está accesible localmente. Si no es necesario, restringir el binding a localhost."
                : "Restringir acceso (firewall/VPN), habilitar autenticación y evitar exposición innecesaria en la red.",
        });
    }
}

module.exports = {
    DEFAULT_PORTS,
    parseNmapGrepable,
    parseNmapPingScan,
    runHostDiscovery,
    runPortsNmap,
    addPortFindings,
};
