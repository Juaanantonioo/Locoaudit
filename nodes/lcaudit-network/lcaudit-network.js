/**
 * lcaudit-network — Nodo de auditoría de red para Node-RED
 *
 * Descubre hosts activos en CIDR, luego ejecuta escaneos por host.
 */

module.exports = function (RED) {
    const os = require("os");
    const fs = require("fs");
    const path = require("path");

    const {
        safeFileName,
        parsePortsList,
        parseTargets,
        summarize,
    } = require("../../core/helpers");
    const { runSystemModule } = require("../../modules/systemInfo");
    const { runNetworkModule } = require("../../modules/networkInfo");
    const {
        DEFAULT_PORTS,
        runHostDiscovery,
        runPortsNmap,
        addPortFindings,
    } = require("../../modules/nmap");
    const {
        runHttpFingerprintModule,
        addHttpFpFindings,
    } = require("../../modules/httpFingerprint");
    const { runNucleiModule, addNucleiFindings } = require("../../modules/nuclei");
    const { generateDashboard } = require("../../core/reportGenerator");

    function LCAuditNetwork(config) {
        RED.nodes.createNode(this, config);
        const node = this;

        node.on("input", async function (msg, send, done) {
            const _send = send || node.send.bind(node);
            const _done = done || function () { };

            const t0 = Date.now();

            try {
                node.status({ fill: "blue", shape: "dot", text: "descubriendo red..." });

                const scanId = new Date().toISOString();
                const cidr = (config.cidr || "").trim();

                if (!cidr) {
                    node.status({ fill: "red", shape: "ring", text: "CIDR no configurado" });
                    node.error("Debe especificarse un rango CIDR o lista de IPs", msg);
                    _done(new Error("CIDR no configurado"));
                    return;
                }

                const report = {
                    scanId,
                    auditType: "network",
                    host: {
                        hostname: os.hostname(),
                        platform: os.platform(),
                        release: os.release(),
                        arch: os.arch(),
                        uptimeSec: os.uptime(),
                    },
                    cidr,
                    discovery: null,
                    hostReports: [],
                    summary: null,
                    networkSummary: null,
                    findings: [],
                    scanMeta: {
                        modulesRun: ["network-discovery"],
                        durationMs: null,
                    },
                };

                // Fase 1: Descubrimiento de hosts
                let targets = [];
                const isCidr = cidr.includes("/");

                if (isCidr) {
                    const discoveryResult = await runHostDiscovery(cidr);
                    report.discovery = discoveryResult;

                    if (discoveryResult.available === false) {
                        report.findings.push({
                            id: "NMAP_NOT_AVAILABLE",
                            severity: "MEDIUM",
                            category: "network",
                            scope: "network",
                            title: "Nmap no disponible para descubrimiento de red",
                            evidence: { cidr },
                            recommendation: "Instalar nmap para habilitar el descubrimiento de hosts.",
                        });
                    }

                    targets = (discoveryResult.hosts || []).map((h) => h.ip);

                    report.findings.push({
                        id: "NETWORK_DISCOVERY",
                        severity: "INFO",
                        category: "network",
                        scope: "network",
                        title: `Descubrimiento de red: ${targets.length} host(s) activo(s) en ${cidr}`,
                        evidence: {
                            cidr,
                            hostsFound: targets.length,
                            hosts: discoveryResult.hosts || [],
                        },
                        recommendation: "Revisar que todos los hosts activos sean conocidos y autorizados.",
                    });
                } else {
                    targets = parseTargets(cidr);
                }

                if (targets.length === 0) {
                    node.status({ fill: "yellow", shape: "dot", text: "sin hosts" });
                    report.scanMeta.durationMs = Date.now() - t0;
                    report.summary = summarize(report.findings);
                    msg.payload = report;
                    _send(msg);
                    _done();
                    return;
                }

                // Fase 2: Escaneo por host
                const runPorts = config.runPorts !== false;
                const runHttpFp = config.runHttpFp === true;
                const runNuclei = config.runNuclei === true;
                const customPorts = parsePortsList(config.portsList);
                const portsToTest = customPorts && customPorts.length ? customPorts : DEFAULT_PORTS;
                const serviceDetect = config.nmapServiceDetect === true;
                const network = runNetworkModule();

                for (let i = 0; i < targets.length; i++) {
                    const target = targets[i];
                    node.status({
                        fill: "blue",
                        shape: "dot",
                        text: `escaneando ${i + 1}/${targets.length}: ${target}`,
                    });

                    const hostReport = {
                        target,
                        portsReport: null,
                        httpFpReport: null,
                        nucleiReport: null,
                        findings: [],
                    };

                    if (runPorts) {
                        hostReport.portsReport = await runPortsNmap(target, portsToTest, serviceDetect);
                        addPortFindings(hostReport.findings, hostReport.portsReport, network);
                    }

                    if (runHttpFp && hostReport.portsReport) {
                        const allowInsecure = config.httpFpAllowInsecure === true;
                        const timeoutMs = Number.isFinite(+config.httpFpTimeoutMs) ? +config.httpFpTimeoutMs : 2500;

                        hostReport.httpFpReport = await runHttpFingerprintModule(hostReport.portsReport, {
                            allowInsecure,
                            timeoutMs,
                        });
                        addHttpFpFindings(hostReport.findings, hostReport.httpFpReport);
                    }

                    if (runNuclei && hostReport.portsReport) {
                        const nucleiSeverity = (config.nucleiSeverity || "").trim();
                        const nucleiTemplates = (config.nucleiTemplates || "").trim();

                        hostReport.nucleiReport = await runNucleiModule(hostReport.portsReport, {
                            severity: nucleiSeverity,
                            templates: nucleiTemplates,
                        });
                        addNucleiFindings(hostReport.findings, hostReport.nucleiReport);
                    }

                    hostReport.summary = summarize(hostReport.findings);
                    report.hostReports.push(hostReport);
                    report.findings.push(...hostReport.findings);
                }

                if (runPorts) report.scanMeta.modulesRun.push("ports:nmap");
                if (runHttpFp) report.scanMeta.modulesRun.push("httpfp");
                if (runNuclei) report.scanMeta.modulesRun.push("nuclei");

                report.summary = summarize(report.findings);
                report.networkSummary = {
                    totalHosts: targets.length,
                    hostsWithIssues: report.hostReports.filter(
                        (hr) => hr.summary?.maxSeverity && hr.summary.maxSeverity !== "INFO"
                    ).length,
                    maxSeverity: report.summary.maxSeverity,
                };
                report.scanMeta.durationMs = Date.now() - t0;

                // Guardar reporte
                const saveReport = config.saveReport !== false;
                const outputPath = (config.outputPath || "").trim();
                let reportPath = null;
                let dashboardPath = null;

                if (saveReport) {
                    const baseDir = outputPath || path.join(os.homedir(), "audit-reports");
                    fs.mkdirSync(baseDir, { recursive: true });

                    reportPath = path.join(baseDir, `audit-network-${safeFileName(scanId)}.json`);
                    fs.writeFileSync(reportPath, JSON.stringify(report, null, 2), "utf8");

                    try {
                        dashboardPath = generateDashboard(baseDir);
                    } catch (e) {
                        node.warn("No se pudo generar el dashboard HTML: " + e.message);
                    }
                }

                msg.payload = report;
                msg.audit = { saved: saveReport, reportPath, dashboardPath };

                const max = report.summary?.maxSeverity || "INFO";
                const statusColor = max === "CRITICAL" || max === "HIGH" ? "red" : max === "MEDIUM" ? "yellow" : "green";

                node.status({
                    fill: statusColor,
                    shape: "dot",
                    text: `${max} — ${targets.length} hosts`,
                });

                _send(msg);
                _done();
            } catch (err) {
                node.status({ fill: "red", shape: "ring", text: "error" });
                node.error(err, msg);
                _done(err);
            }
        });
    }

    RED.nodes.registerType("lcaudit-network", LCAuditNetwork);
};
