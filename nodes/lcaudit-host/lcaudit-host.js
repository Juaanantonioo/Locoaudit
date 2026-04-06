/**
 * lcaudit-host — Nodo de auditoría de host individual para Node-RED
 *
 * Ejecuta: System, Network, Nmap, HTTP Fingerprint, Nuclei
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
        severityRank,
    } = require("../../core/helpers");
    const { runSystemModule } = require("../../modules/systemInfo");
    const { runNetworkModule } = require("../../modules/networkInfo");
    const {
        DEFAULT_PORTS,
        runPortsNmap,
        addPortFindings,
    } = require("../../modules/nmap");
    const {
        runHttpFingerprintModule,
        addHttpFpFindings,
    } = require("../../modules/httpFingerprint");
    const { runNucleiModule, addNucleiFindings } = require("../../modules/nuclei");
    const { generateDashboard } = require("../../core/reportGenerator");

    // ── Findings de sistema ──────────────────────────────────────────────────

    function addSystemFindings(findings, report) {
        const mem = report.system?.memory;
        if (mem?.freeRatio != null) {
            let sev = "INFO";
            let threshold = "OK";
            const platform = report.host?.platform;

            if (platform === "darwin") {
                if (mem.freeRatio < 0.01) {
                    sev = "HIGH";
                    threshold = "HIGH < 1% (macOS)";
                } else if (mem.freeRatio < 0.03) {
                    sev = "MEDIUM";
                    threshold = "MEDIUM < 3% (macOS)";
                } else if (mem.freeRatio < 0.07) {
                    sev = "LOW";
                    threshold = "LOW < 7% (macOS)";
                }
            } else {
                if (mem.freeRatio < 0.03) {
                    sev = "HIGH";
                    threshold = "HIGH < 3%";
                } else if (mem.freeRatio < 0.07) {
                    sev = "MEDIUM";
                    threshold = "MEDIUM < 7%";
                } else if (mem.freeRatio < 0.12) {
                    sev = "LOW";
                    threshold = "LOW < 12%";
                }
            }

            findings.push({
                id: "MEMORY_FREE_RATIO",
                severity: sev,
                category: "performance",
                scope: "host",
                title:
                    sev === "INFO"
                        ? "Memoria libre dentro de umbral"
                        : "Memoria libre baja",
                evidence: {
                    freeRatio: mem.freeRatio,
                    freeMiB: mem.freeMiB,
                    totalGiB: mem.totalGiB,
                    threshold,
                    platform,
                },
                recommendation:
                    sev === "INFO"
                        ? "Sin acción requerida."
                        : "Cerrar aplicaciones/procesos no necesarios y revisar consumo de memoria.",
            });
        }

        // Red
        const ext = report.network?.externalIPv4
            ? Object.keys(report.network.externalIPv4)
            : [];
        if (ext.length === 0) {
            findings.push({
                id: "NO_EXTERNAL_IPV4",
                severity: "LOW",
                category: "network",
                scope: "host",
                title: "No se detectó IPv4 externa",
                evidence: {},
                recommendation:
                    "Revisar conectividad de red o configuración de interfaces.",
            });
        } else {
            findings.push({
                id: "EXTERNAL_IPV4_DETECTED",
                severity: "INFO",
                category: "network",
                scope: "host",
                title: "IPv4 externa detectada",
                evidence: {
                    interfaces: ext,
                    primaryIPv4: report.network?.primaryIPv4 || null,
                },
                recommendation: "Sin acción requerida.",
            });
        }
    }

    // ── Nodo principal ───────────────────────────────────────────────────────

    function LCAuditHost(config) {
        RED.nodes.createNode(this, config);
        const node = this;

        node.on("input", async function (msg, send, done) {
            const _send = send || node.send.bind(node);
            const _done = done || function () { };

            const t0 = Date.now();

            try {
                node.status({ fill: "blue", shape: "dot", text: "auditando host..." });

                const scanId = new Date().toISOString();
                let targets = parseTargets(config.targets);
                if (targets.length === 0) targets = ["127.0.0.1"];

                const report = {
                    scanId,
                    auditType: "host",
                    host: {
                        hostname: os.hostname(),
                        platform: os.platform(),
                        release: os.release(),
                        arch: os.arch(),
                        uptimeSec: os.uptime(),
                    },
                    targets,
                    system: null,
                    network: null,
                    portsResults: [],
                    httpFingerprintResults: [],
                    nucleiResults: [],
                    findings: [],
                    summary: null,
                    scanMeta: {
                        modulesRun: [],
                        durationMs: null,
                    },
                };

                // Módulos base
                const runSystem = config.runSystem !== false;
                const runNetwork = config.runNetwork !== false;
                const runPorts = config.runPorts === true;
                const runHttpFp = config.runHttpFp === true;
                const runNuclei = config.runNuclei === true;

                if (runSystem) {
                    report.system = runSystemModule();
                    report.scanMeta.modulesRun.push("system");
                }

                if (runNetwork) {
                    report.network = runNetworkModule();
                    report.scanMeta.modulesRun.push("network");
                }

                // Escaneos por target
                const customPorts = parsePortsList(config.portsList);
                const portsToTest =
                    customPorts && customPorts.length ? customPorts : DEFAULT_PORTS;
                const serviceDetect = config.nmapServiceDetect === true;

                for (let i = 0; i < targets.length; i++) {
                    const target = targets[i];
                    node.status({
                        fill: "blue",
                        shape: "dot",
                        text: `host ${i + 1}/${targets.length}: ${target}`,
                    });

                    let portsReport = null;

                    if (runPorts) {
                        portsReport = await runPortsNmap(target, portsToTest, serviceDetect);
                        report.portsResults.push(portsReport);
                    }

                    if (runHttpFp) {
                        const allowInsecure = config.httpFpAllowInsecure === true;
                        const timeoutMs = Number.isFinite(+config.httpFpTimeoutMs)
                            ? +config.httpFpTimeoutMs
                            : 2500;

                        const httpFpReport = await runHttpFingerprintModule(portsReport, {
                            allowInsecure,
                            timeoutMs,
                        });
                        report.httpFingerprintResults.push(httpFpReport);
                    }

                    if (runNuclei) {
                        const nucleiSeverity = (config.nucleiSeverity || "").trim();
                        const nucleiTemplates = (config.nucleiTemplates || "").trim();

                        const nucleiReport = await runNucleiModule(portsReport, {
                            severity: nucleiSeverity,
                            templates: nucleiTemplates,
                        });
                        report.nucleiResults.push(nucleiReport);
                    }
                }

                if (runPorts) report.scanMeta.modulesRun.push("ports:nmap");
                if (runHttpFp) report.scanMeta.modulesRun.push("httpfp");
                if (runNuclei) report.scanMeta.modulesRun.push("nuclei");

                // Generar findings
                const findings = [];
                addSystemFindings(findings, report);
                for (const pr of report.portsResults) {
                    addPortFindings(findings, pr, report.network);
                }
                for (const hfpr of report.httpFingerprintResults) {
                    addHttpFpFindings(findings, hfpr);
                }
                for (const nr of report.nucleiResults) {
                    addNucleiFindings(findings, nr);
                }

                report.findings = findings;
                report.summary = summarize(findings);
                report.scanMeta.durationMs = Date.now() - t0;

                // Guardar reporte
                const saveReport = config.saveReport !== false;
                const outputPath = (config.outputPath || "").trim();

                let reportPath = null;
                let dashboardPath = null;

                if (saveReport) {
                    const baseDir =
                        outputPath || path.join(os.homedir(), "audit-reports");
                    fs.mkdirSync(baseDir, { recursive: true });

                    reportPath = path.join(
                        baseDir,
                        `audit-host-${safeFileName(scanId)}.json`
                    );
                    fs.writeFileSync(reportPath, JSON.stringify(report, null, 2), "utf8");

                    try {
                        dashboardPath = generateDashboard(baseDir);
                    } catch (e) {
                        node.warn(
                            "No se pudo generar el dashboard HTML: " + e.message
                        );
                    }
                }

                msg.payload = report;
                msg.audit = { saved: saveReport, reportPath, dashboardPath };

                const max = report.summary?.maxSeverity || "INFO";
                const statusColor =
                    max === "CRITICAL" || max === "HIGH"
                        ? "red"
                        : max === "MEDIUM"
                            ? "yellow"
                            : "green";

                node.status({
                    fill: statusColor,
                    shape: "dot",
                    text: reportPath ? `${max} (guardado)` : max,
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

    RED.nodes.registerType("lcaudit-host", LCAuditHost);
};
