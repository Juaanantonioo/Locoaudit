/**
 * lcaudit-image — Nodo de auditoría de imágenes Docker / filesystem para Node-RED
 *
 * Ejecuta: Trivy (image/fs)
 */

module.exports = function (RED) {
    const os = require("os");
    const fs = require("fs");
    const path = require("path");

    const {
        safeFileName,
        parseTargets,
        summarize,
    } = require("../../core/helpers");
    const {
        runVulnTrivy,
        parseTrivyFindings,
        addTrivyFindings,
    } = require("../../modules/trivy");
    const { generateDashboard } = require("../../core/reportGenerator");

    function LCAuditImage(config) {
        RED.nodes.createNode(this, config);
        const node = this;

        node.on("input", async function (msg, send, done) {
            const _send = send || node.send.bind(node);
            const _done = done || function () { };

            const t0 = Date.now();

            try {
                const targetType = (config.targetType || "docker-image").trim();
                const label = targetType === "docker-image" ? "imagen Docker" : "filesystem";

                node.status({ fill: "blue", shape: "dot", text: `analizando ${label}...` });

                const scanId = new Date().toISOString();
                let targets = parseTargets(config.targets);

                if (targets.length === 0) {
                    if (targetType === "docker-image") targets = ["alpine:latest"];
                    else targets = ["."];
                }

                const report = {
                    scanId,
                    auditType: "image",
                    host: {
                        hostname: os.hostname(),
                        platform: os.platform(),
                        release: os.release(),
                        arch: os.arch(),
                        uptimeSec: os.uptime(),
                    },
                    targetType,
                    targets,
                    vulnerabilitiesResults: [],
                    findings: [],
                    summary: null,
                    scanMeta: {
                        modulesRun: [],
                        durationMs: null,
                    },
                };

                const mode = targetType === "docker-image" ? "image" : "fs";

                for (let i = 0; i < targets.length; i++) {
                    const target = targets[i];
                    node.status({
                        fill: "blue",
                        shape: "dot",
                        text: `${label} ${i + 1}/${targets.length}: ${target}`,
                    });

                    const vulnReport = await runVulnTrivy(mode, target);
                    if (vulnReport.available) {
                        vulnReport.parsed = parseTrivyFindings(vulnReport);
                    } else {
                        vulnReport.parsed = [];
                    }
                    report.vulnerabilitiesResults.push(vulnReport);
                }

                report.scanMeta.modulesRun.push(`vulnerabilities:trivy:${targetType}`);

                // Generar findings
                const findings = [];
                for (const vr of report.vulnerabilitiesResults) {
                    addTrivyFindings(findings, vr);
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
                    const baseDir = outputPath || path.join(os.homedir(), "audit-reports");
                    fs.mkdirSync(baseDir, { recursive: true });

                    reportPath = path.join(baseDir, `audit-image-${safeFileName(scanId)}.json`);
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

    RED.nodes.registerType("lcaudit-image", LCAuditImage);
};
