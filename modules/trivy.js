"use strict";

const { which, execFilePromise, mapTrivySeverity } = require("../core/helpers");

// ── Escaneo Trivy ──────────────────────────────────────────────────────────

async function runVulnTrivy(mode, target) {
    const trivyPath = which("trivy");

    if (!trivyPath) {
        return {
            mode: "trivy",
            available: false,
            target,
            vulnerabilities: [],
            note: "trivy no está instalado o no está en PATH",
        };
    }

    const m = (mode || "fs").trim();
    let args;

    if (m === "image") {
        args = ["image", "--quiet", "-f", "json", target];
    } else {
        args = ["fs", "--quiet", "-f", "json", target];
    }

    try {
        const { stdout } = await execFilePromise(trivyPath, args, {
            timeout: 120000,
        });

        let parsed;
        try {
            parsed = JSON.parse(stdout);
        } catch {
            parsed = null;
        }

        return {
            mode: "trivy",
            available: true,
            target,
            scanMode: m,
            raw: parsed,
        };
    } catch (err) {
        return {
            mode: "trivy",
            available: true,
            target,
            scanMode: m,
            error: err.message,
        };
    }
}

// ── Parser de resultados Trivy ─────────────────────────────────────────────

function parseTrivyFindings(trivyReport) {
    const vulns = [];
    if (!trivyReport) return vulns;
    if (!trivyReport.raw) return vulns;
    if (!trivyReport.raw.Results) return vulns;

    for (const result of trivyReport.raw.Results) {
        const vulnerabilities = result.Vulnerabilities || [];
        for (const v of vulnerabilities) {
            vulns.push({
                id: v.VulnerabilityID,
                severity: v.Severity || "UNKNOWN",
                package: v.PkgName,
                installedVersion: v.InstalledVersion,
                fixedVersion: v.FixedVersion || null,
                title: v.Title || null,
                description: v.Description || null,
                target: trivyReport.target,
            });
        }
    }

    return vulns;
}

// ── Findings de Trivy ──────────────────────────────────────────────────────

function addTrivyFindings(findings, vulnReport) {
    if (!vulnReport) return;

    if (vulnReport.available === false) {
        findings.push({
            id: "TRIVY_NOT_AVAILABLE",
            severity: "LOW",
            category: "vulnerability",
            scope: "image",
            title: "Trivy no disponible",
            evidence: { target: vulnReport.target || "unknown" },
            recommendation:
                "Instalar Trivy para habilitar el escaneo de vulnerabilidades.",
        });
        return;
    }

    if (vulnReport.error) {
        findings.push({
            id: "TRIVY_SCAN_ERROR",
            severity: "MEDIUM",
            category: "vulnerability",
            scope: "image",
            title: `Error al ejecutar Trivy sobre ${vulnReport.target}`,
            evidence: {
                target: vulnReport.target || "unknown",
                scanMode: vulnReport.scanMode || "unknown",
                error: vulnReport.error,
            },
            recommendation:
                "Revisar el objetivo indicado y el modo de escaneo de Trivy.",
        });
        return;
    }

    const vulnerabilities = Array.isArray(vulnReport.parsed)
        ? vulnReport.parsed
        : [];

    if (vulnerabilities.length === 0) {
        findings.push({
            id: "NO_VULNERABILITIES_DETECTED",
            severity: "INFO",
            category: "vulnerability",
            scope: "image",
            title: `No se detectaron vulnerabilidades en ${vulnReport.target}`,
            evidence: { target: vulnReport.target || "unknown" },
            recommendation: "Sin acción requerida. Mantener el sistema actualizado.",
        });
        return;
    }

    for (const vuln of vulnerabilities) {
        const severity = mapTrivySeverity(vuln.severity);
        findings.push({
            id: `VULN_${vuln.id}`,
            severity,
            category: "vulnerability",
            scope: "image",
            title: vuln.title || `Vulnerabilidad detectada: ${vuln.id}`,
            evidence: {
                target: vuln.target || vulnReport.target,
                vulnerabilityId: vuln.id,
                package: vuln.package,
                installedVersion: vuln.installedVersion,
                fixedVersion: vuln.fixedVersion,
                description: vuln.description,
            },
            recommendation: vuln.fixedVersion
                ? `Actualizar ${vuln.package} de versión ${vuln.installedVersion} a ${vuln.fixedVersion} o superior.`
                : "Revisar la vulnerabilidad en bases de datos públicas y aplicar mitigaciones recomendadas.",
        });
    }
}

module.exports = { runVulnTrivy, parseTrivyFindings, addTrivyFindings };
