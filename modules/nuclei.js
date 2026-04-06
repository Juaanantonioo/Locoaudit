"use strict";

const {
    which,
    execFilePromise,
    toBaseUrl,
    mapNucleiSeverity,
} = require("../core/helpers");

// ── Parser de JSON Lines de Nuclei ─────────────────────────────────────────

function parseNucleiJsonLines(stdout) {
    const lines = String(stdout || "")
        .split("\n")
        .map((l) => l.trim())
        .filter(Boolean);

    const results = [];
    for (const line of lines) {
        try {
            const obj = JSON.parse(line);
            results.push(obj);
        } catch (_) { }
    }
    return results;
}

// ── Construir URLs desde puertos abiertos ──────────────────────────────────

function buildNucleiUrlsFromPortsReport(portsReport) {
    if (!portsReport || portsReport.available === false) return [];

    const webPorts = new Set([80, 443, 8080, 8443, 1880]);
    const urls = [];

    for (const p of portsReport.openPorts || []) {
        if (!webPorts.has(p.port)) continue;
        const protocol =
            p.port === 443 || p.port === 8443 ? "https" : "http";
        urls.push(toBaseUrl(protocol, portsReport.target, p.port));
    }

    return urls;
}

// ── Escaneo Nuclei por URL ─────────────────────────────────────────────────

async function runNucleiForUrl(url, options = {}) {
    const nucleiPath = which("nuclei");

    if (!nucleiPath) {
        return {
            mode: "nuclei",
            available: false,
            target: url,
            results: [],
            note: "nuclei no está instalado o no está en PATH",
        };
    }

    const args = [
        "-u", url,
        "-jsonl",
        "-silent",
        "-no-stdin",         // evitar bloqueo esperando stdin
        "-nh",               // no ejecutar httpx (ya tenemos la URL)
        "-timeout", "15",    // timeout por request en segundos
        "-no-mhe",           // no saltar hosts por errores
    ];

    const sev = String(options.severity || "").trim();
    if (sev) args.push("-severity", sev);

    const tpl = String(options.templates || "").trim();
    if (tpl) args.push("-t", tpl);

    try {
        const { stdout, stderr } = await execFilePromise(nucleiPath, args, {
            timeout: 300000,   // 5 min para que nuclei cargue ~10k templates
        });

        return {
            mode: "nuclei",
            available: true,
            target: url,
            stderr: stderr || "",
            results: parseNucleiJsonLines(stdout),
        };
    } catch (err) {
        return {
            mode: "nuclei",
            available: true,
            target: url,
            error: err.message,
            stderr: err.stderr || "",
            stdout: err.stdout || "",
            timedOut: !!err.killed,
            results: parseNucleiJsonLines(err.stdout || ""),
        };
    }
}

// ── Módulo Nuclei completo (desde puertos) ─────────────────────────────────

async function runNucleiModule(portsReport, options = {}) {
    const urls = buildNucleiUrlsFromPortsReport(portsReport);
    const executions = [];

    if (urls.length === 0) {
        return {
            mode: "nuclei",
            available: true,
            targets: [],
            executions: [],
            note: "no hay endpoints web derivados de puertos abiertos",
        };
    }

    for (const url of urls) {
        const result = await runNucleiForUrl(url, options);
        executions.push(result);
    }

    return {
        mode: "nuclei",
        available: executions.every((e) => e.available !== false),
        targets: urls,
        executions,
    };
}

// ── Findings de Nuclei ─────────────────────────────────────────────────────

function addNucleiFindings(findings, nucleiReport) {
    if (!nucleiReport) return;

    if (nucleiReport.available === false) {
        findings.push({
            id: "NUCLEI_NOT_AVAILABLE",
            severity: "LOW",
            category: "vulnerability",
            scope: "host",
            title: "Nuclei no disponible",
            evidence: {},
            recommendation:
                "Instalar nuclei para habilitar el escaneo de vulnerabilidades remotas.",
        });
        return;
    }

    const executions = nucleiReport.executions || [];
    if (executions.length === 0) {
        findings.push({
            id: "NUCLEI_NO_TARGETS",
            severity: "INFO",
            category: "vulnerability",
            scope: "host",
            title: "Nuclei no encontró objetivos web para analizar",
            evidence: { note: nucleiReport.note || null },
            recommendation:
                "Abrir puertos web o ejecutar primero Nmap para que el nodo derive URLs a analizar.",
        });
        return;
    }

    let totalMatches = 0;

    for (const exec of executions) {
        if (exec.error && (!exec.results || exec.results.length === 0)) {
            findings.push({
                id: "NUCLEI_SCAN_ERROR",
                severity: "MEDIUM",
                category: "vulnerability",
                scope: "host",
                title: `Error al ejecutar Nuclei sobre ${exec.target}`,
                evidence: {
                    target: exec.target,
                    error: exec.error,
                    stderr: exec.stderr || null,
                    timedOut: exec.timedOut || false,
                },
                recommendation:
                    "Revisar conectividad, plantillas seleccionadas y la instalación de Nuclei.",
            });
            continue;
        }

        const results = exec.results || [];
        if (results.length === 0) {
            findings.push({
                id: "NUCLEI_NO_FINDINGS",
                severity: "INFO",
                category: "vulnerability",
                scope: "host",
                title: `Nuclei no detectó vulnerabilidades remotas en ${exec.target}`,
                evidence: { target: exec.target },
                recommendation: "Sin acción requerida.",
            });
            continue;
        }

        totalMatches += results.length;

        for (const r of results) {
            const severity = mapNucleiSeverity(r.info?.severity);
            findings.push({
                id: `NUCLEI_${r["template-id"] || "match"}`,
                severity,
                category: "vulnerability",
                scope: "host",
                title: r.info?.name || `Hallazgo Nuclei en ${exec.target}`,
                evidence: {
                    target: exec.target,
                    templateId: r["template-id"] || null,
                    matcherName: r["matcher-name"] || null,
                    type: r.type || null,
                    severity: r.info?.severity || null,
                    description: r.info?.description || null,
                    matchedAt: r["matched-at"] || null,
                    extractedResults: r["extracted-results"] || null,
                    tags: r.info?.tags || null,
                    reference: r.info?.reference || null,
                },
                recommendation:
                    "Revisar el hallazgo detectado por Nuclei y aplicar mitigaciones según la tecnología expuesta.",
            });
        }
    }

    if (totalMatches > 0) {
        findings.push({
            id: "NUCLEI_MATCHES_DETECTED",
            severity: "MEDIUM",
            category: "vulnerability",
            scope: "host",
            title: `Nuclei detectó ${totalMatches} posible(s) vulnerabilidad(es) remota(s)`,
            evidence: { totalMatches, targets: nucleiReport.targets || [] },
            recommendation:
                "Priorizar la revisión de los hallazgos remotos detectados por Nuclei.",
        });
    }
}

module.exports = {
    parseNucleiJsonLines,
    buildNucleiUrlsFromPortsReport,
    runNucleiForUrl,
    runNucleiModule,
    addNucleiFindings,
};
