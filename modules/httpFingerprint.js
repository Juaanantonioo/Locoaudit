"use strict";

const http = require("http");
const https = require("https");
const { isLocalTarget, toBaseUrl } = require("../core/helpers");

// ── Helpers de detección ────────────────────────────────────────────────────

function extractTitle(html) {
    if (!html) return null;
    const m = html.match(/<title[^>]*>([\s\S]*?)<\/title>/i);
    if (!m) return null;
    const t = m[1].replace(/\s+/g, " ").trim();
    return t || null;
}

function detectTechHints(headers, bodyText) {
    const hints = new Set();

    const h = headers || {};
    const server = String(h["server"] || "");
    const powered = String(h["x-powered-by"] || "");
    const ct = String(h["content-type"] || "");

    if (server) hints.add(`server:${server}`);
    if (powered) hints.add(`x-powered-by:${powered}`);
    if (ct) hints.add(`content-type:${ct}`);

    const body = (bodyText || "").toLowerCase();

    if (body.includes("node-red") || body.includes("nodered"))
        hints.add("node-red");
    if (body.includes("express")) hints.add("express");
    if (body.includes("nginx")) hints.add("nginx");
    if (body.includes("apache")) hints.add("apache");
    if (body.includes("grafana")) hints.add("grafana");
    if (body.includes("prometheus")) hints.add("prometheus");

    if (powered.toLowerCase().includes("express")) hints.add("express");
    if (server.toLowerCase().includes("nginx")) hints.add("nginx");
    if (server.toLowerCase().includes("apache")) hints.add("apache");

    return Array.from(hints);
}

function isProbablyNodeRed(headers, bodyText, title) {
    const h = headers || {};
    const powered = String(h["x-powered-by"] || "").toLowerCase();
    const server = String(h["server"] || "").toLowerCase();
    const t = String(title || "").toLowerCase();
    const b = String(bodyText || "").toLowerCase();

    if (b.includes("node-red")) return true;
    if (t.includes("node-red")) return true;
    if (powered.includes("express") && b.includes("red") && b.includes("flows"))
        return true;
    if (
        (server.includes("nginx") || server.includes("apache")) &&
        b.includes("node-red")
    )
        return true;

    return false;
}

// ── HTTP GET con límite ────────────────────────────────────────────────────

function httpGetWithLimit(
    url,
    { timeoutMs = 2500, maxBytes = 256 * 1024, allowInsecure = false } = {}
) {
    return new Promise((resolve) => {
        let finished = false;
        const finish = (data) => {
            if (finished) return;
            finished = true;
            resolve(data);
        };

        try {
            const isHttps = url.startsWith("https://");
            const lib = isHttps ? https : http;

            const req = lib.request(
                url,
                {
                    method: "GET",
                    headers: {
                        "User-Agent": "lcaudit-httpfp/2.0",
                        Accept: "text/html,application/json;q=0.9,*/*;q=0.8",
                    },
                    ...(isHttps ? { rejectUnauthorized: !allowInsecure } : {}),
                },
                (res) => {
                    const headers = res.headers || {};
                    const statusCode = res.statusCode || null;

                    let received = 0;
                    const chunks = [];

                    res.on("data", (chunk) => {
                        if (!chunk) return;
                        received += chunk.length;

                        if (received <= maxBytes) chunks.push(chunk);

                        if (received > maxBytes) {
                            try {
                                req.destroy();
                            } catch (_) { }
                        }
                    });

                    res.on("end", () => {
                        const buf = Buffer.concat(chunks);
                        const bodySnippet = buf.toString("utf8");
                        finish({ ok: true, url, statusCode, headers, bodySnippet });
                    });
                }
            );

            req.setTimeout(timeoutMs, () => {
                try {
                    req.destroy();
                } catch (_) { }
                finish({ ok: false, url, error: "timeout" });
            });

            req.on("error", (err) => {
                finish({ ok: false, url, error: err.code || err.message || "error" });
            });

            req.end();
        } catch (e) {
            finish({ ok: false, url, error: e.message || "exception" });
        }
    });
}

// ── Módulo de fingerprinting HTTP ──────────────────────────────────────────

async function runHttpFingerprintModule(portsReport, options = {}) {
    const {
        allowInsecure = false,
        timeoutMs = 2500,
        maxBytes = 256 * 1024,
        portsCandidate = [80, 443, 1880, 8080],
    } = options;

    if (!portsReport || portsReport.available === false) {
        return {
            mode: "httpfp",
            available: false,
            note: "no hay reporte de puertos disponible para fingerprinting",
            endpoints: [],
        };
    }

    const target = portsReport.target;
    const openPorts = (portsReport.openPorts || []).map((p) => p.port);
    const openSet = new Set(openPorts);
    const portsToProbe = portsCandidate.filter((p) => openSet.has(p));

    const endpoints = [];
    for (const port of portsToProbe) {
        const protocol = port === 443 ? "https" : "http";
        const base = toBaseUrl(protocol, target, port);
        const url = `${base}/`;

        const r = await httpGetWithLimit(url, {
            timeoutMs,
            maxBytes,
            allowInsecure,
        });

        if (!r.ok) {
            endpoints.push({
                target,
                port,
                protocol,
                url,
                ok: false,
                error: r.error,
            });
            continue;
        }

        const title = extractTitle(r.bodySnippet);
        const techHints = detectTechHints(r.headers, r.bodySnippet);
        const nodeRedDetected = isProbablyNodeRed(r.headers, r.bodySnippet, title);

        endpoints.push({
            target,
            port,
            protocol,
            url,
            ok: true,
            statusCode: r.statusCode,
            headers: r.headers,
            title,
            techHints,
            nodeRedDetected,
            snippet: (r.bodySnippet || "").slice(0, 600),
        });
    }

    return {
        mode: "httpfp",
        available: true,
        target,
        endpoints,
    };
}

// ── Findings de HTTP fingerprint ───────────────────────────────────────────

function addHttpFpFindings(findings, httpFpReport) {
    if (!httpFpReport) return;
    if (httpFpReport.available === false) return;

    const endpoints = httpFpReport.endpoints || [];
    if (endpoints.length === 0) {
        findings.push({
            id: "HTTPFP_NO_ENDPOINTS",
            severity: "INFO",
            category: "web",
            scope: "host",
            title: `Fingerprinting HTTP: no hay endpoints web abiertos para analizar (${httpFpReport.target || "?"})`,
            evidence: { target: httpFpReport.target || null },
            recommendation: "Sin acción requerida.",
        });
        return;
    }

    for (const ep of endpoints) {
        if (!ep.ok) {
            findings.push({
                id: `HTTPFP_FAILED_${ep.port}`,
                severity: "INFO",
                category: "web",
                scope: "host",
                title: `Fingerprinting HTTP falló en ${ep.protocol.toUpperCase()} ${ep.target}:${ep.port}`,
                evidence: { url: ep.url, error: ep.error },
                recommendation:
                    "Puede ser normal (servicio no HTTP, redirecciones, TLS, etc.).",
            });
            continue;
        }

        findings.push({
            id: `HTTPFP_${ep.port}`,
            severity: "INFO",
            category: "web",
            scope: "host",
            title: `Servicio web identificado en ${ep.target}:${ep.port}`,
            evidence: {
                target: ep.target,
                url: ep.url,
                statusCode: ep.statusCode,
                title: ep.title,
                techHints: ep.techHints,
                headers: ep.headers,
                snippet: ep.snippet,
            },
            recommendation:
                "Usar esta información para identificar software expuesto y endurecer configuración si aplica.",
        });

        if (ep.nodeRedDetected) {
            const local = isLocalTarget(ep.target);
            findings.push({
                id: `HTTPFP_NODE_RED_${ep.port}`,
                severity: local ? "LOW" : "MEDIUM",
                category: "web",
                scope: "host",
                title: local
                    ? `Node-RED detectado solo en localhost (${ep.target}:${ep.port})`
                    : `Node-RED detectado y expuesto por red (${ep.target}:${ep.port})`,
                evidence: { url: ep.url, title: ep.title, techHints: ep.techHints },
                recommendation: local
                    ? "Si no es necesario, mantenerlo en localhost y habilitar autenticación si procede."
                    : "Habilitar autenticación, restringir acceso (firewall/VPN), y evitar exposición innecesaria.",
            });
        }
    }
}

module.exports = {
    extractTitle,
    detectTechHints,
    isProbablyNodeRed,
    httpGetWithLimit,
    runHttpFingerprintModule,
    addHttpFpFindings,
};
