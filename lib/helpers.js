"use strict";

const os = require("os");
const fs = require("fs");
const path = require("path");
const { execFile } = require("child_process");

// ── Formateo ────────────────────────────────────────────────────────────────

function safeFileName(iso) {
    return iso.replace(/[:.]/g, "-");
}

function bytesToMiB(bytes) {
    return Math.round((bytes / (1024 * 1024)) * 10) / 10;
}

function bytesToGiB(bytes) {
    return Math.round((bytes / (1024 * 1024 * 1024)) * 100) / 100;
}

// ── Severidad ───────────────────────────────────────────────────────────────

function severityRank(s) {
    const map = { INFO: 0, LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 };
    return map[s] ?? 0;
}

function mapTrivySeverity(trivySeverity) {
    const s = String(trivySeverity || "").trim().toUpperCase();
    if (s === "CRITICAL") return "CRITICAL";
    if (s === "HIGH") return "HIGH";
    if (s === "MEDIUM") return "MEDIUM";
    if (s === "LOW") return "LOW";
    return "INFO";
}

function mapNucleiSeverity(nucleiSeverity) {
    const s = String(nucleiSeverity || "").trim().toUpperCase();
    if (s === "CRITICAL") return "CRITICAL";
    if (s === "HIGH") return "HIGH";
    if (s === "MEDIUM") return "MEDIUM";
    if (s === "LOW") return "LOW";
    return "INFO";
}

function summarize(findings) {
    const empty = { INFO: 0, LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0 };

    const counts = { ...empty };
    const hostCounts = { ...empty };
    const imageCounts = { ...empty };

    let max = "INFO";
    let hostMax = "INFO";
    let imageMax = "INFO";

    for (const f of findings) {
        counts[f.severity] = (counts[f.severity] || 0) + 1;

        if (f.category !== "performance") {
            if (severityRank(f.severity) > severityRank(max)) {
                max = f.severity;
            }
        }

        if (f.scope === "image") {
            imageCounts[f.severity] = (imageCounts[f.severity] || 0) + 1;
            if (severityRank(f.severity) > severityRank(imageMax)) {
                imageMax = f.severity;
            }
        } else {
            hostCounts[f.severity] = (hostCounts[f.severity] || 0) + 1;
            if (severityRank(f.severity) > severityRank(hostMax)) {
                hostMax = f.severity;
            }
        }
    }

    return {
        maxSeverity: max,
        counts,
        host: { maxSeverity: hostMax, counts: hostCounts },
        image: { maxSeverity: imageMax, counts: imageCounts },
    };
}

// ── Utilidades del sistema ──────────────────────────────────────────────────

function which(cmd) {
    const paths = (process.env.PATH || "").split(path.delimiter);
    for (const p of paths) {
        const full = path.join(p, cmd);
        try {
            if (fs.existsSync(full)) return full;
            if (process.platform === "win32" && fs.existsSync(full + ".exe"))
                return full + ".exe";
        } catch (_) { }
    }
    return null;
}

function execFilePromise(file, args, opts = {}) {
    return new Promise((resolve, reject) => {
        execFile(
            file,
            args,
            { ...opts, maxBuffer: 10 * 1024 * 1024 },
            (err, stdout, stderr) => {
                if (err) {
                    err.stdout = stdout;
                    err.stderr = stderr;
                    reject(err);
                } else {
                    resolve({ stdout, stderr });
                }
            }
        );
    });
}

// ── Parsing ─────────────────────────────────────────────────────────────────

function parsePortsList(input) {
    const s = (input || "").trim();
    if (!s) return null;

    const ports = new Set();
    const parts = s
        .split(",")
        .map((x) => x.trim())
        .filter(Boolean);

    for (const p of parts) {
        if (p.includes("-")) {
            const [a, b] = p.split("-").map((x) => parseInt(x.trim(), 10));
            if (
                !Number.isNaN(a) &&
                !Number.isNaN(b) &&
                a > 0 &&
                b <= 65535 &&
                a <= b
            ) {
                for (let i = a; i <= b; i++) ports.add(i);
            }
        } else {
            const n = parseInt(p, 10);
            if (!Number.isNaN(n) && n > 0 && n <= 65535) ports.add(n);
        }
    }

    return Array.from(ports).sort((x, y) => x - y);
}

function parseTargets(input) {
    const raw = String(input || "")
        .split(/[\n,;]/)
        .map((x) => x.trim())
        .filter(Boolean);

    return Array.from(new Set(raw));
}

function isLocalTarget(t) {
    const target = (t || "").trim().toLowerCase();
    return target === "127.0.0.1" || target === "localhost" || target === "::1";
}

function toBaseUrl(protocol, host, port) {
    const defaultPort = protocol === "https" ? 443 : 80;
    const showPort = port !== defaultPort;
    return `${protocol}://${host}${showPort ? ":" + port : ""}`;
}

// ── Escape HTML ─────────────────────────────────────────────────────────────

function escHtml(str) {
    return String(str || "")
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;");
}

module.exports = {
    safeFileName,
    bytesToMiB,
    bytesToGiB,
    severityRank,
    mapTrivySeverity,
    mapNucleiSeverity,
    summarize,
    which,
    execFilePromise,
    parsePortsList,
    parseTargets,
    isLocalTarget,
    toBaseUrl,
    escHtml,
};
