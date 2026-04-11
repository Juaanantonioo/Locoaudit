"use strict";

/**
 * normalizer.js — Convierte salidas raw de módulos al esquema Finding canónico.
 *
 * API pública:
 *   normalizeHost(raw, source)    → Finding[]
 *   normalizeNetwork(raw, source) → Finding[]
 *   normalizeImage(raw, source)   → Finding[]
 *
 * Internamente delega a subfunciones por herramienta:
 *   fromNative(raw, scope)  — módulos os/child_process
 *   fromNmap(raw)           — nmap-wrapper
 *   fromLynis(raw)          — lynis wrapper
 *   fromTrivyFs(raw)        — trivy fs (host)
 *   fromTrivyImage(raw)     — trivy image (docker)
 */

const { createFinding } = require("./finding-schema");
const { fromTrivy, fromLynis } = require("./severity-map");

// ── Helpers internos ────────────────────────────────────────────────────────

function safe(val, fallback = "—") {
  return val != null ? String(val) : fallback;
}

// ── Normalizadores por herramienta ──────────────────────────────────────────

/**
 * Convierte raw data de módulos nativos (os, child_process) a findings.
 * El caller decide el scope ("host" | "network" | "image") y el category.
 *
 * @param {Array<{id, title, severity, evidence, fix, category}>} raw
 * @param {string} source
 * @returns {Finding[]}
 */
function fromNative(raw, source = "native") {
  if (!Array.isArray(raw)) return [];
  return raw.map((item) =>
    createFinding({
      id: item.id,
      title: item.title,
      severity: item.severity || "info",
      evidence: safe(item.evidence),
      fix: item.fix || null,
      category: item.category || "other",
      source,
    })
  );
}

/**
 * Convierte la salida de nmap-wrapper a findings.
 * Espera un array de objetos: { port, protocol, state, service, version, severity? }
 *
 * @param {Array} raw
 * @returns {Finding[]}
 */
function fromNmap(raw) {
  if (!Array.isArray(raw)) return [];
  return raw
    .filter((p) => p.state === "open")
    .map((p, i) => {
      const portStr = `${p.port}/${p.protocol || "tcp"}`;
      const svc = p.service ? ` (${p.service}${p.version ? " " + p.version : ""})` : "";
      return createFinding({
        id: `NET-PORT-${String(i + 1).padStart(3, "0")}`,
        title: `Puerto abierto: ${portStr}${svc}`,
        severity: p.severity || "info",
        evidence: `Puerto ${portStr} en estado open${svc}`,
        fix: p.fix || null,
        category: "network",
        source: "nmap",
      });
    });
}

/**
 * Convierte la salida del parser de Lynis a findings.
 * Espera un array de objetos: { id, title, level, description, solution? }
 * donde level es "WARNING" | "SUGGESTION" | "NONE".
 *
 * @param {Array} raw
 * @returns {Finding[]}
 */
function fromLynisRaw(raw) {
  if (!Array.isArray(raw)) return [];
  return raw.map((item, i) => {
    const sev = fromLynis(item.level || "NONE");
    return createFinding({
      id: item.id || `HOST-LYN-${String(i + 1).padStart(3, "0")}`,
      title: safe(item.title, "Hallazgo Lynis"),
      severity: sev,
      evidence: safe(item.description),
      fix: item.solution || null,
      category: item.category || "system",
      source: "lynis",
    });
  });
}

/**
 * Convierte la salida JSON de `trivy fs` o `trivy image` a findings.
 * Espera la estructura estándar de Trivy: { Results: [{ Vulnerabilities: [...] }] }
 *
 * @param {Object} raw         Objeto JSON parseado de Trivy.
 * @param {string} idPrefix    Prefijo para el id: "HOST-CVE" | "IMG-CVE"
 * @param {string} category    "vulnerability"
 * @param {string} source      "trivy"
 * @returns {Finding[]}
 */
function fromTrivyJson(raw, idPrefix, category = "vulnerability", source = "trivy") {
  const findings = [];
  const results = raw?.Results || [];
  let counter = 1;

  for (const result of results) {
    const vulns = result.Vulnerabilities || [];
    for (const v of vulns) {
      const sev = fromTrivy(v.Severity);
      findings.push(
        createFinding({
          id: `${idPrefix}-${String(counter++).padStart(3, "0")}`,
          title: `${v.VulnerabilityID}: ${v.PkgName}@${v.InstalledVersion || "?"}`,
          severity: sev,
          evidence: `${v.VulnerabilityID} en ${v.PkgName} ${v.InstalledVersion || ""}. ${v.Description ? v.Description.slice(0, 200) : ""}`,
          fix: v.FixedVersion ? `Actualizar a ${v.FixedVersion}` : null,
          category,
          source,
        })
      );
    }
  }

  return findings;
}

// ── API pública ─────────────────────────────────────────────────────────────

/**
 * Normaliza raw data del nodo audit-host.
 * @param {*} raw
 * @param {"native"|"lynis"|"trivy"} source
 * @returns {Finding[]}
 */
function normalizeHost(raw, source = "native") {
  if (source === "lynis") return fromLynisRaw(raw);
  if (source === "trivy") return fromTrivyJson(raw, "HOST-CVE", "vulnerability", "trivy");
  return fromNative(raw, "native");
}

/**
 * Normaliza raw data del nodo audit-network.
 * @param {*} raw
 * @param {"native"|"nmap"} source
 * @returns {Finding[]}
 */
function normalizeNetwork(raw, source = "native") {
  if (source === "nmap") return fromNmap(raw);
  return fromNative(raw, "native");
}

/**
 * Normaliza raw data del nodo audit-image.
 * @param {*} raw
 * @param {"docker"|"trivy"} source
 * @returns {Finding[]}
 */
function normalizeImage(raw, source = "docker") {
  if (source === "trivy") return fromTrivyJson(raw, "IMG-CVE", "vulnerability", "trivy");
  return fromNative(raw, source);
}

module.exports = {
  normalizeHost,
  normalizeNetwork,
  normalizeImage,
  // Subfunciones expuestas para tests unitarios
  fromNative,
  fromNmap,
  fromLynisRaw,
  fromTrivyJson,
};
