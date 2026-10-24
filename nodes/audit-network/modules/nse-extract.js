"use strict";

// Resume el subárbol NSE de un puerto con su severidad ya resuelta.
// Vive aquí porque lib/ no importa de nodes/; el normalizador solo pone ids y textos.

const { fromCvss, max } = require("../../../lib/severity-map");
const { findScript, tablesByKey, elemValue, elemList } = require("./nmap-xml");
const {
  TLS_GRADE_SEVERITY, sshAlgoSeverity, hasVersion, OFFERED_NOT_NEGOTIATED,
} = require("./nse-catalog");

// CVE de vulners por CPE. El grupo toma la severidad del peor CVE, no la media.
// Los exploits no generan hallazgo propio, pero se cuentan porque cambian la urgencia.
function extractVulns(scripts) {
  const node = findScript(scripts, "vulners");
  if (!node) return [];

  const outputUrls = new Map();
  const output = String(node.output || "");
  const outputLine = /(?:^|\n)\s*(\S+)\s+[\d.]+\s+(https?:\/\/\S+)/g;
  let outputMatch;
  while ((outputMatch = outputLine.exec(output)) !== null) {
    outputUrls.set(outputMatch[1].toUpperCase(), outputMatch[2]);
  }

  const grupos = [];
  for (const tabla of node.children.filter((c) => c.type === "table")) {
    const cves = [];
    let exploits = 0;

    for (const fila of tabla.children.filter((c) => c.type === "table")) {
      const tipo = String(elemValue(fila, "type") || "").toLowerCase();
      const id   = elemValue(fila, "id");
      const esExploit = String(elemValue(fila, "is_exploit")).toLowerCase() === "true";
      if (esExploit) exploits++;
      if (!id) continue;
      if (tipo !== "cve") continue;

      const cvssTxt = elemValue(fila, "cvss");
      const cvss    = parseFloat(cvssTxt);
      cves.push({
        id,
        cvss: Number.isFinite(cvss) ? cvss : null,
        // Sin cvss o con 0, fromCvss da 'medium' para no rebajarlo.
        severity: fromCvss(cvssTxt),
        isExploit: esExploit,
        sourceUrl: outputUrls.get(String(id).toUpperCase()) || null,
      });
    }

    if (!cves.length) continue;
    cves.sort((a, b) => (b.cvss || 0) - (a.cvss || 0));
    grupos.push({
      cpe: tabla.key || "",
      cves,
      exploits,
      maxCvss: cves[0].cvss,
      severity: max(...cves.map((c) => c.severity)),
    });
  }
  return grupos;
}

// Nota TLS de ssl-enum-ciphers (least strength). Fuera de la tabla, severity null = no comprobado.
function extractTls(scripts) {
  const node = findScript(scripts, "ssl-enum-ciphers");
  if (!node) return null;

  const grade = String(elemValue(node, "least strength") || "").trim().toUpperCase();
  const protocolos = node.children
    .filter((c) => c.type === "table" && c.key)
    .map((c) => c.key);

  // Suites flojas, para que el hallazgo diga qué quitar y no solo la nota.
  const flojas = [];
  for (const proto of node.children.filter((c) => c.type === "table" && c.key)) {
    for (const tablaCiphers of tablesByKey(proto, "ciphers")) {
      for (const suite of tablaCiphers.children.filter((c) => c.type === "table")) {
        const nombre = elemValue(suite, "name");
        const nota   = String(elemValue(suite, "strength") || "").toUpperCase();
        if (nombre && nota && nota !== "A") flojas.push({ name: nombre, grade: nota, protocol: proto.key });
      }
    }
  }
  flojas.sort((a, b) => b.grade.localeCompare(a.grade));

  const cert = findScript(scripts, "ssl-cert");
  const validez = cert ? tablesByKey(cert, "validity")[0] : null;

  return {
    grade: grade || null,
    severity: TLS_GRADE_SEVERITY[grade] || null,
    protocols: protocolos,
    weak: flojas,
    cert: cert ? {
      sigAlgo: elemValue(cert, "sig_algo") || null,
      notAfter: validez ? elemValue(validez, "notAfter") || null : null,
      issuer: (() => {
        const t = tablesByKey(cert, "issuer")[0];
        return t ? elemValue(t, "commonName") || null : null;
      })(),
    } : null,
  };
}

// Grupos de ssh2-enum-algos que se evalúan; compression no.
const SSH_GRUPOS = [
  ["kex_algorithms",              "intercambio de claves"],
  ["server_host_key_algorithms",  "clave de servidor"],
  ["encryption_algorithms",       "cifrado"],
  ["mac_algorithms",              "integridad (MAC)"],
];

// Algoritmos SSH ofrecidos; sin débiles queda en 'info' como inventario.
function extractSsh(scripts) {
  const node = findScript(scripts, "ssh2-enum-algos");
  if (!node) return null;

  const debiles = [];
  const grupos  = [];
  let total = 0;

  for (const [clave, etiqueta] of SSH_GRUPOS) {
    const tabla = tablesByKey(node, clave)[0];
    if (!tabla) continue;
    const algos = elemList(tabla);
    total += algos.length;
    grupos.push({ key: clave, label: etiqueta, count: algos.length });
    for (const nombre of algos) {
      const sev = sshAlgoSeverity(nombre);
      if (sev !== "info") debiles.push({ name: nombre, severity: sev, group: etiqueta });
    }
  }

  return {
    groups: grupos,
    weak: debiles,
    total,
    severity: debiles.length ? max(...debiles.map((d) => d.severity)) : "info",
  };
}

// found, no-version, clean o source-unavailable. Solo clean (versión y canario ok) permite decir "sin vulnerabilidades".
function portVulnState(p, vulns, canaryOk) {
  if (vulns && vulns.length) return "found";
  if (!hasVersion(p)) return "no-version";
  return canaryOk ? "clean" : "source-unavailable";
}

// Resumen listo para el normalizador, sin volver a tocar el XML.
function summarizePort(p, opts = {}) {
  const scripts  = (p && p.nse) || [];
  const canaryOk = Boolean(opts.canaryOk);
  const vulns    = extractVulns(scripts);

  return {
    vulnState: portVulnState(p, vulns, canaryOk),
    vulns,
    tls: extractTls(scripts),
    ssh: extractSsh(scripts),
    states: opts.states || null,
    offeredText: OFFERED_NOT_NEGOTIATED,
  };
}

module.exports = {
  extractVulns,
  extractTls,
  extractSsh,
  portVulnState,
  summarizePort,
  SSH_GRUPOS,
};
