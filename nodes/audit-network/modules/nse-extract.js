"use strict";

/**
 * Del subárbol NSE de un puerto a un resumen ya interpretado.
 * Existe aquí porque el normalizador (lib/normalizer.js) necesita las tablas de severidad de nse-catalog.js, y `lib/` no
 * importa de `nodes/`. Este módulo lee el XML ya parseado y resuelve la severidad; el normalizador solo hace ids, esquema y textos.
 */

const { fromCvss, max } = require("../../../lib/severity-map");
const { findScript, tablesByKey, elemValue, elemList } = require("./nmap-xml");
const {
  TLS_GRADE_SEVERITY, sshAlgoSeverity, hasVersion, OFFERED_NOT_NEGOTIATED,
} = require("./nse-catalog");

/**
 * Los CVE de vulners, agrupados por CPE. La severidad del grupo es la del CVE más alto, no la media (diez bajos esconderían un crítico).
 * Los tipos que no son 'cve' (exploitdb, packetstorm, githubexploit…) no generan hallazgo propio, pero se cuentan aparte
 * porque "existe exploit público" cambia la urgencia.
 */
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
        // Un 'cvss' que no llega o llega a 0 no baja el hallazgo a 'low': fromCvss lo manda a
        // 'medium' justamente para que no se cuele por la puerta de atrás.
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

/**
 * La nota TLS y con qué se sostiene. Se usa la `least strength` que calcula ssl-enum-ciphers (la peor suite aceptada) en
 * vez de recalcularla. Una nota fuera de la tabla, incluida 'unknown', devuelve `severity: null`, que el llamante trata
 * como "no se pudo comprobar"; mapearla a 'info' sería un falso verde.
 */
function extractTls(scripts) {
  const node = findScript(scripts, "ssl-enum-ciphers");
  if (!node) return null;

  const grade = String(elemValue(node, "least strength") || "").trim().toUpperCase();
  const protocolos = node.children
    .filter((c) => c.type === "table" && c.key)
    .map((c) => c.key);

  // Las suites peor calificadas, para que el hallazgo diga qué hay que quitar y no solo la nota.
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

/** Los grupos de ssh2-enum-algos que sí son algoritmos. Los demás (`compression`) no se juzgan. */
const SSH_GRUPOS = [
  ["kex_algorithms",              "intercambio de claves"],
  ["server_host_key_algorithms",  "clave de servidor"],
  ["encryption_algorithms",       "cifrado"],
  ["mac_algorithms",              "integridad (MAC)"],
];

/**
 * Los algoritmos SSH ofrecidos, con los débiles separados.
 *
 * `severity` es la del peor encontrado, e 'info' cuando no hay ninguno débil: en ese caso el
 * hallazgo sigue existiendo como INVENTARIO —qué ofrece este SSH— y no como problema.
 */
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

/**
 * Los cuatro estados de vulnerabilidad de un puerto: no "¿tiene CVE?" sino "¿qué sabemos de si los tiene?".
 *   found                salieron CVE.
 *   clean                anunció versión, el canario confirma que la fuente respondió y no vino ningún CVE.
 *                        Es la única combinación que autoriza a decir "sin vulnerabilidades conocidas".
 *   no-version           no anunció versión: nada que consultar. Alcance, no hueco.
 *   source-unavailable   anunció versión y la fuente no está confirmada. Hueco: ámbar.
 */
function portVulnState(p, vulns, canaryOk) {
  if (vulns && vulns.length) return "found";
  if (!hasVersion(p)) return "no-version";
  return canaryOk ? "clean" : "source-unavailable";
}

/**
 * El resumen NSE de un puerto, listo para que el normalizador lo convierta en findings sin
 * volver a tocar XML ni tablas.
 */
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
