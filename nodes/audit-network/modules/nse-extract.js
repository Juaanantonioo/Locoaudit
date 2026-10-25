"use strict";

// Resume el subárbol NSE de un puerto con su severidad ya resuelta.
// Vive aquí porque lib/ no importa de nodes/; el normalizador solo pone ids y textos.

const { severidadCvss, severidadMaxima } = require("../../../lib/severity-map");
const { buscarScript, tablasPorClave, valorElemento, listaElementos } = require("./nmap-xml");
const {
  TLS_GRADE_SEVERITY, severidadAlgoritmoSsh, tieneVersion, OFFERED_NOT_NEGOTIATED,
} = require("./nse-catalog");

// CVE de vulners por CPE. El grupo toma la severidad del peor CVE, no la media.
// Los exploits no generan hallazgo propio, pero se cuentan porque cambian la urgencia.
function extraerVulns(scripts) {
  const node = buscarScript(scripts, "vulners");
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
      const tipo = String(valorElemento(fila, "type") || "").toLowerCase();
      const id   = valorElemento(fila, "id");
      const esExploit = String(valorElemento(fila, "is_exploit")).toLowerCase() === "true";
      if (esExploit) exploits++;
      if (!id) continue;
      if (tipo !== "cve") continue;

      const cvssTxt = valorElemento(fila, "cvss");
      const cvss    = parseFloat(cvssTxt);
      let puntuacion;
      if (Number.isFinite(cvss)) {
        puntuacion = cvss;
      } else {
        puntuacion = null;
      }
      cves.push({
        id,
        cvss: puntuacion,
        // Sin cvss o con 0, severidadCvss da 'medium' para no rebajarlo.
        severity: severidadCvss(cvssTxt),
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
      severity: severidadMaxima(...cves.map((c) => c.severity)),
    });
  }
  return grupos;
}

// Nota TLS de ssl-enum-ciphers (least strength). Fuera de la tabla, severity null = no comprobado.
function extraerTls(scripts) {
  const node = buscarScript(scripts, "ssl-enum-ciphers");
  if (!node) return null;

  const grade = String(valorElemento(node, "least strength") || "").trim().toUpperCase();
  const protocolos = node.children
    .filter((c) => c.type === "table" && c.key)
    .map((c) => c.key);

  // Suites flojas, para que el hallazgo diga qué quitar y no solo la nota.
  const flojas = [];
  for (const proto of node.children.filter((c) => c.type === "table" && c.key)) {
    for (const tablaCiphers of tablasPorClave(proto, "ciphers")) {
      for (const suite of tablaCiphers.children.filter((c) => c.type === "table")) {
        const nombre = valorElemento(suite, "name");
        const nota   = String(valorElemento(suite, "strength") || "").toUpperCase();
        if (nombre && nota && nota !== "A") flojas.push({ name: nombre, grade: nota, protocol: proto.key });
      }
    }
  }
  flojas.sort((a, b) => b.grade.localeCompare(a.grade));

  const cert = buscarScript(scripts, "ssl-cert");
  let validez;
  if (cert) {
    validez = tablasPorClave(cert, "validity")[0];
  } else {
    validez = null;
  }

  let certificado;
  if (cert) {
    let caducidad;
    if (validez) {
      caducidad = valorElemento(validez, "notAfter") || null;
    } else {
      caducidad = null;
    }
    certificado = {
      sigAlgo: valorElemento(cert, "sig_algo") || null,
      notAfter: caducidad,
      issuer: (() => {
        const t = tablasPorClave(cert, "issuer")[0];
        if (t) {
          return valorElemento(t, "commonName") || null;
        } else {
          return null;
        }
      })(),
    };
  } else {
    certificado = null;
  }
  return {
    grade: grade || null,
    severity: TLS_GRADE_SEVERITY[grade] || null,
    protocols: protocolos,
    weak: flojas,
    cert: certificado,
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
function extraerSsh(scripts) {
  const node = buscarScript(scripts, "ssh2-enum-algos");
  if (!node) return null;

  const debiles = [];
  const grupos  = [];
  let total = 0;

  for (const [clave, etiqueta] of SSH_GRUPOS) {
    const tabla = tablasPorClave(node, clave)[0];
    if (!tabla) continue;
    const algos = listaElementos(tabla);
    total += algos.length;
    grupos.push({ key: clave, label: etiqueta, count: algos.length });
    for (const nombre of algos) {
      const sev = severidadAlgoritmoSsh(nombre);
      if (sev !== "info") debiles.push({ name: nombre, severity: sev, group: etiqueta });
    }
  }

  let severidad;
  if (debiles.length) {
    severidad = severidadMaxima(...debiles.map((d) => d.severity));
  } else {
    severidad = "info";
  }
  return {
    groups: grupos,
    weak: debiles,
    total,
    severity: severidad,
  };
}

// found, no-version, clean o source-unavailable. Solo clean (versión y canario ok) permite decir "sin vulnerabilidades".
function estadoVulnPuerto(p, vulns, canaryOk) {
  if (vulns && vulns.length) return "found";
  if (!tieneVersion(p)) return "no-version";
  if (canaryOk) {
    return "clean";
  } else {
    return "source-unavailable";
  }
}

// Resumen listo para el normalizador, sin volver a tocar el XML.
function resumirPuerto(p, opts = {}) {
  const scripts  = (p && p.nse) || [];
  const canaryOk = Boolean(opts.canaryOk);
  const vulns    = extraerVulns(scripts);

  return {
    vulnState: estadoVulnPuerto(p, vulns, canaryOk),
    vulns,
    tls: extraerTls(scripts),
    ssh: extraerSsh(scripts),
    states: opts.states || null,
    offeredText: OFFERED_NOT_NEGOTIATED,
  };
}

module.exports = {
  extraerVulns,
  extraerTls,
  extraerSsh,
  estadoVulnPuerto,
  resumirPuerto,
  SSH_GRUPOS,
};
