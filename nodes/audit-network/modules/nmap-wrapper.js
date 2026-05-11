"use strict";

/**
 * nmap-wrapper.js — Wrapper opcional para Nmap (escáner de red avanzado).
 *
 * Este módulo es el complemento de port-scanner.js en la cadena de audit-network:
 *
 *   port-scanner.js   — Escaneo nativo con "net" de Node.js. Cubre un catálogo
 *                       fijo de puertos conocidos sin ninguna dependencia externa.
 *                       Siempre disponible, siempre ejecutable.
 *
 *   nmap-wrapper.js   — Cuando Nmap está instalado, realiza un escaneo completo
 *                       (-sV para detectar versiones de servicio) que puede
 *                       descubrir puertos no presentes en el catálogo y añadir
 *                       información de versión al finding. Más lento pero más
 *                       exhaustivo que el escáner nativo.
 *
 *   audit-network.js  — Decide cuál usar: intenta nmap primero y, si no está
 *                       instalado o falla, cae en port-scanner como fallback.
 *                       El usuario final ve siempre un resultado, independientemente
 *                       de si Nmap está instalado.
 *
 * Sigue el patrón obligatorio de CLAUDE.md para herramientas opcionales:
 *   si nmap no está instalado → { skipped: true, reason: "nmap not installed" }
 *
 * Comando: nmap -sV -T4 --open -oX - <target>
 *   -sV      detecta versiones de servicios (interroga el banner del proceso)
 *   -T4      timing agresivo — adecuado para localhost, no recomendado en red WAN
 *   --open   filtra solo puertos abiertos en la salida
 *   -oX -    salida XML por stdout (sin fichero temporal)
 *
 * Exporta:
 *   runNmap(options?) → Promise<NmapResult>
 *
 * @typedef {{ port: number, protocol: string, state: string, service: string, version: string, severity: string, fix: string|null }} NmapPort
 * @typedef {{ skipped: true, reason: string } | { skipped: false, ports: NmapPort[] }} NmapResult
 */

const { execCommand, commandExists } = require("../../../lib/executor");
const { PORT_CATALOG }               = require("./port-scanner");
const { getFixForPort }              = require("./network-utils");

// ── Parser XML ────────────────────────────────────────────────────────────────

/**
 * Extrae el valor de un atributo de una cadena de apertura de etiqueta XML.
 * Ejemplo: attrValue('protocol="tcp" portid="22"', "portid") → "22"
 *
 * @param {string} tag   Contenido de atributos de una etiqueta XML
 * @param {string} attr  Nombre del atributo a extraer
 * @returns {string}     Valor del atributo o cadena vacía si no existe
 */
function attrValue(tag, attr) {
  const re = new RegExp(`${attr}="([^"]*)"`, "i");
  const m  = tag.match(re);
  return m ? m[1] : "";
}

/**
 * Parsea la salida XML de nmap -oX y devuelve un array de puertos abiertos.
 *
 * Estructura XML relevante de nmap:
 *   <port protocol="tcp" portid="22">
 *     <state state="open" .../>
 *     <service name="ssh" product="OpenSSH" version="8.9" .../>
 *   </port>
 *
 * @param {string} xml  Salida completa de nmap -oX -
 * @returns {Array<{ port: number, protocol: string, state: string, service: string, version: string }>}
 */
function parseNmapXml(xml) {
  const results    = [];
  const portBlockRe = /<port\s[^>]*>[\s\S]*?<\/port>/g;
  let blockMatch;

  while ((blockMatch = portBlockRe.exec(xml)) !== null) {
    const block = blockMatch[0];

    // Atributos de <port protocol="..." portid="...">
    const portTagMatch = block.match(/^<port\s([^>]*)>/);
    if (!portTagMatch) continue;
    const portTag  = portTagMatch[1];
    const port     = parseInt(attrValue(portTag, "portid"), 10);
    const protocol = attrValue(portTag, "protocol") || "tcp";
    if (isNaN(port)) continue;

    // <state state="open" .../> — --open ya filtra en nmap, pero verificamos
    const stateMatch = block.match(/<state\s([^/]*)\/?>/);
    const state      = stateMatch ? attrValue(stateMatch[1], "state") : "open";
    if (state !== "open") continue;

    // <service name="..." product="..." version="..." .../>
    const serviceMatch = block.match(/<service\s([^/]*)\/?>/);
    const service      = serviceMatch ? attrValue(serviceMatch[1], "name")    : "unknown";
    const product      = serviceMatch ? attrValue(serviceMatch[1], "product") : "";
    const version      = serviceMatch ? attrValue(serviceMatch[1], "version") : "";
    const versionStr   = [product, version].filter(Boolean).join(" ");

    results.push({ port, protocol, state, service, version: versionStr });
  }

  return results;
}

// ── Asignación de severidad ───────────────────────────────────────────────────

/**
 * Enriquece un puerto parseado de nmap con severity y fix del PORT_CATALOG.
 * Si el puerto no está en el catálogo usa severity "low" y un fix genérico.
 *
 * @param {{ port: number, protocol: string, state: string, service: string, version: string }} parsed
 * @returns {NmapPort}
 */
function applyMeta(parsed) {
  const meta = PORT_CATALOG[parsed.port];
  return {
    ...parsed,
    severity: meta ? meta.severity : "low",
    fix:      getFixForPort(parsed.port, process.platform),
  };
}

// ── API pública ───────────────────────────────────────────────────────────────

/**
 * Ejecuta Nmap sobre el target indicado y devuelve los puertos abiertos.
 * Si Nmap no está instalado devuelve { skipped: true }.
 *
 * @param {{ target?: string, timeout?: number }} [options]
 * @returns {Promise<NmapResult>}
 */
async function runNmap(options = {}) {
  const target  = options.target  || "127.0.0.1";
  const timeout = options.timeout || 30000;

  const available = await commandExists("nmap");
  if (!available) {
    return { skipped: true, reason: "nmap not installed" };
  }

  let stdout;
  try {
    stdout = await execCommand(
      `nmap -sV -T4 --open -oX - ${target}`,
      timeout
    );
  } catch (err) {
    // nmap puede salir con código != 0 en algunos sistemas aunque haya producido
    // XML válido (ej: advertencias de permisos en macOS sin sudo).
    stdout = err.stdout || "";
    if (!stdout.includes("<nmaprun")) {
      return {
        skipped: true,
        reason: `nmap failed: ${(err.stderr || err.message || "unknown error").trim()}`,
      };
    }
  }

  const parsed = parseNmapXml(stdout);
  const ports  = parsed.map(applyMeta);

  return { skipped: false, ports };
}

module.exports = { runNmap };
