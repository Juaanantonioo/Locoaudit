"use strict";

/**
 * Único escáner de puertos del nodo: el port-scanner nativo se eliminó al pasar Nmap a requisito.
 * Si no está instalado devuelve { skipped, reason } y el llamante emite el finding de dependencia.
 *
 * El comando va con -sV para las versiones de servicio, -T4, -Pn y -oX - para XML por stdout.
 * El "host up" de -Pn no se usa para nada: siempre dice que sí, y quien decide si el objetivo
 * existe es host-discovery.js.
 */

const os                             = require("os");
const { execCommand, commandExists } = require("../../../lib/executor");
const { PORT_CATALOG }               = require("./port-catalog");
const { getFixForPort }              = require("./network-utils");

/**
 * La interfaz local que comparte subred con el objetivo, para el -e. Hace falta en macOS con
 * varias interfaces en la misma subred: sin -e nmap falla con SO_ERROR 50 al no saber cuál usar.
 *
 * En Windows devuelve siempre null y el comando sale sin -e. os.networkInterfaces() da el nombre
 * amigable ("Wi-Fi") y el nmap de Windows usa sus propios alias o el dispositivo NPF: con
 * `-e Wi-Fi` responde "I cannot figure out what source address to use for device Wi-Fi" y sale
 * con exit="error" y <hosts up="0">, que el pre-check leía como host caído. Sin -e funciona,
 * porque la tabla de rutas ya enruta bien; -e es una optimización, no un requisito. Traducir el
 * nombre con `nmap --iflist` se descartó: una llamada más y un parseo de texto frágil.
 */
function findInterfaceForTarget(targetIp, platform = process.platform) {
  if (platform === "win32") return null;
  if (targetIp === "127.0.0.1" || targetIp === "localhost") return null;
  const targetParts = targetIp.split(".").map(Number);
  if (targetParts.length !== 4 || targetParts.some(isNaN)) return null;

  for (const [name, addrs] of Object.entries(os.networkInterfaces())) {
    for (const addr of addrs) {
      if (addr.family !== "IPv4" || addr.internal) continue;
      const addrParts = addr.address.split(".").map(Number);
      const maskParts = addr.netmask.split(".").map(Number);
      const sameSubnet = maskParts.every(
        (mask, i) => (addrParts[i] & mask) === (targetParts[i] & mask)
      );
      if (sameSubnet) return name;
    }
  }
  return null;
}

/**
 * nmap emite <runstats> aunque aborte, con exit="error" y unos <hosts up="0"> que no son un dato:
 * no llegó a sondear nada. Leerlo como "0 puertos" o como "host caído" es el falso verde de
 * siempre, así que quien llama tiene que poder distinguirlo. Lo usa también host-discovery.
 */
function parseNmapFatalError(xml) {
  const m = String(xml || "").match(/<finished\b([^>]*)>/);
  if (!m) return null;
  const attrs  = m[1];
  const exitAt = attrs.match(/\bexit="([^"]*)"/);
  if (!exitAt || exitAt[1] === "success") return null;
  const msgAt = attrs.match(/\berrormsg="([^"]*)"/);
  const msg   = msgAt ? decodeXmlEntities(msgAt[1]) : "";
  return msg || `nmap terminó con exit="${exitAt[1]}"`;
}

/** Las cinco entidades predefinidas bastan para el errormsg de nmap, que es texto plano. */
function decodeXmlEntities(s) {
  return String(s)
    .replace(/&lt;/g,   "<")
    .replace(/&gt;/g,   ">")
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'")
    .replace(/&amp;/g,  "&");
}

/** attrValue('protocol="tcp" portid="22"', "portid") → "22". */
function attrValue(tag, attr) {
  const re = new RegExp(`${attr}="([^"]*)"`, "i");
  const m  = tag.match(re);
  return m ? m[1] : "";
}

/**
 * Los puertos abiertos del XML. Cada uno viene como
 * <port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH"/></port>.
 */
function parseNmapXml(xml) {
  const results    = [];
  const portBlockRe = /<port\s[^>]*>[\s\S]*?<\/port>/g;
  let blockMatch;

  while ((blockMatch = portBlockRe.exec(xml)) !== null) {
    const block = blockMatch[0];

    const portTagMatch = block.match(/^<port\s([^>]*)>/);
    if (!portTagMatch) continue;
    const portTag  = portTagMatch[1];
    const port     = parseInt(attrValue(portTag, "portid"), 10);
    const protocol = attrValue(portTag, "protocol") || "tcp";
    if (isNaN(port)) continue;

    // Sin --open en el comando, este es el único filtro: closed y filtered ahora llegan al XML.
    const stateMatch = block.match(/<state\s([^/]*)\/?>/);
    const state      = stateMatch ? attrValue(stateMatch[1], "state") : "open";
    if (state !== "open") continue;

    // `[^>]` y no `[^/]`: cuando -sV no reconoce del todo un servicio mete su huella en
    // `servicefp`, y esa huella lleva barras dentro ("HTTP/1\\.1", "AirTunes/950\\.7\\.1"). Con
    // `[^/]` el patrón dejaba de casar en cuanto aparecía la primera, y el servicio caía al
    // fallback "unknown" perdiendo product, version y extrainfo. Un '>' crudo no puede aparecer
    // dentro de un atributo —nmap lo escapa como &gt;—, así que cortar en '>' es fiable.
    const serviceMatch = block.match(/<service\b([^>]*?)\/?>/);
    const service      = serviceMatch ? attrValue(serviceMatch[1], "name")    : "unknown";
    const product      = serviceMatch ? attrValue(serviceMatch[1], "product") : "";
    const version      = serviceMatch ? attrValue(serviceMatch[1], "version") : "";
    const versionStr   = [product, version].filter(Boolean).join(" ");

    results.push({ port, protocol, state, service, version: versionStr });
  }

  return results;
}

/**
 * El PTR que nmap ya resuelve, porque el escaneo no lleva -n. Solo vale type="PTR": el
 * type="user" es el eco del target que escribió el usuario, y presentarlo sería devolverle su
 * propia entrada disfrazada de descubrimiento.
 */
function parsePtrHostname(xml) {
  const m = String(xml || "").match(/<hostname\s+name="([^"]+)"\s+type="PTR"\s*\/>/);
  return m ? m[1] : null;
}

/** Severidad del catálogo y fix por puerto; lo que no está en el catálogo queda en "low". */
function applyMeta(parsed) {
  const meta = PORT_CATALOG[parsed.port];
  return {
    ...parsed,
    severity: meta ? meta.severity : "low",
    fix:      getFixForPort(parsed.port, process.platform),
  };
}

/** Los puertos abiertos del target, o { skipped: true } si nmap no está instalado. */
async function runNmap(options = {}) {
  const target   = options.target  || "127.0.0.1";
  const scanMode = options.scanMode || "standard";
  // Con -Pn contra un host tras firewall, 1-1024 ya pasa de 45 s: por debajo de eso el escaneo
  // se corta y sale un falso "0 puertos". El nodo pasa el suyo según el modo.
  const timeout  = options.timeout || 90000;

  const available = await commandExists("nmap");
  if (!available) {
    return { skipped: true, kind: "not-installed", reason: "Nmap no está instalado en este equipo" };
  }

  // Rango numérico por modo, más los puertos del catálogo que queden por encima: los de dentro
  // ya están cubiertos y repetirlos da el aviso "Duplicate port number(s)" y sondeos de más.
  // El coste lo marcan los puertos filtrados, no los abiertos, porque cada uno espera reintentos:
  // medido contra un host filtrado, 10.000 puertos rondan los 500 s. De ahí que "full" avise.
  const RANGE_MAX = { rapido: 1024, standard: 3000, full: 10000 };
  let portSpec;
  if (scanMode === "custom" && options.customPorts && options.customPorts.trim()) {
    portSpec = options.customPorts.trim();
  } else {
    const max = RANGE_MAX[scanMode] || RANGE_MAX.standard;
    const highPorts = Object.keys(PORT_CATALOG)
      .map(Number)
      .filter((p) => p > max)
      .sort((a, b) => a - b);
    portSpec = highPorts.length ? `1-${max},${highPorts.join(",")}` : `1-${max}`;
  }

  const iface = findInterfaceForTarget(target);
  const ifaceFlag = iface ? `-e ${iface}` : "";
  // --max-retries 2 recorta los reintentos por puerto filtrado sin perder puertos abiertos.
  // Sin --open, que es un filtro de salida y no cambia el sondeo: medido, 45,92 s con él y
  // 45,95 s sin él sobre -p 1-200, y el XML solo crece ~300 bytes porque nmap colapsa lo no
  // abierto en un <extraports>. A cambio vuelven el recuento de filtrados, que es la evidencia
  // de cortafuegos, y su motivo. Con --open, un host sin puertos abiertos no emitía ni <host>.
  const cmd = `nmap -sV -T4 -Pn --max-retries 2 ${ifaceFlag} -p ${portSpec} -oX - ${target}`.trim();

  let stdout;
  let inconclusive = false;
  try {
    stdout = await execCommand(cmd, timeout);
  } catch (err) {
    // Hay sistemas donde nmap sale con código distinto de cero y el XML es válido igual, como
    // con los avisos de permisos de macOS sin sudo.
    stdout = err.stdout || "";
    // Un escaneo válido termina en <runstats>…<finished>. Sin eso no se puede afirmar
    // "0 puertos abiertos": sería un falso "sin riesgo".
    if (!stdout.includes("<runstats") && !stdout.includes("/finished")) {
      return {
        skipped: true,
        inconclusive: true,
        reason: `escaneo no concluyente: ${(err.stderr || err.message || "timeout o proceso interrumpido").trim()}`,
        scan: { target, portSpec, scanMode, completed: false, filteredCount: 0, filteredReason: null, hostname: null },
      };
    }
  }

  // Abortado no es "escaneado sin resultado", es no escaneado. Se junta con el camino de
  // "no concluyente" del timeout, mismo NET-SCAN-WARN, en vez de inventar un estado nuevo.
  const fatalError = parseNmapFatalError(stdout);
  if (fatalError) {
    return {
      skipped: true,
      inconclusive: true,
      reason: `escaneo no concluyente: nmap terminó con error: ${fatalError}`,
      scan: { target, portSpec, scanMode, completed: false, filteredCount: 0, filteredReason: null, hostname: null },
    };
  }

  // De aquí no sale ningún "hostUp": con -Pn el XML trae siempre up="1" y reason="user-set",
  // o sea que no se comprobó nada. Eso lo decide host-discovery.
  const completed = stdout.includes("<runstats") || stdout.includes("/finished");
  // Real desde que se quitó --open: antes este bloque no salía y el recuento era siempre 0.
  const filteredMatch = stdout.match(/<extraports\s+state="filtered"\s+count="(\d+)"/);
  const filteredCount = filteredMatch ? parseInt(filteredMatch[1], 10) : 0;
  // El motivo dominante (no-response, host-unreach…) solo afina el mensaje, no decide nada.
  const reasonMatch = stdout.match(/<extrareasons\s+reason="([^"]*)"/);
  const filteredReason = reasonMatch ? reasonMatch[1] : null;

  // nmap ya lo resolvía y se estaba tirando. Null si el objetivo no tiene DNS inverso.
  const hostname = parsePtrHostname(stdout);

  const parsed = parseNmapXml(stdout);
  const ports  = parsed.map(applyMeta);

  return {
    skipped: false,
    ports,
    inconclusive,
    scan: { target, portSpec, scanMode, completed, filteredCount, filteredReason, hostname },
  };
}

// findInterfaceForTarget se exporta para que el descubrimiento salga por la misma interfaz que
// el escaneo: por otra, el -sn podría decir "no alcanzable" sobre una ruta que el escaneo sí tiene.
module.exports = { runNmap, parseNmapXml, parsePtrHostname, findInterfaceForTarget, parseNmapFatalError };
