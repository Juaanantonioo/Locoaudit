"use strict";

/**
 * nmap-wrapper.js — Wrapper para Nmap, ÚNICO escáner de puertos de audit-network.
 *
 * Cadena del nodo:
 *
 *   nmap-wrapper.js   — Descubre los puertos abiertos con -sV (versiones de
 *                       servicio). Es la única fuente de puertos: el antiguo
 *                       escáner nativo (port-scanner.js) se eliminó al pasar
 *                       Nmap a REQUISITO del nodo.
 *
 *   port-catalog.js   — Catálogo de puertos conocidos → severidad para PC
 *                       personal. Datos puros, sin escaneo.
 *
 *   service-detect.js — Enriquece cada puerto con proceso, PID y dirección de
 *                       bind vía lsof/netstat (solo para targets locales).
 *
 *   audit-network.js  — Orquesta, y si Nmap NO está instalado emite un finding
 *                       con las instrucciones de instalación por plataforma en
 *                       vez de reventar el nodo.
 *
 * Sigue usando commandExists() antes de ejecutar, según CLAUDE.md:
 *   si nmap no está instalado → { skipped: true, reason: "nmap not installed" }
 *   El llamante decide qué hacer con ese caso (aquí: finding de dependencia).
 *
 * Comando: nmap -sV -T4 -Pn --max-retries 2 [-e iface] -p <spec> -oX - <target>
 *   -sV      detecta versiones de servicios (interroga el banner del proceso)
 *   -T4      timing agresivo — adecuado para localhost, no recomendado en red WAN
 *   -Pn      omite el descubrimiento: NO usar su "host up" para nada, siempre
 *            dice que sí (ver host-discovery.js, que es quien lo decide)
 *   -oX -    salida XML por stdout (sin fichero temporal)
 *
 * NO lleva --open: coste medido 0 s y a cambio conserva <extraports>/<extrareasons>
 * (puertos filtrados y su motivo). El filtrado a puertos abiertos lo hace
 * parseNmapXml(), que descarta todo state != "open".
 *
 * Exporta:
 *   runNmap(options?) → Promise<NmapResult>
 *
 * @typedef {{ port: number, protocol: string, state: string, service: string, version: string, severity: string, fix: string|null }} NmapPort
 * @typedef {{ skipped: true, reason: string } | { skipped: false, ports: NmapPort[] }} NmapResult
 */

const os                             = require("os");
const { execCommand, commandExists } = require("../../../lib/executor");
const { PORT_CATALOG }               = require("./port-catalog");
const { getFixForPort }              = require("./network-utils");

/**
 * Detecta qué interfaz de red local está en la misma subred que targetIp.
 * Necesario en macOS cuando hay varias interfaces activas en la misma subred:
 * sin -e, nmap falla con SO_ERROR 50 (ENETDOWN) al no saber cuál usar.
 * Para localhost devuelve null (no hace falta -e).
 *
 * @param {string} targetIp
 * @returns {string|null}  Nombre de interfaz (ej: "en6") o null
 */
function findInterfaceForTarget(targetIp) {
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

    // <state state="open" .../> — al no usar --open, ESTE es el único filtro:
    // descarta closed/filtered, que ahora sí llegan en el XML.
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

/**
 * Extrae el nombre de host resuelto por DNS inverso del XML de nmap.
 *
 * El escaneo NO usa -n, así que nmap resuelve el PTR del objetivo y lo emite en
 * <hostnames>. Tres formas posibles, y solo una es un dato nuevo:
 *
 *   <hostnames><hostname name="mi-nas" type="PTR"/></hostnames>   → dato real
 *   <hostnames><hostname name="example.com" type="user"/></...>   → el eco del
 *       target que escribió el usuario: presentarlo sería devolverle su propia
 *       entrada disfrazada de descubrimiento
 *   <hostnames></hostnames>                                       → sin PTR
 *
 * @param {string} xml  Salida completa de nmap -oX -
 * @returns {string|null}  Nombre PTR, o null si no hay
 */
function parsePtrHostname(xml) {
  const m = String(xml || "").match(/<hostname\s+name="([^"]+)"\s+type="PTR"\s*\/>/);
  return m ? m[1] : null;
}

// ── Asignación de severidad ───────────────────────────────────────────────────

/**
 * Enriquece un puerto parseado de nmap con la severidad del PORT_CATALOG y el fix por puerto.
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
  const target   = options.target  || "127.0.0.1";
  const scanMode = options.scanMode || "standard";
  // -Pn sobre un host tras firewall (puertos filtrados) puede tardar >45s solo
  // con 1-1024; el timeout por defecto debe cubrirlo o el escaneo se corta y
  // produce un falso "0 puertos". El nodo pasa un timeout explícito acorde al modo.
  const timeout  = options.timeout || 90000;

  const available = await commandExists("nmap");
  if (!available) {
    return { skipped: true, reason: "nmap not installed" };
  }

  // Rango de puertos según modo. El catálogo (servicios de gestión: 8006, 10000,
  // 2375…) va SIEMPRE explícito porque nmap lo omitiría; el rango numérico añade
  // cobertura general. Cada rango tiene una etiqueta HONESTA en la UI del nodo.
  //   rapido   → catálogo + 1-1024   (~1000 puertos; segundos en local, ~45s tras firewall)
  //   standard → catálogo + 1-3000   (incluye 2222 SSH-alt; ~2 min tras firewall)
  //   full     → catálogo + 1-10000  (lento: varios minutos tras un firewall)
  //   custom   → lista del usuario
  // NOTA (dato medido contra host filtrado): cada puerto filtrado obliga a nmap a
  // esperar reintentos → el tiempo crece con el nº de puertos, no con los abiertos.
  // 10.000 filtrados ≈ 500s; por eso "full" avisa de su lentitud. --host-timeout NO
  // se usa: cortaría el host antes de sondear los puertos altos y daría un falso 0.
  // Rango numérico por modo. El catálogo se añade SOLO con los puertos por encima
  // del rango (los de dentro ya están cubiertos): así se evita el aviso "Duplicate
  // port number(s)" de nmap y el escaneo redundante de los mismos puertos.
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

  // En macOS con varias interfaces en la misma subred, nmap falla con SO_ERROR 50
  // si no se especifica explícitamente qué interfaz usar.
  const iface = findInterfaceForTarget(target);
  const ifaceFlag = iface ? `-e ${iface}` : "";
  // --max-retries 2: acota los reintentos por puerto filtrado (por defecto son
  // más), reduciendo el tiempo sin perder detección de puertos abiertos.
  //
  // SIN --open (medido): --open es un filtro de SALIDA, no cambia el sondeo —
  // -p 1-200 contra un host muerto tarda 45,92 s con él y 45,95 s sin él, y el
  // XML solo crece ~300 bytes porque nmap colapsa los puertos no abiertos en un
  // único <extraports count="N"><extrareasons reason="…">. A cambio recupera dos
  // señales que --open borraba: el recuento real de puertos filtrados (evidencia
  // de cortafuegos) y el motivo por puerto (host-unreach vs no-response). Con
  // --open, un host sin ningún puerto abierto no emitía NI el bloque <host>.
  const cmd = `nmap -sV -T4 -Pn --max-retries 2 ${ifaceFlag} -p ${portSpec} -oX - ${target}`.trim();

  let stdout;
  let inconclusive = false;
  try {
    stdout = await execCommand(cmd, timeout);
  } catch (err) {
    // nmap puede salir con código != 0 en algunos sistemas aunque haya producido
    // XML válido (ej: advertencias de permisos en macOS sin sudo).
    stdout = err.stdout || "";
    // Un escaneo VÁLIDO termina con <runstats>...<finished>. Si falta (timeout,
    // proceso matado, error de red), el resultado NO es concluyente: NO se puede
    // afirmar "0 puertos abiertos" — sería un falso "sin riesgo".
    if (!stdout.includes("<runstats") && !stdout.includes("/finished")) {
      return {
        skipped: true,
        inconclusive: true,
        reason: `escaneo no concluyente: ${(err.stderr || err.message || "timeout o proceso interrumpido").trim()}`,
        scan: { target, portSpec, scanMode, completed: false, filteredCount: 0, filteredReason: null, hostname: null },
      };
    }
  }

  // NO se deriva aquí ningún "hostUp": con -Pn nmap devuelve SIEMPRE
  // <hosts up="1" down="0"> y <status state="up" reason="user-set">, o sea que
  // no ha comprobado nada. Quien decide si el objetivo existe es
  // host-discovery.js (nmap -sn), única fuente de verdad de ese dato.
  const completed = stdout.includes("<runstats") || stdout.includes("/finished");
  // Recuento de puertos filtrados: real desde que se quitó --open (antes este
  // bloque nunca aparecía en la salida y filteredCount valía siempre 0).
  const filteredMatch = stdout.match(/<extraports\s+state="filtered"\s+count="(\d+)"/);
  const filteredCount = filteredMatch ? parseInt(filteredMatch[1], 10) : 0;
  // Motivo dominante de los puertos no abiertos (no-response, host-unreach,
  // net-unreach, conn-refused…). Solo afina el mensaje: no decide nada.
  const reasonMatch = stdout.match(/<extrareasons\s+reason="([^"]*)"/);
  const filteredReason = reasonMatch ? reasonMatch[1] : null;

  // Nombre PTR del objetivo: dato que nmap ya resolvía y se estaba tirando.
  // null cuando el objetivo no tiene DNS inverso configurado.
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

// findInterfaceForTarget se exporta para que host-discovery.js use EXACTAMENTE
// la misma interfaz en el descubrimiento que la que usará el escaneo: si -sn
// saliera por otra interfaz, podría decir "no alcanzable" sobre una ruta que el
// escaneo sí tiene (o al revés).
module.exports = { runNmap, parseNmapXml, parsePtrHostname, findInterfaceForTarget };
