"use strict";

// Escáner de puertos del nodo. Sin nmap devuelve { skipped, kind, reason } y el nodo emite el hallazgo.
// El "host up" de -Pn no se usa: siempre dice que sí; eso lo decide host-discovery.js.

const os                             = require("os");
const { ejecutar, existeComando } = require("../../../lib/executor");
const { PORT_CATALOG }               = require("./port-catalog");
const { solucionPorPuerto }              = require("./network-utils");
const { decodificarEntidades, leerScripts } = require("./nmap-xml");

// Nombre de interfaz que puede ir en la línea de nmap sin comillas.
const IFACE_NAME_RE = /^[\w.:-]+$/;

// Interfaz para el -e (macOS falla sin ella con varias en la misma subred).
// En Windows null: el nombre amigable ("Wi-Fi") no lo entiende nmap y sin -e funciona.
// Un nombre con otros caracteres se descarta: va a la shell y sin -e el escaneo sigue funcionando.
function interfazParaObjetivo(targetIp, platform = process.platform) {
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
      if (sameSubnet && IFACE_NAME_RE.test(name)) return name;
    }
  }
  return null;
}

// nmap emite <runstats> aunque aborte; esos ceros no son un dato y no deben leerse como "0 puertos".
function errorFatalNmap(xml) {
  const m = String(xml || "").match(/<finished\b([^>]*)>/);
  if (!m) return null;
  const attrs  = m[1];
  const exitAt = attrs.match(/\bexit="([^"]*)"/);
  if (!exitAt || exitAt[1] === "success") return null;
  const msgAt = attrs.match(/\berrormsg="([^"]*)"/);
  let msg;
  if (msgAt) {
    msg = decodificarEntidades(msgAt[1]);
  } else {
    msg = "";
  }
  return msg || `nmap terminó con exit="${exitAt[1]}"`;
}

// valorAtributo('protocol="tcp" portid="22"', "portid") → "22".
function valorAtributo(tag, attr) {
  const re = new RegExp(`\\b${attr}="([^"]*)"`, "i");
  const m  = tag.match(re);
  // Se quitan los saltos: un banner externo podría fabricar una línea "$ orden" en el fix.
  if (m) {
    return decodificarEntidades(m[1]).replace(/[\x00-\x1f\x7f\u2028\u2029]+/g, " ");
  } else {
    return "";
  }
}

// Puertos abiertos del XML de nmap.
function leerXmlNmap(xml) {
  const results    = [];
  const portBlockRe = /<port\s[^>]*>[\s\S]*?<\/port>/g;
  let blockMatch;

  while ((blockMatch = portBlockRe.exec(xml)) !== null) {
    const block = blockMatch[0];

    const portTagMatch = block.match(/^<port\s([^>]*)>/);
    if (!portTagMatch) continue;
    const portTag  = portTagMatch[1];
    const port     = parseInt(valorAtributo(portTag, "portid"), 10);
    const protocol = valorAtributo(portTag, "protocol") || "tcp";
    if (isNaN(port)) continue;

    // Sin --open, closed y filtered llegan al XML y se filtran aquí.
    const stateMatch = block.match(/<state\s([^/]*)\/?>/);
    let state;
    if (stateMatch) {
      state = valorAtributo(stateMatch[1], "state");
    } else {
      state = "open";
    }
    if (state !== "open") continue;

    // `[^>]` y no `[^/]`: servicefp lleva barras, y nmap siempre escapa '>' dentro de un atributo.
    const serviceMatch = block.match(/<service\b([^>]*?)\/?>/);
    let service;
    if (serviceMatch) {
      service = valorAtributo(serviceMatch[1], "name");
    } else {
      service = "unknown";
    }
    let product;
    if (serviceMatch) {
      product = valorAtributo(serviceMatch[1], "product");
    } else {
      product = "";
    }
    let version;
    if (serviceMatch) {
      version = valorAtributo(serviceMatch[1], "version");
    } else {
      version = "";
    }
    let extrainfo;
    if (serviceMatch) {
      extrainfo = valorAtributo(serviceMatch[1], "extrainfo");
    } else {
      extrainfo = "";
    }
    // tunnel="ssl" indica TLS real, también en puertos que no están en ninguna tabla.
    let tunnel;
    if (serviceMatch) {
      tunnel = valorAtributo(serviceMatch[1], "tunnel");
    } else {
      tunnel = "";
    }
    const versionStr   = [product, version].filter(Boolean).join(" ");

    // Se guardan todos los CPE: vulners agrupa sus CVE por ellos.
    const cpes = [];
    const cpeRe = /<cpe>([^<]*)<\/cpe>/g;
    let cpeMatch;
    while ((cpeMatch = cpeRe.exec(block)) !== null) cpes.push(decodificarEntidades(cpeMatch[1]));
    // El de aplicación tiene prioridad sobre el de sistema operativo.
    const cpe = cpes.find((c) => c.startsWith("cpe:/a")) || cpes[0] || "";

    // Vacío si el escaneo fue sin --script.
    const nse = leerScripts(block);

    results.push({
      port, protocol, state, service, version: versionStr,
      extrainfo, tunnel, cpe, cpes, nse,
    });
  }

  return results;
}

// PTR resuelto por nmap. Solo type="PTR": type="user" es el eco de lo que escribió el usuario.
function leerNombrePtr(xml) {
  const m = String(xml || "").match(/<hostname\s+name="([^"]+)"\s+type="PTR"\s*\/>/);
  if (m) {
    return m[1];
  } else {
    return null;
  }
}

// Severidad del catálogo y fix por puerto; fuera del catálogo queda en "low".
function aplicarMeta(parsed) {
  const meta = PORT_CATALOG[parsed.port];
  let severidad;
  if (meta) {
    severidad = meta.severity;
  } else {
    severidad = "low";
  }
  return {
    ...parsed,
    severity: severidad,
    fix:      solucionPorPuerto(parsed.port, process.platform),
  };
}

// Separada de ejecutarNmap() para poder probarla. Sin -O (requiere root), -f (evasión) ni --script-timeout,
// porque un script cortado desaparece del XML igual que uno sin hallazgos.
function comandoEscaneo({ target, portSpec, ifaceFlag = "", nseScripts = [] }) {
  let scriptFlag;
  if (nseScripts.length) {
    scriptFlag = ` --script ${nseScripts.join(",")}`;
  } else {
    scriptFlag = "";
  }
  return `nmap -sV -T4 -Pn --max-retries 2 ${ifaceFlag}${scriptFlag} -p ${portSpec} -oX - ${target}`.trim();
}

// Puertos abiertos del objetivo, o { skipped: true } si nmap no está o el escaneo no terminó.
async function ejecutarNmap(options = {}) {
  const target   = options.target  || "127.0.0.1";
  const scanMode = options.scanMode || "standard";
  // Valor de reserva; el nodo pasa el suyo según el modo.
  const timeout  = options.timeout || 90000;

  const available = await existeComando("nmap");
  if (!available) {
    return { skipped: true, kind: "not-installed", reason: "Nmap no está instalado en este equipo" };
  }

  // Rango del modo más los puertos del catálogo por encima (repetirlos da "Duplicate port number(s)").
  const RANGE_MAX = { rapido: 1024, standard: 3000, full: 65535 };
  let portSpec;
  if (scanMode === "custom" && options.customPorts && options.customPorts.trim()) {
    portSpec = options.customPorts.trim();
  } else {
    const max = RANGE_MAX[scanMode] || RANGE_MAX.standard;
    const highPorts = Object.keys(PORT_CATALOG)
      .map(Number)
      .filter((p) => p > max)
      .sort((a, b) => a - b);
    if (highPorts.length) {
      portSpec = `1-${max},${highPorts.join(",")}`;
    } else {
      portSpec = `1-${max}`;
    }
  }

  const iface = interfazParaObjetivo(target);
  let ifaceFlag;
  if (iface) {
    ifaceFlag = `-e ${iface}`;
  } else {
    ifaceFlag = "";
  }
  // Lista ya filtrada por nse-scripts.js; vacía con NSE apagado.
  let nseScripts;
  if (Array.isArray(options.nseScripts)) {
    nseScripts = options.nseScripts.filter(Boolean);
  } else {
    nseScripts = [];
  }
  // Sin --open para conservar <extraports>, que da el recuento de filtrados (evidencia de cortafuegos).
  const cmd = comandoEscaneo({ target, portSpec, ifaceFlag, nseScripts });

  let stdout;
  let inconclusive = false;
  try {
    stdout = await ejecutar(cmd, timeout);
  } catch (err) {
    // nmap puede salir con error y dejar XML válido (p. ej. macOS sin sudo).
    stdout = err.stdout || "";
    // Sin <runstats>/<finished> no se puede afirmar "0 puertos abiertos".
    if (!stdout.includes("<runstats") && !stdout.includes("/finished")) {
      return {
        skipped: true,
        inconclusive: true,
        reason: `escaneo no concluyente: ${(err.stderr || err.message || "timeout o proceso interrumpido").trim()}`,
        scan: { target, portSpec, scanMode, completed: false, filteredCount: 0, filteredReason: null, hostname: null },
      };
    }
  }

  // Abortado es "no escaneado": sale por el mismo camino no concluyente que el timeout.
  const fatalError = errorFatalNmap(stdout);
  if (fatalError) {
    return {
      skipped: true,
      inconclusive: true,
      reason: `escaneo no concluyente: nmap terminó con error: ${fatalError}`,
      scan: { target, portSpec, scanMode, completed: false, filteredCount: 0, filteredReason: null, hostname: null },
    };
  }

  const completed = stdout.includes("<runstats") || stdout.includes("/finished");
  // Código 0 pero XML truncado o vacío: no se puede afirmar "0 puertos".
  if (!completed) {
    return {
      skipped: true,
      inconclusive: true,
      reason: "escaneo no concluyente: nmap no devolvió un informe completo",
      scan: { target, portSpec, scanMode, completed: false, filteredCount: 0, filteredReason: null, hostname: null },
    };
  }
  const filteredMatch = stdout.match(/<extraports\s+state="filtered"\s+count="(\d+)"/);
  let filteredCount;
  if (filteredMatch) {
    filteredCount = parseInt(filteredMatch[1], 10);
  } else {
    filteredCount = 0;
  }
  // El motivo dominante solo afina el mensaje.
  const reasonMatch = stdout.match(/<extrareasons\s+reason="([^"]*)"/);
  let filteredReason;
  if (reasonMatch) {
    filteredReason = reasonMatch[1];
  } else {
    filteredReason = null;
  }

  // Null si el objetivo no tiene DNS inverso.
  const hostname = leerNombrePtr(stdout);

  const parsed = leerXmlNmap(stdout);
  const ports  = parsed.map(aplicarMeta);

  return {
    skipped: false,
    ports,
    inconclusive,
    scan: { target, portSpec, scanMode, completed, filteredCount, filteredReason, hostname },
  };
}

// interfazParaObjetivo se exporta para que el descubrimiento use la misma interfaz que el escaneo.
module.exports = {
  ejecutarNmap, leerXmlNmap, leerNombrePtr, interfazParaObjetivo, errorFatalNmap,
  comandoEscaneo,
};
