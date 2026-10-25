"use strict";

/**
 * test-nse-parse.js — El mini-parser de NSE lee lo que nmap emite de verdad.
 * Los fixtures son capturas reales de nmap 7.99:
 *   scan-nse-ssh.xml  vulners, ssl-cert, ssh2-enum-algos y banner contra 127.0.0.1 (OpenSSH 10.3), con 11 CVE y su CVSS.
 *   scan-nse-tls.xml  los cinco scripts contra un `openssl s_server` con certificado autofirmado (ssl-cert y ssl-enum-ciphers).
 * Uso: node test/manual/test-nse-parse.js
 */

const fs   = require("fs");
const path = require("path");

const {
  decodificarEntidades, leerScripts, buscarScript, tablasPorClave, valorElemento, listaElementos,
} = require("../../nodes/audit-network/modules/nmap-xml");

const {
  leerAyudaScript, leerNombreRechazado, estadoScripts,
} = require("../../nodes/audit-network/modules/nse-scripts");

const {
  ejecutarCanario, deducirDelEscaneo, canarioCorrecto, CANARY_DETAIL,
} = require("../../nodes/audit-network/modules/vulners-canary");

const {
  comandoEscaneo, leerXmlNmap,
} = require("../../nodes/audit-network/modules/nmap-wrapper");

const {
  aplicaA, tieneVersion, severidadAlgoritmoSsh, tipoFuente,
  TLS_GRADE_SEVERITY, SSH_WEAK_ALGOS, NSE_SCRIPT_IDS, OFFERED_NOT_NEGOTIATED,
} = require("../../nodes/audit-network/modules/nse-catalog");

const {
  resumirPuerto,
} = require("../../nodes/audit-network/modules/nse-extract");

const {
  desdeNse, desdeNseVulns, desdeNseTls, desdeNseServicio, desdeNseOmisiones, normalizarRed,
} = require("../../lib/normalizer");

let failed = 0;
let passed = 0;

function ok(cond, label, detail) {
  if (cond) { passed++; console.log(`  ✓ ${label}`); }
  else { failed++; console.log(`  ✗ ${label}`); if (detail) console.log(`      ${detail}`); }
}

function fixture(name) {
  return fs.readFileSync(path.join(__dirname, "..", "fixtures", "nmap", name), "utf8");
}

/** El primer bloque <port>…</port>, que es lo que recibe leerScripts(). */
function portBlock(xml) {
  const m = xml.match(/<port\s[^>]*>[\s\S]*?<\/port>/);
  return m ? m[0] : "";
}

// ── 1. Entidades, incluidas las numéricas ────────────────────────────────────
console.log("\n1. decodificarEntidades");

ok(decodificarEntidades("a&#xa;b") === "a\nb", "&#xa; hexadecimal → salto de línea");
ok(decodificarEntidades("a&#x9;b") === "a\tb", "&#x9; hexadecimal → tabulador");
ok(decodificarEntidades("a&#10;b") === "a\nb", "&#10; decimal → salto de línea");
ok(decodificarEntidades("&lt;a&gt; &quot;b&quot; &apos;c&apos; &amp;") === "<a> \"b\" 'c' &",
   "las cinco predefinidas");

// Una sola pasada: encadenar decodificaría dos veces y el literal "&lt;" acabaría en "<".
ok(decodificarEntidades("&amp;lt;") === "&lt;", "no se decodifica dos veces");
ok(decodificarEntidades("&#x110000;") === "&#x110000;", "código fuera de rango se deja tal cual");
ok(decodificarEntidades(null) === "" && decodificarEntidades(undefined) === "", "null/undefined → \"\"");

// ── 2. El subárbol de vulners, sobre captura real ───────────────────────────
console.log("\n2. vulners (captura real, puerto 22)");

const sshBlock   = portBlock(fixture("scan-nse-ssh.xml"));
const sshScripts = leerScripts(sshBlock);

ok(sshScripts.map((s) => s.id).join(",") === "vulners,ssh2-enum-algos,banner",
   "salen los tres scripts que produjeron algo",
   sshScripts.map((s) => s.id).join(","));

// ssl-cert no está en el XML porque su portrule no casó con SSH: no se lee como "limpio".
ok(buscarScript(sshScripts, "ssl-cert") === null,
   "ssl-cert no aparece: el portrule no casó, no es un hallazgo vacío");

const vulners = buscarScript(sshScripts, "vulners");
const cpeTable = vulners.children.filter((c) => c.type === "table")[0];

ok(cpeTable.key === "cpe:/a:openbsd:openssh:10.3",
   "la tabla de primer nivel va cifrada por CPE", cpeTable.key);
ok(cpeTable.children.length === 11, "11 CVE", String(cpeTable.children.length));

const first = cpeTable.children[0];
ok(valorElemento(first, "id")   === "CVE-2026-60002", "id del primero");
ok(valorElemento(first, "cvss") === "9.4",            "cvss del primero");
ok(valorElemento(first, "type") === "cve",            "type del primero");
ok(valorElemento(first, "is_exploit") === "false",    "is_exploit del primero");

// El 9.4 es el que convierte un puerto en crítico.
const cvsss = cpeTable.children.map((t) => parseFloat(valorElemento(t, "cvss")));
ok(Math.max(...cvsss) === 9.4, "el CVSS máximo del grupo es 9.4", String(Math.max(...cvsss)));
ok(cvsss.every((n) => Number.isFinite(n)), "los 11 traen CVSS numérico");

// El `output` se guarda SIN interpretar, pero decodificado: es evidencia para leer.
ok(vulners.output.includes("\n") && vulners.output.includes("\t"),
   "el output llega con sus saltos y tabuladores decodificados");
ok(vulners.output.includes("CVE-2026-60002"), "el output conserva el texto original");

// ── 3. Script autocerrado ────────────────────────────────────────────────────
console.log("\n3. <script/> sin subárbol");

const banner = buscarScript(sshScripts, "banner");
ok(banner !== null, "un <script … /> autocerrado se reconoce igual");
ok(banner.children.length === 0, "y no arrastra hijos del script siguiente");
ok(banner.output === "SSH-2.0-OpenSSH_10.3", "su output se lee", banner.output);

// ── 4. Listas sin key: ssh2-enum-algos ───────────────────────────────────────
console.log("\n4. ssh2-enum-algos");

const ssh2 = buscarScript(sshScripts, "ssh2-enum-algos");
const grupos = ssh2.children.filter((c) => c.type === "table").map((c) => c.key);
ok(grupos.join(",") === "kex_algorithms,server_host_key_algorithms,encryption_algorithms,mac_algorithms,compression_algorithms",
   "los cinco grupos, en orden", grupos.join(","));

const kex = listaElementos(tablasPorClave(ssh2, "kex_algorithms")[0]);
ok(kex.length === 10, "10 algoritmos de intercambio", String(kex.length));
ok(kex.includes("curve25519-sha256"), "un valor concreto de la lista");
ok(listaElementos(tablasPorClave(ssh2, "mac_algorithms")[0]).length > 0, "la lista de MAC no viene vacía");

// Lista y diccionario se distinguen porque los hijos de estas tablas no llevan key.
ok(tablasPorClave(ssh2, "kex_algorithms")[0].children.every((c) => c.key === null),
   "los elementos de una lista no llevan key");

// ── 5. TLS, sobre captura real ───────────────────────────────────────────────
console.log("\n5. ssl-enum-ciphers y ssl-cert (captura real, s_server local)");

const tlsScripts = leerScripts(portBlock(fixture("scan-nse-tls.xml")));
const enumC = buscarScript(tlsScripts, "ssl-enum-ciphers");

ok(enumC !== null, "ssl-enum-ciphers aparece en un puerto TLS de verdad");
ok(valorElemento(enumC, "least strength") === "A",
   "la nota agregada va en <elem key=\"least strength\"> a nivel de script",
   JSON.stringify(valorElemento(enumC, "least strength")));
ok(enumC.children.filter((c) => c.type === "table").map((c) => c.key).join(",") === "TLSv1.2,TLSv1.3",
   "y por debajo, una tabla por protocolo");

const cert = buscarScript(tlsScripts, "ssl-cert");
ok(cert !== null && valorElemento(cert, "sig_algo") !== "", "ssl-cert trae su algoritmo de firma");
ok(tablasPorClave(cert, "validity").length === 1, "y su tabla de vigencia");

// sslv2 no salió (el servidor no lo soporta): "aplicaba y no hubo respuesta" no es limpio.
ok(buscarScript(tlsScripts, "sslv2") === null, "sslv2 no produjo nada contra un servidor moderno");

// -sV añade sus propios scripts al XML; no se confunden con los nuestros.
ok(buscarScript(tlsScripts, "fingerprint-strings") !== null,
   "fingerprint-strings, que lo emite -sV y no está en nuestra lista, se parsea sin romper");
ok(!NSE_SCRIPT_IDS.includes("fingerprint-strings"),
   "y no está en la lista nominal, así que nadie lo interpretará");

// ── 6. Puerto sin scripts ────────────────────────────────────────────────────
console.log("\n6. bordes");

ok(leerScripts("<port protocol=\"tcp\" portid=\"80\"><state state=\"open\"/></port>").length === 0,
   "un puerto sin <script> devuelve lista vacía");
ok(leerScripts("").length === 0 && leerScripts(null).length === 0, "vacío y null no rompen");

// ── 7. Aplicabilidad ─────────────────────────────────────────────────────────
console.log("\n7. aplicaA");

ok(aplicaA("vulners", { port: 22, service: "ssh", version: "OpenSSH 10.3" }).applies,
   "vulners aplica con versión");
ok(aplicaA("vulners", { port: 22, service: "ssh", cpe: "cpe:/a:openbsd:openssh:10.3" }).applies,
   "vulners aplica solo con CPE");

const sinVer = aplicaA("vulners", { port: 9999, service: "unknown" });
ok(!sinVer.applies, "vulners no aplica sin versión ni CPE");
ok(/versión/.test(sinVer.reason), "y explica por qué", sinVer.reason);

ok(aplicaA("ssl-enum-ciphers", { port: 14443, service: "ssl", tunnel: "ssl" }).applies,
   "TLS por tunnel=\"ssl\"");
ok(aplicaA("ssl-cert", { port: 443, service: "http" }).applies, "TLS por número de puerto");
ok(aplicaA("sslv2", { port: 8888, service: "imaps" }).applies, "TLS por nombre de servicio");
ok(!aplicaA("ssl-cert", { port: 22, service: "ssh" }).applies, "TLS no aplica a SSH");

ok(aplicaA("ssh2-enum-algos", { port: 22, service: "ssh" }).applies, "SSH por servicio y puerto");
ok(aplicaA("ssh2-enum-algos", { port: 2222, service: "ssh" }).applies, "SSH en puerto no estándar");
ok(!aplicaA("ssh2-enum-algos", { port: 443, service: "https" }).applies, "SSH no aplica a HTTPS");

// Un script desconocido no se interpreta a ciegas.
const desconocido = aplicaA("http-title", { port: 80, service: "http" });
ok(!desconocido.applies && /No hay condición/.test(desconocido.reason),
   "un script sin condición declarada lo dice en vez de suponer");

ok(tieneVersion({ version: "OpenSSH 10.3" }) && !tieneVersion({}) && !tieneVersion(null),
   "hasVersion cubre sus tres casos");
ok(tipoFuente("vulners") === "remote-api" && tipoFuente("ssl-cert") === "target",
   "vulners es fuente remota; el resto habla con el objetivo");

// ── 8. Las dos tablas de severidad ───────────────────────────────────────────
console.log("\n8. severidad de algoritmos");

ok(severidadAlgoritmoSsh("ssh-dss") === "medium", "ssh-dss → medium (techo de la tabla SSH)");
ok(severidadAlgoritmoSsh("diffie-hellman-group1-sha1") === "medium", "DH grupo 1 → medium");
ok(severidadAlgoritmoSsh("hmac-md5-96") === "medium", "hmac-md5-96 → medium");
ok(severidadAlgoritmoSsh("3des-cbc") === "low", "3des-cbc → low");
ok(severidadAlgoritmoSsh("hmac-sha1") === "low", "hmac-sha1 → low");
ok(severidadAlgoritmoSsh("aes128-cbc") === "low", "un *-cbc no listado cae a low por el sufijo");
ok(severidadAlgoritmoSsh("AES256-CBC") === "low", "y sin depender de las mayúsculas");
ok(severidadAlgoritmoSsh("curve25519-sha256") === "info", "lo actual es inventario, no hallazgo");
ok(severidadAlgoritmoSsh("") === "info" && severidadAlgoritmoSsh(null) === "info", "vacío no rompe");

// En SSH ningún algoritmo llega a 'high': hace falta un cliente que lo elija.
ok(Object.values(SSH_WEAK_ALGOS).every((s) => s === "medium" || s === "low"),
   "ningún algoritmo SSH llega a high: el riesgo depende del cliente");

ok(TLS_GRADE_SEVERITY.A === "info" && TLS_GRADE_SEVERITY.B === "low" &&
   TLS_GRADE_SEVERITY.C === "medium" && TLS_GRADE_SEVERITY.D === "medium" &&
   TLS_GRADE_SEVERITY.E === "high" && TLS_GRADE_SEVERITY.F === "high",
   "la tabla TLS A-F conserva sus seis valores");

// 'unknown' significa "no se pudo comprobar" y no lleva severidad.
ok(!("unknown" in TLS_GRADE_SEVERITY), "'unknown' no tiene severidad asignada");

// La nota que sale del XML real tiene que existir en la tabla.
ok(TLS_GRADE_SEVERITY[valorElemento(enumC, "least strength")] === "info",
   "la nota A de la captura real se traduce a info");

ok(/OFRECE/.test(OFFERED_NOT_NEGOTIATED) && /cliente antiguo/.test(OFFERED_NOT_NEGOTIATED),
   "la frase de procedencia dice 'ofrece' y nombra al cliente antiguo");

// ── 9. Disponibilidad de scripts ─────────────────────────────────────────────
console.log("\n9. nmap --script-help");

// Salida real de nmap 7.99, recortada. El ancla es la línea "Categories:".
const HELP_OK = [
  "Starting Nmap 7.99 ( https://nmap.org ) at 2026-09-13 12:52 +0200",
  "ssh2-enum-algos",
  "Categories: safe discovery",
  "https://nmap.org/nsedoc/scripts/ssh2-enum-algos.html",
  "Reports the number of algorithms the target SSH2 server offers.",
  "ssl-cert",
  "Categories: default safe discovery",
  "https://nmap.org/nsedoc/scripts/ssl-cert.html",
  "Retrieves a server's SSL certificate.",
].join("\n");

const encontrados = leerAyudaScript(HELP_OK);
ok(encontrados.has("ssh2-enum-algos") && encontrados.has("ssl-cert"),
   "reconoce los scripts listados");
ok(encontrados.size === 2, "y solo esos", [...encontrados].join(","));

// La descripción de un script cita a otro: buscar nombres sueltos lo daría por instalado.
const HELP_CITA = [
  "ssl-cert",
  "Categories: default safe discovery",
  "Complementa a ssl-enum-ciphers y a vulners, que no están instalados.",
].join("\n");
ok(!leerAyudaScript(HELP_CITA).has("vulners"),
   "un nombre citado en una descripción NO cuenta como instalado");
ok(!leerAyudaScript(HELP_CITA).has("ssl-enum-ciphers"), "ni aunque aparezca dos veces");

// stderr real de nmap 7.99 con un nombre que no existe.
const HELP_KO = [
  "NSE: failed to initialize the script engine:",
  "/opt/homebrew/bin/../share/nmap/nse_main.lua:829: 'noexiste' did not match a category, filename, or directory",
  "stack traceback:",
  "QUITTING!",
].join("\n");
ok(leerNombreRechazado(HELP_KO) === "noexiste", "se extrae el nombre que nmap rechaza");
ok(leerNombreRechazado("todo bien") === null, "y no se inventa uno cuando no lo hay");

// ── 10. Estado por script y puerto ───────────────────────────────────────────
console.log("\n10. estadoScripts");

const TODOS = { checked: true, available: new Set(NSE_SCRIPT_IDS), missing: [] };

// El puerto 22 real: vulners y ssh2-enum-algos dieron dato; los tres de TLS no le tocaban.
const p22 = {
  port: 22, service: "ssh", version: "OpenSSH 10.3",
  cpe: "cpe:/a:openbsd:openssh:10.3", nse: sshScripts,
};
const e22 = estadoScripts(p22, TODOS);

ok(e22.vulners.state === "found", "vulners: found");
ok(e22["ssh2-enum-algos"].state === "found", "ssh2-enum-algos: found");
ok(e22["ssl-cert"].state === "not-applicable", "ssl-cert en un puerto SSH: not-applicable");
ok(/no parece servir TLS/.test(e22["ssl-cert"].reason), "y con el motivo escrito",
   e22["ssl-cert"].reason);
ok(e22["ssl-cert"].kind === "not-applicable", "con su kind, para no comparar textos");

// El caso que separa un hueco de un límite: aplicaba y no salió.
const p14443 = { port: 14443, service: "unknown", tunnel: "ssl", nse: tlsScripts };
const e14443 = estadoScripts(p14443, TODOS);
ok(e14443["ssl-enum-ciphers"].state === "found", "ssl-enum-ciphers en el puerto TLS: found");
ok(e14443.sslv2.state === "not-run" && e14443.sslv2.kind === "no-output",
   "sslv2 aplicaba y no salió: not-run, no 'limpio'");
ok(/no completó el diálogo/.test(e14443.sslv2.reason),
   "y el motivo apunta al objetivo, que es con quien hablaba", e14443.sslv2.reason);

// Un puerto sin versión: vulners no tiene con qué preguntar. Eso es alcance, no hueco.
const pSinVer = { port: 9999, service: "unknown", nse: [] };
ok(estadoScripts(pSinVer, TODOS).vulners.state === "not-applicable",
   "sin versión, vulners es not-applicable");

// Script ausente del sistema: hueco, con su nombre.
const SIN_VULNERS = {
  checked: true,
  available: new Set(NSE_SCRIPT_IDS.filter((i) => i !== "vulners")),
  missing: ["vulners"],
};
const eSin = estadoScripts({ port: 22, service: "ssh", version: "OpenSSH 10.3", nse: [] }, SIN_VULNERS);
ok(eSin.vulners.state === "not-run" && eSin.vulners.kind === "script-missing",
   "un script no instalado es un hueco, no un 'no aplica'");

// No se pudo averiguar qué hay instalado: TODO queda en no comprobado. Nada cae a limpio.
const NO_SE_SABE = { checked: false, available: new Set(), missing: [], reason: "nmap no respondió" };
const eNada = estadoScripts({ port: 22, service: "ssh", version: "OpenSSH 10.3", nse: [] }, NO_SE_SABE);
ok(NSE_SCRIPT_IDS.every((id) => eNada[id].state === "not-run" && eNada[id].kind === "nse-unavailable"),
   "sin saber qué hay instalado, los cinco quedan en not-run");
ok(eNada.vulners.reason === "nmap no respondió", "arrastrando el motivo real");

// Lo que NO puede existir: un estado que diga 'limpio'. Afirmar limpio es cosa del canario.
ok(Object.values(e22).concat(Object.values(e14443))
     .every((e) => ["found", "not-applicable", "not-run"].includes(e.state)),
   "solo hay tres estados, y ninguno es 'clean'");

// ── 11. Canario de vulners ───────────────────────────────────────────────────
// Sin sonda de red a Vulners (exigiría suplantar al plugin de nmap): solo se infiere del escaneo.
console.log("\n11. canario");

const PORTS_CON_CVE = [{ port: 22, version: "OpenSSH 10.3", nse: sshScripts }];
const PORTS_CON_VER = [{ port: 22, version: "OpenSSH 10.3", nse: [] }];
const PORTS_SIN_VER = [{ port: 80, service: "http", nse: [] }];

(async () => {
  ok(deducirDelEscaneo(PORTS_CON_CVE), "un <script id=\"vulners\"> prueba que la fuente respondió");
  ok(!deducirDelEscaneo(PORTS_CON_VER), "y sin él no se infiere nada");

  const r1 = ejecutarCanario(PORTS_CON_CVE, { hasVersion: tieneVersion });
  ok(r1.state === "ok-inferred" && r1.probed === false,
     "un solo puerto con CVE certifica la fuente para todo el escaneo, sin pedir nada a nadie");

  const rNo = ejecutarCanario(PORTS_SIN_VER, { hasVersion: tieneVersion });
  ok(rNo.state === "not-needed", "sin ningún puerto con versión no hay nada que comprobar", rNo.state);

  const rAmb = ejecutarCanario(PORTS_CON_VER, { hasVersion: tieneVersion });
  ok(rAmb.state === "unconfirmed",
     "con versión y sin datos de vulners, el caso ambiguo se nombra: no se sabe", rAmb.state);
  ok(!canarioCorrecto(rAmb.state), "y 'unconfirmed' NO es un visto bueno");
  ok(rAmb.probed === false, "nunca se sale a la red: `probed` vale false en todos los caminos");

  const rApagado = ejecutarCanario(PORTS_CON_VER, { hasVersion: tieneVersion, nseEnabled: false });
  ok(rApagado.state === "not-run", "con NSE apagado el canario ni se plantea la pregunta");

  // Sin sonda, un equipo al día sale "sin comprobar" y el informe explica por qué.
  ok(/equipo\s+al día/.test(CANARY_DETAIL.unconfirmed) &&
     /resultado ESPERADO/.test(CANARY_DETAIL.unconfirmed),
     "el texto de 'unconfirmed' explica que un equipo actualizado cae justo ahí");
  ok(/no lanza consultas propias/.test(CANARY_DETAIL.unconfirmed),
     "y que LoCoAudit no consulta vulners.com por su cuenta");

  // La regla que sostiene todo lo demás: un solo estado autoriza a decir limpio.
  const todos = Object.keys(CANARY_DETAIL);
  ok(todos.filter(canarioCorrecto).join(",") === "ok-inferred",
     "solo UNO de los estados es visto bueno", todos.filter(canarioCorrecto).join(","));
  ok(todos.length === 4, "y solo hay cuatro estados: los de la sonda se fueron con ella", String(todos.length));
  ok(todos.every((e) => CANARY_DETAIL[e] && CANARY_DETAIL[e].length > 40),
     "los " + todos.length + " tienen texto propio para el informe");

  // Que no vuelva por la puerta de atrás: ningún módulo de red puede hablar con vulners.com.
  const mod = require("fs").readFileSync(
    require("path").join(__dirname, "../../nodes/audit-network/modules/vulners-canary.js"), "utf8");
  const codigo = mod.replace(/\/\*[\s\S]*?\*\//g, "").replace(/^\s*\/\/.*$/gm, "");
  ok(!/fetch\s*\(|https?:\/\//.test(codigo),
     "el canario no tiene ni una petición ni una URL fuera de los comentarios");
  ok(!/User-Agent/i.test(codigo),
     "ni una cabecera User-Agent: suplantar al plugin de nmap para pasar su filtro no es una opción");

  // ── 12. El comando ─────────────────────────────────────────────────────────
  console.log("\n12. comandoEscaneo");

  // Línea exacta escrita a mano: derivarla de la función bajo prueba aprobaría cualquier cambio.
  const ANTES_SIN_IFACE = "nmap -sV -T4 -Pn --max-retries 2  -p 1-3000 -oX - 127.0.0.1";
  const ANTES_CON_IFACE = "nmap -sV -T4 -Pn --max-retries 2 -e en0 -p 1-1024 -oX - 192.168.0.30";

  ok(comandoEscaneo({ target: "127.0.0.1", portSpec: "1-3000" }) === ANTES_SIN_IFACE,
     "sin NSE, el comando es byte a byte el de siempre (incluido el doble espacio)",
     comandoEscaneo({ target: "127.0.0.1", portSpec: "1-3000" }));
  ok(comandoEscaneo({ target: "192.168.0.30", portSpec: "1-1024", ifaceFlag: "-e en0" }) === ANTES_CON_IFACE,
     "y también con -e");
  ok(comandoEscaneo({ target: "127.0.0.1", portSpec: "22", nseScripts: [] }) === "nmap -sV -T4 -Pn --max-retries 2  -p 22 -oX - 127.0.0.1",
     "una lista vacía no añade --script");

  const conNse = comandoEscaneo({ target: "127.0.0.1", portSpec: "22", nseScripts: NSE_SCRIPT_IDS });
  ok(conNse.includes(`--script ${NSE_SCRIPT_IDS.join(",")}`), "con lista, --script va con los nombres separados por coma", conNse);
  ok(!/--script[= ](vuln|safe|default|intrusive|all)\b/.test(conNse),
     "y NUNCA una categoría: una categoría arrastra scripts que nadie ha revisado");
  ok(!/\s-O\b/.test(conNse), "sin -O: necesitaría root");
  ok(!/\s-f\b/.test(conNse), "sin -f: fragmentar es evadir, no auditar");
  ok(!/--script-timeout/.test(conNse),
     "sin --script-timeout: un script matado por timeout se vuelve indistinguible de uno sin hallazgos");

  // El parser del wrapper trae lo que aplicaA necesita (sobre captura real).
  const puertosTls = leerXmlNmap(fixture("scan-nse-tls.xml"));
  ok(puertosTls[0].tunnel === "ssl",
     "el wrapper extrae tunnel=\"ssl\" pese al servicefp lleno de barras", JSON.stringify(puertosTls[0].tunnel));
  ok(aplicaA("ssl-enum-ciphers", puertosTls[0]).applies,
     "y con eso un puerto TLS fuera de toda lista se reconoce igual");

  const puertosSsh = leerXmlNmap(fixture("scan-nse-ssh.xml"));
  ok(puertosSsh[0].cpe === "cpe:/a:openbsd:openssh:10.3", "y el <cpe> del servicio", puertosSsh[0].cpe);
  ok(puertosSsh[0].nse.length === 3, "y el subárbol NSE del puerto");
  ok(leerXmlNmap(fixture("scan-ports-open.xml"))[0].nse.length === 0,
     "un escaneo sin --script deja el subárbol vacío, no ausente");

  // ── 13. Los findings ───────────────────────────────────────────────────────
  console.log("\n13. lib/normalizer: de resumen NSE a findings");

  // Cadena completa sobre el XML real: parser, extractor y normalizador.
  const conResumen = (xml, canaryOk) => {
    const puertos = leerXmlNmap(fixture(xml));
    for (const p of puertos) p.nseSummary = resumirPuerto(p, { canaryOk });
    return puertos;
  };

  const OPTS = { target: "127.0.0.1", targetIsLocal: true, nse: { enabled: true } };

  // --- NET-VULN: el crítico llega entero, con los 11 CVE y con la procedencia ---
  const pSsh  = conResumen("scan-nse-ssh.xml", true);
  const vulns = desdeNseVulns(pSsh, OPTS);

  ok(vulns.length === 1, "11 CVE del mismo servicio son UN finding, no once", String(vulns.length));
  ok(vulns[0].severity === "critical",
     "y su severidad es la del peor CVE (9.4), no la media de los once", vulns[0].severity);
  ok(vulns[0].id === "NET-VULN-001" && vulns[0].category === "network" && vulns[0].source === "nmap",
     "con id, categoría y fuente del esquema canónico");
  // Los CVE van en la tabla; la evidencia dice cuántos son, el peor CVSS y que no hay descripción.
  ok(/vulners\.com devuelve 11 CVE para la versión anunciada/.test(vulns[0].evidence),
     "la evidencia dice cuántos CVE son y quién los devuelve");
  ok(/el más grave puntúa 9\.4/.test(vulns[0].evidence),
     "y cuánto puntúa el peor");
  ok(/vulners no aporta una descripción por CVE/.test(vulns[0].evidence),
     "y que vulners no describe cada CVE: de cada uno solo hay id, nota y si tiene exploit");
  ok(vulns[0].vulnerabilities.length === 11 &&
     vulns[0].vulnerabilities.every((v) => /^CVE-\d{4}-\d+$/.test(v.id)),
     "y los ONCE viajan enteros en la lista: recortar a los peores fue el bug que ya hubo que deshacer en Trivy",
     String(vulns[0].vulnerabilities.length));

  // Criterio de aceptación 1: el crítico NUNCA viaja sin las cuatro advertencias.
  for (const [frase, re] of [
    ["la versión la anuncia el servicio",  /anuncia el propio servicio/],
    ["no se verificó contra el objetivo",  /NO se ha verificado contra el objetivo/],
    ["backports sin cambiar de versión",   /sin cambiar el n[úu]mero de versi[óo]n/],
    ["la nota es de vulners, no del NVD",  /puede diferir de la del NVD/],
    ["un CVE de cliente en su servidor",   /solo afecta al cliente puede aparecer atribuido a su servidor/],
  ]) ok(re.test(vulns[0].evidence), `la evidencia dice que ${frase}`);

  ok(vulns[0].fix && !vulns[0].isCommand && !vulns[0].command,
     "sin comando copiable: el gestor de paquetes del equipo auditado puede no ser el de este");
  ok(vulns[0].target === "127.0.0.1" && vulns[0].isLocalTarget === true,
     "y arrastra target para que el chat no tenga que reinferirlo");
  ok(vulns[0].port === 22 && vulns[0].protocol === "tcp" && vulns[0].service === "ssh",
     "el finding conserva el puerto y el servicio como datos estructurados");
  ok(vulns[0].vulnerabilities.length === 11 && vulns[0].vulnerabilities[0].cvss === 9.4,
     "los CVE y sus puntuaciones viajan en una lista estructurada");
  ok(vulns[0].vulnerabilities[0].url === "https://nvd.nist.gov/vuln/detail/CVE-2026-60002" &&
     vulns[0].vulnerabilities[0].label === "NVD",
     "los CVE usan el advisory canónico del NVD");
  ok(vulns[0].provenance && /versión la anuncia el propio servicio/.test(vulns[0].provenance),
     "la procedencia viaja separada de la evidencia legible");

  // --- NET-SVC: el techo de SSH ---
  const svc = desdeNseServicio(pSsh, OPTS);
  ok(svc.length === 1 && svc[0].id === "NET-SVC-001", "un finding de algoritmos por puerto SSH");
  ok(svc[0].severity === "low", "hmac-sha1 es débil, no roto: low", svc[0].severity);
  ok(/hmac-sha1 \[integridad \(MAC\)\]/.test(svc[0].evidence),
     "el algoritmo se nombra con el grupo al que pertenece");
  ok(svc[0].evidence.includes(OFFERED_NOT_NEGOTIATED),
     "y la frase de 'ofrece, no negocia' va LITERAL, sin reescribir");
  ok(/sshd_config/.test(svc[0].fix), "el fix nombra dónde se toca");

  // --- NET-TLS: la nota A y el certificado ---
  const pTls = conResumen("scan-nse-tls.xml", true);
  const tls  = desdeNseTls(pTls, OPTS);
  ok(tls.length === 1 && tls[0].severity === "info", "nota A es informativa, no un problema", tls[0] && tls[0].severity);
  ok(/TLSv1\.2/.test(tls[0].evidence) && /TLSv1\.3/.test(tls[0].evidence), "los protocolos aceptados constan");
  ok(/sha256WithRSAEncryption/.test(tls[0].evidence), "y la firma del certificado");

  // Techos asimétricos: la tabla TLS llega a high, la de SSH se queda en medium. A propósito.
  ok(Object.values(TLS_GRADE_SEVERITY).includes("high") &&
     !Object.values(SSH_WEAK_ALGOS).includes("high"),
     "TLS puede llegar a high y SSH no: en TLS el riesgo no depende de que el cliente colabore");

  // --- Las omisiones: lo que NO se comprobó también es un finding ---
  const apagado = desdeNseOmisiones(pSsh, { nse: { enabled: false } });
  ok(apagado.length === 1 && apagado[0].skipped === true && apagado[0].kind === "nse-disabled",
     "con NSE apagado sale UN aviso, marcado como omisión");
  ok(/no que no las haya/.test(apagado[0].evidence),
     "y dice explícitamente que la ausencia de CVE significa que no se buscaron");

  const sinCanario = desdeNseOmisiones(conResumen("scan-nse-ssh.xml", false).map((p) => {
    p.nseSummary.vulns = [];                      // sin CVE y sin fuente: el falso verde clásico
    p.nseSummary.vulnState = "source-unavailable";
    return p;
  }), { nse: { enabled: true, canary: { detail: "vulners.com no respondió." } } });
  const hueco = sinCanario.find((f) => f.kind === "source-unavailable");
  ok(hueco && hueco.skipped === true, "un puerto con versión y sin fuente produce su propio aviso");
  ok(hueco && !hueco.notApplicable,
     "y NO se marca como 'no aplica': es un hueco de esta ejecución, y merece ámbar");
  ok(hueco && /22\/tcp/.test(hueco.evidence) && /no respondió/.test(hueco.evidence),
     "con el puerto afectado y el motivo real, no un texto genérico");

  const faltan = desdeNseOmisiones([], {
    nse: { enabled: true, availability: { checked: true, missing: ["vulners"] } },
  });
  ok(faltan.length === 1 && faltan[0].kind === "script-missing" && /vulners/.test(faltan[0].title),
     "un script no instalado se nombra en vez de desaparecer del informe");

  const sinLista = desdeNseOmisiones([], {
    nse: { enabled: true, availability: { checked: false, reason: "nmap salió con código 2" } },
  });
  ok(sinLista.length === 1 && sinLista[0].kind === "nse-unavailable" && /código 2/.test(sinLista[0].evidence),
     "y no poder comprobar qué hay instalado guarda el motivo real como evidencia");

  // --- El enganche en normalizarRed ---
  const puertosRaw = leerXmlNmap(fixture("scan-nse-ssh.xml"));
  const sinNse = normalizarRed(puertosRaw, "nmap", { target: "127.0.0.1", targetIsLocal: true });
  ok(sinNse.every((f) => f.id.startsWith("NET-PORT")),
     "sin opts.nse, normalizarRed devuelve exactamente lo de siempre");

  const conNseF = normalizarRed(conResumen("scan-nse-ssh.xml", true), "nmap", OPTS);
  const ids = conNseF.map((f) => f.id.replace(/-\d+$/, ""));
  ok(ids[0] === "NET-PORT", "los puertos siguen yendo primero: es lo primero que se busca", ids.join(" "));
  ok(ids.includes("NET-VULN") && ids.includes("NET-SVC"), "y detrás va lo de NSE", ids.join(" "));
  ok(conNseF.every((f) => f.scope === "network"), "todo sale sellado con su ámbito");

  // El NET-PORT no hereda la severidad de los CVE del servicio.
  const port22    = conNseF.find((f) => f.id.startsWith("NET-PORT"));
  const port22Sin = sinNse.find((f) => f.id.startsWith("NET-PORT"));
  ok(port22.severity === port22Sin.severity,
     "el NET-PORT conserva su severidad de catálogo: los CVE del servicio NO lo suben a crítico",
     `${port22Sin.severity} -> ${port22.severity}`);
  ok(port22.evidence === port22Sin.evidence,
     "y su evidencia tampoco cambia: NSE añade hallazgos, no reescribe los que ya había");

  // --- 'no aplica' contra 'no se pudo' ---
  const { SKIP_KINDS_NO_APLICA } = require("../../lib/normalizer");
  ok(SKIP_KINDS_NO_APLICA.has("no-version") && SKIP_KINDS_NO_APLICA.has("not-applicable"),
     "sin versión y no aplicable son alcance del método: no se arreglan reintentando");
  ok(!SKIP_KINDS_NO_APLICA.has("source-unavailable") && !SKIP_KINDS_NO_APLICA.has("script-missing"),
     "fuente caída y script ausente NO: ahí falta un dato que debería estar");

  // ── 14. El cableado del nodo y su casilla ──────────────────────────────────
  /**
   * Comprobaciones sobre el fuente del nodo y su diálogo: el defecto apagado, el presupuesto
   * de tiempo sumado y la consulta a Vulners escrita dentro de la casilla.
   */
  console.log("\n14. nodo y diálogo");

  const fuenteNodo = require("fs").readFileSync(
    require("path").join(__dirname, "../../nodes/audit-network/audit-network.js"), "utf8");
  const fuenteHtml = require("fs").readFileSync(
    require("path").join(__dirname, "../../nodes/audit-network/audit-network.html"), "utf8");

  ok(/nseEnabled:\s*\{\s*value:\s*false\s*\}/.test(fuenteHtml),
     "la casilla viene APAGADA de fábrica: activarla consulta una base de datos externa");
  ok(/config\.nseEnabled === true \|\| config\.nseEnabled === "true"/.test(fuenteNodo),
     "y el nodo la lee con el mismo patrón estricto que forceScan, sin colar un string vacío");

  // El presupuesto se suma a tiempoMaximoEscaneo(), no lo sustituye.
  ok(/tiempoMaximoEscaneo\(scanMode,[^)]*\)\s*\+\s*extraNse/.test(fuenteNodo) && /extraNse = nseTimeout;[\s\S]{0,80}extraNse = 0;/.test(fuenteNodo),
     "el tiempo de los scripts se SUMA al del modo, no lo sustituye");

  // El orden que evita que dos puertos de la misma ejecución reciban veredictos distintos.
  ok(fuenteNodo.indexOf("ejecutarCanario(") < fuenteNodo.indexOf("resumirPuerto("),
     "el canario se resuelve antes que el resumen de cada puerto: es propiedad del escaneo entero");

  // Un nmap recortado no puede costar el escaneo: se pregunta antes qué scripts existen.
  ok(fuenteNodo.indexOf("existeScript(") < fuenteNodo.indexOf("ejecutarNmap("),
     "se comprueba qué scripts hay instalados ANTES de lanzar el escaneo");
  ok(/nseScripts = \[\.\.\.nseAvailability\.available\]/.test(fuenteNodo),
     "y solo se le pide a nmap lo que ese nmap tiene: un nombre inexistente aborta el escaneo entero");

  // La consulta tiene que estar dentro del <label> de la casilla, no en un párrafo aparte.
  const etiqueta = fuenteHtml.match(
    /<label for="node-input-nseEnabled"[\s\S]*?<\/label>/);
  ok(etiqueta && /Vulners/i.test(etiqueta[0]) && /base de datos/.test(etiqueta[0]),
     "el texto de la casilla dice, él mismo, que consulta la base de datos de Vulners");

  ok(/scanMeta[\s\S]*?nse:\s*\{[\s\S]*?canary:/.test(fuenteNodo),
     "y el estado del análisis viaja en scanMeta.nse para quien lee el JSON");

  // ── Resumen ────────────────────────────────────────────────────────────────
  console.log(`\n${failed === 0 ? "OK" : "FALLOS"}: ${passed} pasadas, ${failed} fallidas\n`);
  process.exit(failed === 0 ? 0 : 1);
})();
