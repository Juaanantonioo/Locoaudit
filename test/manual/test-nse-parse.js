"use strict";

/**
 * test-nse-parse.js — El mini-parser de NSE lee lo que nmap emite de verdad.
 *
 * Los dos fixtures son CAPTURAS REALES de nmap 7.99, no XML escrito a mano:
 *
 *   scan-nse-ssh.xml  nmap -sV -Pn -T4 -p 22 --script vulners,ssl-cert,ssh2-enum-algos,banner
 *                     contra 127.0.0.1 (OpenSSH 10.3). Trae el caso que importa: 11 CVE con su
 *                     CVSS dentro del subárbol de vulners.
 *   scan-nse-tls.xml  los cinco scripts contra un `openssl s_server` levantado en 14443 para
 *                     esto, con certificado autofirmado de un día. Trae ssl-cert y
 *                     ssl-enum-ciphers con su nota.
 *
 * Se capturan y no se inventan porque todo el diseño depende de la FORMA del XML —dónde está
 * la nota, si la lista lleva key, qué pasa con un script autocerrado—, y un fixture escrito de
 * memoria confirma lo que uno creía, no lo que nmap hace.
 *
 * Uso:
 *   node test/manual/test-nse-parse.js
 */

const fs   = require("fs");
const path = require("path");

const {
  decodeXmlEntities, parseScripts, findScript, tablesByKey, elemValue, elemList,
} = require("../../nodes/audit-network/modules/nmap-xml");

const {
  parseScriptHelp, parseRejectedName, scriptStates,
} = require("../../nodes/audit-network/modules/nse-scripts");

const {
  runCanary, inferFromScan, canaryIsOk, CANARY_DETAIL,
} = require("../../nodes/audit-network/modules/vulners-canary");

const {
  buildScanCommand, parseNmapXml,
} = require("../../nodes/audit-network/modules/nmap-wrapper");

const {
  appliesTo, hasVersion, sshAlgoSeverity, sourceKind,
  TLS_GRADE_SEVERITY, SSH_WEAK_ALGOS, NSE_SCRIPT_IDS, OFFERED_NOT_NEGOTIATED,
} = require("../../nodes/audit-network/modules/nse-catalog");

const {
  summarizePort,
} = require("../../nodes/audit-network/modules/nse-extract");

const {
  fromNse, fromNseVulns, fromNseTls, fromNseSvc, fromNseOmissions, normalizeNetwork,
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

/** El primer bloque <port>…</port>, que es lo que recibe parseScripts(). */
function portBlock(xml) {
  const m = xml.match(/<port\s[^>]*>[\s\S]*?<\/port>/);
  return m ? m[0] : "";
}

// ── 1. Entidades, incluidas las numéricas ────────────────────────────────────
console.log("\n1. decodeXmlEntities");

ok(decodeXmlEntities("a&#xa;b") === "a\nb", "&#xa; hexadecimal → salto de línea");
ok(decodeXmlEntities("a&#x9;b") === "a\tb", "&#x9; hexadecimal → tabulador");
ok(decodeXmlEntities("a&#10;b") === "a\nb", "&#10; decimal → salto de línea");
ok(decodeXmlEntities("&lt;a&gt; &quot;b&quot; &apos;c&apos; &amp;") === "<a> \"b\" 'c' &",
   "las cinco predefinidas");

// Una sola pasada, no cinco encadenadas: encadenar volvería a decodificar lo ya decodificado y
// este texto —que es el literal "&lt;"— acabaría siendo "<".
ok(decodeXmlEntities("&amp;lt;") === "&lt;", "no se decodifica dos veces");
ok(decodeXmlEntities("&#x110000;") === "&#x110000;", "código fuera de rango se deja tal cual");
ok(decodeXmlEntities(null) === "" && decodeXmlEntities(undefined) === "", "null/undefined → \"\"");

// ── 2. El subárbol de vulners, sobre captura real ───────────────────────────
console.log("\n2. vulners (captura real, puerto 22)");

const sshBlock   = portBlock(fixture("scan-nse-ssh.xml"));
const sshScripts = parseScripts(sshBlock);

ok(sshScripts.map((s) => s.id).join(",") === "vulners,ssh2-enum-algos,banner",
   "salen los tres scripts que produjeron algo",
   sshScripts.map((s) => s.id).join(","));

// ssl-cert iba en el comando y NO está en el XML: su portrule no casó con un puerto SSH. Ese
// hueco es justo lo que appliesTo() tiene que explicar, y por eso no se lee como "limpio".
ok(findScript(sshScripts, "ssl-cert") === null,
   "ssl-cert no aparece: el portrule no casó, no es un hallazgo vacío");

const vulners = findScript(sshScripts, "vulners");
const cpeTable = vulners.children.filter((c) => c.type === "table")[0];

ok(cpeTable.key === "cpe:/a:openbsd:openssh:10.3",
   "la tabla de primer nivel va cifrada por CPE", cpeTable.key);
ok(cpeTable.children.length === 11, "11 CVE", String(cpeTable.children.length));

const first = cpeTable.children[0];
ok(elemValue(first, "id")   === "CVE-2026-60002", "id del primero");
ok(elemValue(first, "cvss") === "9.4",            "cvss del primero");
ok(elemValue(first, "type") === "cve",            "type del primero");
ok(elemValue(first, "is_exploit") === "false",    "is_exploit del primero");

// El 9.4 es el que convierte un puerto en crítico. Si esto deja de salir, el criterio de
// aceptación 1 deja de tener sujeto.
const cvsss = cpeTable.children.map((t) => parseFloat(elemValue(t, "cvss")));
ok(Math.max(...cvsss) === 9.4, "el CVSS máximo del grupo es 9.4", String(Math.max(...cvsss)));
ok(cvsss.every((n) => Number.isFinite(n)), "los 11 traen CVSS numérico");

// El `output` se guarda SIN interpretar, pero decodificado: es evidencia para leer.
ok(vulners.output.includes("\n") && vulners.output.includes("\t"),
   "el output llega con sus saltos y tabuladores decodificados");
ok(vulners.output.includes("CVE-2026-60002"), "el output conserva el texto original");

// ── 3. Script autocerrado ────────────────────────────────────────────────────
console.log("\n3. <script/> sin subárbol");

const banner = findScript(sshScripts, "banner");
ok(banner !== null, "un <script … /> autocerrado se reconoce igual");
ok(banner.children.length === 0, "y no arrastra hijos del script siguiente");
ok(banner.output === "SSH-2.0-OpenSSH_10.3", "su output se lee", banner.output);

// ── 4. Listas sin key: ssh2-enum-algos ───────────────────────────────────────
console.log("\n4. ssh2-enum-algos");

const ssh2 = findScript(sshScripts, "ssh2-enum-algos");
const grupos = ssh2.children.filter((c) => c.type === "table").map((c) => c.key);
ok(grupos.join(",") === "kex_algorithms,server_host_key_algorithms,encryption_algorithms,mac_algorithms,compression_algorithms",
   "los cinco grupos, en orden", grupos.join(","));

const kex = elemList(tablesByKey(ssh2, "kex_algorithms")[0]);
ok(kex.length === 10, "10 algoritmos de intercambio", String(kex.length));
ok(kex.includes("curve25519-sha256"), "un valor concreto de la lista");
ok(elemList(tablesByKey(ssh2, "mac_algorithms")[0]).length > 0, "la lista de MAC no viene vacía");

// La distinción entre lista y diccionario es la forma del dato: los hijos de estas tablas NO
// llevan key, y perder eso sería perder la diferencia.
ok(tablesByKey(ssh2, "kex_algorithms")[0].children.every((c) => c.key === null),
   "los elementos de una lista no llevan key");

// ── 5. TLS, sobre captura real ───────────────────────────────────────────────
console.log("\n5. ssl-enum-ciphers y ssl-cert (captura real, s_server local)");

const tlsScripts = parseScripts(portBlock(fixture("scan-nse-tls.xml")));
const enumC = findScript(tlsScripts, "ssl-enum-ciphers");

ok(enumC !== null, "ssl-enum-ciphers aparece en un puerto TLS de verdad");
ok(elemValue(enumC, "least strength") === "A",
   "la nota agregada va en <elem key=\"least strength\"> a nivel de script",
   JSON.stringify(elemValue(enumC, "least strength")));
ok(enumC.children.filter((c) => c.type === "table").map((c) => c.key).join(",") === "TLSv1.2,TLSv1.3",
   "y por debajo, una tabla por protocolo");

const cert = findScript(tlsScripts, "ssl-cert");
ok(cert !== null && elemValue(cert, "sig_algo") !== "", "ssl-cert trae su algoritmo de firma");
ok(tablesByKey(cert, "validity").length === 1, "y su tabla de vigencia");

// sslv2 iba en el comando y no salió: el servidor no lo soporta. Es el caso "aplicaba y no hubo
// respuesta" de una fuente 'target', que NO se puede leer como limpio.
ok(findScript(tlsScripts, "sslv2") === null, "sslv2 no produjo nada contra un servidor moderno");

// -sV mete sus propios scripts en el XML sin que nadie se lo pida. El parser no puede
// atragantarse con ellos ni confundirlos con los nuestros.
ok(findScript(tlsScripts, "fingerprint-strings") !== null,
   "fingerprint-strings, que lo emite -sV y no está en nuestra lista, se parsea sin romper");
ok(!NSE_SCRIPT_IDS.includes("fingerprint-strings"),
   "y no está en la lista nominal, así que nadie lo interpretará");

// ── 6. Puerto sin scripts ────────────────────────────────────────────────────
console.log("\n6. bordes");

ok(parseScripts("<port protocol=\"tcp\" portid=\"80\"><state state=\"open\"/></port>").length === 0,
   "un puerto sin <script> devuelve lista vacía");
ok(parseScripts("").length === 0 && parseScripts(null).length === 0, "vacío y null no rompen");

// ── 7. Aplicabilidad ─────────────────────────────────────────────────────────
console.log("\n7. appliesTo");

ok(appliesTo("vulners", { port: 22, service: "ssh", version: "OpenSSH 10.3" }).applies,
   "vulners aplica con versión");
ok(appliesTo("vulners", { port: 22, service: "ssh", cpe: "cpe:/a:openbsd:openssh:10.3" }).applies,
   "vulners aplica solo con CPE");

const sinVer = appliesTo("vulners", { port: 9999, service: "unknown" });
ok(!sinVer.applies, "vulners no aplica sin versión ni CPE");
ok(/versión/.test(sinVer.reason), "y explica por qué", sinVer.reason);

ok(appliesTo("ssl-enum-ciphers", { port: 14443, service: "ssl", tunnel: "ssl" }).applies,
   "TLS por tunnel=\"ssl\"");
ok(appliesTo("ssl-cert", { port: 443, service: "http" }).applies, "TLS por número de puerto");
ok(appliesTo("sslv2", { port: 8888, service: "imaps" }).applies, "TLS por nombre de servicio");
ok(!appliesTo("ssl-cert", { port: 22, service: "ssh" }).applies, "TLS no aplica a SSH");

ok(appliesTo("ssh2-enum-algos", { port: 22, service: "ssh" }).applies, "SSH por servicio y puerto");
ok(appliesTo("ssh2-enum-algos", { port: 2222, service: "ssh" }).applies, "SSH en puerto no estándar");
ok(!appliesTo("ssh2-enum-algos", { port: 443, service: "https" }).applies, "SSH no aplica a HTTPS");

// Un script desconocido no se interpreta a ciegas.
const desconocido = appliesTo("http-title", { port: 80, service: "http" });
ok(!desconocido.applies && /No hay condición/.test(desconocido.reason),
   "un script sin condición declarada lo dice en vez de suponer");

ok(hasVersion({ version: "OpenSSH 10.3" }) && !hasVersion({}) && !hasVersion(null),
   "hasVersion cubre sus tres casos");
ok(sourceKind("vulners") === "remote-api" && sourceKind("ssl-cert") === "target",
   "vulners es fuente remota; el resto habla con el objetivo");

// ── 8. Las dos tablas de severidad ───────────────────────────────────────────
console.log("\n8. severidad de algoritmos");

ok(sshAlgoSeverity("ssh-dss") === "medium", "ssh-dss → medium (techo de la tabla SSH)");
ok(sshAlgoSeverity("diffie-hellman-group1-sha1") === "medium", "DH grupo 1 → medium");
ok(sshAlgoSeverity("hmac-md5-96") === "medium", "hmac-md5-96 → medium");
ok(sshAlgoSeverity("3des-cbc") === "low", "3des-cbc → low");
ok(sshAlgoSeverity("hmac-sha1") === "low", "hmac-sha1 → low");
ok(sshAlgoSeverity("aes128-cbc") === "low", "un *-cbc no listado cae a low por el sufijo");
ok(sshAlgoSeverity("AES256-CBC") === "low", "y sin depender de las mayúsculas");
ok(sshAlgoSeverity("curve25519-sha256") === "info", "lo actual es inventario, no hallazgo");
ok(sshAlgoSeverity("") === "info" && sshAlgoSeverity(null) === "info", "vacío no rompe");

// El techo es la decisión, no un detalle: en SSH ningún algoritmo llega a 'high' porque hace
// falta un cliente que lo elija. Si alguien mete un 'high' aquí, esto se pone rojo.
ok(Object.values(SSH_WEAK_ALGOS).every((s) => s === "medium" || s === "low"),
   "ningún algoritmo SSH llega a high: el riesgo depende del cliente");

ok(TLS_GRADE_SEVERITY.A === "info" && TLS_GRADE_SEVERITY.B === "low" &&
   TLS_GRADE_SEVERITY.C === "medium" && TLS_GRADE_SEVERITY.D === "medium" &&
   TLS_GRADE_SEVERITY.E === "high" && TLS_GRADE_SEVERITY.F === "high",
   "la tabla TLS A-F conserva sus seis valores");

// 'unknown' no es un nivel de riesgo: es "no se pudo comprobar", y darle severidad sería
// convertir un fallo de la herramienta en un dato.
ok(!("unknown" in TLS_GRADE_SEVERITY), "'unknown' no tiene severidad asignada");

// La nota que sale del XML real tiene que existir en la tabla.
ok(TLS_GRADE_SEVERITY[elemValue(enumC, "least strength")] === "info",
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

const encontrados = parseScriptHelp(HELP_OK);
ok(encontrados.has("ssh2-enum-algos") && encontrados.has("ssl-cert"),
   "reconoce los scripts listados");
ok(encontrados.size === 2, "y solo esos", [...encontrados].join(","));

// La descripción de un script cita a otro: buscar nombres sueltos lo daría por instalado.
const HELP_CITA = [
  "ssl-cert",
  "Categories: default safe discovery",
  "Complementa a ssl-enum-ciphers y a vulners, que no están instalados.",
].join("\n");
ok(!parseScriptHelp(HELP_CITA).has("vulners"),
   "un nombre citado en una descripción NO cuenta como instalado");
ok(!parseScriptHelp(HELP_CITA).has("ssl-enum-ciphers"), "ni aunque aparezca dos veces");

// stderr real de nmap 7.99 con un nombre que no existe.
const HELP_KO = [
  "NSE: failed to initialize the script engine:",
  "/opt/homebrew/bin/../share/nmap/nse_main.lua:829: 'noexiste' did not match a category, filename, or directory",
  "stack traceback:",
  "QUITTING!",
].join("\n");
ok(parseRejectedName(HELP_KO) === "noexiste", "se extrae el nombre que nmap rechaza");
ok(parseRejectedName("todo bien") === null, "y no se inventa uno cuando no lo hay");

// ── 10. Estado por script y puerto ───────────────────────────────────────────
console.log("\n10. scriptStates");

const TODOS = { checked: true, available: new Set(NSE_SCRIPT_IDS), missing: [] };

// El puerto 22 real: vulners y ssh2-enum-algos dieron dato; los tres de TLS no le tocaban.
const p22 = {
  port: 22, service: "ssh", version: "OpenSSH 10.3",
  cpe: "cpe:/a:openbsd:openssh:10.3", nse: sshScripts,
};
const e22 = scriptStates(p22, TODOS);

ok(e22.vulners.state === "found", "vulners: found");
ok(e22["ssh2-enum-algos"].state === "found", "ssh2-enum-algos: found");
ok(e22["ssl-cert"].state === "not-applicable", "ssl-cert en un puerto SSH: not-applicable");
ok(/no parece servir TLS/.test(e22["ssl-cert"].reason), "y con el motivo escrito",
   e22["ssl-cert"].reason);
ok(e22["ssl-cert"].kind === "not-applicable", "con su kind, para no comparar textos");

// El caso que separa un hueco de un límite: aplicaba y no salió.
const p14443 = { port: 14443, service: "unknown", tunnel: "ssl", nse: tlsScripts };
const e14443 = scriptStates(p14443, TODOS);
ok(e14443["ssl-enum-ciphers"].state === "found", "ssl-enum-ciphers en el puerto TLS: found");
ok(e14443.sslv2.state === "not-run" && e14443.sslv2.kind === "no-output",
   "sslv2 aplicaba y no salió: not-run, no 'limpio'");
ok(/no completó el diálogo/.test(e14443.sslv2.reason),
   "y el motivo apunta al objetivo, que es con quien hablaba", e14443.sslv2.reason);

// Un puerto sin versión: vulners no tiene con qué preguntar. Eso es alcance, no hueco.
const pSinVer = { port: 9999, service: "unknown", nse: [] };
ok(scriptStates(pSinVer, TODOS).vulners.state === "not-applicable",
   "sin versión, vulners es not-applicable");

// Script ausente del sistema: hueco, con su nombre.
const SIN_VULNERS = {
  checked: true,
  available: new Set(NSE_SCRIPT_IDS.filter((i) => i !== "vulners")),
  missing: ["vulners"],
};
const eSin = scriptStates({ port: 22, service: "ssh", version: "OpenSSH 10.3", nse: [] }, SIN_VULNERS);
ok(eSin.vulners.state === "not-run" && eSin.vulners.kind === "script-missing",
   "un script no instalado es un hueco, no un 'no aplica'");

// No se pudo averiguar qué hay instalado: TODO queda en no comprobado. Nada cae a limpio.
const NO_SE_SABE = { checked: false, available: new Set(), missing: [], reason: "nmap no respondió" };
const eNada = scriptStates({ port: 22, service: "ssh", version: "OpenSSH 10.3", nse: [] }, NO_SE_SABE);
ok(NSE_SCRIPT_IDS.every((id) => eNada[id].state === "not-run" && eNada[id].kind === "nse-unavailable"),
   "sin saber qué hay instalado, los cinco quedan en not-run");
ok(eNada.vulners.reason === "nmap no respondió", "arrastrando el motivo real");

// Lo que NO puede existir: un estado que diga 'limpio'. Afirmar limpio es cosa del canario.
ok(Object.values(e22).concat(Object.values(e14443))
     .every((e) => ["found", "not-applicable", "not-run"].includes(e.state)),
   "solo hay tres estados, y ninguno es 'clean'");

// ── 11. Canario de vulners ───────────────────────────────────────────────────
/**
 * LOS NÚMEROS QUE MATARON EL NIVEL 2. Medidos a mano contra vulners.com el 2026-09-13, desde
 * macOS, con curl y sin proxy. Se guardan aquí porque son el motivo por el que el módulo NO
 * tiene sonda de red, y ese motivo no se puede recomprobar automáticamente sin salir a internet
 * —cosa que ningún test de este repositorio hace—.
 *
 *   GET https://vulners.com/api/v3/burp/software/?software=cpe:/a:openbsd:openssh:7.4
 *                                                &version=7.4&type=cpe
 *
 *   sin cabecera User-Agent                → HTTP 403, cuerpo "Just a moment..." (reto anti-bot)
 *   User-Agent: LoCoAudit/1.0 (...)        → HTTP 403, el mismo reto
 *   User-Agent: Vulners NMAP Plugin 1.7    → HTTP 200, {"result":"OK"}, 45.820 bytes
 *
 *   Mismo resultado en /api/v3/search/id/ y en /api/v3/burp/softwareapi/.
 *   vulners.nse fija api_version="1.2" en su línea 64, y su propio comentario admite que el
 *   script muere en silencio si la petición HTTP falla.
 *
 * Conclusión: la única sonda que habría funcionado era suplantar al plugin de nmap. Se descartó,
 * y con ella el nivel 2 entero. Aquí solo queda la inferencia, que no habla con nadie.
 */
console.log("\n11. canario");

const PORTS_CON_CVE = [{ port: 22, version: "OpenSSH 10.3", nse: sshScripts }];
const PORTS_CON_VER = [{ port: 22, version: "OpenSSH 10.3", nse: [] }];
const PORTS_SIN_VER = [{ port: 80, service: "http", nse: [] }];

(async () => {
  ok(inferFromScan(PORTS_CON_CVE), "un <script id=\"vulners\"> prueba que la fuente respondió");
  ok(!inferFromScan(PORTS_CON_VER), "y sin él no se infiere nada");

  const r1 = runCanary(PORTS_CON_CVE, { hasVersion });
  ok(r1.state === "ok-inferred" && r1.probed === false,
     "un solo puerto con CVE certifica la fuente para todo el escaneo, sin pedir nada a nadie");

  const rNo = runCanary(PORTS_SIN_VER, { hasVersion });
  ok(rNo.state === "not-needed", "sin ningún puerto con versión no hay nada que comprobar", rNo.state);

  const rAmb = runCanary(PORTS_CON_VER, { hasVersion });
  ok(rAmb.state === "unconfirmed",
     "con versión y sin datos de vulners, el caso ambiguo se nombra: no se sabe", rAmb.state);
  ok(!canaryIsOk(rAmb.state), "y 'unconfirmed' NO es un visto bueno");
  ok(rAmb.probed === false, "nunca se sale a la red: `probed` vale false en todos los caminos");

  const rApagado = runCanary(PORTS_CON_VER, { hasVersion, nseEnabled: false });
  ok(rApagado.state === "not-run", "con NSE apagado el canario ni se plantea la pregunta");

  // El coste de no tener sonda, dicho en el informe y no solo en un comentario: un equipo al día
  // cae aquí, y quien lo lea tiene que entender por qué su equipo bien mantenido sale "sin
  // comprobar" en vez de limpio.
  ok(/equipo\s+al día/.test(CANARY_DETAIL.unconfirmed) &&
     /resultado ESPERADO/.test(CANARY_DETAIL.unconfirmed),
     "el texto de 'unconfirmed' explica que un equipo actualizado cae justo ahí");
  ok(/no lanza consultas propias/.test(CANARY_DETAIL.unconfirmed),
     "y que LoCoAudit no consulta vulners.com por su cuenta");

  // La regla que sostiene todo lo demás: un solo estado autoriza a decir limpio.
  const todos = Object.keys(CANARY_DETAIL);
  ok(todos.filter(canaryIsOk).join(",") === "ok-inferred",
     "solo UNO de los estados es visto bueno", todos.filter(canaryIsOk).join(","));
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
  console.log("\n12. buildScanCommand");

  // La línea EXACTA de antes de este trabajo. Escrita entera y a mano a propósito: si se
  // derivara de la función bajo prueba, el test aprobaría cualquier cambio.
  const ANTES_SIN_IFACE = "nmap -sV -T4 -Pn --max-retries 2  -p 1-3000 -oX - 127.0.0.1";
  const ANTES_CON_IFACE = "nmap -sV -T4 -Pn --max-retries 2 -e en0 -p 1-1024 -oX - 192.168.0.30";

  ok(buildScanCommand({ target: "127.0.0.1", portSpec: "1-3000" }) === ANTES_SIN_IFACE,
     "sin NSE, el comando es byte a byte el de siempre (incluido el doble espacio)",
     buildScanCommand({ target: "127.0.0.1", portSpec: "1-3000" }));
  ok(buildScanCommand({ target: "192.168.0.30", portSpec: "1-1024", ifaceFlag: "-e en0" }) === ANTES_CON_IFACE,
     "y también con -e");
  ok(buildScanCommand({ target: "127.0.0.1", portSpec: "22", nseScripts: [] }) === "nmap -sV -T4 -Pn --max-retries 2  -p 22 -oX - 127.0.0.1",
     "una lista vacía no añade --script");

  const conNse = buildScanCommand({ target: "127.0.0.1", portSpec: "22", nseScripts: NSE_SCRIPT_IDS });
  ok(conNse.includes(`--script ${NSE_SCRIPT_IDS.join(",")}`), "con lista, --script va con los nombres separados por coma", conNse);
  ok(!/--script[= ](vuln|safe|default|intrusive|all)\b/.test(conNse),
     "y NUNCA una categoría: una categoría arrastra scripts que nadie ha revisado");
  ok(!/\s-O\b/.test(conNse), "sin -O: necesitaría root");
  ok(!/\s-f\b/.test(conNse), "sin -f: fragmentar es evadir, no auditar");
  ok(!/--script-timeout/.test(conNse),
     "sin --script-timeout: un script matado por timeout se vuelve indistinguible de uno sin hallazgos");

  // El parser del wrapper tiene que traer lo que la aplicabilidad necesita, o appliesTo decide
  // a ciegas. Es el enganche entre el paso 2 y el paso 7, y se comprueba sobre captura real.
  const puertosTls = parseNmapXml(fixture("scan-nse-tls.xml"));
  ok(puertosTls[0].tunnel === "ssl",
     "el wrapper extrae tunnel=\"ssl\" pese al servicefp lleno de barras", JSON.stringify(puertosTls[0].tunnel));
  ok(appliesTo("ssl-enum-ciphers", puertosTls[0]).applies,
     "y con eso un puerto TLS fuera de toda lista se reconoce igual");

  const puertosSsh = parseNmapXml(fixture("scan-nse-ssh.xml"));
  ok(puertosSsh[0].cpe === "cpe:/a:openbsd:openssh:10.3", "y el <cpe> del servicio", puertosSsh[0].cpe);
  ok(puertosSsh[0].nse.length === 3, "y el subárbol NSE del puerto");
  ok(parseNmapXml(fixture("scan-ports-open.xml"))[0].nse.length === 0,
     "un escaneo sin --script deja el subárbol vacío, no ausente");

  // ── 13. Los findings ───────────────────────────────────────────────────────
  console.log("\n13. lib/normalizer: de resumen NSE a findings");

  // Se parte del XML real y se atraviesa TODA la cadena —parser, extractor, normalizador—,
  // porque los fallos que importan viven en las juntas, no dentro de cada pieza.
  const conResumen = (xml, canaryOk) => {
    const puertos = parseNmapXml(fixture(xml));
    for (const p of puertos) p.nseSummary = summarizePort(p, { canaryOk });
    return puertos;
  };

  const OPTS = { target: "127.0.0.1", targetIsLocal: true, nse: { enabled: true } };

  // --- NET-VULN: el crítico llega entero, con los 11 CVE y con la procedencia ---
  const pSsh  = conResumen("scan-nse-ssh.xml", true);
  const vulns = fromNseVulns(pSsh, OPTS);

  ok(vulns.length === 1, "11 CVE del mismo servicio son UN finding, no once", String(vulns.length));
  ok(vulns[0].severity === "critical",
     "y su severidad es la del peor CVE (9.4), no la media de los once", vulns[0].severity);
  ok(vulns[0].id === "NET-VULN-001" && vulns[0].category === "network" && vulns[0].source === "nmap",
     "con id, categoría y fuente del esquema canónico");
  // La evidencia ya NO vuelca los CVE uno a uno: los pinta la tabla del hallazgo desde
  // `vulnerabilities`, y repetirlos obligaba a leer la misma lista dos veces. Lo que la
  // frase sigue teniendo que decir: cuántos son, cuánto puntúa el peor, y que de cada
  // uno no hay descripción —sin esa última frase, una tabla de identificadores sin
  // texto se lee como un dato que falta por cargar—.
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
  const svc = fromNseSvc(pSsh, OPTS);
  ok(svc.length === 1 && svc[0].id === "NET-SVC-001", "un finding de algoritmos por puerto SSH");
  ok(svc[0].severity === "low", "hmac-sha1 es débil, no roto: low", svc[0].severity);
  ok(/hmac-sha1 \[integridad \(MAC\)\]/.test(svc[0].evidence),
     "el algoritmo se nombra con el grupo al que pertenece");
  ok(svc[0].evidence.includes(OFFERED_NOT_NEGOTIATED),
     "y la frase de 'ofrece, no negocia' va LITERAL, sin reescribir");
  ok(/sshd_config/.test(svc[0].fix), "el fix nombra dónde se toca");

  // --- NET-TLS: la nota A y el certificado ---
  const pTls = conResumen("scan-nse-tls.xml", true);
  const tls  = fromNseTls(pTls, OPTS);
  ok(tls.length === 1 && tls[0].severity === "info", "nota A es informativa, no un problema", tls[0] && tls[0].severity);
  ok(/TLSv1\.2/.test(tls[0].evidence) && /TLSv1\.3/.test(tls[0].evidence), "los protocolos aceptados constan");
  ok(/sha256WithRSAEncryption/.test(tls[0].evidence), "y la firma del certificado");

  // Techos asimétricos: la tabla TLS llega a high, la de SSH se queda en medium. A propósito.
  ok(Object.values(TLS_GRADE_SEVERITY).includes("high") &&
     !Object.values(SSH_WEAK_ALGOS).includes("high"),
     "TLS puede llegar a high y SSH no: en TLS el riesgo no depende de que el cliente colabore");

  // --- Las omisiones: lo que NO se comprobó también es un finding ---
  const apagado = fromNseOmissions(pSsh, { nse: { enabled: false } });
  ok(apagado.length === 1 && apagado[0].skipped === true && apagado[0].kind === "nse-disabled",
     "con NSE apagado sale UN aviso, marcado como omisión");
  ok(/no que no las haya/.test(apagado[0].evidence),
     "y dice explícitamente que la ausencia de CVE significa que no se buscaron");

  const sinCanario = fromNseOmissions(conResumen("scan-nse-ssh.xml", false).map((p) => {
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

  const faltan = fromNseOmissions([], {
    nse: { enabled: true, availability: { checked: true, missing: ["vulners"] } },
  });
  ok(faltan.length === 1 && faltan[0].kind === "script-missing" && /vulners/.test(faltan[0].title),
     "un script no instalado se nombra en vez de desaparecer del informe");

  const sinLista = fromNseOmissions([], {
    nse: { enabled: true, availability: { checked: false, reason: "nmap salió con código 2" } },
  });
  ok(sinLista.length === 1 && sinLista[0].kind === "nse-unavailable" && /código 2/.test(sinLista[0].evidence),
     "y no poder comprobar qué hay instalado guarda el motivo real como evidencia");

  // --- El enganche en normalizeNetwork ---
  const puertosRaw = parseNmapXml(fixture("scan-nse-ssh.xml"));
  const sinNse = normalizeNetwork(puertosRaw, "nmap", { target: "127.0.0.1", targetIsLocal: true });
  ok(sinNse.every((f) => f.id.startsWith("NET-PORT")),
     "sin opts.nse, normalizeNetwork devuelve exactamente lo de siempre");

  const conNseF = normalizeNetwork(conResumen("scan-nse-ssh.xml", true), "nmap", OPTS);
  const ids = conNseF.map((f) => f.id.replace(/-\d+$/, ""));
  ok(ids[0] === "NET-PORT", "los puertos siguen yendo primero: es lo primero que se busca", ids.join(" "));
  ok(ids.includes("NET-VULN") && ids.includes("NET-SVC"), "y detrás va lo de NSE", ids.join(" "));
  ok(conNseF.every((f) => f.scope === "network"), "todo sale sellado con su ámbito");

  // El puerto vale lo que vale el puerto. Hay 11 CVE y uno de 9.4 en ese mismo servicio, y aun
  // así el NET-PORT no se mueve: heredar la severidad de los CVE convertiría "SSH abierto" en
  // crítico por un fallo que el backporting quizá ya corrigió.
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
   * Estas comprobaciones leen el FUENTE del nodo y de su diálogo, no su comportamiento: un nodo
   * de Node-RED no se puede instanciar fuera de Node-RED, y la validación de verdad es la
   * auditoría real. Lo que cubren es lo que una prueba manual no pilla porque "parece que va":
   * que el defecto siga apagado, que el presupuesto de tiempo se SUME, y que la cesión de datos
   * siga escrita dentro de la casilla. Son las tres cosas que se deshacen solas en una limpieza
   * de seis meses.
   */
  console.log("\n14. nodo y diálogo");

  const fuenteNodo = require("fs").readFileSync(
    require("path").join(__dirname, "../../nodes/audit-network/audit-network.js"), "utf8");
  const fuenteHtml = require("fs").readFileSync(
    require("path").join(__dirname, "../../nodes/audit-network/audit-network.html"), "utf8");

  ok(/nseEnabled:\s*\{\s*value:\s*false\s*\}/.test(fuenteHtml),
     "la casilla viene APAGADA de fábrica: activarla cede datos a un tercero");
  ok(/config\.nseEnabled === true \|\| config\.nseEnabled === "true"/.test(fuenteNodo),
     "y el nodo la lee con el mismo patrón estricto que forceScan, sin colar un string vacío");

  // El presupuesto se suma. Si alguien lo cambia por una sustitución, los 90/240/620 s dejan de
  // cubrir lo que fueron calibrados para cubrir y el escaneo de puertos se corta.
  ok(/\(NMAP_TIMEOUT_BY_MODE\[scanMode\] \|\| 240000\) \+ \(nseEnabled \? nseTimeout : 0\)/.test(fuenteNodo),
     "el tiempo de los scripts se SUMA al del modo, no lo sustituye");

  // El orden que evita que dos puertos de la misma ejecución reciban veredictos distintos.
  ok(fuenteNodo.indexOf("runCanary(") < fuenteNodo.indexOf("summarizePort("),
     "el canario se resuelve antes que el resumen de cada puerto: es propiedad del escaneo entero");

  // Un nmap recortado no puede costar el escaneo: se pregunta antes qué scripts existen.
  ok(fuenteNodo.indexOf("scriptExists(") < fuenteNodo.indexOf("runNmap("),
     "se comprueba qué scripts hay instalados ANTES de lanzar el escaneo");
  ok(/nseScripts = \[\.\.\.nseAvailability\.available\]/.test(fuenteNodo),
     "y solo se le pide a nmap lo que ese nmap tiene: un nombre inexistente aborta el escaneo entero");

  // La cesión va DENTRO del texto que se marca. Se comprueba sobre el <label> de la casilla, no
  // sobre el fichero entero: una advertencia en un párrafo aparte no cuenta, porque no se lee.
  const etiqueta = fuenteHtml.match(
    /<label for="node-input-nseEnabled"[\s\S]*?<\/label>/);
  ok(etiqueta && /vulners\.com/.test(etiqueta[0]) && /versi[óo]n/.test(etiqueta[0]),
     "el texto de la casilla dice, él mismo, que envía las versiones a vulners.com");

  ok(/scanMeta[\s\S]*?nse:\s*\{[\s\S]*?canary:/.test(fuenteNodo),
     "y el estado del análisis viaja en scanMeta.nse para quien lee el JSON");

  // ── Resumen ────────────────────────────────────────────────────────────────
  console.log(`\n${failed === 0 ? "OK" : "FALLOS"}: ${passed} pasadas, ${failed} fallidas\n`);
  process.exit(failed === 0 ? 0 : 1);
})();
