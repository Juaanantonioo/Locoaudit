"use strict";

/**
 * Qué scripts NSE lanza audit-network y a qué puertos aplica cada uno.
 *
 * Datos puros, sin ejecutar nada, como port-catalog.js. Las dos tablas de severidad de aquí
 * (TLS_GRADE_SEVERITY y SSH_WEAK_ALGOS) son catálogo, del mismo tipo que PORT_CATALOG: asocian
 * un nombre conocido a un nivel. La traducción de una PUNTUACIÓN a un nivel —fromCvss— vive en
 * lib/severity-map.js, que sigue siendo la única vara para eso.
 *
 * LISTA NOMINAL, NUNCA CATEGORÍAS. Ni `vuln`, ni `safe`, ni `not intrusive`. Dos motivos
 * comprobados contra nmap 7.99:
 *   - `not intrusive` excluiría ssl-enum-ciphers, que es `discovery, intrusive` y es justo uno
 *     de los que queremos;
 *   - `vuln` arrastra scripts intrusive contra servicios HTTP y SMB que nadie ha pedido.
 *
 * Y un motivo estructural para que la lista viva en un sitio y no repartida: un nombre que no
 * exista ABORTA EL ESCANEO ENTERO. Comprobado:
 *   nmap -sV -Pn -p 22 --script vulners,noexiste 127.0.0.1
 *   → exit=1, <finished exit="error" errormsg="NSE: failed to initialize the script engine…">
 *            <hosts up="0" down="0" total="0"/>
 * Ese XML lo recoge parseNmapFatalError() y acaba en NET-SCAN-WARN, así que no produce un falso
 * verde; pero convierte un escaneo bueno en no concluyente. Por eso nse-scripts.js poda la lista
 * ANTES de construir el comando, y por eso la lista tiene que ser una sola.
 */

/**
 * Los cinco. Las categorías están verificadas una a una contra el nsedoc de la instalación real
 * (nmap --script-help), no copiadas de la documentación web.
 *
 * `banner` se evaluó y se descartó: emite <script id="banner" output="…"/> AUTOCERRADO, sin
 * <table> ni <elem>, o sea que solo se puede leer por el atributo de texto plano —justo lo que
 * este diseño no hace— y además es redundante con lo que -sV ya devuelve en product/version/
 * extrainfo y <cpe>.
 */
const NSE_SCRIPTS = [
  {
    id: "vulners",
    categories: ["vuln", "safe", "external"],
    // `external` no es un adorno: consulta https://vulners.com/api/v3/burp/software/ y le manda
    // el CPE y la versión de cada servicio detectado. Es una cesión de datos a un tercero, y por
    // eso todo esto es opt-in y el toggle lo dice con esas palabras.
    what: "CVE conocidos para la versión que anuncia el servicio",
  },
  {
    id: "ssl-cert",
    categories: ["default", "safe", "discovery"],
    what: "certificado TLS: emisor, vigencia, algoritmo de firma",
  },
  {
    id: "ssl-enum-ciphers",
    categories: ["discovery", "intrusive"],
    // Se acepta `intrusive` a conciencia: negocia muchas suites contra el servicio. Es el otro
    // motivo de peso para que el análisis NSE sea opt-in y no venga activado de fábrica.
    what: "suites TLS aceptadas y su nota A-F",
  },
  {
    id: "sslv2",
    categories: ["default", "safe"],
    what: "SSLv2 residual",
  },
  {
    id: "ssh2-enum-algos",
    categories: ["safe", "discovery"],
    what: "algoritmos SSH ofrecidos (intercambio, cifrado, MAC)",
  },
];

/** Los nombres, para construir --script y --script-help. */
const NSE_SCRIPT_IDS = NSE_SCRIPTS.map((s) => s.id);

/**
 * Puertos donde se espera TLS aunque -sV no marque tunnel="ssl". No pretende ser exhaustiva:
 * es la aproximación declarada de la que habla appliesTo().
 */
const TLS_PORTS = new Set([
  443,   // https
  465,   // smtps
  563,   // nntps
  636,   // ldaps
  989,   // ftps-data
  990,   // ftps
  993,   // imaps
  995,   // pop3s
  5061,  // sip-tls
  6697,  // ircs-u
  8443,  // https-alt
  8883,  // secure-mqtt
  9443,  // https-alt de paneles de gestión
]);

/** Nombres de servicio de -sV que implican TLS. */
const TLS_SERVICES = new Set([
  "https", "ssl", "imaps", "pop3s", "smtps", "ldaps", "ftps", "ftps-data",
  "https-alt", "sip-tls", "ircs-u", "secure-mqtt", "nntps",
]);

/** Los tres que miran TLS comparten condición de aplicabilidad. */
const TLS_SCRIPTS = new Set(["ssl-cert", "ssl-enum-ciphers", "sslv2"]);

/**
 * ¿Anunció el servicio una versión con la que vulners pueda trabajar?
 *
 * Es la MISMA pregunta que hace el portrule del script (`port.version.version ~= nil`,
 * vulners.nse:68-71), y de ahí sale el estado "no analizado por falta de versión". Se acepta
 * también el <cpe> porque -sV lo emite cuando reconoce el producto, y sin CPE vulners aún puede
 * preguntar por software+versión.
 */
function hasVersion(p) {
  if (!p) return false;
  if (p.version && String(p.version).trim()) return true;
  if (p.cpe && String(p.cpe).trim()) return true;
  return false;
}

/**
 * ¿Debería haberse ejecutado este script en este puerto?
 *
 * APROXIMACIÓN DECLARADA, NO UNA RÉPLICA DEL portrule. Replicar los portrule de cinco scripts
 * sería mantener una copia del criterio de nmap que se desincroniza en cuanto nmap lo cambia;
 * esto es un criterio propio, corto y auditable, y cuando se equivoca lo dice.
 *
 * Para qué sirve: NO para decidir qué se le manda a nmap —se le manda la lista entera podada y
 * son sus portrule los que deciden—, sino para INTERPRETAR LA AUSENCIA. Un puerto sin
 * <script id="X"> puede ser "no le tocaba" o "le tocaba y no salió", y son cosas distintas que
 * no pueden acabar en el mismo sitio.
 *
 * Devuelve { applies, reason }; `reason` se guarda como evidencia y viaja al informe.
 */
function appliesTo(scriptId, p) {
  const port    = p && Number(p.port);
  const service = String((p && p.service) || "").toLowerCase();

  if (scriptId === "vulners") {
    return hasVersion(p)
      ? { applies: true, reason: null }
      : {
          applies: false,
          reason: "El servicio no anunció versión ni CPE: vulners no tiene con qué consultar.",
        };
  }

  if (TLS_SCRIPTS.has(scriptId)) {
    if (p && p.tunnel === "ssl") {
      return { applies: true, reason: null };
    }
    if (TLS_SERVICES.has(service)) {
      return { applies: true, reason: null };
    }
    if (TLS_PORTS.has(port)) {
      return { applies: true, reason: null };
    }
    return {
      applies: false,
      reason: `El puerto ${port}/${service || "desconocido"} no parece servir TLS ` +
              "(nmap no lo marcó como tunnel=\"ssl\" y ni el puerto ni el servicio están en la " +
              "lista de TLS conocidos).",
    };
  }

  if (scriptId === "ssh2-enum-algos") {
    if (service === "ssh" || port === 22) {
      return { applies: true, reason: null };
    }
    return {
      applies: false,
      reason: `El puerto ${port}/${service || "desconocido"} no parece servir SSH.`,
    };
  }

  // Un script que no esté en la tabla no se interpreta a ciegas: se dice que no se sabe.
  return {
    applies: false,
    reason: `No hay condición de aplicabilidad declarada para '${scriptId}'.`,
  };
}

/**
 * La fuente de un script: de dónde vendría la respuesta.
 *
 *  - 'remote-api'  vulners pregunta a vulners.com. Su silencio es ambiguo (puede ser "no hay
 *                  CVE" o "no pude preguntar") y por eso existe el canario.
 *  - 'target'      los ssl-* y ssh2-* hablan con el propio objetivo. Si la condición de
 *                  aplicabilidad casó y aun así no volvió nada, es que el handshake no se
 *                  completó: NUESTRA aproximación falló. Eso es "no aplicable, con motivo",
 *                  nunca "aplicable y limpio". No hay estado 'clean' para esta familia.
 */
function sourceKind(scriptId) {
  return scriptId === "vulners" ? "remote-api" : "target";
}

/**
 * Frase de procedencia de todo hallazgo de configuración de servicio (NET-TLS-*, NET-SVC-*).
 * Va literal en la evidencia: sin ella, "SSH ofrece hmac-sha1" se lee como "tu SSH usa
 * hmac-sha1", que es falso mientras el cliente no lo elija.
 */
const OFFERED_NOT_NEGOTIATED =
  "el servicio OFRECE este algoritmo; un cliente actualizado negociará uno más fuerte. " +
  "El riesgo es que un cliente antiguo acepte el débil.";

/* ---------------------------------------------------------------------------
 * LAS DOS TABLAS NO ESTÁN EN LA MISMA ESCALA, Y ES A PROPÓSITO
 *
 * TLS llega hasta 'high'; SSH se queda en 'medium'. No es un descuido ni falta de coherencia:
 * el criterio es SI EL RIESGO DEPENDE DE UN TERCERO, no la antigüedad del algoritmo.
 *
 *  - En SSH, el hash de intercambio cubre los mensajes KEXINIT. Un atacante en la red no puede
 *    recortar la lista ofrecida sin que el intercambio falle: no hay degradación forzada desde
 *    la red. Para que el algoritmo débil se use hace falta un CLIENTE que lo elija. Riesgo
 *    condicionado a un tercero → techo 'medium'.
 *  - En TLS, el grado F incluye SSLv2, SSLv3, suites NULL y export. Son explotables del lado
 *    servidor sin cooperación del cliente: DROWN ataca al cliente moderno usando el SSLv2 que
 *    el servidor sigue aceptando, aunque ese cliente jamás negocie SSLv2. Riesgo incondicionado
 *    → 'high'.
 *
 * Por eso un '3des-cbc' en SSH es 'low' y un grado F en TLS es 'high' aunque ambos sean viejos.
 * Quien quiera mover una de las dos tablas tiene que argumentar sobre esta línea, no sobre la
 * simetría.
 * ------------------------------------------------------------------------- */

/**
 * Nota A-F de ssl-enum-ciphers → severidad. La emite el propio script en
 * <elem key="least strength">, ya agregada por puerto.
 *
 * 'unknown' NO está aquí, y no es un olvido: no es un nivel de riesgo, es el estado de "no se
 * pudo comprobar". Mapearlo a 'info' sería convertir un fallo de la herramienta en un dato
 * tranquilizador, que es justo lo que prohíbe "fallo de la herramienta ≠ dato negativo". Lo
 * trata el camino de omisión.
 */
const TLS_GRADE_SEVERITY = {
  A: "info",     // configuración actual
  B: "low",
  C: "medium",
  D: "medium",
  E: "high",     // ver el bloque de arriba: explotable sin cooperación del cliente
  F: "high",     // SSLv2/SSLv3, NULL, export
};

/**
 * Algoritmos SSH que ssh2-enum-algos puede listar, con su nivel. Techo 'medium' por el motivo
 * documentado arriba.
 *
 * Lista corta de lo roto sin discusión; lo que no esté aquí es INVENTARIO INFORMATIVO, no un
 * implícito de "seguro": nadie afirma que un algoritmo ausente de esta tabla sea bueno, solo
 * que este catálogo no se pronuncia sobre él.
 */
const SSH_WEAK_ALGOS = {
  // Roto de raíz: firma DSA de 1024 bits fija, RC4, MD5, y Diffie-Hellman de grupo fijo o
  // negociado con SHA-1 (Logjam).
  "ssh-dss": "medium",
  "arcfour": "medium",
  "arcfour128": "medium",
  "arcfour256": "medium",
  "hmac-md5": "medium",
  "hmac-md5-96": "medium",
  "diffie-hellman-group1-sha1": "medium",
  "diffie-hellman-group-exchange-sha1": "medium",

  // Débil pero no roto: CBC en SSH (ataque de recuperación de texto plano de 2008, mitigado en
  // las implementaciones actuales) y SHA-1 como MAC, donde la colisión no se explota.
  "3des-cbc": "low",
  "hmac-sha1": "low",
  "hmac-sha1-96": "low",
};

/** Nivel de un algoritmo SSH. Cualquier *-cbc no listado cae a 'low'; el resto es inventario. */
function sshAlgoSeverity(name) {
  const n = String(name || "").trim().toLowerCase();
  if (!n) return "info";
  if (SSH_WEAK_ALGOS[n]) return SSH_WEAK_ALGOS[n];
  if (n.endsWith("-cbc")) return "low";
  return "info";
}

module.exports = {
  NSE_SCRIPTS,
  NSE_SCRIPT_IDS,
  TLS_PORTS,
  TLS_SERVICES,
  TLS_SCRIPTS,
  TLS_GRADE_SEVERITY,
  SSH_WEAK_ALGOS,
  OFFERED_NOT_NEGOTIATED,
  hasVersion,
  appliesTo,
  sourceKind,
  sshAlgoSeverity,
};
