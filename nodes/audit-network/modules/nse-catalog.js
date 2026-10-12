"use strict";

/**
 * Qué scripts NSE lanza audit-network y a qué puertos aplica cada uno. Datos puros, como port-catalog.js. La traducción de una
 * puntuación a un nivel (fromCvss) vive en lib/severity-map.js.
 *
 * Lista nominal, nunca categorías (comprobado con nmap 7.99): `not intrusive` excluiría ssl-enum-ciphers (`discovery, intrusive`)
 * y `vuln` arrastra scripts intrusive contra HTTP y SMB. Un nombre que no exista aborta el escaneo entero ("failed to initialize
 * the script engine"), por eso nse-scripts.js poda la lista antes de construir el comando y la lista es una sola.
 */

/**
 * Los cinco, con las categorías verificadas contra `nmap --script-help` de la instalación real. `banner` se descartó: emite
 * <script id="banner"> autocerrado, solo legible por el atributo de texto, y es redundante con lo que -sV ya devuelve.
 */
const NSE_SCRIPTS = [
  {
    id: "vulners",
    categories: ["vuln", "safe", "external"],
    // `external` no es un adorno: consulta https://vulners.com/api/v3/burp/software/ con el CPE
    // y la versión de cada servicio detectado, y nada más del equipo. Depende de un servicio
    // externo, y por eso la casilla lo dice en su propio texto.
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

/** ¿Anunció el servicio una versión con la que vulners pueda trabajar? Es la misma pregunta que el portrule del script
 *  (vulners.nse:68-71); se acepta también el <cpe> porque sin él vulners aún puede preguntar por software y versión. */
function hasVersion(p) {
  if (!p) return false;
  if (p.version && String(p.version).trim()) return true;
  if (p.cpe && String(p.cpe).trim()) return true;
  return false;
}

/**
 * ¿Debería haberse ejecutado este script en este puerto? Aproximación propia, corta y auditable, no una réplica de los portrule
 * de nmap (se desincronizaría). No decide qué se manda a nmap: sirve para interpretar la ausencia de <script id="X">, que puede ser
 * "no le tocaba" o "le tocaba y no salió". Devuelve { applies, reason }; `reason` viaja al informe como evidencia.
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
 * La fuente de un script. 'remote-api' (vulners): su silencio es ambiguo y por eso existe el canario. 'target' (ssl-*, ssh2-*):
 * si aplicaba y no volvió nada, el handshake no se completó, así que es "no aplicable, con motivo" y nunca "aplicable y limpio".
 */
function sourceKind(scriptId) {
  return scriptId === "vulners" ? "remote-api" : "target";
}

/** Frase de procedencia de todo hallazgo de configuración de servicio (NET-TLS-*, NET-SVC-*), literal en la evidencia:
 *  "SSH ofrece hmac-sha1" no es "tu SSH usa hmac-sha1" mientras el cliente no lo elija. */
const OFFERED_NOT_NEGOTIATED =
  "el servicio OFRECE este algoritmo; un cliente actualizado negociará uno más fuerte. " +
  "El riesgo es que un cliente antiguo acepte el débil.";

/* Las dos tablas no están en la misma escala a propósito. El criterio es si el riesgo depende de un tercero, no la antigüedad:
 * - SSH (techo 'medium'): el hash de intercambio cubre los KEXINIT, no hay degradación forzada desde la red; hace falta un
 *   cliente que elija el algoritmo débil.
 * - TLS (hasta 'high'): el grado F incluye SSLv2/SSLv3, NULL y export, explotables del lado servidor sin el cliente (DROWN).
 * Por eso un '3des-cbc' en SSH es 'low' y un grado F en TLS es 'high'. */

/**
 * Nota A-F de ssl-enum-ciphers → severidad (la emite el script en <elem key="least strength">, ya agregada por puerto).
 * 'unknown' no está a propósito: es "no se pudo comprobar", no un nivel de riesgo, y mapearlo a 'info' sería un falso dato
 * tranquilizador. Lo trata el camino de omisión.
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
 * Algoritmos SSH que ssh2-enum-algos puede listar, con su nivel (techo 'medium'). Lo que no esté aquí es inventario informativo:
 * el catálogo no se pronuncia, no lo da por seguro.
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
