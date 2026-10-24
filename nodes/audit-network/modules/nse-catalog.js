"use strict";

// Scripts NSE que lanza audit-network y a qué puertos aplica cada uno.
// Lista por nombre, nunca por categorías: `vuln` arrastraría scripts intrusivos contra HTTP y SMB.

// Categorías comprobadas con `nmap --script-help`. `banner` no está: es redundante con -sV.
const NSE_SCRIPTS = [
  {
    id: "vulners",
    categories: ["vuln", "safe", "external"],
    // Consulta vulners.com solo con el CPE y la versión de cada servicio.
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
    // Intrusivo a sabiendas (negocia muchas suites): otro motivo para que NSE sea opcional.
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

// Nombres para --script y --script-help.
const NSE_SCRIPT_IDS = NSE_SCRIPTS.map((s) => s.id);

// Puertos donde se espera TLS aunque -sV no marque tunnel="ssl"; no es exhaustiva.
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

// Nombres de servicio de -sV que implican TLS.
const TLS_SERVICES = new Set([
  "https", "ssl", "imaps", "pop3s", "smtps", "ldaps", "ftps", "ftps-data",
  "https-alt", "sip-tls", "ircs-u", "secure-mqtt", "nntps",
]);

// Los tres scripts de TLS comparten condición de aplicabilidad.
const TLS_SCRIPTS = new Set(["ssl-cert", "ssl-enum-ciphers", "sslv2"]);

// Igual que el portrule de vulners.nse: basta con versión o con CPE.
function hasVersion(p) {
  if (!p) return false;
  if (p.version && String(p.version).trim()) return true;
  if (p.cpe && String(p.cpe).trim()) return true;
  return false;
}

// Aproximación propia (no copia los portrule de nmap) para interpretar la ausencia de un <script>.
// No decide qué se manda a nmap. Devuelve { applies, reason }; reason va al informe.
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

  // Un script sin condición declarada no se interpreta a ciegas.
  return {
    applies: false,
    reason: `No hay condición de aplicabilidad declarada para '${scriptId}'.`,
  };
}

// 'remote-api' (vulners): su silencio es ambiguo, de ahí el canario. 'target': habla con el propio servicio.
function sourceKind(scriptId) {
  return scriptId === "vulners" ? "remote-api" : "target";
}

// Va en la evidencia de NET-TLS-* y NET-SVC-*: ofrecer un algoritmo no es usarlo.
const OFFERED_NOT_NEGOTIATED =
  "el servicio OFRECE este algoritmo; un cliente actualizado negociará uno más fuerte. " +
  "El riesgo es que un cliente antiguo acepte el débil.";

// SSH tiene techo 'medium' porque necesita un cliente que elija el algoritmo débil;
// TLS llega a 'high' porque SSLv2/SSLv3, NULL y export se explotan sin el cliente (DROWN).

// Nota A-F de ssl-enum-ciphers a severidad. 'unknown' falta a propósito: es omisión, no riesgo.
const TLS_GRADE_SEVERITY = {
  A: "info",     // configuración actual
  B: "low",
  C: "medium",
  D: "medium",
  E: "high",     // explotable sin cooperación del cliente
  F: "high",     // SSLv2/SSLv3, NULL, export
};

// Algoritmos SSH débiles y su nivel; lo no listado es inventario, no "seguro".
const SSH_WEAK_ALGOS = {
  // Rotos: DSA de 1024 bits, RC4, MD5 y Diffie-Hellman con SHA-1 (Logjam).
  "ssh-dss": "medium",
  "arcfour": "medium",
  "arcfour128": "medium",
  "arcfour256": "medium",
  "hmac-md5": "medium",
  "hmac-md5-96": "medium",
  "diffie-hellman-group1-sha1": "medium",
  "diffie-hellman-group-exchange-sha1": "medium",

  // Débiles pero no rotos: CBC (mitigado hoy) y SHA-1 como MAC.
  "3des-cbc": "low",
  "hmac-sha1": "low",
  "hmac-sha1-96": "low",
};

// Cualquier *-cbc no listado cae a 'low'; el resto es inventario.
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
