"use strict";

// Las órdenes de parada salen de process-fix para no duplicarlas.
const { desactivarSystemd, solucionProceso, unidadDe } = require("../../../lib/process-fix");
const os = require("os");

// "80,443,8000-8080" a números ordenados; null si viene vacía.
function leerPuertos(input) {
  const s = (input || "").trim();
  if (!s) return null;

  const ports = new Set();
  const parts = s
    .split(",")
    .map((x) => x.trim())
    .filter(Boolean);

  for (const p of parts) {
    if (p.includes("-")) {
      const [a, b] = p.split("-").map((x) => parseInt(x.trim(), 10));
      if (!Number.isNaN(a) && !Number.isNaN(b) && a > 0 && b <= 65535 && a <= b) {
        for (let i = a; i <= b; i++) ports.add(i);
      }
    } else {
      const n = parseInt(p, 10);
      if (!Number.isNaN(n) && n > 0 && n <= 65535) ports.add(n);
    }
  }

  return Array.from(ports).sort((x, y) => x - y);
}

// Objetivos separados por coma, punto y coma o salto de línea, sin duplicados.
function leerObjetivos(input) {
  const raw = String(input || "")
    .split(/[\n,;]/)
    .map((x) => x.trim())
    .filter(Boolean);
  return Array.from(new Set(raw));
}

// Valida la lista para -p (va a la línea de nmap): lo que no se entiende se rechaza, no se descarta.
// Devuelve { ok, spec, count } o { ok: false, empty, reason }; count alimenta tiempoMaximoEscaneo().
function validarPuertos(input) {
  let valor;
  if (input == null) {
    valor = "";
  } else {
    valor = input;
  }
  const raw = String(valor).trim();
  if (!raw) return { ok: false, empty: true, reason: "No se ha indicado ningún puerto." };

  const items = raw.split(",").map((x) => x.trim());
  const ranges = [];
  for (const item of items) {
    const m = item.match(/^([1-9]\d{0,4})(?:-([1-9]\d{0,4}))?$/);
    if (!m) {
      return {
        ok: false, empty: false,
        reason: `«${item.slice(0, 30)}» no es un puerto ni un rango válido. Se admiten puertos ` +
                "sueltos y rangos separados por comas, por ejemplo 22,80,443,8000-8080.",
      };
    }
    const a = Number(m[1]);
    let b;
    if (m[2]) {
      b = Number(m[2]);
    } else {
      b = a;
    }
    if (a > 65535 || b > 65535) {
      return { ok: false, empty: false, reason: `«${item}»: los puertos van del 1 al 65535.` };
    }
    if (a > b) {
      return { ok: false, empty: false, reason: `«${item}»: el inicio del rango es mayor que el final.` };
    }
    ranges.push([a, b]);
  }

  // Puertos distintos, sin construir el conjunto: con 1-65535 serían 65535 enteros en memoria.
  const sorted = ranges.slice().sort((x, y) => x[0] - y[0]);
  let count = 0, curA = null, curB = null;
  for (const [a, b] of sorted) {
    if (curB === null || a > curB + 1) {
      if (curB !== null) count += curB - curA + 1;
      curA = a; curB = b;
    } else if (b > curB) {
      curB = b;
    }
  }
  if (curB !== null) count += curB - curA + 1;

  const spec = ranges.map(([a, b]) => {
    if (a === b) {
      return String(a);
    } else {
      return `${a}-${b}`;
    }
  }).join(",");
  return { ok: true, spec, count };
}

// Tiempo máximo de nmap sin NSE: 62 ms por puerto, medido contra un equipo con cortafuegos.
const MS_PER_PORT = 62;
function tiempoMaximoEscaneo(scanMode, portCount) {
  if (scanMode === "rapido")   return 90000;
  if (scanMode === "standard") return 240000;
  let n;
  if (scanMode === "full") {
    n = 65535;
  } else {
    n = Number(portCount) || 0;
  }
  return Math.max(90000, n * MS_PER_PORT);
}

// Solo una IPv4 de un equipo de una red propia: el valor acaba en la línea de nmap y un rango mezclaría hosts.
// Esta función decide; audit-network.html solo marca el campo. Sin ceros a la izquierda (nmap los lee en octal).
function validarObjetivo(input, interfaces = os.networkInterfaces()) {
  let valor;
  if (input == null) {
    valor = "";
  } else {
    valor = input;
  }
  const raw = String(valor).trim();
  if (!raw) {
    return { ok: false, reason: "No se ha indicado ninguna dirección IP." };
  }

  const m = raw.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (!m) {
    return {
      ok: false,
      reason: "No es una dirección IPv4 de un solo equipo. Se admite una dirección con el formato " +
              "192.168.1.10, sin rangos (/24, 1-20), listas, nombres de equipo ni otros caracteres.",
    };
  }

  const octets = m.slice(1);
  if (octets.some((o) => o.length > 1 && o.startsWith("0"))) {
    return { ok: false, reason: "Los números de la dirección no pueden llevar ceros a la izquierda." };
  }
  const n = octets.map(Number);
  if (n.some((o) => o > 255)) {
    return { ok: false, reason: "Cada número de la dirección tiene que estar entre 0 y 255." };
  }

  const ip = n.join(".");
  if (n[0] === 0) {
    return { ok: false, reason: `${ip} no es la dirección de un equipo (rango 0.0.0.0/8, reservado).` };
  }
  if (n[0] >= 224 && n[0] <= 239) {
    return { ok: false, reason: `${ip} es una dirección de multidifusión, no la de un equipo.` };
  }
  if (n[0] >= 240) {
    return { ok: false, reason: `${ip} es una dirección reservada o de difusión, no la de un equipo.` };
  }

  // /31 y /32 no tienen dirección de red ni de difusión (RFC 3021).
  const aEntero = (parts) => parts.reduce((acc, o) => ((acc << 8) | o) >>> 0, 0);
  const target = aEntero(n);
  let inOwnSubnet = false;
  for (const [name, addrs] of Object.entries(interfaces || {})) {
    for (const addr of addrs || []) {
      if (addr.family !== "IPv4" && addr.family !== 4) continue;
      if (addr.internal) continue;
      const mask = aEntero(addr.netmask.split(".").map(Number));
      // Máscara 0.0.0.0 haría de cualquier IP "su red".
      if (mask === 0) continue;
      const network = (aEntero(addr.address.split(".").map(Number)) & mask) >>> 0;
      if (((target & mask) >>> 0) === network) inOwnSubnet = true;
      if (mask >= 0xFFFFFFFE) continue;
      const broadcast = (network | (~mask >>> 0)) >>> 0;
      if (target === network) {
        return { ok: false, reason: `${ip} es la dirección de la red ${addr.cidr || ip} (interfaz ${name}), no la de un equipo.` };
      }
      if (target === broadcast) {
        return { ok: false, reason: `${ip} es la dirección de difusión de la red ${addr.cidr || ""} (interfaz ${name}), no la de un equipo.`.replace(" ()", "") };
      }
    }
  }

  // Ser privada no basta: tiene que ser loopback o de una subred de este equipo.
  if (n[0] !== 127 && !inOwnSubnet) {
    return {
      ok: false,
      reason: `${ip} no está en la misma red que este equipo. Solo se auditan equipos de una red a la que ` +
              "esté conectado este equipo.",
    };
  }

  return { ok: true, ip };
}

// Si es este equipo se usa lsof y se omite el descubrimiento.
function esObjetivoLocal(target) {
  const t = (target || "").trim().toLowerCase();
  return t === "127.0.0.1" || t === "localhost" || t === "::1";
}

// URL base, sin el puerto si es el del protocolo.
function urlBase(protocol, host, port) {
  let defaultPort;
  if (protocol === "https") {
    defaultPort = 443;
  } else {
    defaultPort = 80;
  }
  const showPort = port !== defaultPort;
  let sufijo;
  if (showPort) {
    sufijo = ":" + port;
  } else {
    sufijo = "";
  }
  return `${protocol}://${host}${sufijo}`;
}

// Los textos de macOS de process-fix traen el comando en la primera línea y la nota detrás.
function comandoYNota(texto) {
  const [cmd, ...resto] = String(texto || "").split("\n").map((l) => l.trim()).filter(Boolean);
  const out = ["Identifica el servicio real y deshabilítalo:", `$ ${cmd}`];
  resto.forEach((l) => out.push(`> ${l}`));
  return out.join("\n");
}

// Fix por puerto y plataforma, o null. Gramática del dashboard: "## " rama, "$ " comando, "> " nota, resto pasos.
// Los subtítulos llevan el servicio porque solucionDePuerto() los concatena tras sus propias ramas.
function solucionPorPuerto(port, platform, pkgManager) {
  const plat = platform || process.platform;
  const m = pkgManager || null;
  // Las órdenes salen de process-fix.js, la misma tabla que el fix por proceso.
  const lineas = (texto) => String(texto).split("\n").map((l) => l.trim()).filter(Boolean);
  // "sudo …" es comando, "texto: sudo …" paso con comando, la primera línea el paso y el resto notas.
  const comandosYNotas = (texto) => {
    const out = [];
    lineas(texto).forEach((l, i) => {
      const conCmd = /^(.*?):\s+(sudo\s.+)$/.exec(l);
      if (/^sudo\s/.test(l)) out.push(`$ ${l}`);
      else if (conCmd) out.push(`${conCmd[1]}:`, `$ ${conCmd[2]}`);
      else if (i === 0) out.push(l);
      else out.push(`> ${l.replace(/^\((.*)\)$/, "$1")}`);
    });
    return out;
  };

  switch (port) {
    case 22: { // SSH
      if (plat === "win32") {
        return "## SSH: si no necesitas el acceso remoto\n" +
               "Desactiva el servicio OpenSSH en Servicios del sistema (services.msc → OpenSSH SSH " +
               "Server → Detener y deshabilitar).";
      }
      // Sin una clave ya configurada, `PasswordAuthentication no` deja fuera al usuario: por eso se avisa.
      // `sshd -T` muestra la configuración efectiva, incluida la de sshd_config.d/.
      const harden = [
        "Edita /etc/ssh/sshd_config → PermitRootLogin no.",
        "Si ya entras con clave SSH, añade PasswordAuthentication no. Sin una clave configurada, ese cambio te dejaría sin acceso.",
        "Comprueba la configuración que queda en vigor:",
        "$ sudo sshd -T | grep -Ei 'permitrootlogin|passwordauthentication'",
      ];
      if (plat === "darwin") {
        return [
          "## SSH: si no necesitas el acceso remoto",
          "Desactiva la sesión remota:",
          ...comandosYNotas(solucionProceso("sshd", "darwin")),
          "## SSH: si lo necesitas, asegúralo",
          ...harden,
          "Aplica los cambios desactivando y volviendo a activar «Sesión remota» en Ajustes del Sistema → General → Compartido.",
        ].join("\n");
      }
      const { unit } = unidadDe("ssh", m);
      return [
        "## SSH: si no necesitas el acceso remoto",
        "Deshabilita el servicio:",
        ...comandosYNotas(solucionProceso("sshd", "linux", m)),
        "## SSH: si lo necesitas, asegúralo",
        ...harden,
        "Reinicia el servicio:",
        `$ sudo systemctl restart ${unit}`,
      ].join("\n");
    }

    case 21: // FTP
      if (plat === "win32") {
        return "## FTP: si no lo necesitas\n" +
               "Desactiva el servicio FTP en Panel de control → Características de Windows → " +
               "IIS → Servidor FTP. Si no usas IIS, el puerto lo abre otro programa (por ejemplo, " +
               "FileZilla Server): identifícalo con netstat -ano | findstr :21.";
      }
      if (plat === "darwin") {
        // macOS no trae servidor FTP, así que no se conoce el label real.
        return "## FTP: si no lo necesitas\n" + comandoYNota(solucionProceso("vsftpd", "darwin"));
      }
      return "## FTP: si no lo necesitas\n" +
             "Deshabilita el servicio:\n" +
             "$ " + desactivarSystemd("vsftpd") + "\n" +
             "> Si tu servidor FTP es otro (proftpd, pure-ftpd), cambia vsftpd por su nombre en el comando.";

    case 23: // Telnet
      if (plat === "darwin") {
        return "## Telnet: si no lo necesitas\n" + comandoYNota(solucionProceso("telnetd", "darwin"));
      }
      return ["## Telnet: si no lo necesitas", ...comandosYNotas(solucionProceso("telnetd", plat, m))].join("\n");

    case 80:  // HTTP
    case 443: // HTTPS
      if (plat === "win32") {
        return (
          "## Servidor web: si no lo necesitas\n" +
          "Detén el servicio web de Windows:\n" +
          "$ net stop w3svc\n" +
          "> Si net stop dice que el servicio no existe, el puerto lo abre otro programa: identifícalo con netstat -ano | findstr :" + port + ".\n" +
          "## Servidor web: si lo necesitas\n" +
          "Asegúrate de tener certificado TLS válido y redirige todo HTTP a HTTPS."
        );
      }
      if (plat === "darwin") {
        return (
          "## Servidor web: si no lo necesitas\n" +
          "Si es nginx instalado con Homebrew:\n" +
          "$ brew services stop nginx\n" +
          "Si es el Apache que trae macOS:\n" +
          "$ " + solucionProceso("apache", "darwin") + "\n" +
          "## Servidor web: si lo necesitas\n" +
          "Asegúrate de tener certificado TLS válido y redirige todo HTTP a HTTPS."
        );
      }
      {
        const ap = unidadDe("apache", m);
        let cierre;
        if (ap.note) {
          cierre = ` (${ap.note.trim().replace(/^\(|\)$/g, "").replace(/\.$/, "")}).`;
        } else {
          cierre = ".";
        }
        return (
          "## Servidor web: si no lo necesitas\n" +
          "Deshabilita el servidor web:\n" +
          "$ " + desactivarSystemd("nginx") + "\n" +
          `> Si el servidor es Apache, usa ${ap.unit} en vez de nginx en ese comando` +
          cierre + "\n" +
          "## Servidor web: si lo necesitas\n" +
          "Asegúrate de tener certificado TLS válido y redirige todo HTTP a HTTPS."
        );
      }

    case 3306: // MySQL
      return ["## MySQL: limita el acceso", ...comandosYNotas(solucionProceso("mysqld", plat, m))].join("\n");

    case 5432: // PostgreSQL
      return ["## PostgreSQL: limita el acceso", ...comandosYNotas(solucionProceso("postgres", plat, m))].join("\n");

    case 6379: // Redis
      return ["## Redis: limita el acceso", ...comandosYNotas(solucionProceso("redis", plat, m))].join("\n");

    case 27017: // MongoDB
      return ["## MongoDB: limita el acceso", ...comandosYNotas(solucionProceso("mongod", plat, m))].join("\n");

    default:
      // La guía genérica la arma solucionDePuerto() con el bind y el proceso reales.
      return null;
  }
}

module.exports = { leerPuertos, leerObjetivos, validarPuertos, tiempoMaximoEscaneo, validarObjetivo, esObjetivoLocal, urlBase, solucionPorPuerto };
