"use strict";

// Las órdenes de parada salen de process-fix para no duplicarlas.
const { systemdDisable, getFixForProcess, unitFor } = require("../../../lib/process-fix");
const os = require("os");

// "80,443,8000-8080" a números ordenados; null si viene vacía.
function parsePortsList(input) {
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
function parseTargets(input) {
  const raw = String(input || "")
    .split(/[\n,;]/)
    .map((x) => x.trim())
    .filter(Boolean);
  return Array.from(new Set(raw));
}

// Valida la lista para -p (va a la línea de nmap): lo que no se entiende se rechaza, no se descarta.
// Devuelve { ok, spec, count } o { ok: false, empty, reason }; count alimenta scanTimeoutMs().
function validatePortSpec(input) {
  const raw = String(input == null ? "" : input).trim();
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
    const b = m[2] ? Number(m[2]) : a;
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

  const spec = ranges.map(([a, b]) => (a === b ? String(a) : `${a}-${b}`)).join(",");
  return { ok: true, spec, count };
}

// Tiempo máximo de nmap sin NSE: 62 ms por puerto, medido contra un equipo con cortafuegos.
const MS_PER_PORT = 62;
function scanTimeoutMs(scanMode, portCount) {
  if (scanMode === "rapido")   return 90000;
  if (scanMode === "standard") return 240000;
  const n = scanMode === "full" ? 65535 : (Number(portCount) || 0);
  return Math.max(90000, n * MS_PER_PORT);
}

// Solo una IPv4 de un equipo de una red propia: el valor acaba en la línea de nmap y un rango mezclaría hosts.
// Esta función decide; audit-network.html solo marca el campo. Sin ceros a la izquierda (nmap los lee en octal).
function validateTarget(input, interfaces = os.networkInterfaces()) {
  const raw = String(input == null ? "" : input).trim();
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
  const toInt = (parts) => parts.reduce((acc, o) => ((acc << 8) | o) >>> 0, 0);
  const target = toInt(n);
  let inOwnSubnet = false;
  for (const [name, addrs] of Object.entries(interfaces || {})) {
    for (const addr of addrs || []) {
      if (addr.family !== "IPv4" && addr.family !== 4) continue;
      if (addr.internal) continue;
      const mask = toInt(addr.netmask.split(".").map(Number));
      // Máscara 0.0.0.0 haría de cualquier IP "su red".
      if (mask === 0) continue;
      const network = (toInt(addr.address.split(".").map(Number)) & mask) >>> 0;
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
function isLocalTarget(target) {
  const t = (target || "").trim().toLowerCase();
  return t === "127.0.0.1" || t === "localhost" || t === "::1";
}

// URL base, sin el puerto si es el del protocolo.
function toBaseUrl(protocol, host, port) {
  const defaultPort = protocol === "https" ? 443 : 80;
  const showPort = port !== defaultPort;
  return `${protocol}://${host}${showPort ? ":" + port : ""}`;
}

// Los textos de macOS de process-fix traen el comando en la primera línea y la nota detrás.
function comandoYNota(texto) {
  const [cmd, ...resto] = String(texto || "").split("\n").map((l) => l.trim()).filter(Boolean);
  const out = ["Identifica el servicio real y deshabilítalo:", `$ ${cmd}`];
  resto.forEach((l) => out.push(`> ${l}`));
  return out.join("\n");
}

// Fix por puerto y plataforma, o null. Gramática del dashboard: "## " rama, "$ " comando, "> " nota, resto pasos.
// Los subtítulos llevan el servicio porque buildPortFix() los concatena tras sus propias ramas.
function getFixForPort(port, platform, pkgManager) {
  const plat = platform || process.platform;
  const m = pkgManager || null;
  // Las órdenes salen de process-fix.js, la misma tabla que el fix por proceso.
  const lines = (texto) => String(texto).split("\n").map((l) => l.trim()).filter(Boolean);
  // "sudo …" es comando, "texto: sudo …" paso con comando, la primera línea el paso y el resto notas.
  const cmdAndNotes = (texto) => {
    const out = [];
    lines(texto).forEach((l, i) => {
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
          ...cmdAndNotes(getFixForProcess("sshd", "darwin")),
          "## SSH: si lo necesitas, asegúralo",
          ...harden,
          "Aplica los cambios desactivando y volviendo a activar «Sesión remota» en Ajustes del Sistema → General → Compartido.",
        ].join("\n");
      }
      const { unit } = unitFor("ssh", m);
      return [
        "## SSH: si no necesitas el acceso remoto",
        "Deshabilita el servicio:",
        ...cmdAndNotes(getFixForProcess("sshd", "linux", m)),
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
        return "## FTP: si no lo necesitas\n" + comandoYNota(getFixForProcess("vsftpd", "darwin"));
      }
      return "## FTP: si no lo necesitas\n" +
             "Deshabilita el servicio:\n" +
             "$ " + systemdDisable("vsftpd") + "\n" +
             "> Si tu servidor FTP es otro (proftpd, pure-ftpd), cambia vsftpd por su nombre en el comando.";

    case 23: // Telnet
      if (plat === "darwin") {
        return "## Telnet: si no lo necesitas\n" + comandoYNota(getFixForProcess("telnetd", "darwin"));
      }
      return ["## Telnet: si no lo necesitas", ...cmdAndNotes(getFixForProcess("telnetd", plat, m))].join("\n");

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
          "$ " + getFixForProcess("apache", "darwin") + "\n" +
          "## Servidor web: si lo necesitas\n" +
          "Asegúrate de tener certificado TLS válido y redirige todo HTTP a HTTPS."
        );
      }
      {
        const ap = unitFor("apache", m);
        return (
          "## Servidor web: si no lo necesitas\n" +
          "Deshabilita el servidor web:\n" +
          "$ " + systemdDisable("nginx") + "\n" +
          `> Si el servidor es Apache, usa ${ap.unit} en vez de nginx en ese comando` +
          (ap.note ? ` (${ap.note.trim().replace(/^\(|\)$/g, "").replace(/\.$/, "")}).` : ".") + "\n" +
          "## Servidor web: si lo necesitas\n" +
          "Asegúrate de tener certificado TLS válido y redirige todo HTTP a HTTPS."
        );
      }

    case 3306: // MySQL
      return ["## MySQL: limita el acceso", ...cmdAndNotes(getFixForProcess("mysqld", plat, m))].join("\n");

    case 5432: // PostgreSQL
      return ["## PostgreSQL: limita el acceso", ...cmdAndNotes(getFixForProcess("postgres", plat, m))].join("\n");

    case 6379: // Redis
      return ["## Redis: limita el acceso", ...cmdAndNotes(getFixForProcess("redis", plat, m))].join("\n");

    case 27017: // MongoDB
      return ["## MongoDB: limita el acceso", ...cmdAndNotes(getFixForProcess("mongod", plat, m))].join("\n");

    default:
      // La guía genérica la arma buildPortFix() con el bind y el proceso reales.
      return null;
  }
}

module.exports = { parsePortsList, parseTargets, validatePortSpec, scanTimeoutMs, validateTarget, isLocalTarget, toBaseUrl, getFixForPort };
