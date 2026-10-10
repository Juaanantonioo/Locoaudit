"use strict";

// Parar un servicio systemd con su .socket tiene una sola definición: duplicarla aquí acabaría
// divergiendo de la de los fixes de proceso.
const { systemdDisable, getFixForProcess, unitFor } = require("../../../lib/process-fix");
const os = require("os");

/** "80,443,8000-8080" a números ordenados; null si la cadena viene vacía. */
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

/** Targets separados por coma, punto y coma o salto de línea, sin duplicados. */
function parseTargets(input) {
  const raw = String(input || "")
    .split(/[\n,;]/)
    .map((x) => x.trim())
    .filter(Boolean);
  return Array.from(new Set(raw));
}

/**
 * ¿Es `input` una lista de puertos válida para -p? Devuelve { ok: true, spec, count } o
 * { ok: false, empty, reason }.
 *
 * Por qué existe. El campo "Puertos a escanear" del modo personalizado iba tal cual a la línea de
 * nmap (`-p ${portSpec}`), igual que iba la IP antes de validateTarget(): `22; orden` era una
 * orden más para la shell. parsePortsList(), que ya existía, no sirve para esto porque descarta
 * en silencio lo que no entiende, y aquí lo que no se entiende no se escanea: se rechaza.
 *
 * Qué admite: elementos separados por comas, cada uno un puerto (`22`) o un rango (`8000-8080`),
 * de 1 a 65535 y con el inicio del rango menor o igual que el final. Los espacios alrededor de
 * las comas se toleran y desaparecen en `spec`, que es lo que se pasa a nmap. Nada más: ni
 * prefijos de protocolo de nmap (`T:`, `U:`), ni nombres de servicio, ni comodines.
 *
 * `count` son los puertos distintos que cubre la lista, y de él sale el tiempo máximo del escaneo
 * (scanTimeoutMs). Antes el modo personalizado tenía 90 s fijos, y 1-65535 nunca podía terminar.
 */
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

/**
 * Tiempo máximo de nmap, sin contar el de NSE, para un modo y un número de puertos.
 *
 * Rápido y estándar conservan los valores que ya estaban medidos (90 s y 240 s). Completo y
 * personalizado dependen ahora del número de puertos: 62 ms por puerto, que es la misma
 * proporción que daba el límite anterior del modo completo (620 s para 10.000 puertos, medido
 * contra un equipo con cortafuegos, donde cada puerto filtrado espera sus reintentos). Con los
 * 65535 puertos salen unos 68 minutos. Nunca menos de 90 s.
 */
const MS_PER_PORT = 62;
function scanTimeoutMs(scanMode, portCount) {
  if (scanMode === "rapido")   return 90000;
  if (scanMode === "standard") return 240000;
  const n = scanMode === "full" ? 65535 : (Number(portCount) || 0);
  return Math.max(90000, n * MS_PER_PORT);
}

/**
 * ¿Es `input` la dirección IPv4 de UN equipo? Devuelve { ok: true, ip } o { ok: false, reason }.
 *
 * Por qué existe. El campo "Dirección IP del equipo" se pasaba tal cual a la línea de nmap. Con
 * eso pasaban dos cosas, las dos comprobadas:
 *   - Un rango (10.10.10.0/24) se aceptaba, y el nodo está hecho para un equipo: parseNmapXml()
 *     junta los <port> de todos los <host> sin decir de cuál es cada uno, y el hostname es el
 *     del primero. Un escaneo de red que terminase daría los puertos de varios equipos como si
 *     fueran de uno, con el nombre de otro. Medido con un /24 real: no llegó a terminar
 *     (420 s de límite, -Pn sondea las 256 direcciones), pero con un rango pequeño sí terminaría.
 *   - El texto llegaba a la shell sin filtrar: `1.2.3.4; cualquier-cosa` era una orden más.
 *
 * Qué admite: solo cuatro octetos decimales, 0-255, sin ceros a la izquierda (`010` lo lee nmap
 * como octal en algunas versiones y apunta a otro equipo). Nada de nombres, rangos, máscaras,
 * listas ni IPv6: el comando no lleva -6 y findInterfaceForTarget() solo entiende IPv4, así que
 * aceptarlos sería prometer algo que el resto del nodo no hace.
 *
 * Qué rechaza aunque tenga forma de IPv4, porque no es la dirección de un equipo:
 *   0.0.0.0/8 ("esta red"), 224.0.0.0/4 (multidifusión), 240.0.0.0/4 (reservada, incluye la
 *   difusión 255.255.255.255), y la dirección de red o de difusión de una subred a la que este
 *   equipo está conectado. Esta última solo se puede saber para las subredes propias, que son
 *   las que conocemos por su máscara; para una subred remota no hay forma de distinguirla.
 *
 * Es la única regla: audit-network.html hace una comprobación de forma para pintar el campo en
 * rojo, pero quien decide si se escanea es esta función.
 */
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

  // Red y difusión de las subredes propias. /31 y /32 no tienen ninguna de las dos (RFC 3021).
  const toInt = (parts) => parts.reduce((acc, o) => ((acc << 8) | o) >>> 0, 0);
  const target = toInt(n);
  for (const [name, addrs] of Object.entries(interfaces || {})) {
    for (const addr of addrs || []) {
      if (addr.family !== "IPv4" && addr.family !== 4) continue;
      if (addr.internal) continue;
      const mask = toInt(addr.netmask.split(".").map(Number));
      if (mask >= 0xFFFFFFFE) continue;
      const network   = (toInt(addr.address.split(".").map(Number)) & mask) >>> 0;
      const broadcast = (network | (~mask >>> 0)) >>> 0;
      if (target === network) {
        return { ok: false, reason: `${ip} es la dirección de la red ${addr.cidr || ip} (interfaz ${name}), no la de un equipo.` };
      }
      if (target === broadcast) {
        return { ok: false, reason: `${ip} es la dirección de difusión de la red ${addr.cidr || ""} (interfaz ${name}), no la de un equipo.`.replace(" ()", "") };
      }
    }
  }

  return { ok: true, ip };
}

/** Decide si el objetivo es este equipo, y con eso si se ejecutan lsof y el descubrimiento. */
function isLocalTarget(target) {
  const t = (target || "").trim().toLowerCase();
  return t === "127.0.0.1" || t === "localhost" || t === "::1";
}

/** URL base, con el puerto omitido si es el que corresponde al protocolo. */
function toBaseUrl(protocol, host, port) {
  const defaultPort = protocol === "https" ? 443 : 80;
  const showPort = port !== defaultPort;
  return `${protocol}://${host}${showPort ? ":" + port : ""}`;
}

/**
 * Las entradas de FTP y telnet para macOS de lib/process-fix.js —fichero que no se edita desde
 * aquí— tienen esta forma exacta: comando en la primera línea y explicación detrás del salto.
 * Se traducen a "paso + $ comando + > nota" sin adivinar nada: el troceo es por \n, no por
 * el aspecto del texto.
 */
function comandoYNota(texto) {
  const [cmd, ...resto] = String(texto || "").split("\n").map((l) => l.trim()).filter(Boolean);
  const out = ["Identifica el servicio real y deshabilítalo:", `$ ${cmd}`];
  resto.forEach((l) => out.push(`> ${l}`));
  return out.join("\n");
}

/**
 * Fix por puerto conocido y plataforma; null si no hay uno específico.
 *
 * Gramática (la misma que el resto de los `fix`, y la que lee el dashboard):
 *   "## " abre una rama excluyente · "$ " es el comando del paso anterior · "> " es una nota
 *   que no se numera · el resto son pasos. Nunca "1)" ni "2)": el orden lo pone la lista.
 *
 * Los subtítulos llevan delante el servicio ("SSH: …") porque buildPortFix() concatena este
 * texto DETRÁS de su propia pareja "Si no lo necesitas / Si lo necesitas": sin el prefijo se
 * leerían como la misma rama repetida.
 *
 * LÍMITE CONOCIDO, no corregido aquí: para 80, 443, 3306, 5432, 6379 y 27017 solo win32 tiene
 * rama propia, así que macOS recibe los comandos de Linux (systemctl, rutas de /etc). Estaba
 * así antes de migrar los textos y arreglarlo es otro trabajo.
 */
function getFixForPort(port, platform, pkgManager) {
  const plat = platform || process.platform;
  const m = pkgManager || null;
  // Las órdenes salen de process-fix.js, la misma tabla que usa el fix por proceso. Antes este
  // switch repetía el texto a mano y la copia se desincronizó: macOS recibía las órdenes de Linux
  // (systemctl, /etc/mysql) en los puertos 80, 443, 3306, 5432, 6379 y 27017.
  const lines = (texto) => String(texto).split("\n").map((l) => l.trim()).filter(Boolean);
  // A la gramática del dashboard: una línea que empieza por sudo es el comando del paso; "texto:
  // sudo …" es un paso con su comando; la primera línea sin comando es el paso; el resto, notas.
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
      // PasswordAuthentication no sin una clave ya configurada deja al usuario fuera del equipo:
      // la versión anterior lo recomendaba sin avisar. `sshd -T` muestra la configuración
      // efectiva, que es la que cuenta: un fichero de /etc/ssh/sshd_config.d/ puede imponerse
      // al principal.
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
        // macOS no trae servidor FTP, así que el label real se desconoce: ver process-fix.js.
        // Ese texto tiene el comando en la 1ª línea y la explicación detrás del salto.
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
      // La guía genérica la arma buildPortFix() en el normalizador, con el bind real y el
      // proceso detectado. Repetirla aquí daba dos versiones divergentes de los mismos pasos.
      return null;
  }
}

module.exports = { parsePortsList, parseTargets, validatePortSpec, scanTimeoutMs, validateTarget, isLocalTarget, toBaseUrl, getFixForPort };
