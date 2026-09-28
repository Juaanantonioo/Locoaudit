"use strict";

// Parar un servicio systemd con su .socket tiene una sola definición: duplicarla aquí acabaría
// divergiendo de la de los fixes de proceso.
const { systemdDisable, getFixForProcess } = require("../../../lib/process-fix");

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
function getFixForPort(port, platform) {
  const plat = platform || process.platform;

  switch (port) {
    case 22: // SSH
      if (plat === "win32") {
        return "## SSH: si no necesitas el acceso remoto\n" +
               "Desactiva el servicio OpenSSH en Servicios del sistema (services.msc → OpenSSH " +
               "Server → Detener y deshabilitar).";
      }
      if (plat === "darwin") {
        return (
          "## SSH: si no necesitas el acceso remoto\n" +
          "Desactiva la sesión remota:\n" +
          "$ sudo systemsetup -setremotelogin off\n" +
          "## SSH: si lo necesitas, asegúralo\n" +
          "Edita /etc/ssh/sshd_config → PermitRootLogin no, PasswordAuthentication no.\n" +
          "Vuelve a activar la sesión remota:\n" +
          "$ sudo systemsetup -setremotelogin on"
        );
      }
      return (
        "## SSH: si no necesitas el acceso remoto\n" +
        "Deshabilita el servicio:\n" +
        "$ " + systemdDisable("ssh") + "\n" +
        "## SSH: si lo necesitas, asegúralo\n" +
        "Edita /etc/ssh/sshd_config → PermitRootLogin no, PasswordAuthentication no.\n" +
        "Reinicia el servicio:\n" +
        "$ sudo systemctl restart ssh"
      );

    case 21: // FTP
      if (plat === "win32") {
        return "## FTP: si no lo necesitas\n" +
               "Desactiva el servicio FTP en Panel de control → Características de Windows → " +
               "IIS → Servidor FTP.";
      }
      if (plat === "darwin") {
        // macOS no trae servidor FTP, así que el label real se desconoce: ver process-fix.js.
        // Ese texto tiene el comando en la 1ª línea y la explicación detrás del salto.
        return "## FTP: si no lo necesitas\n" + comandoYNota(getFixForProcess("vsftpd", "darwin"));
      }
      return "## FTP: si no lo necesitas\n" +
             "Deshabilita el servicio:\n" +
             "$ " + systemdDisable("vsftpd");

    case 23: // Telnet
      if (plat === "win32") {
        return "## Telnet: si no lo necesitas\n" +
               "Desactiva el cliente Telnet en Panel de control → Características de Windows → " +
               "Cliente Telnet.";
      }
      if (plat === "darwin") {
        return "## Telnet: si no lo necesitas\n" + comandoYNota(getFixForProcess("telnetd", "darwin"));
      }
      return (
        "## Telnet: si no lo necesitas\n" +
        "Deshabilita el servicio:\n" +
        "$ " + systemdDisable("telnet") + "\n" +
        "Si no lo usas, desinstálalo:\n" +
        "$ sudo apt remove telnetd"
      );

    case 80:  // HTTP
    case 443: // HTTPS
      if (plat === "win32") {
        return (
          "## Servidor web: si no lo necesitas\n" +
          "Detén el servicio web de Windows:\n" +
          "$ net stop w3svc\n" +
          "## Servidor web: si lo necesitas\n" +
          "Asegúrate de tener certificado TLS válido y redirige todo HTTP a HTTPS."
        );
      }
      return (
        "## Servidor web: si no lo necesitas\n" +
        "Deshabilita el servidor web:\n" +
        "$ " + systemdDisable("nginx") + "\n" +
        "> Si el servidor es Apache, usa apache2 en vez de nginx en ese comando.\n" +
        "## Servidor web: si lo necesitas\n" +
        "Asegúrate de tener certificado TLS válido y redirige todo HTTP a HTTPS."
      );

    case 3306: // MySQL
      if (plat === "win32") {
        return (
          "## MySQL: limita el acceso\n" +
          "En my.ini añade bind-address = 127.0.0.1 bajo [mysqld].\n" +
          "Reinicia el servicio MySQL desde services.msc."
        );
      }
      return (
        "## MySQL: limita el acceso\n" +
        "Edita /etc/mysql/mysql.conf.d/mysqld.cnf → bind-address = 127.0.0.1\n" +
        "Reinicia el servicio:\n" +
        "$ sudo systemctl restart mysql"
      );

    case 5432: // PostgreSQL
      if (plat === "win32") {
        return (
          "## PostgreSQL: limita el acceso\n" +
          "Edita postgresql.conf → listen_addresses = 'localhost'\n" +
          "Edita pg_hba.conf para restringir IPs.\n" +
          "Reinicia el servicio PostgreSQL desde services.msc."
        );
      }
      return (
        "## PostgreSQL: limita el acceso\n" +
        "Edita postgresql.conf → listen_addresses = 'localhost'\n" +
        "Edita pg_hba.conf para restringir IPs.\n" +
        "Reinicia el servicio:\n" +
        "$ sudo systemctl restart postgresql"
      );

    case 6379: // Redis
      if (plat === "win32") {
        return (
          "## Redis: limita el acceso\n" +
          "Edita redis.windows.conf → bind 127.0.0.1\n" +
          "Añade requirepass con contraseña fuerte.\n" +
          "Reinicia el servicio Redis desde services.msc."
        );
      }
      return (
        "## Redis: limita el acceso\n" +
        "Edita /etc/redis/redis.conf → bind 127.0.0.1\n" +
        "Añade requirepass con contraseña fuerte.\n" +
        "Reinicia el servicio:\n" +
        "$ sudo systemctl restart redis"
      );

    case 27017: // MongoDB
      if (plat === "win32") {
        return (
          "## MongoDB: limita el acceso\n" +
          "Edita mongod.cfg → bindIp: 127.0.0.1\n" +
          "Habilita autenticación: security.authorization: enabled\n" +
          "Reinicia el servicio MongoDB."
        );
      }
      return (
        "## MongoDB: limita el acceso\n" +
        "Edita /etc/mongod.conf → bindIp: 127.0.0.1\n" +
        "Habilita autenticación: security.authorization: enabled"
      );

    default:
      // La guía genérica la arma buildPortFix() en el normalizador, con el bind real y el
      // proceso detectado. Repetirla aquí daba dos versiones divergentes de los mismos pasos.
      return null;
  }
}

module.exports = { parsePortsList, parseTargets, isLocalTarget, toBaseUrl, getFixForPort };
