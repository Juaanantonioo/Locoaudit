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

/** Fix por puerto conocido y plataforma; null si no hay uno específico. */
function getFixForPort(port, platform) {
  const plat = platform || process.platform;

  switch (port) {
    case 22: // SSH
      if (plat === "win32") {
        return "Desactiva el servicio OpenSSH en Servicios del sistema (services.msc → OpenSSH Server → Detener y deshabilitar).";
      }
      if (plat === "darwin") {
        return (
          "Para deshabilitar: sudo systemsetup -setremotelogin off\n" +
          "Para asegurar: edita /etc/ssh/sshd_config → PermitRootLogin no, PasswordAuthentication no.\n" +
          "Luego reactiva con: sudo systemsetup -setremotelogin on"
        );
      }
      return (
        "Para deshabilitar: " + systemdDisable("ssh") + "\n" +
        "Para asegurar: edita /etc/ssh/sshd_config → PermitRootLogin no, PasswordAuthentication no.\n" +
        "Luego: sudo systemctl restart ssh"
      );

    case 21: // FTP
      if (plat === "win32") {
        return "Desactiva el servicio FTP en Panel de control → Características de Windows → IIS → Servidor FTP.";
      }
      if (plat === "darwin") {
        // macOS no trae servidor FTP, así que el label real se desconoce: ver process-fix.js.
        return getFixForProcess("vsftpd", "darwin");
      }
      return systemdDisable("vsftpd");

    case 23: // Telnet
      if (plat === "win32") {
        return "Desactiva el cliente Telnet en Panel de control → Características de Windows → Cliente Telnet.";
      }
      if (plat === "darwin") {
        return getFixForProcess("telnetd", "darwin");
      }
      return systemdDisable("telnet") + "\nSi no lo usas, desinstálalo: sudo apt remove telnetd";

    case 80:  // HTTP
    case 443: // HTTPS
      if (plat === "win32") {
        return (
          "Si no necesitas servidor web: net stop w3svc\n" +
          "Si lo necesitas: asegúrate de tener certificado TLS válido y redirige todo HTTP a HTTPS."
        );
      }
      return (
        "Si no necesitas servidor web: " + systemdDisable("nginx") + " (o apache2 en vez de nginx)\n" +
        "Si lo necesitas: asegúrate de tener certificado TLS válido y redirige todo HTTP a HTTPS."
      );

    case 3306: // MySQL
      if (plat === "win32") {
        return (
          "Limita acceso: en my.ini añade bind-address = 127.0.0.1 bajo [mysqld].\n" +
          "Luego reinicia el servicio MySQL desde services.msc."
        );
      }
      return (
        "Limita acceso: edita /etc/mysql/mysql.conf.d/mysqld.cnf → bind-address = 127.0.0.1\n" +
        "Luego: sudo systemctl restart mysql"
      );

    case 5432: // PostgreSQL
      if (plat === "win32") {
        return (
          "Limita acceso: edita postgresql.conf → listen_addresses = 'localhost'\n" +
          "y pg_hba.conf para restringir IPs. Luego reinicia el servicio PostgreSQL desde services.msc."
        );
      }
      return (
        "Limita acceso: edita postgresql.conf → listen_addresses = 'localhost'\n" +
        "y pg_hba.conf para restringir IPs. Luego: sudo systemctl restart postgresql"
      );

    case 6379: // Redis
      if (plat === "win32") {
        return (
          "Edita redis.windows.conf → bind 127.0.0.1\n" +
          "Añade requirepass con contraseña fuerte. Luego reinicia el servicio Redis desde services.msc."
        );
      }
      return (
        "Edita /etc/redis/redis.conf → bind 127.0.0.1\n" +
        "Añade requirepass con contraseña fuerte. Luego: sudo systemctl restart redis"
      );

    case 27017: // MongoDB
      if (plat === "win32") {
        return (
          "Edita mongod.cfg → bindIp: 127.0.0.1\n" +
          "Habilita autenticación: security.authorization: enabled. Luego reinicia el servicio MongoDB."
        );
      }
      return (
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
