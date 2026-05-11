"use strict";

/**
 * process-fix.js — Fix concreto a partir del nombre de proceso o imagen.
 *
 * Fuente centralizada usada por los tres nodos de auditoría:
 *   audit-network → fix para puertos cuyo proceso es conocido aunque el puerto no esté en catálogo
 *   audit-host    → fix para servicios peligrosos detectados en el inventario de software
 *   audit-image   → fix para contenedores cuyo servicio se identifica por nombre de imagen
 *
 * API pública:
 *   getFixForProcess(rawName, platform)  → string|null
 *   normalizeName(raw)                   → string
 *   DANGEROUS_SERVICES                   → Set<string>  (nombres normalizados)
 */

/**
 * Normaliza el nombre de un proceso o imagen a su forma canónica en minúsculas.
 * Elimina rutas, sufijos .exe, versiones de imagen y texto extra tras el primer espacio.
 *
 * Ejemplos:
 *   "/usr/sbin/sshd"        → "sshd"
 *   "nginx: master process" → "nginx"
 *   "mysql:8.0"             → "mysql"
 *   "Python.exe"            → "python"
 *
 * @param {string} raw
 * @returns {string}
 */
function normalizeName(raw) {
  if (!raw || typeof raw !== "string") return "";
  return raw
    .split(/[/\\]/).pop()        // basename (quita ruta)
    .split(/[\s:]/)[0]           // primer token (quita " master process", ":8.0", etc.)
    .toLowerCase()
    .replace(/\.exe$/i, "")      // quita .exe en Windows
    .replace(/\d+$/, "")         // quita sufijo numérico (python3 → python)
    .trim();
}

// ── Mapa de nombres de proceso/imagen → función de fix ──────────────────────

const FIXES = {
  // SSH
  sshd: (p) => p === "win32"
    ? "Desactiva el servicio OpenSSH en services.msc → OpenSSH Server → Detener y deshabilitar."
    : p === "darwin"
      ? "sudo systemsetup -setremotelogin off"
      : "sudo systemctl stop ssh && sudo systemctl disable ssh",

  // FTP
  vsftpd: (p) => p === "win32"
    ? "Desactiva el servicio FTP en Panel de control → Características de Windows → IIS."
    : p === "darwin"
      ? "sudo launchctl disable system/ftp"
      : "sudo systemctl stop vsftpd && sudo systemctl disable vsftpd",
  ftpd:       (p) => FIXES.vsftpd(p),
  proftpd:    (p) => p === "linux"
    ? "sudo systemctl stop proftpd && sudo systemctl disable proftpd"
    : FIXES.vsftpd(p),
  "pure-ftpd": (p) => p === "linux"
    ? "sudo systemctl stop pure-ftpd && sudo systemctl disable pure-ftpd"
    : FIXES.vsftpd(p),

  // Telnet
  telnetd: (p) => p === "win32"
    ? "Desactiva el cliente Telnet en Panel de control → Características de Windows."
    : p === "darwin"
      ? "sudo launchctl disable system/telnet"
      : "sudo systemctl stop telnet && sudo apt remove telnetd",

  // MySQL / MariaDB
  mysqld: (p) => p === "win32"
    ? "Limita acceso: en my.ini añade bind-address = 127.0.0.1 bajo [mysqld].\nLuego reinicia MySQL desde services.msc."
    : "Limita acceso: edita /etc/mysql/mysql.conf.d/mysqld.cnf → bind-address = 127.0.0.1\nLuego: sudo systemctl restart mysql",
  mysql:    (p) => FIXES.mysqld(p),
  mariadbd: (p) => p === "win32"
    ? "Limita acceso: en my.ini añade bind-address = 127.0.0.1 bajo [mysqld].\nLuego reinicia MariaDB desde services.msc."
    : "Limita acceso: edita /etc/mysql/mariadb.conf.d/50-server.cnf → bind-address = 127.0.0.1\nLuego: sudo systemctl restart mariadb",
  mariadb: (p) => FIXES.mariadbd(p),

  // PostgreSQL
  postgres: (p) => p === "win32"
    ? "Edita postgresql.conf → listen_addresses = 'localhost'.\nLuego reinicia el servicio PostgreSQL desde services.msc."
    : "Edita postgresql.conf → listen_addresses = 'localhost'\ny pg_hba.conf para restringir IPs. Luego: sudo systemctl restart postgresql",
  postgresql: (p) => FIXES.postgres(p),

  // Redis
  "redis-server": (p) => p === "win32"
    ? "Edita redis.windows.conf → bind 127.0.0.1 y añade requirepass.\nLuego reinicia Redis desde services.msc."
    : "Edita /etc/redis/redis.conf → bind 127.0.0.1\nAñade requirepass con contraseña fuerte. Luego: sudo systemctl restart redis",
  redis: (p) => FIXES["redis-server"](p),

  // MongoDB
  mongod: (p) => p === "win32"
    ? "Edita mongod.cfg → bindIp: 127.0.0.1 y habilita security.authorization: enabled.\nLuego reinicia MongoDB desde services.msc."
    : "Edita /etc/mongod.conf → bindIp: 127.0.0.1\nHabilita autenticación: security.authorization: enabled",
  mongodb: (p) => FIXES.mongod(p),
  mongo:   (p) => FIXES.mongod(p),

  // Web servers
  nginx: (p) => p === "win32"
    ? "Si no necesitas nginx: nginx -s stop\nSi lo usas: asegúrate de tener TLS válido y redirigir HTTP a HTTPS."
    : "Si no necesitas nginx: sudo systemctl stop nginx && sudo systemctl disable nginx\nSi lo usas: asegúrate de tener TLS válido y redirigir HTTP a HTTPS.",
  apache: (p) => p === "darwin"
    ? "sudo apachectl stop && sudo launchctl disable system/org.apache.httpd"
    : p === "win32"
      ? "net stop Apache2.4"
      : "sudo systemctl stop apache2 && sudo systemctl disable apache2",
  apache2: (p) => FIXES.apache(p),
  httpd:   (p) => FIXES.apache(p),

  // Dev servers (no plataforma específica)
  node:    () => "Asegúrate de que el servidor Node.js escucha en 127.0.0.1, no en 0.0.0.0. Si es producción, ponlo detrás de un proxy (nginx/caddy).",
  python:  () => "Asegúrate de que el servidor Python escucha en 127.0.0.1, no en 0.0.0.0. Si es producción, usa gunicorn/uvicorn detrás de un proxy.",
  ruby:    () => "Asegúrate de que el servidor Ruby escucha en 127.0.0.1, no en 0.0.0.0.",
  java:    () => "Revisa el bind address del servicio Java. Si es solo local, configúralo para escuchar en 127.0.0.1.",

  // Samba / SMB
  smbd: (p) => p === "darwin"
    ? "sudo launchctl disable system/smbd"
    : p === "win32"
      ? "Desactiva el Uso compartido de archivos en Panel de control → Centro de redes."
      : "sudo systemctl stop smbd && sudo systemctl disable smbd",
  samba: (p) => FIXES.smbd(p),

  // Elasticsearch
  elasticsearch: () => "Limita Elasticsearch a localhost: edita elasticsearch.yml → network.host: 127.0.0.1\nLuego reinicia el servicio.",

  // RabbitMQ
  rabbitmq: (p) => p === "win32"
    ? "Limita RabbitMQ: rabbitmqctl set_permissions -p / guest '' '' ''\nY elimina el usuario guest si no se usa."
    : "Limita RabbitMQ: edita rabbitmq.conf → listeners.tcp.local = 127.0.0.1:5672\nLuego: sudo systemctl restart rabbitmq-server",

  // Docker Registry
  registry: () => "Si el registro Docker está expuesto, añade autenticación TLS. Considera usar Docker Hub o un registro privado.",

  // Jupyter
  jupyter: () => "Jupyter expuesto en red es un riesgo crítico. Configura contraseña: jupyter notebook password\nY escucha solo en 127.0.0.1: jupyter notebook --ip=127.0.0.1",
};

/**
 * Servicios que, si están instalados en el host, generan un finding de advertencia.
 * Clave: nombre normalizado del paquete. Valor: severidad del finding.
 */
const DANGEROUS_SERVICES = new Map([
  ["vsftpd",      "high"],
  ["ftpd",        "high"],
  ["proftpd",     "high"],
  ["pure-ftpd",   "high"],
  ["telnetd",     "high"],
  ["telnet",      "medium"],
  ["rsh-server",  "high"],
  ["rsh-client",  "medium"],
  ["rlogin",      "high"],
  ["tftpd",       "high"],
  ["tftpd-hpa",   "high"],
  ["nis",         "medium"],
  ["yp-tools",    "medium"],
  ["talk",        "medium"],
  ["ntalk",       "medium"],
]);

// ── API pública ───────────────────────────────────────────────────────────────

/**
 * Devuelve el fix concreto para un proceso/imagen conocido, o null si no hay mapeo.
 *
 * @param {string} rawName   Nombre de proceso, binario o imagen Docker (sin normalizar)
 * @param {string} platform  process.platform: 'darwin' | 'linux' | 'win32'
 * @returns {string|null}
 */
function getFixForProcess(rawName, platform) {
  const name = normalizeName(rawName);
  if (!name) return null;
  const plat = platform || process.platform;
  const fn = FIXES[name];
  return fn ? fn(plat) : null;
}

module.exports = { getFixForProcess, normalizeName, DANGEROUS_SERVICES };
