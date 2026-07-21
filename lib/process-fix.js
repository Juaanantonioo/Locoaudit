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
 *   getFixForProcess(rawName, platform, pkgManager)  → string|null
 *   getSystemService(rawName, platform)  → {label, what, soft, warn}|null
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
const { removeCmd, managerLabel } = require("./pkg-manager");

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

// ── Parada de servicios systemd ─────────────────────────────────────────────

/**
 * Comando systemd para detener Y deshabilitar un servicio junto con su socket.
 *
 * El `.socket` es obligatorio: con activación por socket, parar solo el
 * `.service` NO cierra el puerto — systemd sigue escuchando y relanza el
 * servicio en la siguiente conexión. El usuario creería haberlo cerrado.
 *
 * Si la distro no define la unidad `.socket`, systemctl avisa de que no existe;
 * por eso el comando va acompañado de la nota de repetirlo solo con `.service`.
 *
 * @param {string} unit  Nombre base de la unidad (sin sufijo). Ej: "cups"
 * @returns {string}
 */
function systemdDisable(unit) {
  return `sudo systemctl disable --now ${unit}.service ${unit}.socket`;
}

// ── Mapa de nombres de proceso/imagen → función de fix ──────────────────────

const FIXES = {
  // SSH
  sshd: (p) => p === "win32"
    ? "Desactiva el servicio OpenSSH en services.msc → OpenSSH Server → Detener y deshabilitar."
    : p === "darwin"
      ? "sudo systemsetup -setremotelogin off"
      : systemdDisable("ssh"),

  ssh: (p) => FIXES.sshd(p),   // nombre de servicio del catálogo de puertos

  // FTP
  vsftpd: (p) => p === "win32"
    ? "Desactiva el servicio FTP en Panel de control → Características de Windows → IIS."
    : p === "darwin"
      // macOS retiró el servidor FTP del sistema base en 10.13, así que
      // `system/ftp` casi nunca existe: launchctl fallaría con "service not
      // found". Se ofrece el paso de AVERIGUACIÓN (solo lectura, inofensivo) como
      // comando copiable, y la acción en prosa con el label real del usuario.
      ? "launchctl list | grep -i ftp\n" +
        "macOS ya no trae servidor FTP en el sistema base (se retiró en 10.13). Si este puerto está " +
        "abierto, el servidor lo instalaste tú: el comando de arriba lista los servicios cargados y su " +
        "label REAL. Deshabilita ese label concreto con sudo launchctl disable system/<label>, o " +
        "desinstala el programa que lo instaló. No uses un label supuesto: launchctl fallaría."
      : systemdDisable("vsftpd"),
  ftpd:       (p) => FIXES.vsftpd(p),
  ftp:        (p) => FIXES.vsftpd(p),   // nombre de servicio del catálogo de puertos
  proftpd:    (p) => p === "linux"
    ? systemdDisable("proftpd")
    : FIXES.vsftpd(p),
  "pure-ftpd": (p) => p === "linux"
    ? systemdDisable("pure-ftpd")
    : FIXES.vsftpd(p),

  // Telnet
  telnetd: (p, m) => p === "win32"
    ? "Desactiva el cliente Telnet en Panel de control → Características de Windows."
    : p === "darwin"
      // Mismo caso que FTP: telnetd tampoco viene ya en el sistema base.
      ? "launchctl list | grep -i telnet\n" +
        "macOS ya no trae servidor telnet en el sistema base. Si el puerto está abierto, el servidor " +
        "lo instalaste tú: el comando de arriba muestra su label REAL. Deshabilítalo con " +
        "sudo launchctl disable system/<label>, o desinstálalo. Telnet no cifra nada: usa SSH en su lugar."
      // La nota usa el gestor REAL; antes decía apt en cualquier distribución.
      : systemdDisable("telnet") +
        (removeCmd(m, "telnetd") ? `\nSi no lo usas, desinstálalo: ${removeCmd(m, "telnetd")}` : ""),

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
    : "Si no necesitas nginx: " + systemdDisable("nginx") + "\nSi lo usas: asegúrate de tener TLS válido y redirigir HTTP a HTTPS.",
  apache: (p) => p === "darwin"
    ? "sudo apachectl stop && sudo launchctl disable system/org.apache.httpd"
    : p === "win32"
      ? "net stop Apache2.4"
      : systemdDisable("apache2"),
  apache2: (p) => FIXES.apache(p),
  httpd:   (p) => FIXES.apache(p),

  // Dev servers (no plataforma específica)
  node:    () => "Asegúrate de que el servidor Node.js escucha en 127.0.0.1, no en 0.0.0.0. Si es producción, ponlo detrás de un proxy (nginx/caddy).",
  python:  () => "Asegúrate de que el servidor Python escucha en 127.0.0.1, no en 0.0.0.0. Si es producción, usa gunicorn/uvicorn detrás de un proxy.",
  ruby:    () => "Asegúrate de que el servidor Ruby escucha en 127.0.0.1, no en 0.0.0.0.",
  java:    () => "Revisa el bind address del servicio Java. Si es solo local, configúralo para escuchar en 127.0.0.1.",

  // VNC / RDP — escritorio remoto (nombres de servicio del catálogo de puertos)
  vnc: (p) => p === "darwin"
    ? "Ajustes del Sistema → General → Compartido → desactiva «Compartir pantalla»."
    : p === "win32"
      ? "Detén y deshabilita el servidor VNC que tengas instalado (services.msc)."
      // No existe una unidad "vncserver" estándar: depende del servidor instalado.
      // Se da el listado (solo lectura) como comando y el disable en prosa.
      : "systemctl list-units --type=service | grep -i vnc\n" +
        "No hay una unidad estándar para VNC: el nombre depende del servidor instalado (x11vnc, " +
        "tigervnc, tightvnc…). El comando de arriba lista las unidades activas que coinciden; si no " +
        "sale ninguna, prueba con systemctl list-unit-files | grep -i vnc. Después deshabilita la que " +
        "aparezca con sudo systemctl disable --now <unidad>.service (y su .socket si existe).",
  rdp: (p) => p === "win32"
    ? "Configuración → Sistema → Escritorio remoto → desactívalo. Si lo necesitas, exige autenticación a nivel de red (NLA)."
    : p === "darwin"
      ? "Ajustes del Sistema → General → Compartido → desactiva «Compartir pantalla»/«Gestión remota»."
      : systemdDisable("xrdp"),

  // Samba / SMB
  smbd: (p) => p === "darwin"
    ? "sudo launchctl disable system/smbd"
    : p === "win32"
      ? "Desactiva el Uso compartido de archivos en Panel de control → Centro de redes."
      : systemdDisable("smbd"),
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

  // CUPS (impresión, puerto 631). En Linux hay que parar también el .socket y
  // el .path: si solo se para el .service, systemd lo relanza a demanda.
  cupsd: (p) => p === "darwin"
    ? "CUPS es el sistema de impresión de macOS. Desactívalo solo si no imprimes desde este equipo: sudo launchctl disable system/org.cups.cupsd"
    : p === "win32"
      ? "Detén el servicio de cola de impresión (Print Spooler) en services.msc si no imprimes desde este equipo."
      : systemdDisable("cups") + "\n(CUPS también tiene unidad .path: sudo systemctl disable --now cups.path)",
  cups: (p) => FIXES.cupsd(p),

  // ── Servicios/clientes heredados inseguros (detectados en el inventario) ────
  // Protocolos sin cifrado: el fix es desinstalarlos. En Linux son comandos
  // ejecutables; en macOS/Windows rara vez están presentes → guía genérica.
  telnet:       (p, m) => removeFix("telnet", p, m),
  "rsh-server": (p, m) => removeFix("rsh-server", p, m),
  "rsh-client": (p, m) => removeFix("rsh-client", p, m),
  rlogin:       (p, m) => removeFix("rsh-client", p, m),
  tftpd:        (p, m) => removeFix("tftpd", p, m),
  "tftpd-hpa":  (p, m) => removeFix("tftpd-hpa", p, m),
  nis:          (p, m) => removeFix("nis", p, m),
  "yp-tools":   (p, m) => removeFix("yp-tools", p, m),
  talk:         (p, m) => removeFix("talk", p, m),
  ntalk:        (p, m) => removeFix("ntalk", p, m),
};

/**
 * Fix de desinstalación para un paquete heredado inseguro.
 * Linux → comando ejecutable (apt/dnf); resto → guía genérica.
 * @param {string} pkg
 * @param {string} platform
 * @returns {string}
 */
function removeFix(pkg, platform, pkgManager) {
  // Gestor REAL detectado. Antes esto era `sudo apt remove` + una nota de dnf
  // pegada en la misma cadena: inejecutable en Arch/openSUSE, y el botón de
  // copiar arrastraba la nota. Ahora el comando es del gestor que existe, y la
  // explicación va en línea aparte (createFinding copia solo la primera).
  const cmd = removeCmd(pkgManager, pkg);
  if (cmd) {
    return `${cmd}\nEs un servicio o protocolo heredado que transmite datos sin cifrar; desinstálalo si no lo usas.`;
  }
  return `Desinstala ${pkg} si no lo necesitas: es un servicio/protocolo heredado sin cifrado. ` +
    `Usa ${managerLabel(pkgManager)} para eliminarlo.`;
}

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

// ── Naturaleza del fix: detener el servicio vs limitar su exposición ────────

/**
 * Nombres cuyo fix NO detiene el servicio, sino que limita su exposición
 * (rebind a 127.0.0.1, autenticación, TLS...). Son bases de datos y servidores
 * de aplicación: pararlos rompería la aplicación que los usa, así que lo
 * razonable es dejar de exponerlos a la red, no apagarlos.
 *
 * Distinguirlo importa: presentar un "bind-address = 127.0.0.1" bajo el
 * epígrafe "detén el servicio" haría creer al usuario que el puerto se cierra.
 */
const LIMIT_ONLY = new Set([
  "mysqld", "mysql", "mariadbd", "mariadb",
  "postgres", "postgresql",
  "redis-server", "redis",
  "mongod", "mongodb", "mongo",
  "elasticsearch", "rabbitmq", "registry", "jupyter",
  "node", "python", "ruby", "java",
]);

/**
 * ¿El fix de este proceso lo DETIENE o solo limita su exposición?
 * @param {string} rawName
 * @returns {"stop"|"limit"|null}  null si no hay fix conocido para ese nombre
 */
function getFixKind(rawName) {
  const name = normalizeName(rawName);
  if (!name || !FIXES[name]) return null;
  return LIMIT_ONLY.has(name) ? "limit" : "stop";
}

// ── Servicios propios del sistema operativo ─────────────────────────────────

/**
 * Servicios que forman parte del SO y NO deben matarse "a lo bruto".
 *
 * Un `kill`/`launchctl disable` sobre uno de estos rompe funciones del sistema
 * (y en macOS launchd suele relanzarlo, así que además no cierra el puerto).
 * Para ellos el fix explica QUÉ es el servicio y ofrece la vía soportada por el
 * propio SO (un ajuste), avisando de lo que se pierde al desactivarlo.
 *
 * Clave: nombre normalizado (normalizeName). Ojo: `lsof` trunca el nombre del
 * proceso, por eso "ControlCe" (Centro de Control de macOS) y no "ControlCenter".
 *
 * Campos: label (nombre humano) · what (qué hace) · soft (vía soportada) ·
 *         warn (qué se pierde al desactivarlo).
 */
const SYSTEM_SERVICES = {
  darwin: {
    controlce: {
      label: "Centro de Control de macOS (Receptor AirPlay)",
      what: "Es un proceso del propio macOS. Mantiene abiertos los puertos 5000 y 7000 " +
            "porque publica el Receptor AirPlay: permite que otros dispositivos Apple envíen " +
            "pantalla o audio a este Mac.",
      soft: "Ajustes del Sistema → General → AirDrop y Handoff → desactiva «Receptor AirPlay».",
      warn: "No lo mates con kill ni launchctl: launchd lo relanza (el puerto no se cerraría) " +
            "y el Centro de Control forma parte del sistema. Al desactivar el Receptor AirPlay " +
            "este Mac deja de poder recibir AirPlay desde iPhone/iPad/otro Mac.",
    },
    controlcenter: { alias: "controlce" },
    rapportd: {
      label: "rapportd (Continuidad / Handoff)",
      what: "Proceso del sistema que da soporte a Handoff, Portapapeles Universal y Llamadas " +
            "desde el iPhone entre tus dispositivos Apple.",
      soft: "Ajustes del Sistema → General → AirDrop y Handoff → desactiva «Permitir Handoff».",
      warn: "Perderás Handoff y el Portapapeles Universal con tus otros dispositivos Apple.",
    },
    sharingd: {
      label: "sharingd (AirDrop y Compartido)",
      what: "Proceso del sistema que gestiona AirDrop y los servicios de compartición de macOS.",
      soft: "Ajustes del Sistema → General → Compartido → desactiva los servicios que no uses. " +
            "Para AirDrop: Finder → AirDrop → «Permitir que me descubran: Nadie».",
      warn: "Perderás AirDrop y la compartición con otros equipos.",
    },
    mdnsresponder: {
      label: "mDNSResponder (Bonjour)",
      what: "Es el servicio de DNS y descubrimiento de red de macOS. Resuelve nombres y " +
            "descubre impresoras y dispositivos de la red local.",
      soft: "No se desactiva: macOS lo necesita para resolver nombres de dominio. " +
            "Si te preocupa el descubrimiento, desactiva los servicios que publican (Compartido, AirPlay).",
      warn: "Desactivarlo dejaría este Mac sin resolución DNS.",
    },
    cupsd: {
      label: "CUPS (sistema de impresión de macOS)",
      what: "Es el servicio de impresión del propio macOS. Escucha en el puerto 631 para " +
            "gestionar las impresoras configuradas.",
      soft: "Elimina las impresoras que no uses en Ajustes del Sistema → Impresoras y escáneres. " +
            "Solo si no imprimes nunca desde este equipo: sudo launchctl disable system/org.cups.cupsd",
      warn: "Sin CUPS este Mac no puede imprimir.",
    },
    smbd: {
      label: "smbd (Compartir archivos de macOS)",
      what: "Servicio de compartición de archivos por SMB del propio macOS (puerto 445).",
      soft: "Ajustes del Sistema → General → Compartido → desactiva «Compartir archivos».",
      warn: "Otros equipos dejarán de ver las carpetas compartidas de este Mac.",
    },
    sshd: {
      label: "sshd (Sesión remota de macOS)",
      what: "Servidor SSH del propio macOS. Está abierto porque la «Sesión remota» está activada.",
      soft: "Ajustes del Sistema → General → Compartido → desactiva «Sesión remota». " +
            "Equivalente por terminal: sudo systemsetup -setremotelogin off",
      warn: "Perderás el acceso por SSH a este Mac. No lo desactives si administras el equipo en remoto.",
    },
    screensharing: {
      label: "Compartir pantalla de macOS",
      what: "Servidor VNC del propio macOS (puerto 5900), activo porque «Compartir pantalla» está habilitado.",
      soft: "Ajustes del Sistema → General → Compartido → desactiva «Compartir pantalla».",
      warn: "Perderás el control remoto del escritorio de este Mac.",
    },
    screensharingd: { alias: "screensharing" },
    ardagent:       { alias: "screensharing" },
  },
  linux: {
    "systemd-resolve": {
      label: "systemd-resolved (DNS local)",
      what: "Es el resolvedor DNS de systemd. Escucha en 127.0.0.53:53, una dirección de " +
            "loopback: solo este equipo puede usarlo, no está expuesto a la red.",
      soft: "No lo desactives: es la resolución de nombres del sistema. Al no estar expuesto, no hay nada que cerrar.",
      warn: "Desactivarlo dejaría el equipo sin resolución DNS.",
    },
    resolved: { alias: "systemd-resolve" },
    "avahi-daemon": {
      label: "avahi-daemon (mDNS / Bonjour)",
      what: "Servicio de descubrimiento de la red local: encuentra impresoras y equipos por su nombre .local.",
      soft: `Si no usas descubrimiento local: ${systemdDisable("avahi-daemon")}`,
      warn: "Dejarás de descubrir impresoras y equipos de la red local por nombre.",
    },
    avahi: { alias: "avahi-daemon" },
    cupsd: {
      label: "CUPS (sistema de impresión)",
      what: "Servicio de impresión del sistema. Escucha en el 631 para gestionar impresoras.",
      soft: `Solo si no imprimes desde este equipo: ${systemdDisable("cups")}\n` +
            "(CUPS también tiene unidad .path: sudo systemctl disable --now cups.path)",
      warn: "Sin CUPS este equipo no puede imprimir.",
    },
    cups: { alias: "cupsd" },
  },
  win32: {
    svchost: {
      label: "svchost.exe (servicio del sistema de Windows)",
      what: "Es el contenedor genérico de servicios de Windows: el puerto lo abre un servicio " +
            "alojado dentro, no el propio svchost.",
      soft: "Identifica el servicio concreto: en PowerShell (como administrador) " +
            "Get-Process -Id <PID> y  netstat -ano | findstr :<PUERTO>. " +
            "Después detén ESE servicio en services.msc, no svchost.",
      warn: "Nunca termines svchost.exe: arrastraría servicios críticos de Windows.",
    },
    system: {
      label: "System (SMB / compartir archivos de Windows)",
      what: "El proceso System de Windows atiende el puerto 445 (SMB), usado para compartir " +
            "archivos e impresoras.",
      soft: "Panel de control → Centro de redes → Configuración de uso compartido avanzado → " +
            "desactiva «Compartir archivos e impresoras» en la red que no lo necesite.",
      warn: "No termines el proceso System. Al desactivar SMB dejarás de compartir carpetas e impresoras.",
    },
    spoolsv: {
      label: "Print Spooler (cola de impresión de Windows)",
      what: "Servicio de impresión de Windows.",
      soft: "Solo si no imprimes desde este equipo: services.msc → Cola de impresión → Detener y Deshabilitar.",
      warn: "Sin la cola de impresión este equipo no puede imprimir.",
    },
  },
};

// ── API pública ───────────────────────────────────────────────────────────────

/**
 * Devuelve el fix concreto para un proceso/imagen conocido, o null si no hay mapeo.
 *
 * @param {string} rawName   Nombre de proceso, binario o imagen Docker (sin normalizar)
 * @param {string} platform  process.platform: 'darwin' | 'linux' | 'win32'
 * @returns {string|null}
 */
function getFixForProcess(rawName, platform, pkgManager) {
  const name = normalizeName(rawName);
  if (!name) return null;
  const plat = platform || process.platform;
  const fn = FIXES[name];
  return fn ? fn(plat, pkgManager || null) : null;
}

/**
 * Devuelve la ficha del servicio si el proceso pertenece al propio SO, o null.
 *
 * Se consulta ANTES que getFixForProcess al construir el fix de un puerto: para
 * un servicio del sistema no se propone pararlo a lo bruto, sino la vía soportada.
 *
 * @param {string} rawName   Nombre de proceso tal cual lo reporta lsof/netstat
 * @param {string} platform  'darwin' | 'linux' | 'win32'
 * @returns {{label: string, what: string, soft: string, warn: string}|null}
 */
function getSystemService(rawName, platform) {
  const name = normalizeName(rawName);
  if (!name) return null;
  const table = SYSTEM_SERVICES[platform || process.platform];
  if (!table) return null;

  const resolve = (e) => (e && e.alias ? table[e.alias] || null : e || null);

  if (table[name]) return resolve(table[name]);

  // lsof trunca la columna COMMAND a 9 caracteres ("ControlCenter" → "ControlCe",
  // "systemd-resolved" → "systemd-r"). Se acepta el nombre truncado como prefijo,
  // pero solo si identifica a UN único servicio del catálogo (los alias que
  // apuntan a la misma ficha no cuentan como ambigüedad).
  if (name.length < 5) return null;
  const hits = [];
  for (const k of Object.keys(table)) {
    if (!k.startsWith(name)) continue;
    const target = resolve(table[k]);
    if (target && !hits.includes(target)) hits.push(target);
  }
  return hits.length === 1 ? hits[0] : null;
}

module.exports = {
  getFixForProcess,
  getFixKind,
  getSystemService,
  systemdDisable,
  normalizeName,
  DANGEROUS_SERVICES,
  SYSTEM_SERVICES,
};
