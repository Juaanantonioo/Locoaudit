"use strict";

/** Fix concreto a partir del nombre de proceso o imagen. Lo usan los tres nodos: puertos con
 *  proceso conocido, servicios peligrosos del inventario y contenedores por nombre de imagen. */

/** Nombre canónico en minúsculas: sin ruta, sin .exe, sin versión y sin lo que siga al primer
 *  espacio. "/usr/sbin/sshd" → "sshd"; "nginx: master process" → "nginx". */
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

/** Detiene y deshabilita un servicio systemd y, si existe, su socket: con activación por socket, parar solo el `.service`
 *  deja el puerto escuchando. Van en dos órdenes porque `systemctl disable --now X.service X.socket` depende de la versión
 *  (comprobado el 2026-10-10): systemd 249 avisa y deshabilita el .service, y systemd 255 rechaza la orden ENTERA si no hay
 *  .socket y deja el servicio habilitado. Ahora el .service va primero y la ausencia del .socket no hace fallar la línea. */
function systemdDisable(unit) {
  return `sudo systemctl disable --now ${unit}.service && { sudo systemctl disable --now ${unit}.socket 2>/dev/null || true; }`;
}

/** Nombre de la unidad systemd según la distribución. El mismo servicio se llama distinto en
 *  Debian y Ubuntu (gestor apt) que en Arch y Fedora. Con el gestor desconocido se usa el nombre
 *  de Debian y se añade una nota con el otro, en vez de adivinar. */
const UNIT_NAMES = {
  ssh:    { apt: "ssh",     other: "sshd" },
  apache: { apt: "apache2", other: "httpd" },
  smb:    { apt: "smbd",    other: "smb" },
  redis:  { apt: "redis-server", other: "redis" },
};
function unitFor(kind, mgr) {
  const u = UNIT_NAMES[kind];
  if (mgr === "apt") return { unit: u.apt, note: "" };
  if (mgr) return { unit: u.other, note: "" };
  return { unit: u.apt, note: `\n(En Arch y Fedora la unidad se llama ${u.other}.)` };
}

/** macOS: servicios instalados con Homebrew. Se detienen con `brew services` y su configuración
 *  vive bajo `$(brew --prefix)/etc`. */
function brewStop(formula) {
  return `brew services stop ${formula}\nSi lo instalaste de otra forma, detenlo desde la aplicación que lo instaló.`;
}

const FIXES = {
  sshd: (p, m) => {
    if (p === "win32") return "Desactiva el servicio OpenSSH en services.msc → OpenSSH SSH Server → Detener y deshabilitar.";
    if (p === "darwin") return "sudo systemsetup -setremotelogin off\nEn las versiones recientes de macOS, systemsetup exige que el Terminal tenga Acceso total al disco; si da error, desactiva «Sesión remota» en Ajustes del Sistema → General → Compartido.";
    const { unit, note } = unitFor("ssh", m);
    return systemdDisable(unit) + note;
  },

  ssh: (p, m) => FIXES.sshd(p, m),   // nombre de servicio del catálogo de puertos

  vsftpd: (p) => p === "win32"
    ? "Desactiva el servicio FTP en Panel de control → Características de Windows → IIS."
    : p === "darwin"
            // macOS quitó el servidor FTP del sistema base en 10.13, así que `system/ftp` casi nunca
            // existe y launchctl fallaría. Se copia el paso de averiguación, y la acción va en prosa.
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

  telnetd: (p, m) => p === "win32"
            // El cliente Telnet de Windows no abre ningún puerto, y Windows 10 y 11 ya no incluyen
            // servidor telnet: si el 23 está abierto, lo abrió un programa instalado aparte.
    ? "netstat -ano | findstr :23\nWindows ya no incluye un servidor Telnet: el puerto lo abre un programa que instalaste aparte. Con el PID de la última columna, identifícalo en el Administrador de tareas (pestaña Detalles) y desinstálalo o deshabilita su servicio en services.msc."
    : p === "darwin"
            // Igual que FTP: telnetd tampoco viene ya en el sistema base.
      ? "launchctl list | grep -i telnet\n" +
        "macOS ya no trae servidor telnet en el sistema base. Si el puerto está abierto, el servidor " +
        "lo instalaste tú: el comando de arriba muestra su label REAL. Deshabilítalo con " +
        "sudo launchctl disable system/<label>, o desinstálalo. Telnet no cifra nada: usa SSH en su lugar."
            // La nota usa el gestor real; antes decía apt en cualquier distribución.
            // En Debian y Ubuntu telnetd se lanza desde inetd y no tiene unidad telnet.service, así
            // que la versión anterior (systemctl disable telnet.service) fallaba. Lo que cierra el
            // puerto en todas las distribuciones es desinstalar el servidor.
      : (removeCmd(m, m === "dnf" || m === "yum" ? "telnet-server" : "telnetd") ||
         "Desinstala el servidor telnet con tu gestor de paquetes: telnetd en Debian y Ubuntu, telnet-server en Fedora.") +
        "\nTelnet no cifra nada: si necesitas acceso remoto, usa SSH.",

  mysqld: (p) => p === "win32"
    ? "Limita acceso: en my.ini añade bind-address = 127.0.0.1 bajo [mysqld].\nLuego reinicia MySQL desde services.msc."
    : p === "darwin"
      ? "Limita acceso: en $(brew --prefix)/etc/my.cnf, sección [mysqld], pon bind-address = 127.0.0.1.\nReinicia el servicio: brew services restart mysql"
            // La ruta del fichero cambia con la distribución y con el servidor (MySQL o MariaDB):
            // se da la orden que la muestra en vez de suponer la de Ubuntu.
      : "Limita acceso: en la sección [mysqld] de la configuración del servidor pon bind-address = 127.0.0.1. `mysqld --verbose --help | grep -A1 'Default options'` muestra qué ficheros lee (en Ubuntu con MySQL, /etc/mysql/mysql.conf.d/mysqld.cnf).\nReinicia el servicio: sudo systemctl restart mysql\nEn Fedora el servicio se llama mysqld.",
  mysql:    (p) => FIXES.mysqld(p),
  mariadbd: (p) => p === "win32"
    ? "Limita acceso: en my.ini añade bind-address = 127.0.0.1 bajo [mysqld].\nLuego reinicia MariaDB desde services.msc."
    : p === "darwin"
      ? "Limita acceso: en $(brew --prefix)/etc/my.cnf, sección [mysqld], pon bind-address = 127.0.0.1.\nReinicia el servicio: brew services restart mariadb"
      : "Limita acceso: en la sección [mysqld] de la configuración del servidor pon bind-address = 127.0.0.1 (en Debian y Ubuntu, /etc/mysql/mariadb.conf.d/50-server.cnf).\nReinicia el servicio: sudo systemctl restart mariadb",
  mariadb: (p) => FIXES.mariadbd(p),

  postgres: (p) => p === "win32"
    ? "Edita postgresql.conf → listen_addresses = 'localhost' y pg_hba.conf para restringir IPs.\nLuego reinicia el servicio PostgreSQL desde services.msc."
    : p === "darwin"
      ? "Edita postgresql.conf → listen_addresses = 'localhost' (su ruta la muestra psql -c 'SHOW config_file') y pg_hba.conf para restringir IPs.\nReinicia el servicio: brew services restart postgresql (o postgresql@<versión> si instalaste una concreta)"
      : "Edita postgresql.conf → listen_addresses = 'localhost' (su ruta la muestra sudo -u postgres psql -c 'SHOW config_file') y pg_hba.conf para restringir IPs.\nReinicia el servicio: sudo systemctl restart postgresql",
  postgresql: (p) => FIXES.postgres(p),

  "redis-server": (p, m) => {
    if (p === "win32") return "Edita redis.windows.conf → bind 127.0.0.1 y añade requirepass.\nLuego reinicia Redis desde services.msc.";
    if (p === "darwin") return "Edita $(brew --prefix)/etc/redis.conf → bind 127.0.0.1\nAñade requirepass con contraseña fuerte. Reinicia el servicio: brew services restart redis";
    const { unit, note } = unitFor("redis", m);
    return `Edita /etc/redis/redis.conf → bind 127.0.0.1\nAñade requirepass con contraseña fuerte.\nReinicia el servicio: sudo systemctl restart ${unit}${note}`;
  },
  redis: (p, m) => FIXES["redis-server"](p, m),

  mongod: (p) => p === "win32"
    ? "Edita mongod.cfg → bindIp: 127.0.0.1 y habilita security.authorization: enabled.\nLuego reinicia MongoDB desde services.msc."
    : (p === "darwin"
        ? "Edita $(brew --prefix)/etc/mongod.conf: en la sección net, bindIp: 127.0.0.1; en la sección security, authorization: enabled.\nAntes de activar la autenticación, crea un usuario administrador o perderás el acceso.\nReinicia el servicio: brew services restart mongodb-community"
        : "Edita /etc/mongod.conf: en la sección net, bindIp: 127.0.0.1; en la sección security, authorization: enabled.\nAntes de activar la autenticación, crea un usuario administrador o perderás el acceso.\nReinicia el servicio: sudo systemctl restart mongod"),
  mongodb: (p) => FIXES.mongod(p),
  mongo:   (p) => FIXES.mongod(p),

  nginx: (p) => p === "win32"
    ? "Si no necesitas nginx: nginx -s stop\nSi lo usas: asegúrate de tener TLS válido y redirigir HTTP a HTTPS."
    : p === "darwin"
      ? "Si no necesitas nginx: brew services stop nginx\nSi lo usas: asegúrate de tener TLS válido y redirigir HTTP a HTTPS."
      : "Si no necesitas nginx: " + systemdDisable("nginx") + "\nSi lo usas: asegúrate de tener TLS válido y redirigir HTTP a HTTPS.",
  apache: (p, m) => {
    if (p === "darwin") return "sudo apachectl stop && sudo launchctl disable system/org.apache.httpd";
    if (p === "win32") return "net stop Apache2.4";
    const { unit, note } = unitFor("apache", m);
    return systemdDisable(unit) + note;
  },
  apache2: (p, m) => FIXES.apache(p, m),
  httpd:   (p, m) => FIXES.apache(p, m),

  node:    () => "Asegúrate de que el servidor Node.js escucha en 127.0.0.1, no en 0.0.0.0. Si es producción, ponlo detrás de un proxy (nginx/caddy).",
  python:  () => "Asegúrate de que el servidor Python escucha en 127.0.0.1, no en 0.0.0.0. Si es producción, usa gunicorn/uvicorn detrás de un proxy.",
  ruby:    () => "Asegúrate de que el servidor Ruby escucha en 127.0.0.1, no en 0.0.0.0.",
  java:    () => "Revisa el bind address del servicio Java. Si es solo local, configúralo para escuchar en 127.0.0.1.",

  vnc: (p) => p === "darwin"
    ? "Ajustes del Sistema → General → Compartido → desactiva «Compartir pantalla»."
    : p === "win32"
      ? "Detén y deshabilita el servidor VNC que tengas instalado (services.msc)."
            // No hay unidad "vncserver" estándar: depende del servidor instalado. Se copia el listado,
            // que es de solo lectura, y el disable va en prosa.
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

  smbd: (p, m) => {
            // En macOS la etiqueta de launchd es com.apple.smbd y está protegida por SIP: la vía
            // soportada es Ajustes. La versión anterior usaba system/smbd, que no existe.
    if (p === "darwin") return "Ajustes del Sistema → General → Compartido → desactiva «Compartir archivos».";
    if (p === "win32") return "Desactiva el Uso compartido de archivos en Panel de control → Centro de redes.";
    const { unit, note } = unitFor("smb", m);
    return systemdDisable(unit) + note;
  },
  samba: (p, m) => FIXES.smbd(p, m),

  elasticsearch: () => "Limita Elasticsearch a localhost: edita elasticsearch.yml → network.host: 127.0.0.1\nLuego reinicia el servicio.",

  rabbitmq: (p) => p === "win32"
    ? "Limita RabbitMQ: en rabbitmq.conf (en %APPDATA%\\RabbitMQ) pon listeners.tcp.local = 127.0.0.1:5672\nLuego reinicia el servicio RabbitMQ desde services.msc."
    : "Limita RabbitMQ: edita rabbitmq.conf → listeners.tcp.local = 127.0.0.1:5672\nReinicia el servicio: sudo systemctl restart rabbitmq-server",

  registry: () => "Si el registro Docker está expuesto, añade autenticación TLS. Considera usar Docker Hub o un registro privado.",

  jupyter: () => "Jupyter expuesto en red es un riesgo crítico. Configura contraseña: jupyter notebook password\nY escucha solo en 127.0.0.1: jupyter notebook --ip=127.0.0.1",

    // CUPS necesita también el .socket y el .path: con solo el .service, systemd lo relanza a demanda.
  cupsd: (p) => p === "darwin"
    ? "CUPS es el sistema de impresión de macOS. Desactívalo solo si no imprimes desde este equipo: sudo launchctl disable system/org.cups.cupsd"
    : p === "win32"
      ? "Detén el servicio de cola de impresión (Print Spooler) en services.msc si no imprimes desde este equipo."
      : systemdDisable("cups") + "\n(CUPS también tiene unidad .path: sudo systemctl disable --now cups.path)",
  cups: (p) => FIXES.cupsd(p),

    // Protocolos sin cifrar: el fix es desinstalarlos. En Linux sale comando; en macOS y Windows
    // rara vez están, así que guía genérica.
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

/** Fix de desinstalación de un paquete heredado inseguro. */
function removeFix(pkg, platform, pkgManager) {
    // Gestor real detectado. Antes era `sudo apt remove` con una nota de dnf pegada en la misma
    // cadena: inejecutable en Arch y el botón de copiar arrastraba la nota.
  const cmd = removeCmd(pkgManager, pkg);
  if (cmd) {
    return `${cmd}\nEs un servicio o protocolo heredado que transmite datos sin cifrar; desinstálalo si no lo usas.`;
  }
  return `Desinstala ${pkg} si no lo necesitas: es un servicio/protocolo heredado sin cifrado. ` +
    `Usa ${managerLabel(pkgManager)} para eliminarlo.`;
}

/** Servicios que, instalados en el host, generan un finding. Valor: severidad. */
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

/** Nombres cuyo fix no detiene el servicio, sino que limita su exposición (rebind a 127.0.0.1,
 *  auth, TLS): pararlos rompería la aplicación que los usa. Presentar un bind-address bajo
 *  "detén el servicio" haría creer que el puerto queda cerrado. */
const LIMIT_ONLY = new Set([
  "mysqld", "mysql", "mariadbd", "mariadb",
  "postgres", "postgresql",
  "redis-server", "redis",
  "mongod", "mongodb", "mongo",
  "elasticsearch", "rabbitmq", "registry", "jupyter",
  "node", "python", "ruby", "java",
]);

/** ¿El fix de este proceso lo detiene o solo limita su exposición? null si no hay fix conocido. */
function getFixKind(rawName) {
  const name = normalizeName(rawName);
  if (!name || !FIXES[name]) return null;
  return LIMIT_ONLY.has(name) ? "limit" : "stop";
}

/**
 * Servicios del propio SO, que no deben matarse a lo bruto: se rompen funciones del sistema y en
 * macOS launchd los relanza, así que ni siquiera cierra el puerto. Para ellos el fix explica qué
 * son y ofrece la vía soportada, avisando de lo que se pierde.
 *
 * Clave: nombre normalizado. Ojo con lsof, que trunca: "ControlCe", no "ControlCenter".
 * Campos: label · what (qué hace) · soft (vía soportada) · warn (qué se pierde).
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

/** Fix concreto de un proceso o imagen conocidos, o null si no hay mapeo. */
function getFixForProcess(rawName, platform, pkgManager) {
  const name = normalizeName(rawName);
  if (!name) return null;
  const plat = platform || process.platform;
  const fn = FIXES[name];
  return fn ? fn(plat, pkgManager || null) : null;
}

/** Ficha del servicio si el proceso es del propio SO, o null. Se consulta antes que
 *  getFixForProcess: a un servicio del sistema no se le propone matarlo. */
function getSystemService(rawName, platform) {
  const name = normalizeName(rawName);
  if (!name) return null;
  const table = SYSTEM_SERVICES[platform || process.platform];
  if (!table) return null;

  const resolve = (e) => (e && e.alias ? table[e.alias] || null : e || null);

  if (table[name]) return resolve(table[name]);

    // lsof trunca COMMAND a 9 caracteres ("ControlCenter" → "ControlCe"). Se acepta el truncado
    // como prefijo, pero solo si identifica a un único servicio; los alias de la misma ficha no
    // cuentan como ambigüedad.
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
  unitFor,
  getFixKind,
  getSystemService,
  systemdDisable,
  normalizeName,
  DANGEROUS_SERVICES,
  SYSTEM_SERVICES,
};
