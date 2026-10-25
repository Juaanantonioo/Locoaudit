"use strict";

/** Texto en castellano y paso de resolución de cada control de Lynis, indexado por ID completo.
 *  Tabla estática para que el informe sea reproducible; sin `fix` ni `noAction` es que falta el paso. */

/** Solo los controles vistos en los informes de referencia. Campos: `es`, `fix` (texto u objeto por
 *  plataforma), `pkg`, `noAction` y `v` ("macos" probado en real, "doc" sacado de la documentación). */
const LYNIS_ES = {
  // ── ACCT · Contabilidad de procesos ───────────────────────────────────────
  "ACCT-9622": {
    es: "La contabilidad de procesos no está activada: el sistema no guarda registro de qué programas se han ejecutado ni quién los lanzó",
    // En Arch no se ha podido confirmar el paquete, así que sin orden.
    fix: { linux: "Instala el paquete de contabilidad de procesos (`acct` en Debian y Ubuntu, `psacct` en Fedora) y activa su servicio. Después, `lastcomm` muestra los programas ejecutados y `sa` un resumen por usuario.", all: null },
    pkg: { apt: "acct", dnf: "psacct", yum: "psacct" }, v: "doc",
  },
  "ACCT-9626": {
    es: "Sysstat no está recogiendo estadísticas: no se guarda el histórico de uso del sistema",
    // En Debian el `systemctl enable` solo no basta: Lynis mira primero /etc/default/sysstat.
    fix: { linux: "Instala `sysstat` y activa la recogida. En Debian y Ubuntu, pon `ENABLED=\"true\"` en /etc/default/sysstat (o ejecuta `sudo dpkg-reconfigure sysstat`) y después `sudo systemctl enable --now sysstat`; en otras distribuciones basta con lo segundo. Después, `sar` muestra el histórico de CPU, memoria, disco y red.", all: null },
    pkg: "sysstat", v: "doc",
  },
  "ACCT-9628": {
    es: "La auditoría del kernel (auditd) no está activa: no se registran los accesos a ficheros ni las llamadas al sistema",
    fix: { linux: "Instala el servicio de auditoría (`auditd` en Debian y Ubuntu, `audit` en Arch y Fedora) y actívalo: `sudo systemctl enable --now auditd`. Define qué vigilar en /etc/audit/rules.d/.", all: null },
    pkg: { apt: "auditd", pacman: "audit", dnf: "audit", yum: "audit" }, v: "doc",
  },

  // ── AUTH · Cuentas y contraseñas ──────────────────────────────────────────
  "AUTH-9230": {
    es: "La configuración de cifrado de contraseñas es más débil de lo recomendable: conviene revisar el número de rondas de hash",
    fix: { linux: "En /etc/login.defs, sube `SHA_CRYPT_MIN_ROUNDS` a 65536 o más. Solo afecta a las contraseñas que se cambien a partir de entonces: las ya guardadas conservan su hash antiguo hasta que se renueven.", all: null },
    v: "doc",
  },
  "AUTH-9262": {
    es: "No hay ningún módulo PAM de robustez de contraseñas instalado: nada impide poner una contraseña trivial",
    // Lynis reconoce pam_cracklib, pam_passwdqc y pam_pwquality (tests_authentication).
    fix: { linux: "Instala el módulo pwquality (`libpam-pwquality` en Debian y Ubuntu, `libpwquality` en Arch y Fedora) y configura la exigencia mínima en /etc/security/pwquality.conf (longitud, variedad de caracteres y comprobación contra diccionario).", all: null },
    pkg: { apt: "libpam-pwquality", pacman: "libpwquality", dnf: "libpwquality", yum: "libpwquality" }, v: "doc",
  },
  "AUTH-9282": {
    es: "Hay cuentas cuya contraseña no caduca nunca",
    fix: { linux: "Revisa qué cuentas son con `sudo chage -l <usuario>` y ponles caducidad: `sudo chage -M 365 <usuario>`. Las cuentas de servicio sin acceso interactivo no necesitan caducidad.", all: null },
    v: "doc",
  },
  "AUTH-9286": {
    es: "No hay caducidad configurada para las contraseñas: no se pide cambiarlas cada cierto tiempo",
    fix: { linux: "Configura `PASS_MIN_DAYS` y `PASS_MAX_DAYS` en /etc/login.defs. Afecta solo a las cuentas creadas después; para las existentes, `sudo chage -M <días> <usuario>`.", all: null },
    v: "doc",
  },
  "AUTH-9328": {
    es: "Los permisos por defecto de los ficheros nuevos (umask) son más abiertos de lo recomendable",
    fix: { linux: "Pon `UMASK 027` en /etc/login.defs para que los ficheros nuevos no sean legibles por otros usuarios. Comprueba el valor actual con `umask`.", all: null },
    v: "doc",
  },

  // ── BANN · Avisos legales ─────────────────────────────────────────────────
  "BANN-7126": {
    es: "El fichero /etc/issue no muestra ningún aviso legal antes de iniciar sesión",
    fix: { linux: "Escribe el aviso en /etc/issue. Es un requisito de algunas normativas; en un equipo personal aporta poco y puedes ignorarlo sin riesgo.", all: null },
    v: "doc",
  },
  "BANN-7130": {
    es: "El fichero /etc/issue.net no muestra ningún aviso legal en los accesos por red",
    fix: { linux: "Escribe el aviso en /etc/issue.net y activa `Banner /etc/issue.net` en /etc/ssh/sshd_config. Solo tiene sentido si aceptas conexiones SSH entrantes.", all: null },
    v: "doc",
  },

  // ── BOOT · Arranque ───────────────────────────────────────────────────────
  "BOOT-5122": {
    es: "El gestor de arranque GRUB no tiene contraseña: cualquiera con acceso físico puede modificar el arranque y entrar sin credenciales",
    // `update-grub` solo existe en Debian y derivadas: en el resto, grub-mkconfig.
    fix: { linux: "Genera un hash con `grub-mkpasswd-pbkdf2` y añádelo en /etc/grub.d/40_custom con las líneas `set superusers=\"root\"` y `password_pbkdf2 root <hash>`. Regenera la configuración con `sudo update-grub` en Debian y Ubuntu, o con `sudo grub-mkconfig -o /boot/grub/grub.cfg` en otras distribuciones. Protege contra alguien con acceso físico al equipo; si nadie más lo toca, es de prioridad baja.", all: null },
    v: "doc",
  },
  "BOOT-5180": {
    es: "Hay servicios que arrancan solos y conviene revisar si todos hacen falta",
    fix: { linux: "Lista los activos con `systemctl list-unit-files --state=enabled` y desactiva los que no uses: `sudo systemctl disable <servicio>`. Cada servicio que no arranca es una superficie de ataque menos.", all: null },
    v: "doc",
  },
  "BOOT-5264": {
    es: "Los servicios del sistema pueden endurecerse: systemd permite restringir a qué puede acceder cada uno",
    // Sí admite acción: Lynis trae en el campo 3 la orden `systemd-analyze security`.
    fix: { linux: "Revisa el nivel de exposición de cada servicio con `systemd-analyze security`, que los puntúa de 0 a 10. Para los peores, añade restricciones (`ProtectSystem`, `PrivateTmp`, `NoNewPrivileges`) en un fichero de sobrescritura: `sudo systemctl edit <servicio>`.", all: null },
    v: "doc",
  },

  // ── DEB · Específicos de Debian y derivadas ───────────────────────────────
  "DEB-0280": {
    es: "El paquete libpam-tmpdir no está instalado: todas las sesiones usan el mismo directorio temporal compartido",
    fix: { linux: "Instala `libpam-tmpdir`. Al iniciar sesión, cada usuario recibe su propio directorio temporal privado (variables TMP y TMPDIR), de modo que los demás usuarios no pueden ver ni manipular sus ficheros temporales.", all: null },
    pkg: "libpam-tmpdir", v: "doc",
  },
  "DEB-0810": {
    es: "El paquete apt-listbugs no está instalado: no se avisa de fallos graves conocidos antes de instalar una actualización",
    fix: { linux: "Instala `apt-listbugs`. A partir de entonces, apt te avisará de los fallos críticos reportados antes de aplicar cada actualización.", all: null },
    pkg: "apt-listbugs", v: "doc",
  },
  "DEB-0831": {
    es: "El paquete needrestart no está instalado: tras actualizar no se avisa de los servicios que siguen usando versiones antiguas de las bibliotecas",
    fix: { linux: "Instala `needrestart`. Después de cada actualización con apt indica qué servicios hay que reiniciar para que dejen de usar las bibliotecas sustituidas; también puedes lanzarlo a mano con `sudo needrestart`.", all: null },
    pkg: "needrestart", v: "doc",
  },
  "DEB-0880": {
    es: "fail2ban no está instalado: no se bloquea a quien falla repetidamente al iniciar sesión",
    fix: { linux: "Si el equipo acepta conexiones entrantes, como SSH, instala `fail2ban` y actívalo: `sudo systemctl enable --now fail2ban`. Comprueba que vigila SSH con `sudo fail2ban-client status sshd`. Si el equipo no acepta conexiones desde fuera, no aporta nada.", all: null },
    pkg: "fail2ban", v: "doc",
  },

  // ── FILE · Sistemas de ficheros ───────────────────────────────────────────
  "FILE-6310": {
    es: "Hay directorios que no están en particiones separadas: si uno se llena puede afectar al resto del sistema",
    // Reparticionar un equipo ya instalado no es un paso que se pueda dar sin reinstalar.
    fix: { all: "Separar /var, /tmp o /home en particiones propias se decide al instalar el sistema; hacerlo después exige reparticionar. En un equipo personal ya instalado, lo práctico es vigilar el espacio libre en vez de reparticionar." },
    v: "doc",
  },
  "FILE-7524": {
    es: "Hay ficheros con permisos más abiertos de lo recomendable",
    fix: { all: "Revisa los ficheros que Lynis señala en la evidencia y ajusta sus permisos con `chmod`. Antes de cambiar ninguno, comprueba qué programa lo usa: quitar permisos a un fichero de configuración en uso puede dejar un servicio sin arrancar." },
    v: "doc",
  },

  // ── FINT · Integridad de ficheros ─────────────────────────────────────────
  "FINT-4350": {
    es: "No hay ninguna herramienta de integridad de ficheros instalada (AIDE, Tripwire): no se detectaría la modificación de un fichero del sistema",
    // `aideinit` es de Debian; en el resto, `aide --init`. En Arch aide está en AUR: sin orden.
    fix: { linux: "Instala `aide` y genera la base de referencia: `sudo aideinit` en Debian y Ubuntu, `sudo aide --init` en otras distribuciones. Compárala periódicamente con `sudo aide --check`. La base hay que regenerarla tras cada actualización del sistema, o dará falsos positivos.", all: null },
    pkg: { apt: "aide", dnf: "aide", yum: "aide" }, v: "doc",
  },

  // ── FIRE · Cortafuegos ────────────────────────────────────────────────────
  "FIRE-4590": {
    es: "No se ha detectado ningún cortafuegos activo que filtre el tráfico de entrada y salida",
    // En macOS Lynis lo da por activo si socketfilterfw dice "Firewall is enabled".
    fix: {
      darwin: "Comprueba su estado con `/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate`. Si está desactivado, actívalo en Ajustes del Sistema, Red, Cortafuegos, o con `sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on`.",
      linux: "Activa un cortafuegos. Con ufw: `sudo ufw enable`. Con firewalld: `sudo systemctl enable --now firewalld`. Si accedes al equipo por SSH, permite antes ese acceso (`sudo ufw allow ssh`) para no quedarte fuera.",
      all: null,
    },
    v: "doc",
  },

  // ── HOME · Directorios personales ─────────────────────────────────────────
  "HOME-9304": {
    es: "Hay directorios personales con permisos más abiertos de lo recomendable: otros usuarios pueden entrar en ellos",
    // Lynis pide 750 o más restrictivo en cada home; no mira los ficheros de dentro.
    fix: { all: "Revisa los permisos con `ls -ld /home/*` (en macOS, `ls -ld /Users/*`) y restringe los directorios que no deban ser accesibles para otros usuarios: `chmod 750 <directorio>`." },
    v: "doc",
  },

  // ── HRDN · Endurecimiento general ─────────────────────────────────────────
  "HRDN-7222": {
    es: "Los compiladores instalados están accesibles para cualquier usuario: conviene restringirlos a administradores",
    fix: { linux: "Limita el acceso al compilador: `sudo chmod 750 /usr/bin/gcc` (y equivalentes). Solo tiene sentido en un servidor con varios usuarios; en un equipo de desarrollo personal, restringir tu propio compilador no aporta nada.", all: null },
    v: "doc",
  },
  "HRDN-7230": {
    es: "No hay ningún antivirus ni escáner de malware instalado",
    fix: {
      linux: "Instala `clamav` si quieres análisis bajo demanda: `sudo freshclam` actualiza las firmas y `clamscan -r <ruta>` analiza una carpeta.",
      darwin: "macOS trae XProtect y Gatekeeper activados de fábrica, que es lo que Lynis no sabe detectar. Comprueba que la protección de integridad sigue activa con `csrutil status`.",
      all: null,
    },
    v: "macos",
  },

  // ── HTTP · Servidor web ───────────────────────────────────────────────────
  "HTTP-6640": {
    es: "El servidor web Apache no tiene instalado el módulo mod_evasive, que mitiga ataques de denegación de servicio y de fuerza bruta",
    // HTTP-6640 es mod_evasive y HTTP-6643 es ModSecurity; es fácil cruzarlos.
    fix: { all: "Si este equipo no sirve páginas web a nadie, lo más seguro es parar Apache. Si sí lo usas y está expuesto a internet, instala mod_evasive y ajusta sus umbrales de peticiones por segundo." },
    v: "doc",
  },
  "HTTP-6643": {
    es: "El servidor web Apache no tiene instalado el módulo de seguridad ModSecurity, que protege frente a ataques a aplicaciones web",
    fix: { all: "Si este equipo no sirve páginas web a nadie, lo más seguro es parar Apache en vez de endurecerlo. Si sí lo usas, instala ModSecurity y activa el conjunto de reglas OWASP CRS." },
    v: "doc",
  },

  // ── LOGG · Registro ───────────────────────────────────────────────────────
  "LOGG-2154": {
    es: "El servicio de registro (syslog) no envía copia a un servidor remoto: si alguien accede al equipo puede borrar sus huellas",
    fix: { linux: "Configura el reenvío en /etc/rsyslog.conf con `*.* @@servidor:514`. Necesita un servidor de registro al que enviar: en un equipo personal sin esa infraestructura, no aplica.", all: null },
    v: "doc",
  },
  "LOGG-2190": {
    es: "Hay ficheros borrados que algún proceso sigue manteniendo abiertos",
    // Ficheros borrados que siguen en uso, no la rotación de registros.
    fix: { all: "Lístalos con `sudo lsof +L1`. Suele tratarse de registros rotados o de bibliotecas sustituidas en una actualización que un servicio sigue usando, y reiniciar ese servicio los libera. Si no reconoces el proceso, investígalo: mantener abierto un fichero borrado es también una forma de ocultarlo." },
    v: "doc",
  },

  // ── NAME · Resolución de nombres ──────────────────────────────────────────
  "NAME-4028": {
    es: "No se ha encontrado el nombre de dominio del equipo",
    // Lynis lo busca con `dnsdomainname`, en /etc/resolv.conf y en el nombre completo del equipo.
    fix: { linux: "Si el equipo pertenece a un dominio, añade en /etc/hosts una línea `127.0.1.1 <nombre>.<dominio> <nombre>`, o el dominio en /etc/resolv.conf. En un equipo doméstico sin dominio, puedes ignorarlo.", all: null },
    v: "doc",
  },
  "NAME-4404": {
    es: "El nombre del equipo no se resuelve correctamente en /etc/hosts",
    fix: { all: "Añade en /etc/hosts una línea que asocie 127.0.0.1 al nombre que devuelve `hostname`. Sin ella, algunos programas tardan en arrancar esperando a resolver su propio nombre." },
    v: "macos",
  },

  // ── NETW · Red ────────────────────────────────────────────────────────────
  "NETW-2704": {
    es: "Alguno de los servidores DNS configurados no responde a las consultas de comprobación. En una red doméstica es normal: muchos proveedores filtran ese tipo de consulta",
    // El DNS del router suele filtrar las consultas SOA que usa Lynis: no hay nada roto.
    noAction: true, v: "macos",
  },
  "NETW-2705": {
    es: "Hay menos de dos servidores DNS respondiendo. En una red doméstica es lo habitual y no supone un problema",
    noAction: true, v: "macos",
  },
  "NETW-3200": {
    es: "Hay protocolos de red poco habituales activados en el kernel (dccp, sctp, rds, tipc): si no los usas, conviene desactivarlos",
    fix: {
      linux: "Comprueba si el protocolo que indica la evidencia se usa en este equipo. Si no, impide que su módulo se cargue creando un fichero en /etc/modprobe.d/ con la línea `install <protocolo> /bin/true`.",
      all: "Comprueba si el protocolo que indica la evidencia se usa en este equipo y desactívalo si no.",
    },
    v: "doc",
  },

  // ── PKGS · Paquetes ───────────────────────────────────────────────────────
  "PKGS-7346": {
    es: "Hay paquetes desinstalados cuyos ficheros de configuración siguen en el sistema",
    // Paquetes en estado "rc" (borrados sin purgar), no huérfanos de apt autoremove.
    fix: { linux: "Lístalos con `dpkg -l | grep '^rc'` y elimina sus restos con `sudo apt purge <paquete>`. Revisa antes la lista: purgar borra también la configuración que hubieras personalizado.", all: null },
    v: "doc",
  },
  "PKGS-7370": {
    es: "debsums está instalado, pero no está programado para comprobar periódicamente la integridad de los paquetes",
    // Solo sale si debsums ya está instalado y no hay comprobación periódica.
    fix: { linux: "Programa la comprobación poniendo `CRON_CHECK=weekly` (o daily o monthly) en /etc/default/debsums. Puedes lanzarla a mano con `sudo debsums -c`, que lista los ficheros cuyo contenido ya no coincide con el del paquete original.", all: null },
    v: "doc",
  },
  "PKGS-7394": {
    es: "El paquete apt-show-versions no está instalado: no se puede ver de un vistazo qué paquetes tienen actualización pendiente",
    // Las actualizaciones automáticas son PKGS-7420, no este control.
    fix: { linux: "Instala `apt-show-versions`. `apt-show-versions -u` lista de una vez todo lo que tiene actualización pendiente y de qué repositorio viene.", all: null },
    pkg: "apt-show-versions", v: "doc",
  },
  "PKGS-7398": {
    es: "No se ha encontrado ninguna herramienta de comprobación de vulnerabilidades del gestor de paquetes",
    // Lynis reconoce, entre otras, arch-audit (Arch) y debsecan (Debian).
    fix: {
      darwin: "Este control lo cubre LoCoAudit por su cuenta: el módulo de vulnerabilidades analiza tus paquetes con Trivy y sus hallazgos están en este mismo informe. En macOS no hay una herramienta equivalente para Homebrew que Lynis reconozca.",
      linux: "Este control lo cubre LoCoAudit por su cuenta: el módulo de vulnerabilidades analiza tus paquetes con Trivy y sus hallazgos están en este mismo informe. Si quieres además una herramienta en el propio sistema que Lynis reconozca, instala `arch-audit` en Arch o `debsecan` en Debian.",
      all: null,
    },
    v: "macos",
  },
  "PKGS-7410": {
    es: "Hay muchos núcleos (kernels) antiguos instalados que ocupan espacio y ya no se usan",
    // Más de cinco núcleos instalados; el reinicio pendiente es KRNL-5830.
    fix: { linux: "Comprueba cuáles hay con `dpkg -l 'linux-image*'` y elimina los antiguos con `sudo apt autoremove`, que conserva el que está en uso. En Fedora, `sudo dnf remove --oldinstallonly`. No borres a mano el núcleo que muestra `uname -r`.", all: null },
    v: "doc",
  },
  "PKGS-7420": {
    es: "No hay ninguna herramienta que instale automáticamente las actualizaciones",
    // Las herramientas de auditoría de paquetes son PKGS-7398, no este control.
    fix: { linux: "En Debian y Ubuntu, instala `unattended-upgrades` y actívalo con `sudo dpkg-reconfigure -plow unattended-upgrades`; en Fedora, `dnf-automatic`. Así las correcciones de seguridad se aplican sin que tengas que acordarte.", all: null },
    pkg: { apt: "unattended-upgrades", dnf: "dnf-automatic" }, v: "doc",
  },

  // ── PRNT · Impresión ──────────────────────────────────────────────────────
  "PRNT-2307": {
    es: "Los permisos del fichero de configuración de CUPS son más abiertos de lo recomendable",
    // Lynis acepta como mucho 660; que CUPS escuche en la red es PRNT-2308.
    fix: { linux: "Restringe el fichero: `sudo chmod 640 /etc/cups/cupsd.conf`. Los usuarios que no son administradores no necesitan leerlo.", all: null },
    v: "doc",
  },

  // ── PROC · Procesos ───────────────────────────────────────────────────────
  "PROC-3614": {
    es: "Hay procesos bloqueados esperando a que termine una operación de disco",
    // Lynis busca procesos en estado "D" (espera de E/S).
    fix: { linux: "Suele ser momentáneo. Si se repite en varias auditorías, localízalos con `ps -eo pid,stat,comm | awk '$2 ~ /^D/'` y revisa el almacenamiento que usan: los procesos que se quedan en este estado apuntan a menudo a un disco lento o a una unidad de red que no responde.", all: null },
    v: "doc",
  },

  // ── STRG · Almacenamiento ─────────────────────────────────────────────────
  "STRG-1846": {
    es: "Los controladores de almacenamiento FireWire están habilitados: cualquiera con acceso físico podría conectar un dispositivo",
    // Es FireWire, no squashfs. Lynis lo da por resuelto con `blacklist` o `install ... /bin/true`.
    fix: { linux: "Si no usas dispositivos FireWire, impide la carga del módulo con un fichero en /etc/modprobe.d/ que contenga `install firewire-core /bin/true`.", all: null },
    v: "doc",
  },

  // ── TOOL · Herramientas de auditoría ──────────────────────────────────────
  "TOOL-5002": {
    es: "No hay ninguna herramienta de gestión automatizada de configuración instalada (Ansible, Puppet, Salt)",
    // Gestión de configuración, no detección de intrusiones (rkhunter, aide).
    fix: { all: "Sirve para reproducir la configuración de un equipo de forma automática y repetible. Tiene sentido cuando administras varias máquinas; en un equipo personal único no aporta nada y puedes ignorarlo." },
    v: "doc",
  },

  // ── USB · Almacenamiento extraíble ────────────────────────────────────────
  "USB-1000": {
    es: "El almacenamiento USB está habilitado sin restricciones: cualquiera con acceso físico puede conectar una memoria y copiar datos",
    fix: { linux: "Si no usas memorias USB en este equipo, impide la carga del módulo con un fichero en /etc/modprobe.d/ que contenga `install usb-storage /bin/true`. Si sí las usas, este control no aplica a tu caso.", all: null },
    v: "doc",
  },
};

/** Candidatos, por preferencia, para distinguir entradas del mismo control, que comparten traducción.
 *  Se devuelven todos para poder bajar al siguiente si uno no distingue. */
function discriminadoresLynis(description, detail) {
  const desc = String(description || "").trim();
  const det = String(detail || "").trim();
  const out = [];

  // 1. Token entrecomillado: así nombra Lynis el protocolo o servicio concreto.
  const entrecomillado = desc.match(/'([^']{1,40})'/);
  if (entrecomillado) out.push({ text: entrecomillado[1], translated: true, source: "quoted" });

  // 2. minimum/maximum: la única diferencia entre las dos sugerencias de AUTH-9286.
  if (/\bminimum\b/i.test(desc)) out.push({ text: "mínima", translated: true, source: "minmax" });
  else if (/\bmaximum\b/i.test(desc)) out.push({ text: "máxima", translated: true, source: "minmax" });

  // 3. Ruta absoluta, salvo las de /etc, que se repiten entre entradas (/etc/login.defs).
  const rutas = (desc.match(/\/[A-Za-z0-9_.\-/]+/g) || [])
    .filter((r) => !/^\/etc\//.test(r));
  if (rutas.length) out.push({ text: rutas[0], translated: true, source: "path" });

  // 4. El campo 3 del .dat (en FILE-6310, el punto de montaje).
  if (det) out.push({ text: det, translated: true, source: "detail" });

  // 5. Último recurso: la frase original en inglés, marcada como no traducida.
  if (desc) out.push({ text: desc, translated: false, source: "original" });

  return out;
}

/** Primer nivel de discriminador que existe y es distinto en todas las entradas, o null si ninguno sirve. */
function elegirDiscriminadores(entradas) {
  const listas = entradas.map((e) => discriminadoresLynis(e.description, e.detail));
  const maxNivel = Math.max(0, ...listas.map((l) => l.length));

  for (let nivel = 0; nivel < maxNivel; nivel++) {
    const cand = listas.map((l) => l[nivel] || null);
    if (cand.some((c) => !c || !c.text)) continue;
    if (new Set(cand.map((c) => c.text)).size !== cand.length) continue;
    return cand;
  }
  return null;
}

/** Controles cubiertos por el diccionario. */
const LYNIS_ES_IDS = Object.keys(LYNIS_ES);

/** Ficha oficial del control en la documentación de Lynis. */
function urlControlLynis(control) {
  const id = String(control || "").trim().toUpperCase();
  if (/^[A-Z]{3,5}-\d{3,5}$/.test(id)) {
    return `https://cisofy.com/lynis/controls/${id}/`;
  } else {
    return null;
  }
}

/** Entrada normalizada, o null. */
function entradaLynis(control) {
  return LYNIS_ES[String(control || "").trim().toUpperCase()] || null;
}

/** Texto de un control; sin traducción, el original en inglés con `translated: false`. */
function textoLynis(control, original) {
  const id = String(control || "").trim().toUpperCase();
  const fallback = String(original || "").trim();
  const e = entradaLynis(id);
  if (e && e.es) return { text: e.es, translated: true };
  if (!fallback) {
    return { text: `Control ${id || "desconocido"} de Lynis, sin descripción disponible`, translated: false };
  }
  return { text: fallback, translated: false };
}

/** Paso de resolución `{ fix, command, noAction }`. `command` solo existe si la entrada
 *  declara `pkg` y se conoce el gestor. */
function solucionLynis(control, platform, pkgManager, installCmd) {
  const e = entradaLynis(control);
  if (!e) return { fix: null, command: null, noAction: false };
  if (e.noAction) return { fix: null, command: null, noAction: true };

  const plat = platform || process.platform;
  const f = e.fix;
  let texto;
  if (typeof f === "string") {
    texto = f;
  } else {
    texto = (f && (f[plat] || f.all)) || null;
  }
  if (!texto) return { fix: null, command: null, noAction: false };

  // El comando va en su propia línea: finding-schema.js solo mira la primera, que aquí es prosa.
  let pkgName;
  if (e.pkg && typeof e.pkg === "object") {
    pkgName = e.pkg[pkgManager];
  } else {
    pkgName = e.pkg;
  }
  let cmd;
  if (pkgName && typeof installCmd === "function") {
    cmd = installCmd(pkgManager, pkgName);
  } else {
    cmd = null;
  }
  let fix;
  if (cmd) {
    fix = `${texto}\n${cmd}`;
  } else {
    fix = texto;
  }
  return { fix, command: cmd, noAction: false };
}

/** Cobertura del diccionario sobre los controles vistos. `missingFix` son los que admiten acción
 *  pero no tienen el paso escrito. */
function coberturaLynis(controles, platform) {
  const plat = platform || process.platform;
  const vistos = [...new Set((controles || []).map((c) => String(c || "").trim().toUpperCase()).filter(Boolean))];

  const traducidos = vistos.filter((c) => entradaLynis(c));
  const conFix = [];
  const sinAccion = [];
  const sinPaso = [];
  for (const c of traducidos) {
    const r = solucionLynis(c, plat, null, null);
    if (r.noAction) sinAccion.push(c);
    else if (r.fix) conFix.push(c);
    else sinPaso.push(c);
  }

  const enSistemaReal = traducidos.filter((c) => entradaLynis(c).v === "macos");
  return {
    total: vistos.length,
    translated: traducidos.length,
    missing: vistos.filter((c) => !entradaLynis(c)).sort(),
    withFix: conFix.length,
    noAction: sinAccion.length,
    missingFix: sinPaso.length,
    noActionIds: sinAccion.sort(),
    missingFixIds: sinPaso.sort(),
    // Qué falta por probar en un sistema real.
    verified: { real: enSistemaReal.sort(), doc: traducidos.filter((c) => entradaLynis(c).v !== "macos").sort() },
  };
}

module.exports = {
  LYNIS_ES, LYNIS_ES_IDS, textoLynis, solucionLynis, coberturaLynis, urlControlLynis,
  discriminadoresLynis, elegirDiscriminadores,
};
