"use strict";

/**
 * lynis-i18n.js — Controles de Lynis: texto en castellano Y paso de resolución.
 *
 * FICHERO DE DATOS. Aquí no se parsea nada ni se decide nada: solo la tabla y el acceso a ella.
 * El parseo del .dat vive en nodes/audit-host/modules/lynis.js y la construcción del finding en
 * lib/normalizer.js.
 *
 * ── Por qué indexado por ID COMPLETO y no por prefijo ─────────────────────────────────────────
 * Los fixes vivían en `FIXES_BY_PLATFORM` (lib/normalizer.js), indexada por el PREFIJO del ID:
 * BOOT-, PKGS-, AUTH-. El prefijo es el área temática, no el problema, así que todos los
 * controles de un área recibían la misma solución. Medido sobre informes reales: 14 de 43 fixes
 * en Debian eran "Revisar la configuración del sistema relacionada con <ID>" —repetir el
 * identificador, no una solución— y otros 9 eran la solución de OTRO problema:
 *
 *   BOOT-5122  GRUB sin contraseña        → "revisar los servicios de arranque"
 *   PKGS-7420  sin auditoría de paquetes  → "sudo apt upgrade", con botón de copiar
 *   FIRE-4590  el cortafuegos no registra → "activar el cortafuegos", que ya estaba activo
 *   TOOL-5002  falta Ansible/Puppet       → "rkhunter, chkrootkit, aide"
 *   ACCT-9626  falta sysstat              → "auditd"
 *
 * Es el mismo fallo que tenía la traducción antes de indexarse por control: la granularidad del
 * índice no coincidía con la del dato. La tabla por prefijo se ha ELIMINADO, no degradado a
 * respaldo: un respaldo plausible pero equivocado es peor que ninguno, porque ocupa el sitio de
 * la recomendación real y nadie lo mira dos veces.
 *
 * ── Sin fix no se inventa uno ────────────────────────────────────────────────────────────────
 * Un control sin entrada `fix` NO produce campo `fix` en el finding. En su lugar se rellena
 * `primaryUrl` con la ficha oficial del control. Mismo principio que "0 vulnerabilidades" no
 * puede parecer un resultado limpio: un fix genérico finge ser una recomendación.
 *
 * ── `noAction`: no es lo mismo que no tenerlo escrito ────────────────────────────────────────
 * Dos motivos distintos para no llevar `fix`, y se distinguen:
 *   - sin `fix` y sin `noAction` → hay acción posible, pero LoCoAudit no tiene el paso escrito.
 *   - `noAction: true`          → el control no admite acción. PROC-3614 informa de que no se
 *                                 han podido comprobar unos límites: no hay nada que arreglar.
 * Colapsarlos daría "13 sin cubrir" mezclando lo que falta por escribir con lo que no existe.
 *
 * ── Por qué no lo traduce ni lo redacta el LLM ───────────────────────────────────────────────
 * El cliente LLM de LoCoAudit es OPCIONAL y no determinista. Dos ejecuciones sobre el mismo .dat
 * darían dos informes distintos, y un informe de auditoría que no se puede reproducir no sirve
 * como evidencia. Una tabla estática da siempre lo mismo.
 *
 * ── Procedencia de cada fix ──────────────────────────────────────────────────────────────────
 * Los marcados `v: "macos"` se han comprobado contra un macOS real (rutas, nombres de ajustes y
 * comandos ejecutados). Los marcados `v: "doc"` proceden de la documentación de Lynis, de Debian
 * y de las páginas de manual, y NO se han ejecutado en el sistema que describen. La distinción
 * viaja en `lynisCoverage().verified` para que el protocolo de validación sepa qué falta probar.
 */

/**
 * Cobertura: solo los controles que aparecen de verdad en los informes de referencia (Debian 13
 * y macOS 26). El catálogo de Lynis pasa de 300 controles y traducirlo entero a ciegas sería
 * inventar texto sobre comprobaciones que nadie ha visto ejecutarse.
 *
 * Forma de cada entrada:
 *   es        texto en castellano del hallazgo (obligatorio)
 *   fix       paso de resolución. String, u objeto { linux, darwin, all }. Ausente ⇒ no se emite.
 *   pkg       paquete a instalar: un nombre, o un objeto { apt, pacman, dnf, ... } cuando cambia
 *             según la distribución. El comando lo compone installCmd() con el gestor real
 *   noAction  true si el control no admite ninguna acción
 *   v         "macos" verificado en sistema real · "doc" desde documentación
 */
const LYNIS_ES = {
  // ── ACCT · Contabilidad de procesos ───────────────────────────────────────
  "ACCT-9622": {
    es: "La contabilidad de procesos no está activada: el sistema no guarda registro de qué programas se han ejecutado ni quién los lanzó",
    // Lynis busca el fichero pacct en /var/account, /var/log/account o /var/log. El paquete se llama
    // `acct` en Debian y `psacct` en Fedora; en Arch no se ha podido confirmar, así que sin orden.
    fix: { linux: "Instala el paquete de contabilidad de procesos (`acct` en Debian y Ubuntu, `psacct` en Fedora) y activa su servicio. Después, `lastcomm` muestra los programas ejecutados y `sa` un resumen por usuario.", all: null },
    pkg: { apt: "acct", dnf: "psacct", yum: "psacct" }, v: "doc",
  },
  "ACCT-9626": {
    es: "Sysstat no está recogiendo estadísticas: no se guarda el histórico de uso del sistema",
    // Lynis mira primero /etc/default/sysstat (ENABLED="true"), que es como lo activa Debian; luego el
    // cron y, en último lugar, la unidad de systemd. En Debian el `systemctl enable` solo no basta.
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
    // El prefijo BOOT proponía revisar los servicios del arranque, que no tiene nada que ver.
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
    // Corregido: la primera versión de esta entrada decía "no se ha podido determinar el estado"
    // y la marcaba como sin acción. Falso — Lynis da aquí una orden concreta en su campo 3
    // (`Run 'systemd-analyze security SERVICE'`), y el propio informe la convierte en un botón.
    // Lo cazó test-normalizer-lynis.js contra el .dat real.
    fix: { linux: "Revisa el nivel de exposición de cada servicio con `systemd-analyze security`, que los puntúa de 0 a 10. Para los peores, añade restricciones (`ProtectSystem`, `PrivateTmp`, `NoNewPrivileges`) en un fichero de sobrescritura: `sudo systemctl edit <servicio>`.", all: null },
    v: "doc",
  },

  // ── DEB · Específicos de Debian y derivadas ───────────────────────────────
  "DEB-0280": {
    es: "El paquete libpam-tmpdir no está instalado: todas las sesiones usan el mismo directorio temporal compartido",
    // Validado el 2026-10-10. Los DEB-* no están en Lynis: son el parche no oficial que añade el paquete
  // de Debian (cisofy.com/lynis/controls/DEB-0880/ lo marca así). Texto comprobado en un informe
  // real de Lynis 3.0.8 sobre Debian (hackmd.io/T3XoVxRpQj6bT4CPJXQ4gA).
    fix: { linux: "Instala `libpam-tmpdir`. Al iniciar sesión, cada usuario recibe su propio directorio temporal privado (variables TMP y TMPDIR), de modo que los demás usuarios no pueden ver ni manipular sus ficheros temporales.", all: null },
    pkg: "libpam-tmpdir", v: "doc",
  },
  "DEB-0810": {
    es: "El paquete apt-listbugs no está instalado: no se avisa de fallos graves conocidos antes de instalar una actualización",
    // Validado el 2026-10-10. Los DEB-* no están en Lynis: son el parche no oficial que añade el paquete
  // de Debian (cisofy.com/lynis/controls/DEB-0880/ lo marca así). Texto comprobado en un informe
  // real de Lynis 3.0.8 sobre Debian (hackmd.io/T3XoVxRpQj6bT4CPJXQ4gA).
    fix: { linux: "Instala `apt-listbugs`. A partir de entonces, apt te avisará de los fallos críticos reportados antes de aplicar cada actualización.", all: null },
    pkg: "apt-listbugs", v: "doc",
  },
  "DEB-0831": {
    es: "El paquete needrestart no está instalado: tras actualizar no se avisa de los servicios que siguen usando versiones antiguas de las bibliotecas",
    // Validado el 2026-10-10. Los DEB-* no están en Lynis: son el parche no oficial que añade el paquete
  // de Debian (cisofy.com/lynis/controls/DEB-0880/ lo marca así). Texto comprobado en un informe
  // real de Lynis 3.0.8 sobre Debian (hackmd.io/T3XoVxRpQj6bT4CPJXQ4gA).
    fix: { linux: "Instala `needrestart`. Después de cada actualización con apt indica qué servicios hay que reiniciar para que dejen de usar las bibliotecas sustituidas; también puedes lanzarlo a mano con `sudo needrestart`.", all: null },
    pkg: "needrestart", v: "doc",
  },
  "DEB-0880": {
    es: "fail2ban no está instalado: no se bloquea a quien falla repetidamente al iniciar sesión",
    // Validado el 2026-10-10. Los DEB-* no están en Lynis: son el parche no oficial que añade el paquete
  // de Debian (cisofy.com/lynis/controls/DEB-0880/ lo marca así). Texto comprobado en un informe
  // real de Lynis 3.0.8 sobre Debian (hackmd.io/T3XoVxRpQj6bT4CPJXQ4gA).
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
    // `aideinit` es el envoltorio de Debian; en el resto, `aide --init`. En Arch, aide solo está en
    // AUR: sin orden de instalación.
    fix: { linux: "Instala `aide` y genera la base de referencia: `sudo aideinit` en Debian y Ubuntu, `sudo aide --init` en otras distribuciones. Compárala periódicamente con `sudo aide --check`. La base hay que regenerarla tras cada actualización del sistema, o dará falsos positivos.", all: null },
    pkg: { apt: "aide", dnf: "aide", yum: "aide" }, v: "doc",
  },

  // ── FIRE · Cortafuegos ────────────────────────────────────────────────────
  "FIRE-4590": {
    es: "No se ha detectado ningún cortafuegos activo que filtre el tráfico de entrada y salida",
    // Validado el 2026-10-10 contra el código de Lynis 3.1.8 (include/tests_*) y los informes reales
  // de test/fixtures/lynis/ (3.1.6 y 3.1.7).
    // Lynis emite este control cuando NO encuentra un cortafuegos activo (FIREWALL_ACTIVE=0). La
    // versión anterior lo describía como "el cortafuegos no registra el tráfico", que es otro
    // problema. En macOS, Lynis lo da por activo si `socketfilterfw --getglobalstate` dice
    // "Firewall is enabled": si ya lo está y aun así sale, no hay nada que cambiar.
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
    // Validado el 2026-10-10 contra el código de Lynis 3.1.8 (include/tests_*) y los informes reales
  // de test/fixtures/lynis/ (3.1.6 y 3.1.7).
    // Lynis comprueba que cada directorio personal sea 750 o más restrictivo (sin escritura para el
    // grupo ni ningún permiso para otros). No mira los ficheros de dentro, como decía la versión
    // anterior.
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
    // Validado el 2026-10-10 contra el código de Lynis 3.1.8 (include/tests_*) y los informes reales
  // de test/fixtures/lynis/ (3.1.6 y 3.1.7).
    // HTTP-6640 es mod_evasive y HTTP-6643 es ModSecurity. La versión anterior los tenía cruzados.
    fix: { all: "Si este equipo no sirve páginas web a nadie, lo más seguro es parar Apache. Si sí lo usas y está expuesto a internet, instala mod_evasive y ajusta sus umbrales de peticiones por segundo." },
    v: "doc",
  },
  "HTTP-6643": {
    es: "El servidor web Apache no tiene instalado el módulo de seguridad ModSecurity, que protege frente a ataques a aplicaciones web",
    // Validado el 2026-10-10 contra el código de Lynis 3.1.8 (include/tests_*) y los informes reales
  // de test/fixtures/lynis/ (3.1.6 y 3.1.7).
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
    // Validado el 2026-10-10 contra el código de Lynis 3.1.8 (include/tests_*) y los informes reales
  // de test/fixtures/lynis/ (3.1.6 y 3.1.7).
    // El control busca ficheros borrados que siguen en uso, no la rotación de registros como decía
    // la versión anterior (que además proponía instalar logrotate).
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
    // Comprobado en macOS: el DNS del router responde a consultas normales y filtra las SOA que
    // usa Lynis. No hay nada roto que arreglar.
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
    // Validado el 2026-10-10 contra el código de Lynis 3.1.8 (include/tests_*) y los informes reales
  // de test/fixtures/lynis/ (3.1.6 y 3.1.7).
    // Lynis cuenta los paquetes en estado "rc" (borrados sin purgar) y recomienda purgarlos. La
    // versión anterior hablaba de paquetes huérfanos y de apt autoremove, que es otra cosa.
    fix: { linux: "Lístalos con `dpkg -l | grep '^rc'` y elimina sus restos con `sudo apt purge <paquete>`. Revisa antes la lista: purgar borra también la configuración que hubieras personalizado.", all: null },
    v: "doc",
  },
  "PKGS-7370": {
    es: "debsums está instalado, pero no está programado para comprobar periódicamente la integridad de los paquetes",
    // Validado el 2026-10-10 contra el código de Lynis 3.1.8 (include/tests_*) y los informes reales
  // de test/fixtures/lynis/ (3.1.6 y 3.1.7).
    // Lynis solo emite este control si debsums ya está instalado y no hay comprobación periódica.
    // La versión anterior hablaba de debsig-verify, que es otra herramienta.
    fix: { linux: "Programa la comprobación poniendo `CRON_CHECK=weekly` (o daily o monthly) en /etc/default/debsums. Puedes lanzarla a mano con `sudo debsums -c`, que lista los ficheros cuyo contenido ya no coincide con el del paquete original.", all: null },
    v: "doc",
  },
  "PKGS-7394": {
    es: "El paquete apt-show-versions no está instalado: no se puede ver de un vistazo qué paquetes tienen actualización pendiente",
    // Validado el 2026-10-10 contra el código de Lynis 3.1.8 (include/tests_*) y los informes reales
  // de test/fixtures/lynis/ (3.1.6 y 3.1.7).
    // La versión anterior trataba aquí las actualizaciones automáticas, que son PKGS-7420.
    fix: { linux: "Instala `apt-show-versions`. `apt-show-versions -u` lista de una vez todo lo que tiene actualización pendiente y de qué repositorio viene.", all: null },
    pkg: "apt-show-versions", v: "doc",
  },
  "PKGS-7398": {
    es: "No se ha encontrado ninguna herramienta de comprobación de vulnerabilidades del gestor de paquetes",
    // El prefijo PKGS proponía `brew upgrade`: actualizar paquetes no instala una herramienta de
    // auditoría, y además ponía un botón de copiar sobre un comando que no resuelve el hallazgo.
    // Validado el 2026-10-10: Lynis reconoce, entre otras, arch-audit (Arch) y debsecan (Debian).
    fix: {
      darwin: "Este control lo cubre LoCoAudit por su cuenta: el módulo de vulnerabilidades analiza tus paquetes con Trivy y sus hallazgos están en este mismo informe. En macOS no hay una herramienta equivalente para Homebrew que Lynis reconozca.",
      linux: "Este control lo cubre LoCoAudit por su cuenta: el módulo de vulnerabilidades analiza tus paquetes con Trivy y sus hallazgos están en este mismo informe. Si quieres además una herramienta en el propio sistema que Lynis reconozca, instala `arch-audit` en Arch o `debsecan` en Debian.",
      all: null,
    },
    v: "macos",
  },
  "PKGS-7410": {
    es: "Hay muchos núcleos (kernels) antiguos instalados que ocupan espacio y ya no se usan",
    // Validado el 2026-10-10 contra el código de Lynis 3.1.8 (include/tests_*) y los informes reales
  // de test/fixtures/lynis/ (3.1.6 y 3.1.7).
    // Lynis lo emite con más de cinco núcleos instalados y recomienda limpiarlos. La versión
    // anterior decía que había que reiniciar, que es KRNL-5830.
    fix: { linux: "Comprueba cuáles hay con `dpkg -l 'linux-image*'` y elimina los antiguos con `sudo apt autoremove`, que conserva el que está en uso. En Fedora, `sudo dnf remove --oldinstallonly`. No borres a mano el núcleo que muestra `uname -r`.", all: null },
    v: "doc",
  },
  "PKGS-7420": {
    es: "No hay ninguna herramienta que instale automáticamente las actualizaciones",
    // Validado el 2026-10-10 contra el código de Lynis 3.1.8 (include/tests_*) y los informes reales
  // de test/fixtures/lynis/ (3.1.6 y 3.1.7).
    // La versión anterior trataba aquí las herramientas de auditoría de paquetes, que son PKGS-7398.
    fix: { linux: "En Debian y Ubuntu, instala `unattended-upgrades` y actívalo con `sudo dpkg-reconfigure -plow unattended-upgrades`; en Fedora, `dnf-automatic`. Así las correcciones de seguridad se aplican sin que tengas que acordarte.", all: null },
    pkg: { apt: "unattended-upgrades", dnf: "dnf-automatic" }, v: "doc",
  },

  // ── PRNT · Impresión ──────────────────────────────────────────────────────
  "PRNT-2307": {
    es: "Los permisos del fichero de configuración de CUPS son más abiertos de lo recomendable",
    // Validado el 2026-10-10 contra el código de Lynis 3.1.8 (include/tests_*) y los informes reales
  // de test/fixtures/lynis/ (3.1.6 y 3.1.7).
    // Lynis acepta el fichero si otros usuarios no tienen ningún permiso (como mucho, 660). Lo de
    // que CUPS escuche en la red es PRNT-2308, no este control.
    fix: { linux: "Restringe el fichero: `sudo chmod 640 /etc/cups/cupsd.conf`. Los usuarios que no son administradores no necesitan leerlo.", all: null },
    v: "doc",
  },

  // ── PROC · Procesos ───────────────────────────────────────────────────────
  "PROC-3614": {
    es: "Hay procesos bloqueados esperando a que termine una operación de disco",
    // Validado el 2026-10-10 contra el código de Lynis 3.1.8 (include/tests_*) y los informes reales
  // de test/fixtures/lynis/ (3.1.6 y 3.1.7).
    // Lynis busca procesos en estado "D" (espera de E/S). La versión anterior lo describía como
    // "no se han podido comprobar los límites de recursos" y lo marcaba sin acción.
    fix: { linux: "Suele ser momentáneo. Si se repite en varias auditorías, localízalos con `ps -eo pid,stat,comm | awk '$2 ~ /^D/'` y revisa el almacenamiento que usan: los procesos que se quedan en este estado apuntan a menudo a un disco lento o a una unidad de red que no responde.", all: null },
    v: "doc",
  },

  // ── STRG · Almacenamiento ─────────────────────────────────────────────────
  "STRG-1846": {
    es: "Los controladores de almacenamiento FireWire están habilitados: cualquiera con acceso físico podría conectar un dispositivo",
    // Validado el 2026-10-10 contra el código de Lynis 3.1.8 (include/tests_*) y los informes reales
  // de test/fixtures/lynis/ (3.1.6 y 3.1.7).
    // El control es FireWire, no squashfs como decía la versión anterior. Lynis lo da por resuelto
    // con `blacklist` o `install ... /bin/true` de firewire-core, firewire-ohci u ohci1394.
    fix: { linux: "Si no usas dispositivos FireWire, impide la carga del módulo con un fichero en /etc/modprobe.d/ que contenga `install firewire-core /bin/true`.", all: null },
    v: "doc",
  },

  // ── TOOL · Herramientas de auditoría ──────────────────────────────────────
  "TOOL-5002": {
    es: "No hay ninguna herramienta de gestión automatizada de configuración instalada (Ansible, Puppet, Salt)",
    // El prefijo TOOL proponía rkhunter/chkrootkit/aide: detección de intrusiones, que es otra
    // cosa distinta de la gestión de configuración.
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

/**
 * Candidatos a DISCRIMINADOR de una entrada, en orden de preferencia.
 *
 * El problema: la traducción se indexa por ID, así que dos entradas del mismo control comparten
 * texto y sus tarjetas parecen duplicadas. Hay que añadir lo que las distingue — pero volcar la
 * descripción entera de Lynis mete inglés sin traducir en un título en castellano:
 *
 *   "No hay caducidad configurada… (Configure minimum password age in /etc/login.defs)"
 *
 * Lo que distingue esas dos entradas es UNA palabra, "minimum" frente a "maximum". El resto de
 * la frase es idéntica y no aporta nada. Estos son los tres patrones que cubren los tres
 * controles que se repiten en los informes de referencia:
 *
 *   NETW-3200  "Determine if protocol 'dccp' is really needed"  → dccp        (entrecomillado)
 *   AUTH-9286  "Configure minimum password age in …"            → mínima      (min/max)
 *   FILE-6310  "…place /var on a separate partition"            → /var        (ruta)
 *
 * Devuelve la lista completa de candidatos y no uno solo: quien llama necesita poder bajar al
 * siguiente si el primero no distingue de verdad. Cada uno dice si está en castellano, para que
 * el último recurso —la frase original— pueda marcarse como lo que es.
 */
function lynisDiscriminators(description, detail) {
  const desc = String(description || "").trim();
  const det = String(detail || "").trim();
  const out = [];

  // 1. Token entrecomillado: es como Lynis nombra el protocolo, el módulo o el servicio
  //    concreto de esa instancia. Es el discriminador más limpio que da.
  const entrecomillado = desc.match(/'([^']{1,40})'/);
  if (entrecomillado) out.push({ text: entrecomillado[1], translated: true, source: "quoted" });

  // 2. minimum/maximum: la única diferencia entre las dos sugerencias de AUTH-9286.
  if (/\bminimum\b/i.test(desc)) out.push({ text: "mínima", translated: true, source: "minmax" });
  else if (/\bmaximum\b/i.test(desc)) out.push({ text: "máxima", translated: true, source: "minmax" });

  // 3. Ruta absoluta de la descripción, saltando las de configuración: /etc/login.defs aparece
  //    en las DOS entradas de AUTH-9286, así que no distingue nada y solo añade ruido.
  const rutas = (desc.match(/\/[A-Za-z0-9_.\-/]+/g) || [])
    .filter((r) => !/^\/etc\//.test(r));
  if (rutas.length) out.push({ text: rutas[0], translated: true, source: "path" });

  // 4. El campo 3 del .dat. En macOS FILE-6310 trae aquí el punto de montaje y es lo único que
  //    separa sus tres entradas.
  if (det) out.push({ text: det, translated: true, source: "detail" });

  // 5. Último recurso: la frase original de Lynis, en inglés y MARCADA como tal para que el
  //    llamante pueda decirlo en vez de colarla como si fuera texto propio.
  if (desc) out.push({ text: desc, translated: false, source: "original" });

  return out;
}

/**
 * Elige el discriminador para un GRUPO de entradas del mismo control.
 *
 * Se elige por grupo y no por entrada porque el criterio es que los títulos queden DISTINTOS: un
 * candidato que da el mismo valor para dos entradas no distingue nada, por muy limpio que sea.
 * Se baja de nivel hasta encontrar uno que exista en todas y sea único en todas.
 *
 * Devuelve un array alineado con `entradas`, o null si ninguna combinación distingue (entonces
 * quien llama deja los títulos como están: repetir el texto es mejor que ensuciarlo sin ganar
 * nada).
 */
function pickLynisDiscriminators(entradas) {
  const listas = entradas.map((e) => lynisDiscriminators(e.description, e.detail));
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
function lynisControlUrl(control) {
  const id = String(control || "").trim().toUpperCase();
  return /^[A-Z]{3,5}-\d{3,5}$/.test(id) ? `https://cisofy.com/lynis/controls/${id}/` : null;
}

/** Entrada normalizada, o null. */
function _entry(control) {
  return LYNIS_ES[String(control || "").trim().toUpperCase()] || null;
}

/**
 * Texto de un control, ya resuelto.
 *
 * Devuelve SIEMPRE algo utilizable: si no hay traducción, el original en inglés con
 * `translated: false`. Nunca cadena vacía y nunca el ID a secas — "AUTH-9286" no le dice nada a
 * quien lee el informe.
 */
function lynisText(control, original) {
  const id = String(control || "").trim().toUpperCase();
  const fallback = String(original || "").trim();
  const e = _entry(id);
  if (e && e.es) return { text: e.es, translated: true };
  if (!fallback) {
    return { text: `Control ${id || "desconocido"} de Lynis, sin descripción disponible`, translated: false };
  }
  return { text: fallback, translated: false };
}

/**
 * Paso de resolución de un control, o null si no hay ninguno que dar.
 *
 * `{ fix, command, noAction }`:
 *   fix       texto, o null. NULL SIGNIFICA QUE NO SE EMITE CAMPO `fix`: nada de rellenarlo con
 *             una frase genérica que finja ser una recomendación.
 *   command   línea ejecutable para el botón de copiar, solo cuando la entrada declara `pkg` y
 *             se conoce el gestor real del equipo. El comando se compone con installCmd(), no se
 *             escribe a mano: así `apt`, `dnf` y `pacman` salen correctos sin tres textos.
 *   noAction  true si el control no admite acción. Distinto de "no lo hemos escrito".
 */
function lynisFix(control, platform, pkgManager, installCmd) {
  const e = _entry(control);
  if (!e) return { fix: null, command: null, noAction: false };
  if (e.noAction) return { fix: null, command: null, noAction: true };

  const plat = platform || process.platform;
  const f = e.fix;
  const texto = typeof f === "string" ? f : (f && (f[plat] || f.all)) || null;
  if (!texto) return { fix: null, command: null, noAction: false };

  // El comando va en su propia línea DETRÁS del texto: el extractor de finding-schema.js solo
  // mira la primera línea, y aquí la primera es prosa a propósito (explica qué hace el comando).
  // `pkg` es un nombre común a todos los gestores o un objeto por gestor, porque el mismo paquete
  // se llama distinto en cada distribución (auditd en Debian, audit en Arch y Fedora). Un gestor
  // sin entrada no recibe orden: mejor prosa que una orden que falla.
  const pkgName = e.pkg && typeof e.pkg === "object" ? e.pkg[pkgManager] : e.pkg;
  const cmd = pkgName && typeof installCmd === "function" ? installCmd(pkgManager, pkgName) : null;
  return { fix: cmd ? `${texto}\n${cmd}` : texto, command: cmd, noAction: false };
}

/**
 * Cobertura del diccionario sobre un conjunto de controles. Tres cifras, no una:
 *
 *   translated     cuántos tienen texto en castellano
 *   withFix        cuántos traen un paso de resolución concreto
 *   noAction       cuántos NO admiten acción (y por eso no traen paso)
 *   missingFix     cuántos admiten acción pero LoCoAudit todavía no tiene el paso escrito
 *
 * `withFix + noAction + missingFix` cubre a los traducidos. Separar los dos últimos importa:
 * "13 sin cubrir" mezclaría lo que falta por escribir con lo que no existe, que es exactamente
 * el colapso de estados que este proyecto lleva corrigiendo.
 *
 * `verified` reparte los IDs por procedencia del fix: comprobado en sistema real o tomado de
 * documentación. Son los IDs y no un recuento porque es material del protocolo de validación.
 */
function lynisCoverage(controles, platform) {
  const plat = platform || process.platform;
  const vistos = [...new Set((controles || []).map((c) => String(c || "").trim().toUpperCase()).filter(Boolean))];

  const traducidos = vistos.filter((c) => _entry(c));
  const conFix = [];
  const sinAccion = [];
  const sinPaso = [];
  for (const c of traducidos) {
    const r = lynisFix(c, plat, null, null);
    if (r.noAction) sinAccion.push(c);
    else if (r.fix) conFix.push(c);
    else sinPaso.push(c);
  }

  const enSistemaReal = traducidos.filter((c) => _entry(c).v === "macos");
  return {
    total: vistos.length,
    translated: traducidos.length,
    missing: vistos.filter((c) => !_entry(c)).sort(),
    withFix: conFix.length,
    noAction: sinAccion.length,
    missingFix: sinPaso.length,
    noActionIds: sinAccion.sort(),
    missingFixIds: sinPaso.sort(),
    // Qué falta por probar en hardware. La lista, no el número.
    verified: { real: enSistemaReal.sort(), doc: traducidos.filter((c) => _entry(c).v !== "macos").sort() },
  };
}

module.exports = {
  LYNIS_ES, LYNIS_ES_IDS, lynisText, lynisFix, lynisCoverage, lynisControlUrl,
  lynisDiscriminators, pickLynisDiscriminators,
};
