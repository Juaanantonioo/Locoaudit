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
 *   pkg       paquete a instalar; el comando lo compone installCmd() con el gestor real
 *   noAction  true si el control no admite ninguna acción
 *   v         "macos" verificado en sistema real · "doc" desde documentación
 */
const LYNIS_ES = {
  // ── ACCT · Contabilidad de procesos ───────────────────────────────────────
  "ACCT-9622": {
    es: "La contabilidad de procesos no está activada: el sistema no guarda registro de qué programas se han ejecutado ni quién los lanzó",
    fix: { linux: "Instala el paquete `acct` y actívalo. Después, `lastcomm` muestra los programas ejecutados y `sa` un resumen por usuario.", all: null },
    pkg: "acct", v: "doc",
  },
  "ACCT-9626": {
    es: "Sysstat no está instalado: no se recogen estadísticas de uso del sistema a lo largo del tiempo",
    // El prefijo ACCT proponía auditd, que es otra herramienta y resuelve otro control.
    fix: { linux: "Instala el paquete `sysstat` y activa su recogida periódica: `sudo systemctl enable --now sysstat`. Después, `sar` muestra el histórico de CPU, memoria, disco y red.", all: null },
    pkg: "sysstat", v: "doc",
  },
  "ACCT-9628": {
    es: "La auditoría del kernel (auditd) no está activa: no se registran los accesos a ficheros ni las llamadas al sistema",
    fix: { linux: "Instala el paquete `auditd` y actívalo: `sudo systemctl enable --now auditd`. Define qué vigilar en /etc/audit/rules.d/.", all: null },
    pkg: "auditd", v: "doc",
  },

  // ── AUTH · Cuentas y contraseñas ──────────────────────────────────────────
  "AUTH-9230": {
    es: "La configuración de cifrado de contraseñas es más débil de lo recomendable: conviene revisar el número de rondas de hash",
    fix: { linux: "En /etc/login.defs, sube `SHA_CRYPT_MIN_ROUNDS` a 65536 o más. Solo afecta a las contraseñas que se cambien a partir de entonces: las ya guardadas conservan su hash antiguo hasta que se renueven.", all: null },
    v: "doc",
  },
  "AUTH-9262": {
    es: "No hay ningún módulo PAM de robustez de contraseñas instalado: nada impide poner una contraseña trivial",
    fix: { linux: "Instala `libpam-pwquality` y configura la exigencia mínima en /etc/security/pwquality.conf (longitud, variedad de caracteres y comprobación contra diccionario).", all: null },
    pkg: "libpam-pwquality", v: "doc",
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
    fix: { linux: "Genera un hash con `grub-mkpasswd-pbkdf2`, añádelo en /etc/grub.d/40_custom junto a `set superusers=\"root\"`, y regenera la configuración con `sudo update-grub`. Protege contra alguien con acceso físico al equipo; si nadie más lo toca, es de prioridad baja.", all: null },
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
    es: "El paquete apt-listbugs no está instalado: no se avisa de fallos graves conocidos antes de instalar una actualización",
    fix: { linux: "Instala `apt-listbugs`. A partir de entonces, apt te avisará de los fallos críticos reportados antes de aplicar cada actualización.", all: null },
    pkg: "apt-listbugs", v: "doc",
  },
  "DEB-0810": {
    es: "El paquete apt-listchanges no está instalado: no se muestran los cambios de un paquete antes de actualizarlo",
    fix: { linux: "Instala `apt-listchanges` para ver el registro de cambios de cada paquete antes de que se actualice.", all: null },
    pkg: "apt-listchanges", v: "doc",
  },
  "DEB-0831": {
    es: "El paquete debsums no está instalado: no se puede comprobar que los ficheros instalados no han sido modificados",
    fix: { linux: "Instala `debsums` y comprueba la integridad con `sudo debsums -c`, que lista los ficheros cuyo contenido ya no coincide con el del paquete original.", all: null },
    pkg: "debsums", v: "doc",
  },
  "DEB-0880": {
    es: "El paquete apt-show-versions no está instalado: no se puede ver de un vistazo qué versión hay disponible de cada paquete",
    fix: { linux: "Instala `apt-show-versions`. `apt-show-versions -u` lista de una vez todo lo que tiene actualización pendiente y de qué repositorio viene.", all: null },
    pkg: "apt-show-versions", v: "doc",
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
    fix: { linux: "Instala `aide`, genera la base de referencia con `sudo aideinit` y compárala periódicamente con `sudo aide --check`. La base hay que regenerarla tras cada actualización del sistema, o dará falsos positivos.", all: null },
    pkg: "aide", v: "doc",
  },

  // ── FIRE · Cortafuegos ────────────────────────────────────────────────────
  "FIRE-4590": {
    es: "El cortafuegos no registra el tráfico que bloquea: si hubiera un intento de acceso, no quedaría constancia",
    // El prefijo FIRE proponía ACTIVAR el cortafuegos, que ya está activo: el fix contradecía
    // el propio hallazgo.
    fix: {
      darwin: "Activa el registro del cortafuegos: `sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setloggingmode on`. El registro se consulta después con `log show --predicate 'process == \"socketfilterfw\"' --last 1h`.",
      linux: "Activa el registro de paquetes descartados en tu cortafuegos. Con ufw: `sudo ufw logging on`. Con firewalld: `sudo firewall-cmd --set-log-denied=all --permanent && sudo firewall-cmd --reload`.",
      all: null,
    },
    v: "macos",
  },

  // ── HOME · Directorios personales ─────────────────────────────────────────
  "HOME-9304": {
    es: "Hay ficheros de configuración en directorios personales con permisos más abiertos de lo recomendable",
    fix: { all: "Restringe los ficheros que Lynis señala a tu usuario: `chmod 600 <fichero>`. Afecta sobre todo a ficheros con credenciales (~/.netrc, ~/.ssh/config, historiales de shell)." },
    v: "macos",
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
    es: "El servidor web Apache no tiene instalado el módulo de seguridad ModSecurity",
    fix: { all: "Si este equipo no sirve páginas web a nadie, lo más seguro es parar Apache en vez de endurecerlo. Si sí lo usas, instala ModSecurity y activa el conjunto de reglas OWASP CRS." },
    v: "macos",
  },
  "HTTP-6643": {
    es: "El servidor web Apache no tiene instalado el módulo mod_evasive, que mitiga ataques de denegación de servicio",
    fix: { all: "Si este equipo no sirve páginas web a nadie, párale Apache. Si sí lo usas y está expuesto a internet, instala mod_evasive y ajusta sus umbrales de peticiones por segundo." },
    v: "macos",
  },

  // ── LOGG · Registro ───────────────────────────────────────────────────────
  "LOGG-2154": {
    es: "El servicio de registro (syslog) no envía copia a un servidor remoto: si alguien accede al equipo puede borrar sus huellas",
    fix: { linux: "Configura el reenvío en /etc/rsyslog.conf con `*.* @@servidor:514`. Necesita un servidor de registro al que enviar: en un equipo personal sin esa infraestructura, no aplica.", all: null },
    v: "doc",
  },
  "LOGG-2190": {
    es: "No se ha encontrado ninguna herramienta de rotación de registros: los ficheros de log pueden crecer sin control",
    fix: { linux: "Instala `logrotate` y define la política en /etc/logrotate.d/. Sin él, un log puede llenar la partición y dejar el sistema sin espacio.", all: null },
    pkg: "logrotate", v: "doc",
  },

  // ── NAME · Resolución de nombres ──────────────────────────────────────────
  "NAME-4028": {
    es: "El nombre de dominio del equipo no está configurado en /etc/hosts",
    fix: { linux: "Añade en /etc/hosts una línea `127.0.1.1 <nombre>.<dominio> <nombre>`. Sin ella, algunos programas tardan en arrancar esperando a que se resuelva su propio nombre.", all: null },
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
    es: "Hay paquetes instalados que ya no dependen de nada y se pueden eliminar",
    fix: { linux: "Revisa qué son antes de borrar nada: `apt list '~o'` y `sudo apt autoremove --dry-run`. Quita el `--dry-run` solo cuando la lista te parezca correcta.", all: null },
    v: "doc",
  },
  "PKGS-7370": {
    es: "La herramienta debsig-verify no está instalada: no se comprueba la firma de los paquetes antes de instalarlos",
    fix: { linux: "Instala `debsig-verify`. Ten en cuenta que apt ya verifica la firma de los repositorios: esto añade la verificación de ficheros .deb sueltos que instales a mano.", all: null },
    pkg: "debsig-verify", v: "doc",
  },
  "PKGS-7394": {
    es: "El gestor de paquetes no está configurado para instalar actualizaciones de seguridad automáticamente",
    fix: { linux: "Instala `unattended-upgrades` y actívalo con `sudo dpkg-reconfigure -plow unattended-upgrades`. Deja aplicadas las correcciones de seguridad sin que tengas que acordarte.", all: null },
    pkg: "unattended-upgrades", v: "doc",
  },
  "PKGS-7398": {
    es: "No se ha encontrado ninguna herramienta de comprobación de vulnerabilidades del gestor de paquetes",
    // El prefijo PKGS proponía `brew upgrade`: actualizar paquetes no instala una herramienta de
    // auditoría, y además ponía un botón de copiar sobre un comando que no resuelve el hallazgo.
    fix: { all: "Este control lo cubre LoCoAudit por su cuenta: el módulo de vulnerabilidades analiza tus paquetes con Trivy y sus hallazgos están en este mismo informe. Si quieres una herramienta aparte, en macOS no hay equivalente nativo para Homebrew." },
    v: "macos",
  },
  "PKGS-7410": {
    es: "El kernel instalado no es el último disponible: conviene reiniciar tras actualizar",
    fix: { linux: "Reinicia el equipo para arrancar con el kernel actualizado. Hasta que reinicies, sigues ejecutando el anterior y sus correcciones de seguridad no están aplicadas.", all: null },
    v: "doc",
  },
  "PKGS-7420": {
    es: "No hay ninguna herramienta que avise de vulnerabilidades conocidas en los paquetes instalados",
    // Mismo caso que PKGS-7398: el prefijo proponía `apt upgrade`.
    fix: { linux: "Este control lo cubre LoCoAudit: el módulo de vulnerabilidades analiza tus paquetes con Trivy y los hallazgos están en este informe. Si quieres una segunda herramienta en el propio sistema, instala `debsecan`, que cruza los paquetes de Debian con su base de datos de seguridad.", all: null },
    v: "doc",
  },

  // ── PRNT · Impresión ──────────────────────────────────────────────────────
  "PRNT-2307": {
    es: "El servicio de impresión CUPS está accesible desde la red: si solo imprimes desde este equipo, conviene limitarlo a local",
    fix: { linux: "En /etc/cups/cupsd.conf, deja `Listen localhost:631` y quita cualquier `Port 631` o `Listen *:631`. Después, `sudo systemctl restart cups`. Si no imprimes desde otros equipos, no perderás nada.", all: null },
    v: "doc",
  },

  // ── PROC · Procesos ───────────────────────────────────────────────────────
  "PROC-3614": {
    es: "No se han podido comprobar los límites de recursos de algunos procesos",
    // Lynis informa de lo que él no pudo mirar: no describe ningún defecto del equipo.
    noAction: true, v: "doc",
  },

  // ── STRG · Almacenamiento ─────────────────────────────────────────────────
  "STRG-1846": {
    es: "El módulo del kernel para el sistema de ficheros squashfs está activo: si no montas imágenes comprimidas, conviene desactivarlo",
    fix: { linux: "Comprueba antes si lo usas: los paquetes snap montan squashfs, y desactivarlo los rompería. Si no usas snap, impide la carga con un fichero en /etc/modprobe.d/ que contenga `install squashfs /bin/true`.", all: null },
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
  const cmd = e.pkg && typeof installCmd === "function" ? installCmd(pkgManager, e.pkg) : null;
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
