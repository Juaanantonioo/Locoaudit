"use strict";

/**
 * lynis-i18n.js — Traducción al castellano de los controles de Lynis.
 *
 * FICHERO DE DATOS. Aquí no se parsea nada ni se decide nada: solo la tabla y el acceso a ella.
 * El parseo del .dat vive en nodes/audit-host/modules/lynis.js y la construcción del finding en
 * lib/normalizer.js.
 *
 * ── Por qué indexado por ID de control y no por el texto ──────────────────────────────────────
 * Los IDs (AUTH-9286, USB-1000, BOOT-5122) son estables entre versiones de Lynis; el texto de la
 * sugerencia no lo es —cambia de redacción, de mayúsculas y de puntuación entre versiones—, así
 * que una tabla indexada por texto se quedaría muda en la siguiente actualización sin que nadie
 * se enterase. Es el mismo criterio que ya usaba getLynisFixText() en lib/normalizer.js, que
 * indexa por prefijo del ID.
 *
 * ── Por qué no lo traduce el LLM ──────────────────────────────────────────────────────────────
 * El cliente LLM de LoCoAudit es OPCIONAL y no determinista. Dos ejecuciones sobre el mismo
 * .dat darían dos informes con textos distintos, y un informe de auditoría que no se puede
 * reproducir no sirve como evidencia. Una tabla estática da siempre lo mismo.
 *
 * ── Cobertura parcial, y dicha ────────────────────────────────────────────────────────────────
 * Solo están los controles que aparecen de verdad en los informes de referencia (Debian 13 y
 * macOS 26). El catálogo completo de Lynis pasa de 300 controles y traducirlo entero a ciegas
 * sería inventar texto sobre comprobaciones que nadie ha visto ejecutarse.
 *
 * Un control sin entrada NO se rompe ni se calla: sale su texto original en inglés, y el finding
 * lleva `translated: false` para que el dashboard pueda decir que no está traducido. Nunca una
 * cadena vacía, nunca el ID pelado. `lynisCoverage()` da el recuento para el informe.
 */

/**
 * control → texto en castellano.
 *
 * La traducción describe QUÉ ha detectado Lynis, no qué hacer: el "cómo se arregla" ya lo produce
 * getLynisFixText() en lib/normalizer.js y duplicarlo aquí crearía dos consejos para el mismo
 * hallazgo. Se traduce el hecho, en la voz del resto del panel: directa, sin jerga innecesaria y
 * explicando el porqué cuando el nombre del control no basta.
 */
const LYNIS_ES = {
  // ── ACCT · Contabilidad de procesos ───────────────────────────────────────
  "ACCT-9622": "La contabilidad de procesos no está activada: el sistema no guarda registro de qué programas se han ejecutado ni quién los lanzó",
  "ACCT-9626": "Sysstat no está instalado: no se recogen estadísticas de uso del sistema a lo largo del tiempo",
  "ACCT-9628": "La auditoría del kernel (auditd) no está activa: no se registran los accesos a ficheros ni las llamadas al sistema",

  // ── AUTH · Cuentas y contraseñas ──────────────────────────────────────────
  "AUTH-9230": "La configuración de cifrado de contraseñas es más débil de lo recomendable: conviene revisar el número de rondas de hash",
  "AUTH-9262": "No hay ningún módulo PAM de robustez de contraseñas instalado: nada impide poner una contraseña trivial",
  "AUTH-9282": "Hay cuentas cuya contraseña no caduca nunca",
  "AUTH-9286": "No hay caducidad configurada para las contraseñas: no se pide cambiarlas cada cierto tiempo",
  "AUTH-9328": "Los permisos por defecto de los ficheros nuevos (umask) son más abiertos de lo recomendable",

  // ── BANN · Avisos legales ─────────────────────────────────────────────────
  "BANN-7126": "El fichero /etc/issue no muestra ningún aviso legal antes de iniciar sesión",
  "BANN-7130": "El fichero /etc/issue.net no muestra ningún aviso legal en los accesos por red",

  // ── BOOT · Arranque ───────────────────────────────────────────────────────
  "BOOT-5122": "El gestor de arranque GRUB no tiene contraseña: cualquiera con acceso físico puede modificar el arranque y entrar sin credenciales",
  "BOOT-5180": "Hay servicios que arrancan solos y conviene revisar si todos hacen falta",
  "BOOT-5264": "No se ha podido determinar el estado de algunos servicios del arranque",

  // ── DEB · Específicos de Debian y derivadas ───────────────────────────────
  "DEB-0280": "El paquete apt-listbugs no está instalado: no se avisa de fallos graves conocidos antes de instalar una actualización",
  "DEB-0810": "El paquete apt-listchanges no está instalado: no se muestran los cambios de un paquete antes de actualizarlo",
  "DEB-0831": "El paquete debsums no está instalado: no se puede comprobar que los ficheros instalados no han sido modificados",
  "DEB-0880": "El paquete apt-show-versions no está instalado: no se puede ver de un vistazo qué versión hay disponible de cada paquete",

  // ── FILE · Sistemas de ficheros ───────────────────────────────────────────
  "FILE-6310": "Hay directorios que no están en particiones separadas: si uno se llena puede afectar al resto del sistema",
  "FILE-7524": "Hay ficheros con permisos más abiertos de lo recomendable",

  // ── FINT · Integridad de ficheros ─────────────────────────────────────────
  "FINT-4350": "No hay ninguna herramienta de integridad de ficheros instalada (AIDE, Tripwire): no se detectaría la modificación de un fichero del sistema",

  // ── FIRE · Cortafuegos ────────────────────────────────────────────────────
  "FIRE-4590": "El cortafuegos no registra el tráfico que bloquea: si hubiera un intento de acceso, no quedaría constancia",

  // ── HOME · Directorios personales ─────────────────────────────────────────
  "HOME-9304": "Hay ficheros de configuración en directorios personales con permisos más abiertos de lo recomendable",

  // ── HRDN · Endurecimiento general ─────────────────────────────────────────
  "HRDN-7222": "Los compiladores instalados están accesibles para cualquier usuario: conviene restringirlos a administradores",
  "HRDN-7230": "No hay ningún antivirus ni escáner de malware instalado",

  // ── HTTP · Servidor web ───────────────────────────────────────────────────
  "HTTP-6640": "El servidor web Apache no tiene instalado el módulo de seguridad ModSecurity",
  "HTTP-6643": "El servidor web Apache no tiene instalado el módulo mod_evasive, que mitiga ataques de denegación de servicio",

  // ── LOGG · Registro ───────────────────────────────────────────────────────
  "LOGG-2154": "El servicio de registro (syslog) no envía copia a un servidor remoto: si alguien accede al equipo puede borrar sus huellas",
  "LOGG-2190": "No se ha encontrado ninguna herramienta de rotación de registros: los ficheros de log pueden crecer sin control",

  // ── NAME · Resolución de nombres ──────────────────────────────────────────
  "NAME-4028": "El nombre de dominio del equipo no está configurado en /etc/hosts",
  "NAME-4404": "El nombre del equipo no se resuelve correctamente en /etc/hosts",

  // ── NETW · Red ────────────────────────────────────────────────────────────
  "NETW-2704": "Alguno de los servidores DNS configurados no responde a las consultas de comprobación. En una red doméstica es normal: muchos proveedores filtran ese tipo de consulta",
  "NETW-2705": "Hay menos de dos servidores DNS respondiendo. En una red doméstica es lo habitual y no supone un problema",
  "NETW-3200": "Hay protocolos de red poco habituales activados en el kernel (dccp, sctp, rds, tipc): si no los usas, conviene desactivarlos",

  // ── PKGS · Paquetes ───────────────────────────────────────────────────────
  "PKGS-7346": "Hay paquetes instalados que ya no dependen de nada y se pueden eliminar",
  "PKGS-7370": "La herramienta debsig-verify no está instalada: no se comprueba la firma de los paquetes antes de instalarlos",
  "PKGS-7394": "El gestor de paquetes no está configurado para instalar actualizaciones de seguridad automáticamente",
  "PKGS-7398": "No se ha encontrado ninguna herramienta de comprobación de vulnerabilidades del gestor de paquetes",
  "PKGS-7410": "El kernel instalado no es el último disponible: conviene reiniciar tras actualizar",
  "PKGS-7420": "No hay ninguna herramienta que avise de vulnerabilidades conocidas en los paquetes instalados",

  // ── PRNT · Impresión ──────────────────────────────────────────────────────
  "PRNT-2307": "El servicio de impresión CUPS está accesible desde la red: si solo imprimes desde este equipo, conviene limitarlo a local",

  // ── PROC · Procesos ───────────────────────────────────────────────────────
  "PROC-3614": "No se han podido comprobar los límites de recursos de algunos procesos",

  // ── STRG · Almacenamiento ─────────────────────────────────────────────────
  "STRG-1846": "El módulo del kernel para el sistema de ficheros squashfs está activo: si no montas imágenes comprimidas, conviene desactivarlo",

  // ── TOOL · Herramientas de auditoría ──────────────────────────────────────
  "TOOL-5002": "No hay ninguna herramienta de gestión automatizada de configuración instalada (Ansible, Puppet, Salt)",

  // ── USB · Almacenamiento extraíble ────────────────────────────────────────
  "USB-1000": "El almacenamiento USB está habilitado sin restricciones: cualquiera con acceso físico puede conectar una memoria y copiar datos",
};

/** Controles cubiertos por el diccionario. Se expone para que los tests puedan comprobar la
 *  cobertura contra la lista real de los informes sin volver a escribirla. */
const LYNIS_ES_IDS = Object.keys(LYNIS_ES);

/**
 * Texto de un control, ya resuelto.
 *
 * Devuelve SIEMPRE algo utilizable: si no hay traducción, el original en inglés con
 * `translated: false`, para que el dashboard pueda marcarlo. Nunca cadena vacía y nunca el ID a
 * secas — "AUTH-9286" no le dice nada a quien lee el informe.
 *
 *   { text, translated }
 */
function lynisText(control, original) {
  const id = String(control || "").trim().toUpperCase();
  const fallback = String(original || "").trim();
  const es = LYNIS_ES[id];
  if (es) return { text: es, translated: true };
  // Sin original NI traducción no hay nada que enseñar salvo el control: es el único caso en que
  // el ID aparece, y va acompañado para que se entienda qué es.
  if (!fallback) {
    return { text: `Control ${id || "desconocido"} de Lynis, sin descripción disponible`, translated: false };
  }
  return { text: fallback, translated: false };
}

/**
 * Cobertura del diccionario sobre un conjunto de controles: cuántos se han traducido de cuántos
 * se han encontrado. El informe lo enseña tal cual — presumir cobertura total sería afirmar algo
 * que no se ha comprobado.
 */
function lynisCoverage(controles) {
  const vistos = [...new Set((controles || []).map((c) => String(c || "").trim().toUpperCase()).filter(Boolean))];
  const traducidos = vistos.filter((c) => LYNIS_ES[c]);
  return {
    total: vistos.length,
    translated: traducidos.length,
    missing: vistos.filter((c) => !LYNIS_ES[c]).sort(),
  };
}

module.exports = { LYNIS_ES, LYNIS_ES_IDS, lynisText, lynisCoverage };
