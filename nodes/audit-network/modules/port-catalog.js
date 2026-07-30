"use strict";

/**
 * port-catalog.js — Catálogo de puertos conocidos con su severidad para un PC personal.
 *
 * Datos puros: no escanea nada. Lo consume nmap-wrapper.js para asignar severidad
 * y fix a cada puerto que Nmap encuentra, y audit-network.js para describir el
 * rango cubierto en scanMeta.
 *
 * Este catálogo vivía en port-scanner.js (el escáner nativo). Ese escáner se
 * eliminó al pasar Nmap a ser requisito del nodo, pero el criterio de severidad
 * es independiente del escáner que descubra el puerto, así que se conserva aquí.
 *
 * ── Criterio de severidad por puerto ─────────────────────────────────────────
 *
 * El criterio sigue la misma filosofía que LYNIS_PERSONAL_SEVERITY en
 * lib/severity-map.js: el target es un usuario doméstico sin conocimientos
 * de seguridad, no un administrador de sistemas.
 *
 * "high"   — El puerto expone un servicio con riesgo real e inmediato en un PC
 *            personal: protocolos sin cifrado que transmiten credenciales en
 *            claro (FTP, Telnet), acceso remoto de escritorio ampliamente
 *            atacado (RDP, VNC), o puertos directamente asociados a backdoors
 *            y herramientas de ataque (4444, 1337).  Un usuario doméstico
 *            no debería tener estos servicios activos bajo ningún uso normal.
 *
 * "medium" — El puerto corresponde a un servicio legítimo pero inusual o
 *            innecesariamente expuesto en un PC personal: bases de datos
 *            accesibles desde la red local (MySQL, PostgreSQL, Redis, MongoDB),
 *            servidores de correo (SMTP) o servidores web alternativos que
 *            podrían quedar olvidados activos.  Requieren atención pero no
 *            son tan urgentes como los "high".
 *
 * "info"   — Servicios habituales en PC de desarrollo o de uso doméstico:
 *            servidores web locales (HTTP/HTTPS), servidores de impresión
 *            (CUPS en macOS/Linux) o puertos típicos de entornos de desarrollo
 *            (3000, 5000, 8000, 9000).  Se informan para que el usuario sea
 *            consciente de lo que tiene activo, pero no implican riesgo.
 *
 * "low"    — Puerto abierto no reconocido en el catálogo.  Puede ser un
 *            servicio legítimo del sistema o una aplicación de usuario.
 *            Se muestra por trazabilidad sin alarmar innecesariamente.
 *
 * Exporta:
 *   PORT_CATALOG — objeto port → { service, severity }
 */

// ── Catálogo de puertos ───────────────────────────────────────────────────────

/**
 * Puertos conocidos con su metadato de severidad para PC personal.
 * Estructura: port → { service, severity, fix }
 *
 * ── Servicios propios de macOS clasificados como "info" ──────────────────────
 *
 * Los puertos 7000 (AirPlay), 5353 (mDNS/Bonjour) y 548 (AFP) aparecen
 * abiertos en cualquier Mac con la configuración por defecto del sistema.
 * No representan un riesgo en sí mismos: son funcionalidades del SO que el
 * usuario ha activado implícitamente al usar AirPlay, compartición de archivos
 * o la resolución de nombres en red local.  Se clasifican como "info" para que
 * el usuario sea consciente de que están activos, pero no se le alarma
 * innecesariamente.
 *
 * El usuario debería desactivarlos únicamente si no usa esas funcionalidades:
 *   - AirPlay receptor: Ajustes → General → AirDrop y Handoff → Receptor AirPlay
 *   - Bonjour/mDNS:    No se puede desactivar de forma granular en macOS sin
 *                      herramientas de terceros; forma parte de la red local.
 *   - AFP (548):       Ajustes → General → Compartir → Compartir archivos (desactivar)
 *
 * Nota sobre el puerto 8021:
 *   En macOS corresponde a un servicio interno del sistema (Control Center /
 *   daemon del sistema) y se clasifica como "info".  En Linux este puerto no
 *   tiene un uso estándar conocido y debería revisarse; si se amplía el soporte
 *   a perfiles de servidor, considerar elevarlo a "medium" en ese contexto.
 */
const PORT_CATALOG = {
  // ── HIGH — riesgo real e inmediato en PC personal ──────────────────────────
  21:    { service: "FTP",        severity: "high" },
  23:    { service: "Telnet",     severity: "high" },
  3389:  { service: "RDP",        severity: "high" },
  5900:  { service: "VNC",        severity: "high" },
  5901:  { service: "VNC-1",      severity: "high" },
  4444:  { service: "Metasploit", severity: "high" },
  1337:  { service: "Backdoor",   severity: "high" },

  // ── MEDIUM — servicio inusual o innecesariamente expuesto en PC personal ───
  22:    { service: "SSH",        severity: "medium" },
  25:    { service: "SMTP",       severity: "medium" },
  3306:  { service: "MySQL",      severity: "medium" },
  5432:  { service: "PostgreSQL", severity: "medium" },
  6379:  { service: "Redis",      severity: "medium" },
  27017: { service: "MongoDB",    severity: "medium" },
  8080:  { service: "HTTP-alt",   severity: "medium" },
  8443:  { service: "HTTPS-alt",  severity: "medium" },

  // ── INFO — habitual en PC de desarrollo o uso doméstico ───────────────────
  80:    { service: "HTTP",       severity: "info" },
  443:   { service: "HTTPS",      severity: "info" },
  631:   { service: "CUPS",       severity: "info" },
  3000:  { service: "Dev/Grafana", severity: "medium" },
  5000:  { service: "Dev-server", severity: "info" },
  8000:  { service: "Dev-server", severity: "info" },
  9000:  { service: "Dev-server", severity: "info" },

  // ── INFO — servicios propios de macOS, normales con configuración por defecto
  88:    { service: "Kerberos",   severity: "info" },
  548:   { service: "AFP",        severity: "info" },
  5353:  { service: "mDNS",       severity: "info" },
  7000:  { service: "AirPlay",    severity: "info" },
  8021:  { service: "macOS-svc",  severity: "info" },

  // ── MEDIUM — paneles de gestión de servidores/homelab expuestos en red ───────
  8006:  { service: "Proxmox-UI",  severity: "medium" },
  9090:  { service: "Cockpit",     severity: "medium" },
  10000: { service: "Webmin",      severity: "medium" },
  2375:  { service: "Docker-API",  severity: "high" },
  2376:  { service: "Docker-TLS",  severity: "medium" },
  9200:  { service: "Elasticsearch-HTTP", severity: "medium" },
  5601:  { service: "Kibana",      severity: "medium" },
  9093:  { service: "Prometheus",  severity: "medium" },
};

module.exports = { PORT_CATALOG };
