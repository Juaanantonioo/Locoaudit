"use strict";

/**
 * Severidad por puerto para un PC personal, no para un servidor: el criterio es el mismo que rige
 * las severidades de Lynis, con un usuario doméstico delante. "high" es riesgo inmediato aquí
 * (credenciales en claro, escritorio remoto, puertos de backdoor); "medium", servicio legítimo
 * pero expuesto sin necesidad; "info", lo normal en un equipo de uso diario o de desarrollo. Lo
 * que no está catalogado sale como "low", por trazabilidad y sin alarmar.
 *
 * Datos puros, sin escaneo. Vivía en el escáner nativo, y sobrevivió a su eliminación porque el
 * criterio no depende de quién descubra el puerto.
 *
 * Los de macOS (548 AFP, 5353 mDNS, 7000 AirPlay) están abiertos en cualquier Mac de fábrica: son
 * funcionalidades que el usuario activó al usar AirPlay o compartir archivos, así que van a
 * "info". El 8021 en macOS es un servicio interno del sistema; en Linux no tiene uso estándar y,
 * si algún día se soportan perfiles de servidor, ahí habría que subirlo.
 */
const PORT_CATALOG = {
  21:    { service: "FTP",        severity: "high" },
  23:    { service: "Telnet",     severity: "high" },
  3389:  { service: "RDP",        severity: "high" },
  5900:  { service: "VNC",        severity: "high" },
  5901:  { service: "VNC-1",      severity: "high" },
  4444:  { service: "Metasploit", severity: "high" },
  1337:  { service: "Backdoor",   severity: "high" },

  22:    { service: "SSH",        severity: "medium" },
  25:    { service: "SMTP",       severity: "medium" },
  3306:  { service: "MySQL",      severity: "medium" },
  5432:  { service: "PostgreSQL", severity: "medium" },
  6379:  { service: "Redis",      severity: "medium" },
  27017: { service: "MongoDB",    severity: "medium" },
  8080:  { service: "HTTP-alt",   severity: "medium" },
  8443:  { service: "HTTPS-alt",  severity: "medium" },

  80:    { service: "HTTP",       severity: "info" },
  443:   { service: "HTTPS",      severity: "info" },
  631:   { service: "CUPS",       severity: "info" },
  3000:  { service: "Dev/Grafana", severity: "medium" },
  5000:  { service: "Dev-server", severity: "info" },
  8000:  { service: "Dev-server", severity: "info" },
  9000:  { service: "Dev-server", severity: "info" },

  // Propios de macOS, normales con la configuración de fábrica.
  88:    { service: "Kerberos",   severity: "info" },
  548:   { service: "AFP",        severity: "info" },
  5353:  { service: "mDNS",       severity: "info" },
  7000:  { service: "AirPlay",    severity: "info" },
  8021:  { service: "macOS-svc",  severity: "info" },

  // Paneles de gestión de servidores y homelab, que nmap no sondearía sin pedírselo.
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
