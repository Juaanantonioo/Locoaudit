"use strict";

// Severidad por puerto para un PC personal: high riesgo inmediato, medium expuesto sin necesidad, info normal.
// Lo no catalogado sale "low".
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
