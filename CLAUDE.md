# CLAUDE.md — Contexto del proyecto LoCoAudit

Este fichero es leído automáticamente por Claude Code al abrir el proyecto.
Contiene las decisiones de arquitectura, convenciones y guías de desarrollo.

---

## Qué es este proyecto

**LoCoAudit** es un paquete npm para Node-RED que añade 3 nodos de auditoría:

- `audit-host` — inventario de hardware/software, métricas del sistema y vulnerabilidades del host
- `audit-network` — escaneo de puertos y detección de servicios expuestos
- `audit-image` — auditoría de imágenes Docker (capas, CVEs, configuración)

Los resultados se visualizan en dashboards de Node-RED (`ui_template`, Dashboard 2.0)
y se descargan en HTML + JSON desde el propio dashboard. No hay nodo generador de
reportes: los dashboards lo sustituyen (el antiguo `audit-reporter` fue eliminado).

**Contexto académico:** TFG del Grado en Ingeniería Informática, Escuela Superior de Ingeniería.
Director: Juan Boubeta Puig. Codirector: Jesús Rosa Bilbao.

---

## Stack de herramientas externas — decisión definitiva

Las herramientas **opcionales** funcionan con fallback nativo si no están instaladas.
Las herramientas **requeridas** bloquean el nodo si faltan.

| Nodo | Herramienta | Tipo | Qué aporta |
|---|---|---|---|
| `audit-host` | `os` + `child_process` | nativo | CPU, RAM, disco, SO — sin dependencias |
| `audit-host` | `lynis` | opcional | Configuración insegura del host, hardening index, +300 comprobaciones |
| `audit-host` | `trivy fs` | opcional | CVEs en paquetes del SO (apt, brew, rpm) contra NVD |
| `audit-network` | `net` nativo | nativo | Escaneo de puertos — fallback siempre disponible |
| `audit-network` | `nmap` | opcional | Puertos, servicios, versiones, OS fingerprint, NSE scripts |
| `audit-image` | `docker` | requerida | Acceso a imágenes y contenedores — sin él el nodo no tiene sentido |
| `audit-image` | `trivy image` | opcional | CVEs, secretos expuestos, misconfigs en imágenes Docker |
| dashboards | `ui_template` (Dashboard 2.0) | nativo | Visualización + descarga de reportes HTML/JSON en el navegador |

### Herramientas evaluadas y descartadas

| Herramienta | Motivo |
|---|---|
| OpenVAS / GVM | Solo Linux, requiere daemon + PostgreSQL + feed NVTs — demasiado complejo para el scope |
| OWASP ZAP | Escáner DAST de aplicaciones web, no audita el SO — resuelve un problema diferente |
| Nuclei | Alta curva de integración, gestión de plantillas YAML, no aporta sobre Nmap+Trivy |
| Grype | Trivy ya cubre el caso de uso con más funciones (secretos, misconfigs, filesystem) |
| Nessus | Propietario y de pago |

### Líneas de trabajo futuro (mencionar en la memoria)

- **`audit-webapp`** — nodo nuevo con OWASP ZAP para escanear servicios web expuestos por el host
- **Integración con OpenVAS** — la arquitectura modular está diseñada para permitirlo
- **Nuclei** — escaneo de vulnerabilidades de red con plantillas YAML personalizables
- **Acciones bidireccionales en dashboards** — actualmente los dashboards
  implementan un botón "Copiar comando" (Opción A) que copia el comando
  de resolución al portapapeles del usuario. La Opción B (ejecución directa)
  requeriría una arquitectura de acciones bidireccionales:
  el ui_template enviaría { action: 'kill', pid: X } o { action: 'upgrade', pkg: Y }
  vía this.$socket.emit() al flujo de Node-RED, donde un nodo function
  ejecutaría el comando y relanzaría la auditoría automáticamente.
  La base técnica (socket de Dashboard 2.0 + executor.js) ya está disponible.
- **`audit-network` multi-dispositivo** — ampliar el nodo para permitir auditar
  otros dispositivos de la red local además de localhost. Implicaría:
  - Host discovery con `nmap -sn <rango CIDR>` para detectar IPs activas
  - El usuario configura manualmente IPs o rangos en la UI del nodo
  - `service-detect.js` se omite para IPs remotas (lsof solo funciona en localhost)
  - Requiere sudo en macOS/Linux para detección de versiones con -sV
  - Justificación arquitectónica: audit-host audita el propio equipo en profundidad,
    audit-network audita la exposición de red (local y dispositivos domésticos)

### Limitación conocida en Windows

Lynis no funciona en Windows sin WSL. En Windows `audit-host` operará con `trivy fs` y módulos nativos, pero sin el análisis de hardening de Lynis. Documentar en la memoria.

---

## Regla de oro: el contrato de finding

**Todo módulo de auditoría debe producir findings con esta forma exacta:**

```js
// lib/finding-schema.js
{
  id:        string,       // semántico: "HOST-CPU-001", "NET-PORT-001", "IMG-CVE-001"
  title:     string,       // descripción breve del hallazgo
  severity:  string,       // "critical" | "high" | "medium" | "low" | "info"
  evidence:  string,       // dato concreto que justifica el hallazgo
  fix:       string|null,  // recomendación de mitigación (null si es informativo)
  category:  string,       // "cpu" | "memory" | "disk" | "network" | "image" | "system" | "vulnerability" | ...
  source:    string,       // "native" | "nmap" | "lynis" | "trivy" | "nuclei"
  timestamp: string        // ISO 8601, generado automáticamente por createFinding()
}
```

Nunca modifiques este esquema sin actualizar todos los módulos que lo usan.

---

## Arquitectura de un nodo (patrón a seguir)

```
nodes/audit-host/
├── audit-host.js       ← registra el nodo en Node-RED, orquesta módulos
├── audit-host.html     ← UI de configuración del nodo (editor de flujos)
└── modules/
    ├── cpu-memory.js   ← datos crudos de CPU y RAM (nativo)
    ├── disk-storage.js ← datos crudos de disco (nativo)
    ├── sw-inventory.js ← software instalado (nativo)
    ├── os-info.js      ← versión SO, uptime, hostname (nativo)
    ├── lynis.js        ← wrapper Lynis (opcional, con fallback)
    └── trivy-fs.js     ← wrapper Trivy fs (opcional, con fallback)
```

**Flujo de datos dentro de un nodo:**

```
módulo.js → raw data → normalizer.js → findings[] → msg.payload → salida Node-RED
```

- Los módulos solo recolectan datos crudos. No deciden severidad.
- `normalizer.js` (en `lib/`) aplica las reglas de negocio y asigna severidad.
- `executor.js` (en `lib/`) lanza todos los comandos del sistema.

### Patrón obligatorio para herramientas opcionales

```js
const { execCommand, commandExists } = require('../../../lib/executor');

module.exports = async function runLynis() {
  const available = await commandExists('lynis');
  if (!available) {
    return { skipped: true, reason: 'lynis not installed' };
  }
  const raw = await execCommand('lynis audit system --quiet --no-colors', 60000);
  return parseLynisReport(raw);
};
```

---

## lib/ — Núcleo compartido

| Fichero | Responsabilidad |
|---|---|
| `executor.js` | `execCommand(cmd, timeoutMs)` y `commandExists(cmd)` — multiplataforma |
| `normalizer.js` | `normalizeHost()`, `normalizeNetwork()`, `normalizeImage()` — convierte raw data a findings[] |
| `finding-schema.js` | `createFinding({...})` — valida y construye un finding con timestamp automático |
| `severity-map.js` | `rank()`, `max()`, `fromTrivy()`, `fromLynis()`, `fromNuclei()`, `summarize()` |
| `utils.js` | `bytesToMiB()`, `bytesToGiB()`, `safeFileName()`, `escHtml()` — utilidades genéricas |

---

## Cómo registrar un nodo en Node-RED

```js
module.exports = function(RED) {
  function AuditHostNode(config) {
    RED.nodes.createNode(this, config);
    const node = this;

    node.on('input', async function(msg, send, done) {
      node.status({ fill: 'blue', shape: 'dot', text: 'Auditando...' });
      try {
        // 1. recoger raw data de los módulos
        // 2. normalizar a findings[]
        // 3. enviar msg.payload = { findings, source, raw }
        send(msg);
        done();
      } catch(err) {
        node.status({ fill: 'red', shape: 'ring', text: 'Error' });
        done(err);
      }
    });
  }
  RED.nodes.registerType('audit-host', AuditHostNode);
};
```

---

## Convenciones de código

- **CommonJS** (`require`/`module.exports`), no ES modules — Node-RED lo requiere
- **async/await** para todo lo asíncrono, sin callbacks anidados
- **Un fichero = una responsabilidad** — si un módulo hace dos cosas, divídelo
- **Multiplataforma desde el inicio:**
  ```js
  const platform = process.platform; // 'darwin' | 'linux' | 'win32'
  ```
- **Todas las herramientas externas son opcionales** salvo Docker en audit-image — usar siempre `commandExists()` antes de ejecutar
- **Timeouts obligatorios** en todos los `exec` — mínimo 5000ms, Lynis usa 60000ms

---

## Convenciones de IDs de findings

| Nodo | Prefijo | Ejemplo |
|---|---|---|
| audit-host (nativo) | `HOST-` | `HOST-CPU-001`, `HOST-MEM-002` |
| audit-host (Lynis) | `HOST-LYN-` | `HOST-LYN-SSH-001`, `HOST-LYN-FW-001` |
| audit-host (Trivy fs) | `HOST-CVE-` | `HOST-CVE-001` |
| audit-network | `NET-` | `NET-PORT-001`, `NET-SVC-002` |
| audit-image | `IMG-` | `IMG-CVE-001`, `IMG-CFG-002` |
| informativo | sufijo `-INF` | `HOST-CPU-INF` |

---

## Lanzador — launcher/lcaudit_launcher.py

El lanzador Python arranca Node-RED tras verificar todas las dependencias.

**Dependencias que comprueba:**

| Herramienta | Tipo | Acción si falta |
|---|---|---|
| `node` (v18+) | requerida | Bloquea el arranque |
| `npm` | requerida | Bloquea el arranque |
| `node-red` | requerida | Bloquea el arranque |
| `docker` | requerida para audit-image | Avisa, no bloquea Node-RED |
| `nmap` | opcional | Avisa con instrucción de instalación |
| `lynis` | opcional | Avisa con instrucción de instalación |
| `trivy` | opcional | Avisa con instrucción de instalación |

Instrucciones de instalación por SO (macOS / Linux / Windows) en `INSTALL_GUIDE` del lanzador.

---

## Estado actual del proyecto

Ver `ROADMAP.md` para el plan completo y el estado de cada tarea.

**Fase actual: Fase 1 — Nodo audit-host**

### Fase 0 — Completada ✓

- [x] CLAUDE.md y ROADMAP.md en el repo
- [x] Stack de herramientas definitivo decidido y documentado
- [x] Lanzador Python con comprobación de dependencias (Lynis, Trivy, Nmap, Docker)
- [x] `lib/finding-schema.js` — esquema combinado definitivo con `createFinding()`
- [x] `lib/executor.js` — `execCommand()` y `commandExists()` multiplataforma
- [x] `lib/severity-map.js` — `rank()`, `max()`, `fromTrivy()`, `fromLynis()`, `fromNuclei()`, `summarize()`
- [x] `lib/normalizer.js` — `normalizeHost()`, `normalizeNetwork()`, `normalizeImage()`
- [x] `lib/utils.js` — utilidades genéricas (bytes, escHtml, safeFileName)
- [x] `nodes/audit-network/modules/network-utils.js` — utilidades de red (parsePortsList, etc.)
- [x] `nodes/audit-host/modules/cpu-memory.js` — renombrado desde systemInfo.js, import corregido

### Fase 1 — Pendiente

- [ ] `cpu-memory.js` — completar con datos de CPU usage (% por core)
- [ ] `disk-storage.js` — uso de disco por partición
- [ ] `sw-inventory.js` — software instalado (brew/dpkg/winget según SO)
- [ ] `os-info.js` — versión SO, uptime, hostname, arch
- [ ] `lynis.js` — wrapper Lynis con fallback
- [ ] `trivy-fs.js` — wrapper Trivy fs con fallback
- [ ] `audit-host.js` — registro del nodo en Node-RED
- [ ] `audit-host.html` — UI de configuración del nodo

---

## Comandos útiles

```bash
# Lanzar LoCoAudit (comprueba dependencias y arranca Node-RED)
python3 launcher/lcaudit_launcher.py

# Instalar el paquete localmente en Node-RED para desarrollo
npm link
cd ~/.node-red && npm link locoaudit

# Ejecutar tests
npm test

# Lanzar Node-RED directamente (sin lanzador)
node-red --userDir ~/.node-red

# Verificar herramientas opcionales manualmente
lynis show version
trivy --version
nmap --version
docker --version
```
