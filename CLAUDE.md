# CLAUDE.md — Contexto del proyecto LoCoAudit

Este fichero es leído automáticamente por Claude Code al abrir el proyecto.
Contiene las decisiones de arquitectura, convenciones y guías de desarrollo.

---

## Qué es este proyecto

**LoCoAudit** es un paquete npm para Node-RED que añade 4 nodos de auditoría:

- `audit-host` — inventario de hardware/software y métricas del sistema
- `audit-network` — escaneo de puertos y detección de servicios expuestos
- `audit-image` — auditoría de imágenes Docker (capas, CVEs, configuración)
- `audit-reporter` — generación de reportes HTML/JSON a partir de findings

**Contexto académico:** TFG del Grado en Ingeniería Informática, Escuela Superior de Ingeniería. Director: Juan Boubeta Puig.

---

## Regla de oro: el contrato de finding

**Todo módulo de auditoría debe producir findings con esta forma exacta:**

```js
// lib/finding-schema.js
{
  id: string,          // e.g. "HOST-CPU-001"
  title: string,       // descripción breve del hallazgo
  severity: string,    // "critical" | "high" | "medium" | "low" | "info"
  evidence: string,    // dato concreto que justifica el hallazgo
  fix: string | null,  // recomendación de mitigación (null si es informativo)
  timestamp: string    // ISO 8601, generado automáticamente
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
    ├── cpu-memory.js   ← recolecta datos crudos (raw)
    ├── disk-storage.js ← recolecta datos crudos (raw)
    └── ...
```

**Flujo de datos dentro de un nodo:**

```
módulo.js → raw data → normalizer.js → findings[] → msg.payload → salida
```

- Los módulos solo recolectan datos crudos. No deciden severidad.
- `normalizer.js` (en lib/) aplica las reglas de negocio y asigna severidad.
- `executor.js` (en lib/) lanza todos los comandos del sistema.

---

## lib/ — Núcleo compartido

| Fichero | Responsabilidad |
|---|---|
| `executor.js` | `execCommand(cmd, timeoutMs)` — lanza procesos con timeout y gestión de errores multiplataforma |
| `normalizer.js` | Funciones `normalizeHost()`, `normalizeNetwork()`, `normalizeImage()` |
| `finding-schema.js` | `createFinding({...})` — valida y construye un finding con timestamp |
| `severity-map.js` | Constantes y umbrales: cuándo un uso de CPU es "high" vs "critical" |

---

## Cómo registrar un nodo en Node-RED

```js
// Patrón mínimo obligatorio
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
- **Multiplataforma desde el inicio:** detectar `process.platform` en cualquier comando del sistema
  ```js
  const platform = process.platform; // 'darwin' | 'linux' | 'win32'
  ```
- **Nmap es opcional:** siempre comprobar si está disponible antes de usarlo
  ```js
  const nmapAvailable = await checkCommand('nmap --version');
  ```
- **Timeouts obligatorios** en todos los `exec`: mínimo 5000ms, configurable por el usuario

---

## Convenciones de IDs de findings

| Nodo | Prefijo | Ejemplo |
|---|---|---|
| audit-host | `HOST-` | `HOST-CPU-001`, `HOST-MEM-002` |
| audit-network | `NET-` | `NET-PORT-001`, `NET-SVC-002` |
| audit-image | `IMG-` | `IMG-CVE-001`, `IMG-CFG-002` |
| informativo | sufijo `-INF` | `HOST-CPU-INF` |

---

## Estado actual del proyecto

Ver `ROADMAP.md` para el plan completo y el estado de cada tarea.

**Fase actual: Fase 0 — Reorganización y base**

Próximos pasos:
1. Crear `lib/finding-schema.js`
2. Crear `lib/severity-map.js`
3. Crear `lib/executor.js`
4. Crear `lib/normalizer.js`

---

## Comandos útiles

```bash
# Instalar el paquete localmente en Node-RED para desarrollo
npm link
cd ~/.node-red && npm link locoaudit

# Ejecutar tests
npm test

# Lanzar Node-RED en modo debug
node-red --userDir ~/.node-red
```
