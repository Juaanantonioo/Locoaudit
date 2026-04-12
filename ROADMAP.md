# LoCoAudit — Roadmap de desarrollo

Extensión modular de bajo código para Node-RED que automatiza auditorías de sistema y genera reportes técnicos.

---

## Estructura del proyecto

```
locoaudit/
├── nodes/
│   ├── audit-host/
│   │   ├── audit-host.js
│   │   ├── audit-host.html
│   │   └── modules/
│   │       ├── cpu-memory.js
│   │       ├── disk-storage.js
│   │       ├── sw-inventory.js
│   │       └── os-info.js
│   ├── audit-network/
│   │   ├── audit-network.js
│   │   ├── audit-network.html
│   │   └── modules/
│   │       ├── port-scanner.js
│   │       ├── nmap-wrapper.js
│   │       ├── service-detect.js
│   │       └── vuln-check.js
│   ├── audit-image/
│   │   ├── audit-image.js
│   │   ├── audit-image.html
│   │   └── modules/
│   │       ├── docker-api.js
│   │       ├── layer-scan.js
│   │       ├── cve-checker.js
│   │       └── config-audit.js
│   └── audit-reporter/
│       ├── audit-reporter.js
│       ├── audit-reporter.html
│       └── modules/
│           ├── html-renderer.js
│           ├── json-exporter.js
│           ├── timestamp-logger.js
│           └── template-engine.js
├── lib/
│   ├── executor.js        ← motor multiplataforma (child_process)
│   ├── normalizer.js      ← convierte raw data a findings[]
│   ├── finding-schema.js  ← esquema y validación de findings
│   └── severity-map.js    ← niveles: critical, high, medium, low, info
├── test/
├── examples/              ← flujos Node-RED de demostración (.json)
├── ROADMAP.md
├── CLAUDE.md
└── package.json
```

---

## Esquema de finding (contrato central)

Todo módulo debe producir objetos con esta forma:

```json
{
  "id": "HOST-CPU-001",
  "title": "Uso de CPU crítico",
  "severity": "high",
  "evidence": "Uso actual: 92%",
  "fix": "Revisar procesos con alto consumo.",
  "timestamp": "2025-04-09T10:00:00.000Z"
}
```

Niveles de severidad válidos: `critical` · `high` · `medium` · `low` · `info`

---

## Fases de desarrollo

### Fase 0 — Reorganización y base (Sem 1–2)
**Objetivo:** repo limpio con el núcleo `lib/` funcionando.

- [x] Auditar código existente y decidir qué conservar
- [x] Crear estructura de carpetas definitiva
- [x] Inicializar repo git + `package.json`
- [x] Implementar `finding-schema.js` y `severity-map.js`
- [x] Implementar `executor.js` multiplataforma (macOS primero)
- [x] Implementar `normalizer.js` base

**Entregable:** `lib/` completo con tests básicos pasando en macOS.

---

### Fase 1 — Nodo audit-host (Sem 3–5)
**Objetivo:** primer nodo arrastrable en Node-RED que emite `findings[]`.

- [x] `cpu-memory.js` — CPU y RAM con módulo `os` nativo
- [x] `disk-storage.js` — uso de disco por partición
- [x] `sw-inventory.js` — software instalado (brew/dpkg/winget según SO)
- [x] `os-info.js` — versión SO, uptime, hostname
- [x] `normalizer.js` para hallazgos de host
- [x] `audit-host.js` — registro del nodo en Node-RED
- [x] `audit-host.html` — UI de configuración del nodo

**Entregable:** nodo `audit-host` instalable via `npm link` en Node-RED local.

---

### Fase 2 — Nodos audit-network y audit-image (Sem 6–9)
**Objetivo:** los tres nodos de auditoría encadenables en un flujo.

**audit-network:**
- [ ] `port-scanner.js` — puertos abiertos con `net` nativo (sin dependencias)
- [ ] `nmap-wrapper.js` — integración opcional con Nmap si está instalado
- [ ] `service-detect.js` — identificación de servicio por número de puerto
- [ ] `vuln-check.js` — detección de servicios en versiones conocidas como inseguras

**audit-image:**
- [ ] `docker-api.js` — conexión a Docker Engine API vía socket local
- [ ] `layer-scan.js` — análisis de capas de la imagen
- [ ] `cve-checker.js` — comprobación básica contra lista de CVEs conocidos
- [ ] `config-audit.js` — variables de entorno expuestas, usuario root, puertos expuestos

**Entregable:** flujo Node-RED con los 3 nodos encadenados produciendo `findings[]` unificado.

---

### Fase 3 — Reporter y dashboard (Sem 10–12)
**Objetivo:** dashboard funcional mostrando resultados en tiempo real.

- [ ] `html-renderer.js` — plantilla HTML con colores por severidad (estilo Figma)
- [ ] `json-exporter.js` — salida estructurada con timestamp para trazabilidad
- [ ] `timestamp-logger.js` — almacenamiento local del histórico de auditorías
- [ ] `template-engine.js` — motor de plantillas (Handlebars o similar)
- [ ] Dashboard en Node-RED UI: widgets agrupados por severidad
- [ ] Tabla de findings con filtros por nodo y severidad
- [ ] Gráfico de evolución temporal (histórico)
- [ ] Flujo de demostración completo (`examples/demo-flow.json`)

**Entregable:** dashboard Node-RED instalable con un `import` del fichero de ejemplo.

---

### Fase 4 — Validación, tests y memoria (Sem 13–16)
**Objetivo:** paquete npm publicable + memoria TFG completa.

- [ ] Tests unitarios de cada módulo en `lib/` y `nodes/` (Jest)
- [ ] Validación en Linux (Ubuntu VM)
- [ ] Validación en Windows (VM o máquina real)
- [ ] Gestión robusta de errores: Nmap no instalado, Docker no activo, timeouts
- [ ] `README.md` completo con instalación, uso y capturas
- [ ] Documentación técnica del paquete npm (JSDoc)
- [ ] Redacción de la memoria según norma UNE 157001

**Entregable:** tag `v1.0.0` en GitHub + memoria TFG lista para entregar.

---

## Decisiones técnicas fijadas

| Decisión | Elección | Motivo |
|---|---|---|
| Runtime | Node.js (CommonJS) | Compatibilidad con Node-RED |
| Ejecución de comandos | `child_process.exec` con timeout | Seguridad y control |
| Nmap | Dependencia opcional | No bloquear en máquinas sin Nmap |
| Docker API | Socket local (`/var/run/docker.sock`) | Sin dependencias externas |
| Formato de reporte | HTML + JSON | Legible para humanos y máquinas |
| Tests | Jest | Integración sencilla con npm scripts |
| SO de desarrollo principal | macOS | Validación cruzada en Linux/Windows en Fase 4 |

---

## Convenciones de commits

```
feat(host): add cpu-memory module
feat(network): add nmap-wrapper with optional dependency
fix(executor): handle timeout on slow commands
test(lib): add finding-schema validation tests
docs: update ROADMAP phase 1 progress
```
