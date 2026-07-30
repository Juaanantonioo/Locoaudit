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
│   │       ├── port-catalog.js
│   │       ├── nmap-wrapper.js
│   │       ├── service-detect.js
│   │       └── vuln-check.js
│   └── audit-image/
│       ├── audit-image.js
│       ├── audit-image.html
│       └── modules/
│           ├── docker-api.js
│           ├── layer-scan.js
│           ├── cve-checker.js
│           └── config-audit.js
│
│   (Sin nodo audit-reporter: los dashboards ui_template visualizan y descargan
│    los reportes en HTML + JSON desde el navegador.)
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
- [x] `nmap-wrapper.js` — escaneo de puertos con Nmap (REQUISITO del nodo)
- [x] `port-catalog.js` — catálogo puerto → severidad para PC personal (datos puros)
- [x] `service-detect.js` — identificación de servicio por número de puerto
- [ ] `vuln-check.js` — detección de servicios en versiones conocidas como inseguras

**audit-image:**
- [x] `docker-api.js` — conexión a Docker Engine vía CLI (docker images, docker ps)
- [ ] `layer-scan.js` — análisis de capas de la imagen
- [x] `cve-checker.js` — CVEs en imágenes Docker con trivy image (opcional)
- [x] `config-audit.js` — variables de entorno expuestas, usuario root, puertos expuestos

**Entregable:** flujo Node-RED con los 3 nodos encadenados produciendo `findings[]` unificado.

---

### Decisiones tomadas en Fase 2

- Nmap es REQUISITO de `audit-network`: es el único escáner. El antiguo escáner TCP
  nativo (`port-scanner.js`) se eliminó, junto con sus opciones de UI (timeout por
  puerto y workers paralelos). Su catálogo de severidades sobrevive en `port-catalog.js`.
  Si Nmap falta, el nodo no revienta: emite `NET-DEP-NMAP` con el comando de instalación
  de la plataforma (brew / apt / pacman / dnf / winget).
- `service-detect.js` (proceso, PID y dirección de bind vía lsof/netstat) ya no es
  opcional: se ejecuta siempre sobre localhost, porque las reglas de resolución dependen
  de esos campos para distinguir loopback de expuesto y daemon del sistema de terceros.
- La severidad de puertos sigue el mismo criterio que `LYNIS_PERSONAL_SEVERITY`: calibrada
  para PC personal, no para servidores.
- `config-audit.js` inspecciona contenedores con `docker inspect` en paralelo (3 comandos
  simultáneos por contenedor).
- `cve-checker.js` usa `trivy image` por imagen con `Promise.allSettled`; una imagen que
  falle no detiene el resto.
- `layer-scan.js` y `vuln-check.js` quedan como trabajo futuro de la Fase 4.
- Escaneo limitado a localhost en esta versión. El soporte multi-dispositivo
  (host discovery + escaneo de rangos CIDR) queda documentado como trabajo futuro.
  La arquitectura modular de nmap-wrapper.js permite añadirlo sin modificar el núcleo.

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
