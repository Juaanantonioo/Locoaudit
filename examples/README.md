# LoCoAudit — Ejemplos de flujos Node-RED

Este directorio contiene flujos de ejemplo listos para importar en Node-RED.

---

## test-audit-host.json

Flujo mínimo para probar el nodo `audit-host` en local.

Contiene:
- **Inject** — dispara la auditoría manualmente con un clic.
- **audit-host** — ejecuta todos los módulos (CPU, disco, software, Lynis, Trivy).
- **Debug (payload completo)** — muestra `msg.payload` entero en el panel Debug.
- **Debug (summary)** — muestra solo `msg.payload.summary` con los contadores de severidad.

### Pasos para instalar y probar

**1. Instalar el paquete en Node-RED (desarrollo local)**

Desde la raíz del proyecto LoCoAudit:

```bash
npm link
```

En el directorio de datos de Node-RED (por defecto `~/.node-red`):

```bash
cd ~/.node-red
npm link locoaudit
```

**2. Arrancar Node-RED**

Con el lanzador Python (recomendado — verifica dependencias primero):

```bash
python3 launcher/lcaudit_launcher.py
```

O directamente:

```bash
node-red --userDir ~/.node-red
```

**3. Importar el flujo de ejemplo**

- Abre Node-RED en el navegador: `http://localhost:1880`
- Menú hamburguesa (☰) → **Import**
- Selecciona el fichero `examples/test-audit-host.json`
- Haz clic en **Import**

**4. Ejecutar la auditoría**

- Haz clic en el botón del nodo **"Disparar auditoría"** (parte izquierda del nodo Inject).
- Observa el estado del nodo `audit-host`: cambia de azul (auditando) a verde/amarillo/rojo según el riesgo detectado.
- Abre el panel **Debug** (icono de bicho en la barra lateral derecha) para ver los findings.

### Estructura del payload de salida

```json
{
  "findings": [
    {
      "id": "HOST-DISK-001",
      "title": "Disco /: 78% en uso",
      "severity": "high",
      "evidence": "Montaje: /, Total: 500 GB, Usado: 390 GB, Libre: 110 GB (78%)",
      "fix": "Liberar espacio en /. Eliminar ficheros temporales o ampliar volumen.",
      "category": "disk",
      "source": "native",
      "timestamp": "2026-04-11T10:00:00.000Z"
    }
  ],
  "summary": {
    "maxSeverity": "high",
    "counts": { "info": 3, "low": 1, "medium": 0, "high": 1, "critical": 0 }
  },
  "host": {
    "hostname": "mi-mac",
    "platform": "darwin",
    "arch": "arm64",
    "uptimeSec": 86400,
    "uptimeHuman": "1d 0h 0m"
  },
  "scanMeta": {
    "modulesRun": ["cpu-memory", "disk-storage", "sw-inventory"],
    "durationMs": 1234
  },
  "source": "audit-host",
  "auditType": "host",
  "timestamp": "2026-04-11T10:00:00.000Z"
}
```

### Herramientas opcionales

| Herramienta | Instalar en macOS | Instalar en Linux |
|---|---|---|
| Lynis | `brew install lynis` | `apt install lynis` |
| Trivy | `brew install aquasecurity/trivy/trivy` | Ver [trivy.dev](https://trivy.dev/latest/getting-started/installation/) |

Si Lynis o Trivy no están instalados, el nodo los omite silenciosamente
y sigue funcionando con los módulos nativos.
