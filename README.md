# LoCoAudit

Framework modular de auditoría de seguridad para Node-RED. Añade cuatro nodos arrastrables que auditan tu equipo, tu red y tus imágenes Docker, y consolidan los hallazgos en reportes HTML/JSON.

Desarrollado como Trabajo de Fin de Grado en Ingeniería Informática — Escuela Superior de Ingeniería (UCA).

---

## ¿Qué es LoCoAudit?

LoCoAudit convierte Node-RED en una plataforma de auditoría de seguridad local. En lugar de ejecutar herramientas de seguridad por separado e interpretar su salida, LoCoAudit las orquesta desde un flujo visual y produce un array de _findings_ unificado con severidad, evidencia y recomendación de mitigación.

Cada finding sigue el mismo contrato:

```json
{
  "id":        "HOST-DISK-001",
  "title":     "Partición / al 82 % de capacidad",
  "severity":  "high",
  "evidence":  "82 % usado (164 GiB de 200 GiB)",
  "fix":       "Libera espacio o amplía la partición",
  "category":  "disk",
  "source":    "native",
  "timestamp": "2026-05-18T10:00:00.000Z"
}
```

### Nodos disponibles

| Nodo | Qué audita | Herramientas |
|---|---|---|
| `audit-host` | CPU, RAM, disco, software instalado, hardening del SO, CVEs | nativo + Lynis + Trivy |
| `audit-network` | Puertos abiertos, versiones de servicios expuestos | nativo + Nmap |
| `audit-image` | CVEs en imágenes Docker, configuración insegura de contenedores | Docker + Trivy |

Los reportes se visualizan y descargan (HTML + JSON) directamente desde los dashboards de Node-RED (nodos `ui_template`), sin nodo generador aparte.

---

## Requisitos previos

Solo necesitas dos herramientas antes de ejecutar el launcher. El resto lo instala el propio asistente de configuración.

| Herramienta | Versión mínima | Dónde obtenerla |
|---|---|---|
| **Node.js** | v18.0.0 | https://nodejs.org |
| **Python** | v3.8+ | https://python.org |

> **npm** y **Node-RED** también son necesarios, pero si no los tienes el launcher te muestra exactamente cómo instalarlos y aborta con un mensaje claro.

---

## Instalación en 3 pasos

### 1. Clona el repositorio

```bash
git clone <url-del-repo> locoaudit
cd locoaudit
```

### 2. Ejecuta el launcher

```bash
python3 launcher/lcaudit_launcher.py
```

El launcher hace todo lo demás de forma automática:

- Verifica que Node.js ≥ v18, npm y Node-RED estén instalados
- Para cada herramienta opcional (Docker, Nmap, Lynis, Trivy) te pregunta si quieres instalarla ahora
- Registra los nodos de LoCoAudit en Node-RED
- Instala automáticamente `@flowfuse/node-red-dashboard` en `~/.node-red` (necesario para los dashboards)
- Carga el flujo de demostración en `~/.node-red/flows.json`
- Arranca Node-RED

### 3. Abre Node-RED en el navegador

```
http://localhost:1880
```

Verás tres pestañas precargadas: **Audit-host**, **Audit-network** y **Audit-image**.

---

## Usar los flujos de demo

Cada pestaña contiene un flujo independiente con:
- Un botón **inject** para disparar la auditoría manualmente
- El nodo de auditoría correspondiente
- Nodos **debug** para inspeccionar los findings en el panel lateral
- Un **dashboard** para visualizar los resultados en `http://localhost:1880/dashboard`

Para lanzar una auditoría: haz clic en el botón **▶** del nodo inject de la pestaña que quieras y observa los resultados en el panel Debug (columna derecha).

### Primero prueba con Audit-host

La pestaña **Audit-host** usa solo módulos nativos (CPU, RAM, disco, SO) que no requieren ninguna herramienta externa. Es el punto de partida ideal para verificar que todo funciona.

Los módulos Lynis y Trivy están activados por defecto. Si no los instalaste durante el setup:

1. Haz **doble clic** en el nodo `audit-host`
2. Desmarca los módulos **Lynis** y **Trivy**
3. Haz clic en **Done** y luego en **Deploy**

---

## Instalar herramientas opcionales después del setup

Si omitiste alguna herramienta durante la configuración inicial puedes instalarla después y volver a ejecutar el launcher (no reinstalas el paquete si ya está registrado, es idempotente).

### Nmap

```bash
# macOS
brew install nmap

# Ubuntu / Debian
sudo apt install nmap

# Arch / Manjaro / CachyOS
sudo pacman -S nmap

# Fedora / RHEL
sudo dnf install nmap
```

### Lynis

```bash
# macOS
brew install lynis

# Ubuntu / Debian
sudo apt install lynis

# Arch / Manjaro / CachyOS
sudo pacman -S lynis

# Fedora / RHEL
sudo dnf install lynis
```

### Trivy

```bash
# macOS
brew install aquasecurity/trivy/trivy

# Linux (todas las distros)
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
  | sudo sh -s -- -b /usr/local/bin
```

### Docker

- **macOS / Windows**: descarga Docker Desktop desde https://www.docker.com/products/docker-desktop
- **Linux**: `curl -fsSL https://get.docker.com | sudo sh`

---

## Troubleshooting

### macOS

**`brew: command not found`**  
Homebrew no está instalado. Ejecútalo primero:
```bash
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
```

**`node-red: command not found` tras instalar con npm**  
El directorio de binarios globales de npm no está en el PATH. Añádelo a `~/.zshrc`:
```bash
export PATH="$PATH:$(npm config get prefix)/bin"
source ~/.zshrc
```

**Lynis pide contraseña de sudo**  
Es el comportamiento esperado: Lynis necesita privilegios para algunas comprobaciones. Para modo sin sudo: `lynis audit system --pentest`

---

### Linux

**`npm install -g node-red` falla con EACCES**  
No uses `sudo` con npm. Instala Node.js a través de `nvm` para evitar el problema de permisos:
```bash
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.7/install.sh | bash
source ~/.bashrc
nvm install 20
npm install -g --unsafe-perm node-red
```

**Trivy no está en los repositorios oficiales de tu distro**  
Usa el script de instalación oficial que funciona en todas las distros:
```bash
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
  | sudo sh -s -- -b /usr/local/bin
```

**Docker: `permission denied` al ejecutar comandos**  
Añade tu usuario al grupo docker (requiere cerrar sesión y volver a entrar):
```bash
sudo usermod -aG docker $USER
```

**El daemon de Docker no arranca**  
```bash
sudo systemctl start docker
sudo systemctl enable docker   # para que arranque automáticamente con el sistema
```

---

### General

**Los nodos de LoCoAudit no aparecen en la paleta de Node-RED**  
El paso de registro (Paso 3 del launcher) pudo fallar. Ejecútalo manualmente desde la carpeta del proyecto:
```bash
npm install "$(pwd)" --prefix ~/.node-red
```
Reinicia Node-RED tras ejecutarlo.

**Ya tengo flujos en Node-RED y no quiero perderlos**  
El launcher no sobreescribe `~/.node-red/flows.json` si ya existe. Para cargar el demo sin perder tus flujos:

1. Abre Node-RED en http://localhost:1880
2. Menú **≡** (esquina superior derecha) → **Import**
3. Sube el archivo `examples/flows.json` del repositorio
4. Los flujos se añaden como pestañas nuevas sin borrar los existentes

**Node-RED muestra "audit-host is not registered"**  
El paquete no se registró correctamente. Comprueba que `~/.node-red/node_modules/locoaudit` existe y vuelve a ejecutar el launcher.

**El panel de dashboard no aparece en Node-RED (pestaña izquierda vacía o nodos `ui_*` con error)**  
El paquete `@flowfuse/node-red-dashboard` no está instalado en Node-RED. El launcher lo instala automáticamente en el Paso 4, pero si ocurrió un error puedes instalarlo manualmente:
```bash
npm install @flowfuse/node-red-dashboard --prefix ~/.node-red
```
Reinicia Node-RED tras ejecutarlo. Los nodos de dashboard que requieren este paquete son: **LocoDashHost**, **LocoDashNet** y **LocoDashImage**.
