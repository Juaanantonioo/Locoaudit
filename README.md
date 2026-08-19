# LoCoAudit

Extensión de bajo código para Node-RED que automatiza auditorías de seguridad locales y presenta los resultados en paneles comprensibles para personas sin formación técnica en seguridad.

LoCoAudit añade nodos que puedes arrastrar a un flujo de Node-RED, conectar y ejecutar. Cada nodo lanza herramientas de auditoría reconocidas (Nmap, Lynis, Trivy), normaliza sus salidas a un formato común y las convierte en hallazgos con evidencia, severidad y pasos de resolución.

---

## Índice

- [Qué problema resuelve](#qué-problema-resuelve)
- [Nodos disponibles](#nodos-disponibles)
- [Requisitos](#requisitos)
- [Instalación con el asistente](#instalación-con-el-asistente)
- [Instalación manual](#instalación-manual)
- [Herramientas externas](#herramientas-externas)
- [Primeros pasos](#primeros-pasos)
- [Cómo leer los resultados](#cómo-leer-los-resultados)
- [Asistente de IA (opcional)](#asistente-de-ia-opcional)
- [Alcance y limitaciones conocidas](#alcance-y-limitaciones-conocidas)
- [Desarrollo](#desarrollo)
- [Contexto académico](#contexto-académico)

---

## Qué problema resuelve

Las herramientas de auditoría de seguridad existentes son potentes pero están pensadas para especialistas. Producen salidas extensas en la terminal, con vocabulario técnico y sin indicar qué requiere acción y qué es meramente informativo. Ejecutarlas de forma periódica y comparar resultados exige montar scripts propios.

LoCoAudit aborda tres puntos concretos:

**Orquestación visual.** Las auditorías se componen arrastrando nodos en un lienzo, sin escribir código. La salida de cada nodo puede encadenarse con el resto del ecosistema de Node-RED: notificaciones, bases de datos, temporizadores.

**Normalización de resultados.** Nmap, Lynis y Trivy devuelven formatos distintos. LoCoAudit los convierte a un esquema único de hallazgo, de modo que el panel los presenta de forma homogénea independientemente de su procedencia.

**Distinción entre lo accionable y lo informativo.** Un análisis de vulnerabilidades en un equipo de desarrollo puede arrojar cientos de resultados de los que ninguno requiere intervención. LoCoAudit clasifica cada hallazgo según si corresponde a software realmente instalado o a una dependencia anotada en un fichero de proyecto, y solo lo primero cuenta para el nivel de riesgo global.

---

## Nodos disponibles

| Nodo | Qué audita | Herramientas que emplea |
| --- | --- | --- |
| `audit-host` | El equipo local: inventario de hardware, almacenamiento, software instalado, endurecimiento del sistema y vulnerabilidades conocidas | Lynis, Trivy (opcionales) |
| `audit-network` | Puertos abiertos y servicios expuestos, en el propio equipo o en otro de la red | Nmap (opcional) |
| `audit-image` | Imágenes Docker presentes en el equipo | Docker, Trivy |
| `llm-config` | Nodo de configuración para conectar un modelo de lenguaje local y habilitar el chat de explicación de hallazgos | Ollama (opcional) |

Las herramientas marcadas como opcionales no bloquean la ejecución. Si Nmap no está instalado, `audit-network` lo indica en el propio panel y el resto de módulos sigue funcionando.

---

## Requisitos

- Node.js 18 o superior
- Node-RED 3.x o superior
- Python 3.8 o superior, únicamente para el asistente de instalación

El asistente comprueba y ayuda a instalar el resto. Si prefieres hacerlo a mano, la sección de instalación manual detalla los pasos equivalentes.

Sistemas operativos verificados: macOS, Linux (probado sobre CachyOS, base Arch) y Windows.

---

## Instalación con el asistente

LoCoAudit incluye un asistente que comprueba qué hace falta, ofrece instalar lo que no encuentre, registra la extensión en Node-RED y lo arranca todo. Es la vía recomendada.

```bash
git clone https://github.com/Juaanantonioo/Locoaudit.git
cd Locoaudit
python3 launcher/lcaudit_launcher.py
```

En Windows, sustituye `python3` por `python`.

El asistente recorre seis pasos:

1. **Dependencias requeridas.** Verifica Node.js (versión 18 o superior), npm y Node-RED. Si falta alguno, indica el comando de instalación para tu sistema operativo y se detiene, ya que sin ellos no puede continuar.
2. **Herramientas opcionales.** Busca Docker, Nmap, Lynis y Trivy. Por cada una que falte, muestra para qué sirve y ofrece instalarla con el gestor de paquetes de tu sistema. Puedes decir que no: el nodo correspondiente seguirá funcionando en modo reducido.
3. **Registro de la extensión.** Instala LoCoAudit dentro del directorio de Node-RED para que sus nodos aparezcan en la paleta.
4. **Dependencias de Node-RED.** Instala `@flowfuse/node-red-dashboard` si no está presente.
5. **Flujos de demostración.** Copia el flujo de ejemplo con los tres nodos ya conectados a sus paneles. Si ya tenías flujos propios en Node-RED, no los sobrescribe: te indica cómo importarlo manualmente.
6. **Arranque.** Lanza Node-RED y ofrece abrir el navegador.

### Dos modos de ejecución

Si tu sistema tiene `tkinter` disponible, el asistente abre una ventana gráfica con el progreso de cada paso y botones para responder a las preguntas de instalación. Es lo que verás en la mayoría de instalaciones de escritorio.

Si no lo tiene, por ejemplo en un servidor sin entorno gráfico, cae automáticamente a modo terminal. Ahí utiliza la biblioteca `rich` para dar formato a la salida, y la instala sola si no la encuentra. Si tampoco puede instalarla, funciona igualmente en texto plano.

Al terminar, el editor queda en `http://localhost:1880` y los paneles en `http://localhost:1880/dashboard`.

---

## Instalación manual

Si prefieres controlar cada paso, o el asistente falla en tu sistema:

### 1. Node.js y Node-RED

```bash
# macOS con Homebrew
brew install node
npm install -g --unsafe-perm node-red

# Debian / Ubuntu
sudo apt install nodejs npm
sudo npm install -g --unsafe-perm node-red

# Arch / CachyOS
sudo pacman -S nodejs npm
sudo npm install -g --unsafe-perm node-red

# Windows (PowerShell como administrador)
winget install OpenJS.NodeJS.LTS
npm install -g --unsafe-perm node-red
```

### 2. Registrar LoCoAudit en Node-RED

```bash
git clone https://github.com/Juaanantonioo/Locoaudit.git
cd Locoaudit
npm install "$(pwd)" --prefix ~/.node-red
npm install @flowfuse/node-red-dashboard --prefix ~/.node-red
```

En Windows, el directorio de Node-RED es `%USERPROFILE%\.node-red`.

### 3. Arrancar e importar el flujo de ejemplo

```bash
node-red
```

Abre `http://localhost:1880`, entra en el menú lateral, elige **Importar** y selecciona `examples/flows.json` del repositorio. Ese flujo trae los tres nodos de auditoría ya conectados a sus paneles.

---

## Herramientas externas

Ninguna es obligatoria para que Node-RED arranque, pero cada módulo necesita la suya para producir resultados.

| Herramienta | Para qué | macOS | Linux | Windows |
| --- | --- | --- | --- | --- |
| Nmap | Escaneo de puertos | `brew install nmap` | `sudo pacman -S nmap` / `sudo apt install nmap` | `winget install -e --id Insecure.Nmap` |
| Trivy | Vulnerabilidades en dependencias e imágenes | `brew install trivy` | Repositorio oficial de Aqua Security | Binario desde las *releases* de GitHub |
| Lynis | Endurecimiento del sistema | `brew install lynis` | `sudo pacman -S lynis` / `sudo apt install lynis` | No disponible de forma nativa |
| Docker | Necesario para `audit-image` | Docker Desktop | Paquete de la distribución | Docker Desktop con WSL2 |

El asistente de instalación ofrece instalar Nmap, Lynis, Trivy y Docker por ti cuando detecta un gestor de paquetes compatible (Homebrew en macOS; apt, pacman, dnf o zypper en Linux; winget en Windows). Si no lo encuentra, muestra el comando exacto para que lo hagas a mano.

Una vez en marcha, cuando falta una herramienta el nodo correspondiente lo señala en el propio panel con la instrucción de instalación concreta, en lugar de fallar sin explicación.

---

## Primeros pasos

1. **Arrastra un nodo de auditoría** al lienzo, por ejemplo `audit-host`.
2. **Conecta un nodo `inject`** a su entrada, para poder disparar la auditoría manualmente. También puedes configurarlo con un intervalo si prefieres ejecuciones periódicas.
3. **Conecta la salida** al nodo `ui_template` correspondiente, ya presente en el flujo de ejemplo.
4. **Despliega** y pulsa el botón del `inject`.
5. **Abre el panel** en `/dashboard` y consulta los resultados.

La primera ejecución de `audit-host` puede tardar varios minutos: Lynis recorre más de doscientos controles y Trivy descarga su base de datos de vulnerabilidades. Las siguientes son considerablemente más rápidas gracias a la caché.

### Auditar otro equipo de la red

`audit-network` permite indicar una dirección IP distinta de la del propio equipo. Antes del escaneo completo, comprueba si el objetivo responde. Si no lo hace, no ejecuta el análisis de puertos y muestra el estado **No auditado**, en lugar de informar de cero puertos abiertos, que podría interpretarse erróneamente como ausencia de riesgo.

Audita únicamente equipos de tu propiedad o para los que dispongas de autorización expresa.

---

## Cómo leer los resultados

### Requieren tu atención frente a informativos

La cabecera de cada panel separa ambos grupos. Un hallazgo cuenta como accionable cuando existe algo concreto que puedas hacer al respecto en este equipo.

### Declarado frente a instalado

En el panel del host, cada vulnerabilidad lleva una de estas dos etiquetas:

- **Instalado**: el paquete afectado está presente y en uso en tu sistema. Puede actualizarse, y el panel muestra el comando concreto según tu gestor de paquetes.
- **Declarado**: la versión vulnerable aparece mencionada en un fichero de dependencias (`package-lock.json`, `poetry.lock`, `pom.xml`, entre otros), pero no hay software ejecutándose con ella. No hay nada que actualizar.

Los hallazgos declarados se listan para que conozcas su existencia, no como tareas pendientes, y no elevan el nivel de riesgo global del equipo.

### Alcance del análisis

Bajo la cabecera del panel de host aparece un bloque que detalla qué se ha examinado: qué carpeta, cuántas subcarpetas, cuáles se han excluido y por qué, y si los paquetes del sistema operativo se han analizado o no. Esta última información importa porque Trivy no soporta todos los gestores de paquetes; en distribuciones basadas en Arch, por ejemplo, el software instalado por el sistema queda fuera del análisis. El panel lo indica explícitamente en lugar de dejar que el usuario suponga una cobertura mayor de la real.

### Severidad de los hallazgos de Lynis

Lynis no asigna niveles de severidad a sus controles. LoCoAudit los deriva del grupo al que pertenece cada control (autenticación, cortafuegos, red, registros) y de si se trata de un aviso o de una sugerencia. Los paneles lo indican con la anotación *criterio de LoCoAudit* junto al nivel, para que quede claro que ese dato no procede de la herramienta original.

### Exportación

Cada panel dispone de botones para descargar el informe en HTML (autocontenido, incluye estilos y puede abrirse en cualquier navegador) o en JSON (pensado para procesamiento posterior).

---

## Asistente de IA (opcional)

Si configuras un nodo `llm-config` apuntando a una instancia de [Ollama](https://ollama.com), aparece un botón **Preguntar a la IA** junto a cada hallazgo. Permite pedir explicaciones en lenguaje llano sobre qué significa una vulnerabilidad concreta y qué implica en tu contexto.

La consulta se realiza a través de Node-RED, no directamente desde el navegador, de modo que el contexto de los hallazgos no sale del servidor. Sin nodo `llm-config`, el botón no aparece y el resto de la herramienta funciona con normalidad.

---

## Alcance y limitaciones conocidas

Conviene tenerlas presentes para interpretar correctamente los resultados.

**LoCoAudit no ejecuta comandos de corrección.** Muestra el comando recomendado con un botón para copiarlo, pero la ejecución queda siempre en manos del usuario.

**Es una fotografía puntual, no un sistema de monitorización.** Cada ejecución refleja el estado del equipo en ese instante. No hay vigilancia continua ni comparación automática con ejecuciones anteriores.

**Trivy no cubre todos los gestores de paquetes.** Los paquetes instalados mediante `pacman` (Arch y derivadas) quedan fuera del análisis, ya que Trivy no sabe leer su base de datos. En sistemas basados en Debian o Red Hat sí pueden analizarse activando la opción correspondiente en el nodo.

**Lynis no funciona en Windows sin WSL.** El módulo lo detecta y lo comunica como límite de la plataforma, sin interrumpir el resto de la auditoría.

**El análisis de red examina un único equipo por ejecución.** Los rangos CIDR no están soportados.

### Trabajo futuro

- Escaneo de múltiples dispositivos mediante rangos de red
- Integración de `arch-audit` para cubrir los paquetes de sistema en distribuciones Arch
- Módulo de auditoría de aplicaciones web basado en OWASP ZAP
- Comparación histórica entre ejecuciones sucesivas

---

## Desarrollo

### Estructura del repositorio

```
launcher/
  lcaudit_launcher.py    Asistente de instalación y arranque
  lcaudit_gui.py         Interfaz gráfica del asistente (Tkinter)
lib/                     Módulos compartidos: normalizador, esquema de
                         hallazgos, mapa de severidades, ejecutor de comandos
nodes/
  audit-host/            Nodo y módulos de auditoría del equipo local
  audit-network/         Nodo y módulos de auditoría de red
  audit-image/           Nodo y módulos de auditoría de imágenes Docker
examples/
  flows.json             Flujo de ejemplo listo para importar
  dashboard-*.html       Plantillas Vue de los paneles
scripts/                 Utilidades de verificación del repositorio
test/
  manual/                Pruebas ejecutables con node, sin framework
  fixtures/              Salidas reales capturadas de las herramientas
```

### Ejecutar las pruebas

```bash
for f in test/manual/test-*.js; do node "$f" || echo "FALLÓ: $f"; done
```

Las pruebas no requieren que Nmap, Trivy o Lynis estén instalados: emplean salidas reales previamente capturadas en `test/fixtures/`, lo que las hace deterministas y ejecutables en cualquier sistema.

### Verificaciones del repositorio

```bash
node scripts/build-dashboards.js --check    # las plantillas coinciden con flows.json
node scripts/export-parity.js               # cableado y sincronía de los paneles
```

### Esquema de hallazgo

Todos los módulos producen objetos con la misma forma:

```javascript
{
  id: "HOST-CVE-001",        // prefijo según origen: HOST-CVE, HOST-LYN, NET, IMG
  title: "...",              // descripción legible
  severity: "high",          // critical | high | medium | low | info
  evidence: "...",           // qué se ha encontrado exactamente
  fix: "...",                // pasos de resolución
  isCommand: true,           // si fix es un comando ejecutable
  category: "vulnerability",
  source: "trivy",
  scope: "host",             // host | network | image
  origin: "installed",       // installed | declared (solo vulnerabilidades)
  timestamp: "..."
}
```

---

## Contexto académico

LoCoAudit es el resultado de un Trabajo Fin de Grado del Grado en Ingeniería Informática de la Escuela Superior de Ingeniería de la Universidad de Cádiz.

- **Autor**: Juan Antonio Salvado García
- **Director**: Juan Boubeta Puig
- **Codirector**: Jesús Rosa Bilbao
- **Departamento**: Ingeniería Informática

---

## Licencia

Pendiente de definir.
