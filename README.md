# LoCoAudit

Extensión de bajo código para Node-RED que automatiza auditorías de seguridad locales y presenta los resultados en paneles comprensibles para personas sin formación técnica en seguridad.

LoCoAudit añade nodos que se arrastran a un flujo de Node-RED, se conectan y se ejecutan. Cada nodo lanza herramientas de auditoría reconocidas (Nmap, Lynis y Trivy), normaliza sus salidas a un formato común y las convierte en hallazgos con evidencia, severidad y pasos de resolución.

> El [manual de usuario](docs/LoCoAudit-manual-de-usuario.pdf) explica la instalación paso a paso en cada sistema operativo y cómo interpretar los resultados.

---

## Índice

- [Qué problema resuelve](#qué-problema-resuelve)
- [Nodos disponibles](#nodos-disponibles)
- [Requisitos](#requisitos)
- [Instalación con el asistente](#instalación-con-el-asistente)
- [Instalación en Windows](#instalación-en-windows)
- [Instalación manual](#instalación-manual)
- [Herramientas externas](#herramientas-externas)
- [Primeros pasos](#primeros-pasos)
- [Cómo leer los resultados](#cómo-leer-los-resultados)
- [Asistente de IA (opcional)](#asistente-de-ia-opcional)
- [Alcance y limitaciones conocidas](#alcance-y-limitaciones-conocidas)
- [Desarrollo](#desarrollo)
- [Contexto académico](#contexto-académico)
- [Licencia](#licencia)

---

## Qué problema resuelve

Las herramientas de auditoría de seguridad están pensadas para personas con conocimientos de ciberseguridad. Producen salidas extensas en la terminal, con vocabulario técnico y sin indicar qué requiere acción y qué es solo informativo. Ejecutarlas de forma periódica y comparar resultados exige montar scripts propios.

LoCoAudit aborda tres puntos concretos.

**Orquestación visual.** Las auditorías se componen arrastrando nodos en un lienzo, sin escribir código. La salida de cada nodo puede encadenarse con el resto del ecosistema de Node-RED, como notificaciones, bases de datos o temporizadores.

**Normalización de resultados.** Nmap, Lynis y Trivy devuelven formatos distintos. LoCoAudit los convierte a un esquema único de hallazgo, de modo que el panel los presenta igual sea cual sea su procedencia.

**Distinción entre lo accionable y lo informativo.** Un análisis de vulnerabilidades en un equipo de desarrollo puede arrojar cientos de resultados de los que ninguno requiere intervención. LoCoAudit distingue si cada vulnerabilidad corresponde a software realmente instalado o a una dependencia anotada en un fichero de proyecto, y solo lo primero cuenta para el nivel de riesgo del equipo.

---

## Nodos disponibles

| Nodo | Qué audita | Herramientas que emplea |
| --- | --- | --- |
| `audit-host` | El equipo local: recursos, almacenamiento, software instalado, endurecimiento del sistema, actualizaciones pendientes, eventos de seguridad, vulnerabilidades conocidas y secretos guardados en ficheros | Lynis, Trivy |
| `audit-network` | Puertos abiertos y servicios expuestos, en el propio equipo o en otro de la red local | Nmap |
| `audit-image` | Imágenes y contenedores Docker del equipo, o imágenes concretas de Docker Hub u otro registro | Docker, Trivy |
| `llm-config` | Nodo de configuración que conecta un modelo de lenguaje local para explicar los hallazgos | Ollama |

---

## Requisitos

| Componente | Versión |
| --- | --- |
| Node.js | 22 LTS o posterior. Probado con 22.20 |
| Node-RED | 4.x. Probado con 4.1.5 |
| Python | 3.10 o posterior, solo para el asistente de instalación |

Node.js y npm se instalan a mano antes de ejecutar el asistente. El asistente comprueba esos requisitos y ofrece instalar Node-RED junto con las herramientas de auditoría cuando el sistema dispone de un comando automático.

**Sobre la versión de Node-RED.** El asistente instala la última versión publicada si Node-RED no está instalado, y hoy es la 5, que necesita Node.js 22.9 o posterior. LoCoAudit se ha probado con Node-RED 4. Para usar esa misma versión, basta con instalarla antes de ejecutar el asistente, que la detecta y no la sustituye:

```bash
npm install -g node-red@4        # en Linux, con sudo
```

**Sistemas probados:** macOS, Debian 13, Linux Mint, CachyOS y Windows 11.

---

## Instalación con el asistente

LoCoAudit incluye un asistente que comprueba los requisitos, ofrece instalar Node-RED y las herramientas de auditoría, registra la extensión en Node-RED y lo arranca todo.

```bash
git clone https://github.com/Juaanantonioo/Locoaudit.git
cd Locoaudit
python3 launcher/lcaudit_launcher.py
```

En Windows se usa `python` en lugar de `python3`, o `py` si el primero no se reconoce.

El asistente recorre seis pasos:

1. **Dependencias requeridas.** Verifica Node.js (versión 18 o superior) y npm. Si falta alguno, indica cómo instalarlo y se detiene. Si falta Node-RED, lo ofrece en el paso siguiente.
2. **Instalaciones automáticas.** Ofrece instalar Node-RED, Docker, Nmap, Lynis y Trivy cuando existe un comando automático para el sistema. Cada herramienta puede rechazarse, pero Node-RED tiene que quedar instalado para continuar.
3. **Registro de la extensión.** Instala LoCoAudit en el directorio de Node-RED para que sus nodos aparezcan en la paleta.
4. **Dependencias de Node-RED.** Instala `@flowfuse/node-red-dashboard` si no está presente.
5. **Flujos de demostración.** Copia el flujo de ejemplo con los tres nodos de auditoría ya conectados a sus paneles. Si ya hay flujos propios en Node-RED, no los sobrescribe e indica cómo importar el ejemplo a mano.
6. **Arranque.** Lanza Node-RED y muestra la dirección del editor. En la ventana gráfica, un botón la abre en el navegador.

Si una herramienta se rechaza, los módulos que la necesitan no podrán ejecutarse: el nodo se detendrá con un error que explica cómo instalarla o qué opción desactivar.

### Dos modos de ejecución

Si Python tiene `tkinter`, el asistente abre una ventana con el progreso de cada paso y botones para responder a las preguntas de instalación. Si no lo tiene, por ejemplo en un servidor sin entorno gráfico, funciona en la terminal.

En la terminal usa la biblioteca `rich` para dar formato a la salida. Si no la encuentra, intenta instalarla, y para ello puede pedir la contraseña del equipo nada más arrancar. Se puede escribir o dejar en blanco: si la biblioteca no se instala, el asistente sigue en texto plano.

Al terminar, el editor queda en `http://localhost:1880` y los paneles en `http://localhost:1880/dashboard`.

---

## Instalación en Windows

En Windows el asistente funciona igual que en el resto de sistemas, con una diferencia: al instalar **Nmap** aparece el diálogo de control de cuentas de usuario (UAC) pidiendo permisos de administrador. Esta sección explica por qué y qué se hace exactamente con ese permiso.

### Qué ocurre

El asistente muestra el comando exacto que va a ejecutar en la propia pregunta de instalación, junto con el motivo del permiso. Si se acepta, se abre una ventana de terminal como administrador **únicamente** para ejecutar ese comando. Cuando termina, la ventana se cierra y el asistente continúa sin privilegios.

### Por qué hace falta

El instalador de Nmap registra la ruta del programa en el PATH del sistema (`HKLM`), una operación reservada a administradores. En las pruebas, sin ese permiso el instalador copiaba los ficheros pero esa parte fallaba sin avisar: `winget list` daba Nmap por instalado y el ejecutable estaba en `C:\Program Files (x86)\Nmap\nmap.exe`, pero el sistema no encontraba el comando `nmap`, ni siquiera tras reiniciar. Con la instalación elevada funciona a la primera.

### Qué no se hace

- **El asistente no se ejecuta como administrador, y Node-RED tampoco.** Node-RED lanza herramientas de auditoría y sirve un panel web en el puerto 1880, y ejecutarlo con privilegios elevados ampliaría la superficie de ataque sin necesidad. Es el principio de mínimo privilegio.
- **Node-RED no se abre a la red.** El asistente lo arranca con `launcher/node-red-settings.js`, que escucha solo en `127.0.0.1`, salvo que el usuario haya fijado otra dirección, y rechaza las peticiones que llegan desde otra web abierta en el navegador. Con la configuración de fábrica, Node-RED escucha en todas las interfaces y no pide contraseña. El `settings.js` del usuario no se modifica. Para acceder desde otro equipo hay que arrancar `node-red` a mano después de configurar `adminAuth`.
- **LoCoAudit no modifica el PATH del usuario ni del sistema por su cuenta.** No usa `setx` ni escribe en el registro. Quien registra la ruta es el instalador oficial de Nmap, igual que si se instalase a mano.

### Si se prefiere no dar el permiso

El diálogo de UAC puede rechazarse. En ese caso se omite esa instalación, el asistente muestra el comando para hacerla a mano y el resto del proceso continúa. Instalado desde una terminal de administrador, el resultado es idéntico:

```powershell
winget install --id Insecure.Nmap --source winget -e
```

La versión de Nmap que publica winget es la 7.80. Quien prefiera la última puede instalarla desde [nmap.org](https://nmap.org/download.html).

**Trivy no necesita elevación**, porque winget lo registra en su propia carpeta de enlaces, que ya está en el PATH del usuario. **El instalador de Docker Desktop pide permisos de administrador por su cuenta**, con el mismo diálogo de UAC.

### Después de instalar

Las herramientas instaladas quedan disponibles para LoCoAudit en la misma sesión, sin reiniciar nada, porque el asistente pasa sus rutas al Node-RED que arranca. Para que también las reconozcan otros programas o terminales, conviene reiniciar Windows más adelante. Es una recomendación, no un requisito para usar LoCoAudit.

---

## Instalación manual

Para controlar cada paso, o si el asistente falla en el sistema.

### 1. Node.js y Node-RED

Primero se instala Node.js 22 LTS o posterior. npm se instala junto con Node.js.

```bash
# macOS con Homebrew
brew install node
npm install -g node-red@4

# Linux: instalar Node.js siguiendo la guía oficial
# https://nodejs.org/en/download
sudo npm install -g node-red@4

# Windows (PowerShell)
winget install --id OpenJS.NodeJS.LTS --source winget -e
npm install -g node-red@4
```

### 2. Registrar LoCoAudit en Node-RED

```bash
git clone https://github.com/Juaanantonioo/Locoaudit.git
cd Locoaudit
npm install "$(pwd)" --prefix ~/.node-red
npm install @flowfuse/node-red-dashboard --prefix ~/.node-red
```

En Windows, el directorio de Node-RED es `%USERPROFILE%\.node-red`, y en PowerShell se escribe `--prefix "$env:USERPROFILE\.node-red"`.

### 3. Arrancar e importar el flujo de ejemplo

```bash
node-red
```

Se abre `http://localhost:1880`, se elige **Importar** en el menú principal y se selecciona `examples/flows.json` del repositorio. Ese flujo trae los tres nodos de auditoría ya conectados a sus paneles.

Arrancado así, Node-RED usa su configuración de fábrica: escucha en todas las interfaces y no pide contraseña. Para limitarlo al propio equipo, hay que arrancarlo con el asistente o configurar `uiHost` y `adminAuth` en `settings.js`.

---

## Herramientas externas

Ninguna es obligatoria para que Node-RED arranque, pero cada módulo necesita la suya para producir resultados.

| Herramienta | Para qué | macOS | Linux | Windows |
| --- | --- | --- | --- | --- |
| Nmap | Escaneo de puertos | `brew install nmap` | `sudo apt install nmap` / `sudo pacman -S nmap` | `winget install -e --id Insecure.Nmap` |
| Trivy | Vulnerabilidades, secretos e imágenes | `brew install trivy` | [Script oficial de Aqua Security](https://trivy.dev/docs/latest/getting-started/installation/) | `winget install -e --id AquaSecurity.Trivy` |
| Lynis | Endurecimiento del sistema | `brew install lynis` | `sudo apt install lynis` / `sudo pacman -S lynis` | No disponible |
| Docker | Modo de imágenes locales de `audit-image` | Docker Desktop | `get.docker.com` o paquete de la distribución | Docker Desktop |

El asistente ofrece instalar Nmap, Lynis, Trivy y Docker cuando detecta un gestor de paquetes compatible: Homebrew en macOS; apt, pacman, dnf o zypper en Linux; y winget en Windows. En macOS, Docker Desktop se instala a mano. Si no encuentra gestor, muestra el comando para hacerlo a mano.

Una vez en marcha, si falta una herramienta que el nodo tiene activada, el nodo se detiene con un error que indica cómo instalarla o qué opción desactivar, y su estado en el editor lo resume (por ejemplo, «Nmap no instalado»). El panel no recibe resultado de esa ejecución. Las comprobaciones que no existen en un sistema, como Lynis en Windows o los paquetes del sistema en macOS y Windows, aparecen en el informe como no aplicables y el resto de la auditoría continúa.

---

## Primeros pasos

1. **Arrastrar un nodo de auditoría** al lienzo, por ejemplo `audit-host`.
2. **Conectar un nodo `inject`** a su entrada para disparar la auditoría a mano. También puede configurarse con un intervalo para ejecuciones periódicas.
3. **Conectar la salida** al nodo `ui-template` correspondiente, que ya está en el flujo de ejemplo. Si se crea uno nuevo, se pega en su campo «Template» el fichero `examples/dashboard-<tipo>-template.html` completo y se le asigna un grupo de **ancho 6 o más**: con menos ancho las tarjetas de hallazgos se descolocan.
4. **Pulsar «Instanciar»** (*Deploy* en la interfaz en inglés) y después el botón del `inject`.
5. **Abrir el panel** en `http://localhost:1880/dashboard` y consultar los resultados.

La primera ejecución de `audit-host` puede tardar varios minutos, porque Lynis recorre todos sus controles y Trivy descarga su base de datos de vulnerabilidades. Las siguientes son más rápidas porque Trivy reutiliza esa base de datos.

### Auditar otro equipo de la red

`audit-network` permite indicar la dirección IPv4 de otro equipo, que tiene que estar en una de las redes a las que está conectado el equipo que audita. Una dirección privada de otra red se rechaza igual que una pública. Antes del escaneo, comprueba si el objetivo responde. Si no lo hace, no escanea los puertos y muestra el estado **No auditado**, en lugar de informar de cero puertos abiertos, que podría leerse como ausencia de riesgo.

Solo deben auditarse equipos propios o para los que se tenga autorización expresa.

---

## Cómo leer los resultados

### Requieren atención frente a informativos

La cabecera de cada panel separa ambos grupos. Un hallazgo requiere atención cuando hay algo concreto que hacer al respecto en el equipo. Los informativos no cuentan para el nivel de riesgo.

### Instalado frente a declarado

En el panel del equipo, cada vulnerabilidad lleva una de estas dos etiquetas:

- **Instalado**: el paquete afectado está presente en el sistema. Puede actualizarse, y el panel muestra el comando según el gestor de paquetes.
- **Declarado**: la versión vulnerable solo aparece en un fichero de dependencias (`package-lock.json`, `poetry.lock`, `pom.xml`, entre otros), sin software instalado con ella.

Los hallazgos declarados se listan para que se conozca su existencia, no como tareas pendientes, y no elevan el nivel de riesgo del equipo.

### Alcance del análisis

Bajo la cabecera del panel del equipo, un bloque detalla qué se ha examinado: qué carpeta, cuántas subcarpetas, cuáles se han excluido y por qué, y si se han analizado los paquetes del sistema operativo. Trivy solo sabe leer los paquetes de algunas distribuciones Linux. En macOS, Windows y las distribuciones basadas en Arch, el software instalado por el sistema queda fuera del análisis, y el panel lo indica en lugar de dejar suponer una cobertura mayor de la real.

### Severidad de los hallazgos de Lynis

Lynis no asigna severidad a sus controles. LoCoAudit la deriva del grupo al que pertenece cada control (cortafuegos, SSH, autenticación, cifrado…) y de si es un aviso o una sugerencia, con ajustes para algunos controles concretos pensados para un equipo personal. Los paneles lo señalan con la anotación *criterio de LoCoAudit* junto al nivel.

### Exportación

Cada panel tiene botones para descargar el informe en HTML (un único fichero con sus estilos, que se abre en cualquier navegador) o en JSON (para procesarlo con otras herramientas).

---

## Asistente de IA (opcional)

Con un nodo `llm-config` apuntando a una instancia de [Ollama](https://ollama.com), aparece el botón **Preguntar a la IA** en cada hallazgo. Permite pedir explicaciones en lenguaje llano sobre qué significa un hallazgo y cómo resolverlo.

La consulta viaja desde Node-RED hasta la dirección de Ollama configurada, no directamente desde el navegador. Si Ollama está en el propio equipo, los datos de los hallazgos no salen de él. El asistente solo conversa y nunca ejecuta comandos. Sin nodo `llm-config`, el botón no aparece y el resto de la herramienta funciona igual.

---

## Alcance y limitaciones conocidas

Conviene tenerlas presentes para interpretar bien los resultados.

**LoCoAudit no ejecuta comandos de corrección.** Muestra el comando recomendado con un botón para copiarlo, pero la ejecución queda siempre en manos del usuario.

**Es una fotografía puntual, no un sistema de monitorización.** Cada ejecución refleja el estado del equipo en ese instante. No hay vigilancia continua ni comparación automática con ejecuciones anteriores.

**Las vulnerabilidades de los paquetes del sistema solo se analizan en Linux.** Trivy no sabe leer los paquetes de macOS, Windows ni Arch Linux y derivadas. En macOS y Windows, el informe muestra las actualizaciones pendientes que indica el sistema, pero no las relaciona con ningún CVE.

**Lynis no funciona en Windows.** El módulo lo detecta y lo indica como no aplicable, sin interrumpir el resto de la auditoría.

**El análisis de red examina un único equipo por ejecución** y solo dentro de la red local. No admite rangos ni nombres de equipo.

**La búsqueda de CVE por versión depende de un servicio externo.** El script `vulners` de Nmap consulta la API de vulners.com, enviando solo el nombre y la versión de cada servicio. Si la API no responde o rechaza la consulta, el script no devuelve ningún error ni ningún dato, y ese silencio es indistinguible del de un servicio sin vulnerabilidades conocidas.

**Por eso, un equipo bien mantenido aparecerá como «sin comprobar», no como «limpio».** Ante la duda, LoCoAudit no da nada por limpio y marca esos servicios como versión sin comprobar frente a la base de CVE. En un equipo actualizado es el resultado esperado y no significa que esté mal. Leer el silencio como «sin vulnerabilidades» sería un falso resultado limpio, que es justo lo que la herramienta evita.

**La versión que se consulta es la que el servicio anuncia.** No se verifica contra el equipo. Debian, Ubuntu y Red Hat corrigen fallos sin cambiar el número de versión (*backporting*), así que un servicio ya corregido puede aparecer con sus CVE. Cada hallazgo lo advierte en su evidencia, y la comprobación definitiva es el registro de cambios del paquete en el propio equipo.

### Trabajo futuro

- Escaneo de varios equipos mediante rangos de red
- Integración de `arch-audit` para cubrir los paquetes del sistema en distribuciones Arch
- Módulo de auditoría de aplicaciones web basado en OWASP ZAP
- Comparación histórica entre ejecuciones

---

## Desarrollo

### Estructura del repositorio

```
launcher/
  lcaudit_launcher.py    Asistente de instalación y arranque
  lcaudit_gui.py         Interfaz gráfica del asistente (Tkinter)
  node-red-settings.js   Ajustes con los que el asistente arranca Node-RED
lib/                     Módulos compartidos: normalizador, esquema de
                         hallazgos, mapa de severidades, ejecutor de comandos
nodes/
  audit-host/            Nodo y módulos de auditoría del equipo local
  audit-network/         Nodo y módulos de auditoría de red
  audit-image/           Nodo y módulos de auditoría de imágenes Docker
  llm-config/            Nodo de configuración del asistente de IA
  */icons/               Icono de cada nodo en la paleta de Node-RED
docs/
  LoCoAudit-manual-de-usuario.pdf
examples/
  flows.json             Flujo de ejemplo listo para importar
  dashboard-*.html       Plantillas Vue de los paneles
scripts/                 Construcción de los paneles y validación de extremo a extremo
test/
  manual/                Pruebas ejecutables con node, sin framework
  fixtures/              Salidas reales capturadas de las herramientas
```

### Ejecutar las pruebas

```bash
for f in test/manual/test-*.js; do node "$f" || echo "FALLÓ: $f"; done
```

Las pruebas no necesitan Nmap, Trivy ni Lynis instalados. Usan salidas reales capturadas en `test/fixtures/` o datos construidos para cada caso, así que son deterministas y se ejecutan en cualquier sistema. Algunas comprobaciones, como las de PowerShell, solo se ejecutan en Windows.

### Verificaciones del repositorio

```bash
node scripts/build-dashboards.js --check    # las plantillas coinciden con flows.json
node scripts/export-parity.js               # cableado y sincronía de los paneles
node scripts/validate-all.js                # validación de extremo a extremo de los tres paneles
```

`validate-all.js` arranca Node-RED y un navegador sin interfaz, lanza una auditoría real desde cada panel y comprueba el resultado, el informe exportado y el contraste de los textos (`contrast-audit.js`).

### Esquema de hallazgo

Todos los módulos producen objetos con la misma forma base:

```javascript
{
  id: "HOST-CVE-001",        // prefijo según el origen: HOST-, NET-, IMG-
  title: "...",              // descripción legible
  severity: "high",          // critical | high | medium | low | info
  evidence: "...",           // qué se ha encontrado exactamente
  fix: "...",                // pasos de resolución
  isCommand: true,           // si la resolución incluye un comando para copiar
  command: "...",            // el comando que copia el panel, o null
  category: "vulnerability",
  source: "trivy",
  timestamp: "...",
  // Campos opcionales según el módulo, por ejemplo:
  scope: "host",             // host | network | image
  origin: "installed",       // installed | declared (solo vulnerabilidades)
  skipped: false             // true en las comprobaciones no realizadas
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

LoCoAudit se distribuye bajo la licencia MIT. El texto completo está en el fichero [`LICENSE`](LICENSE).
