# Inventario de fixes estáticos — LoCoAudit

Mapa de los **pasos de resolución estáticos** (campo `fix` de un finding, generado por
código, sin intervención del LLM), con las sospechas clasificadas por categoría.

Fecha: 2026-07-21 · Rama `main` · **3ª pasada: 0 sospechosos.**
Las versiones anteriores (esquema 🟥/🟧/🟨 del commit `f9bc811`, y la 1ª pasada de este
mismo esquema) quedan en el historial de git.

## Qué cambió en esta pasada

| Cambio | Qué resuelve |
|---|---|
| **1. `platform` + gestor real a todos los generadores** (`lib/pkg-manager.js`, nuevo) | `[PLATAFORMA]` — ningún fix asume ya el SO ni el gestor. En Linux se detecta pacman/apt/dnf/zypper/apk/emerge con `commandExists`; en macOS brew/port; en Windows winget/choco/scoop. |
| **2. Trivy sin `Type` → prosa, nunca adivinar** | `[ECOSISTEMA]` — borradas la heurística por ruta (`/Cellar/`→brew) y el fallback por plataforma (linux→apt). Añadidos `arch`, `gentoo`, `azurelinux`… a `TRIVY_OS_TYPES`. |
| **3. Comando ≠ nota** (`finding.command` nuevo) | `[PROSA-COMO-COMANDO]` — `_isCmd` exige una sola línea sin prosa; `command` guarda solo la línea ejecutable y es lo único que copia el dashboard. |
| **4. Borrado de código muerto** | `PORT_CATALOG[*].fix` (35 textos) y las ramas `context==="image"` de `getTrivyFixCommand`. |
| **5. Aviso de elevación en el modal** | `[SUDO-SIN-AVISO]` — el aviso 🔒 ya no depende de `isCommand`: aparece siempre que el paso contenga `sudo`. Los 29 fixes no se tocan. |
| **6. `RDP_HARDEN_FIX` separa cerrar de filtrar** | `[FILTRAR≠CERRAR]` — misma regla que se aplicó en audit-network. |
| **7. Nada de identificadores de servicio supuestos** | `[OTRO]` — si el label de launchctl o la unidad de systemd no se pueden conocer con seguridad, el copiable pasa a ser el paso de AVERIGUACIÓN (solo lectura) y la acción va en prosa. |

`isCommand` / `command` los calcula `createFinding()` (`lib/finding-schema.js`):
`command` = primera línea del fix **si por sí sola** es un comando (una línea, sin prosa);
`isCommand` = `Boolean(command)`. La nota explicativa sigue en `fix`, fuera del portapapeles.

## Categorías de sospecha

| Etiqueta | Significado |
|---|---|
| `[ECOSISTEMA]` | Gestor de paquetes que no corresponde al tipo del paquete. |
| `[IMAGEN]` | Comando de host / "actualizar paquetes" en un finding de imagen Docker. |
| `[PLATAFORMA]` | Comando o ruta de un SO distinto al del finding. |
| `[FILTRAR≠CERRAR]` | Cortafuegos presentado como si cerrara el puerto. |
| `[SERVICIO-SISTEMA]` | Deshabilitar un servicio propio del SO sin explicar el impacto. |
| `[PROSA-COMO-COMANDO]` | `isCommand=true` con un texto que no es un comando ejecutable. |
| `[SUDO-SIN-AVISO]` | Usa `sudo`/elevación sin advertirlo. |
| `[OTRO]` | Nombre de unidad/servicio adivinado, código muerto, etc. |

---

## 1. audit-host — nativo, Lynis y eventos (`lib/normalizer.js`)

| # | Prefijo | Fuente | Fix | isCmd | Plataforma | Gestor | Sospechoso |
|---|---|---|---|---|---|---|---|
| 1 | `HOST-CPU-001` | `cpuInspectFix()` :91 | win32 → Administrador de tareas · darwin → Monitor de Actividad · linux → top/htop | no | **las 3, ramificado** | — | no *(antes `[PLATAFORMA]`)* |
| 2 | `HOST-MEM-001` | :166 | "Identificar procesos con alto consumo de RAM…" | no | ninguna | — | no |
| 3 | `HOST-DISK-nnn` | :193 | "Liberar espacio en `<mount>`…" | no | ninguna | — | no |
| 4 | `HOST-SW-DANGER-nnn` | `fromSwInventory()` :208 | `getFixForProcess(name, platform, pkgManager)` (§7) | según §7 | recibida | **real detectado** | no *(antes `[PLATAFORMA]`)* |
| 5 | *(retirado)* | — | `HOST-LYN-IDX` dejó de ser finding: el hardening index es una métrica y viaja en `scanMeta.lynis` | — | — | — | — |
| 6 | `HOST-LYN-<CTRL>-<hash>` | `getLynisFixText(id, platform, pkgManager)` | 15 prefijos × plataforma, aplicado ahora a **todos** los controles (antes solo a ≤5 avisos). Pasos: sugerencia → guía del SO → orden del campo 3 si la hay | sí, si el campo 3 trae `Run '<cmd>'` o el prefijo es PKGS | **ramificado** | real (PKGS) | no |
| 7 | *(retirado)* | — | `HOST-LYN-WARN-EXTRA`: el cajón de avisos sobrantes desaparece con un finding por entrada | — | — | — | — |
| 8 | *(retirado)* | — | `HOST-LYN-SUG`: las sugerencias ya no colapsan en una tarjeta que remitía a `lynis show suggestions` | — | — | — | — |
| 9 | `HOST-SEC-SKIP` | :431 | Acceso a logs en Linux / macOS / Windows | no | las 3 | — | no |
| 10 | `HOST-SEC-SRC` | :451 | "Revisar permisos de lectura de logs." | no | ninguna | — | no |
| 11 | `HOST-SEC-SSH-R-nnn` | `sshHardenFix(platform)` :475 | linux → sshd_config + fail2ban · darwin → sshd_config + Sesión remota · win32 → OpenSSH Server | no | **ramificado** | — | no *(antes `[PLATAFORMA]`)* |
| 12 | `HOST-SEC-SSH-nnn` | :569 | "Revisar sshd_config y authorized_keys." | no | Unix | — | no |
| 13 | `HOST-SEC-SSHF-001` | :611 | `sshHardenFix(platform)` | no | **ramificado** | — | no *(antes `[PLATAFORMA]`)* |
| 14 | `HOST-SEC-SUDOF-001` | :645 | "Verificar qué usuario falla… visudo…" | no | Unix | visudo | no |
| 15 | `HOST-SEC-SES-nnn` | :663 | "Ciérrala manualmente…" | no | Unix | — | no |
| 16 | `HOST-SEC-WIN-PERM` | :731 | "Ejecuta Node-RED como administrador." | no | win32 | — | no |
| 17 | `HOST-SEC-WIN-RDP-nnn` | `RDP_HARDEN_FIX` :710 | 1) CERRAR: desactivar Escritorio remoto · 2) si se necesita: NLA + contraseñas · nota: el firewall solo FILTRA | no | win32 | — | no *(antes `[FILTRAR≠CERRAR]`)* |
| 18 | `HOST-SEC-WINF-001` | :802 | `RDP_HARDEN_FIX` | no | win32 | — | no *(ídem)* |
| 19 | `HOST-SEC-WIN-PRIV-nnn` | :821 | prosa + `RDP_HARDEN_FIX` | no | win32 | — | no *(ídem)* |
| 20 | `HOST-SEC-WIN-UAC` | :855 | `auditpol /set /subcategory:…` | no | win32 | auditpol | no |
| 21 | `HOST-SEC-SES-nnn` (win) | :876 | "Ciérrala desde el Administrador de tareas…" | no | win32 | — | no |

`fix: null` (informativos): `HOST-MEM-INF`, `HOST-SW-001`, `HOST-SEC-SSH-EXTRA`,
`HOST-SEC-SUDO-001`, `HOST-SEC-INF`, `HOST-SEC-WIN-RDP-EXTRA`, `HOST-SEC-WIN-LOC`,
`HOST-SEC-WIN-PRIVL`, `HOST-SEC-SES-LOC` → **9**.

---

## 2. CVEs de Trivy — host (`getTrivyFixCommand` :1008)

Regla nueva: **el ecosistema sale del campo `Type` de Trivy o no sale.** Sin `Type` no se
adivina — se emite prosa con `isCommand=false`.

| # | Prefijo | Rama | Fix | isCmd | Gestor | Sospechoso |
|---|---|---|---|---|---|---|
| 22 | `HOST-CVE-nnn` | Type de SO (`osHostUpdateCmd` :979) | `managerForTrivyType(Type)` → pacman · apt · dnf · zypper · apk · emerge; si el Type no se reconoce, el gestor **realmente detectado** | sí | real | no *(antes `[ECOSISTEMA]`: faltaban Arch y Gentoo)* |
| 23 | `HOST-CVE-nnn` | Type de lenguaje | `cargo update -p` · `npm update` · `pnpm` · `yarn` · `pip install --upgrade` · `poetry` · `go get -u` · `bundle` · `composer` | sí | el del ecosistema | no |
| 24 | `HOST-CVE-nnn` | Type sin comando fiable (jar, pom, nuget, conan, cocoapods, hex, cran…) | prosa | no | — | no |
| 25 | `HOST-CVE-nnn` | Binario Go (`gobinary` o path de módulo) | "actualiza la herramienta que lo incluye con `<gestor real>`" | no | real | no *(antes `[PLATAFORMA]`: asumía brew)* |
| 26 | `HOST-CVE-nnn` | Type presente no mapeado | "Actualiza `<pkg>` con el gestor de `<type>`" | no | — | no |
| 27 | `HOST-CVE-nnn` | **Sin Type** | "Trivy no ha indicado a qué ecosistema pertenece…; comprueba de dónde viene y usa su propio gestor" | **no** | — | no *(antes `[ECOSISTEMA]`: heurística por ruta + fallback por plataforma — **borradas**)* |
| 28 | `HOST-CVE-nnn` | sin FixedVersion | "No hay versión corregida aún… monitorizar" | no | — | no |
| 29 | `HOST-CVE-MED-nnn` | :1297 | "Actualizar los paquetes afectados en `<target>`" | no | — | no |
| 30 | `HOST-CVE-LOW` | :1323 | "Revisar y actualizar paquetes cuando sea posible" | no | — | no |

---

## 3. CVEs de Trivy — imagen (`IMG-CVE-*`)

| # | Prefijo | Fuente | Fix | isCmd | Sospechoso |
|---|---|---|---|---|---|
| 31 | `IMG-CVE-nnn` (crit/high) | `buildImageFix()` :1121 | tag corregido → base más pequeña/mantenida → esperar parche → rebuild propio | **no** (forzado) | no |
| 32 | `IMG-CVE-MED-nnn` | :1297 | `buildImageFix()` | **no** | no |
| 33 | `IMG-CVE-LOW` | :1323 | `buildImageFix()` | **no** | no |

*(Las ramas `context === "image"` de `getTrivyFixCommand` — inalcanzables — se han **borrado**.)*

---

## 4. audit-image — nodo y configuración

| # | Prefijo | Fuente | Fix | isCmd | Sospechoso |
|---|---|---|---|---|---|
| 34 | `IMG-IMAGE-NONE` | audit-image.js:180 | "Indica una imagen en el nodo…" | no | no |
| 35 | `IMG-TRIVY-OFF` | :205 | "Instalar Trivy: https://trivy.dev/…" | no | no |
| 36 | `IMG-SCAN-ERR-nnn` | :243 | "Consulta el detalle del error arriba…" | no | no |
| 37 | `IMG-DOCKER-OFF` | :289 | "Instalar Docker Desktop…" | no | no |
| 38 | `IMG-CFG-001` | config-audit.js:129 | "Añadir `USER <usuario>` no root en el Dockerfile." | no | no |
| 39 | `IMG-CFG-002` | :143 | "Usar Docker secrets…" | no | no |
| 40 | `IMG-CFG-003` | :151-161 | "`-p 127.0.0.1:<puerto>:<puerto>`…" | no | no |
| 41 | `IMG-CFG-004` | :179 | "Evitar montar docker.sock…" | no | no |

---

## 5. audit-network — findings del nodo

| # | Prefijo | Fuente | Fix | isCmd | Sospechoso |
|---|---|---|---|---|---|
| 42 | `NET-PORTS-BAD` | audit-network.js:87 | "Configura los puertos en el nodo…" | no | no |
| 43 | `NET-SCAN-WARN` (timeout) | :198 | "Reintenta con el modo Completo…" | no | no |
| 44 | `NET-SCAN-WARN` (host down) | :210 | "Prueba el modo Completo." | no | no |
| 45 | `NET-PORT-INF` | normalizer.js:1637 | `null` | — | no |

---

## 6. audit-network — fixes de puerto (`buildPortFix` :1386)

Corregidos en la ronda anterior: el fix estático propone **una sola acción fiable**
(cerrar el puerto parando el servicio, siempre condicional). El cortafuegos vive en el
prompt del LLM; el detectado va a la evidencia.

| # | Caso | Fix | isCmd | Sospechoso |
|---|---|---|---|---|
| 46 | Terceros, expuesto | lsof/netstat + parada condicional (con `.socket` en Linux) | no | no |
| 47 | Servicio del SO (`SYSTEM_SERVICES`) | Qué es + vía soportada del SO + aviso de impacto | no | no |
| 48 | Bind en loopback | "No expuesto a la red, no hay nada que cerrar" | no | no |
| 49 | Target remoto | "Actúa en ese dispositivo" | no | no |
| 50 | Proceso desconocido | Identificación + guía de parada por SO | no | no |
| 51 | `getFixForPort()` — 22, 21, 23, 80/443, 3306, 5432, 6379, 27017 | Notas por puerto, por plataforma (`default` → `null`) | varía | no |

*(`PORT_CATALOG[*].fix` — 35 textos muertos — **borrado**: ni `port-scanner.js` ni
`nmap-wrapper.js` lo leían; solo usaban `service` y `severity`.)*

---

## 7. `lib/process-fix.js` — catálogo compartido

| # | Familia | Fix (Linux / macOS / Windows) | isCmd | Sospechoso |
|---|---|---|---|---|
| 52 | `sshd`, `ssh` | `systemctl disable --now ssh.*` / `systemsetup -setremotelogin off` / services.msc | sí | no |
| 53 | `vsftpd`, `ftpd`, `ftp`, `proftpd`, `pure-ftpd` | `systemctl disable --now …` / **`launchctl list \| grep -i ftp`** + acción en prosa / Características de Windows | sí (solo el listado) | no *(antes `[OTRO]`: label `system/ftp` supuesto)* |
| 54 | `telnetd` | `systemctl disable --now telnet.*` + nota con el gestor real / **`launchctl list \| grep -i telnet`** + acción en prosa / Panel de control | sí (solo el listado) | no *(antes `[OTRO]`)* |
| 55 | `mysqld`/`mariadb*`, `postgres*`, `redis*`, `mongo*` | rebind a 127.0.0.1 + autenticación | no | no |
| 56 | `nginx`, `apache*`, `httpd` | parada del servicio por SO | sí (parcial) | no |
| 57 | `node`, `python`, `ruby`, `java` | "Escucha en 127.0.0.1, no en 0.0.0.0" | no | no |
| 58 | `vnc`, `rdp` | **`systemctl list-units --type=service \| grep -i vnc`** + acción en prosa / `xrdp.*` / Ajustes | sí (solo el listado) | no *(antes `[OTRO]`: unidad `vncserver` supuesta)* |
| 59 | `smbd`, `samba` | parada del servicio por SO | sí | no |
| 60 | `elasticsearch`, `rabbitmq`, `registry`, `jupyter` | rebind / autenticación / TLS | **no** | no *(antes `[PROSA-COMO-COMANDO]` en jupyter)* |
| 61 | `cupsd`, `cups` | `systemctl disable --now cups.*` + nota `.path` en línea aparte | sí (solo el comando) | no *(antes `[PROSA-COMO-COMANDO]`)* |
| 62 | `removeFix()` — telnet, rsh-*, rlogin, tftpd*, nis, yp-tools, talk, ntalk | `removeCmd(gestor real, pkg)` + nota en línea aparte | sí (solo el comando) | no *(antes `[PLATAFORMA]` + `[PROSA-COMO-COMANDO]`)* |
| 63 | `SYSTEM_SERVICES` (12 fichas) | Qué es + vía soportada + impacto | no | no |
| 64 | Global | `sudo` presente en muchas variantes | — | no *(cubierto por el aviso 🔒 del modal)* |

---

## 8. RESUMEN

### Totales

| Métrica | Antes | Ahora |
|---|---|---|
| Sitios que generan fix estático | 72 | **64** (−8: código muerto borrado y ramas fusionadas) |
| Findings informativos con `fix: null` | 10 | 10 |
| **Filas sospechosas** | **17** | **0** |

### Conteo por categoría

| Categoría | Antes | Ahora | Qué lo resolvió |
|---|---|---|---|
| `[PLATAFORMA]` | 7 | **0** | Cambio 1: `platform` + gestor real en todos los generadores |
| `[PROSA-COMO-COMANDO]` | 4 | **0** | Cambio 3: `command` separado de la nota; `_isCmd` de una línea |
| `[FILTRAR≠CERRAR]` | 4 | **0** | `RDP_HARDEN_FIX` reescrito + borrado del catálogo muerto |
| `[OTRO]` | 4 | **0** | Cambio 7: paso de averiguación copiable + acción en prosa |
| `[ECOSISTEMA]` | 3 | **0** | Cambio 2: sin `Type` no se adivina; +arch/gentoo |
| `[SUDO-SIN-AVISO]` | 1 | **0** | Aviso 🔒 genérico en el modal, sin tocar los 29 fixes |
| `[SERVICIO-SISTEMA]` | 1 | **0** | Muere con el catálogo muerto |
| `[IMAGEN]` | 0 | **0** | Ya resuelto (`buildImageFix`) |

### Sin sospechosos pendientes

Los 3 casos que quedaban (`launchctl disable system/ftp`, `system/telnet` y
`systemctl disable --now vncserver.service`) compartían el mismo defecto: un identificador
de servicio **supuesto**. Resueltos con la misma regla que ya se aplica en Trivy y en red —
*si no se puede conocer con seguridad, no se emite un comando que falla*:

| Caso | Copiable ahora (solo lectura) | Acción |
|---|---|---|
| FTP en macOS | `launchctl list \| grep -i ftp` | prosa: deshabilitar el label REAL que devuelva |
| Telnet en macOS | `launchctl list \| grep -i telnet` | prosa: ídem |
| VNC en Linux | `systemctl list-units --type=service \| grep -i vnc` | prosa: `systemctl disable --now <unidad>` con la unidad real |

El paso de averiguación sí es copiable porque es una línea inofensiva de solo lectura:
no falla ni destruye nada. Lo que ya no se ofrece como comando es el `disable` con un
nombre inventado. El mismo texto se reutiliza desde `network-utils.js` (puertos 21 y 23),
que antes duplicaba los labels supuestos.

Observación (no contabilizada): los fixes de rebind de bases de datos (fila 55) citan rutas
de Debian (`/etc/mysql/mysql.conf.d/`), distintas en Arch o RHEL. Es prosa de configuración,
no un comando, así que no rompe nada al ejecutarse.
