# Inventario de fixes estáticos de LoCoAudit

> Generado en la auditoría de calidad de correcciones (Tarea G).
> **No modifica código.** Es una foto de TODOS los `fix` que emiten los normalizadores/módulos.
>
> `isCommand` = valor que calcula `createFinding` vía `_isCmd(fix)` en `lib/finding-schema.js`.
> `_isCmd` es **ancla-inicio**: sólo es `true` si el texto **empieza** por
> `brew|sudo|npm|yarn|pip|composer|go|apt|dnf|yum|winget|choco|lsof|nslookup|kill|systemctl|launchctl` (+`\s`).
> Prosa que *contenga* un comando en medio → `isCommand=false`.
>
> Marcas de sospecha (PASO 2):
> - 🟥 **P1** — image sugiere comando de gestor de paquetes del host / comando en plataforma equivocada.
> - 🟧 **P2** — comando real que NO se marca `isCommand` (falso negativo → sin botón copiar) o comando con `sudo` sin aviso.
> - 🟨 **P3** — fix genérico poco accionable.

---

## HOST — módulo `cpu-memory` (`fromCpuMemory`)

| ID | Plataforma | fix | isCommand | Comando literal | Sospecha |
|---|---|---|---|---|---|
| HOST-CPU-001 | todas | `Revisar procesos con alto consumo con top/htop.` (sólo si sev≠info; si no, `null`) | false | — | — |
| HOST-MEM-INF | darwin | `null` | false | — | — |
| HOST-MEM-001 | linux/win32 | `Identificar procesos con alto consumo de RAM. Considerar ampliar memoria.` (sólo si sev≠info) | false | — | — |

## HOST — módulo `disk-storage` (`fromDisk`)

| ID | Plataforma | fix | isCommand | Comando literal | Sospecha |
|---|---|---|---|---|---|
| HOST-DISK-NNN | todas | `Liberar espacio en <mount>. Eliminar ficheros temporales o ampliar volumen.` (sólo si sev≠info) | false | — | — |

## HOST — módulo `sw-inventory` (`fromSwInventory`)

| ID | Plataforma | fix | isCommand | Comando literal | Sospecha |
|---|---|---|---|---|---|
| HOST-SW-001 | todas | `null` (info) | false | — | — |
| HOST-SW-DANGER-NNN | todas | `getFixForProcess(name, platform)` — ver tabla process-fix; o fallback `Desinstala <name> si no lo necesitas activamente.` | según fix | ver process-fix | 🟧 los servicios de `DANGEROUS_SERVICES` sin entrada en `FIXES` (telnet, rsh-server, rsh-client, rlogin, tftpd, tftpd-hpa, nis, yp-tools, talk, ntalk) caen siempre al fallback `Desinstala X` — nunca dan comando |

## HOST — módulo `lynis` (`fromLynisRaw` + `getLynisFixText`)

| ID | Plataforma | fix | isCommand | Comando literal | Sospecha |
|---|---|---|---|---|---|
| HOST-LYN-IDX | todas | `Revisar las advertencias y sugerencias de Lynis para mejorar el hardening.` (o `null` si info) | false | — | — |
| HOST-LYN-NNN | todas | `getLynisFixText(id)` → prosa por prefijo (NETW/SSH/FIRE/AUTH/KRNL/PKGS/LOGG/TIME/CRYP/MAIL/USB/BANN/ACCT/STRG/TOOL) | false | — | 🟨 el fallback `Revisar la configuración del sistema relacionada con <id>.` es genérico |
| HOST-LYN-WARN-EXTRA | todas | `Ejecutar 'lynis show warnings'…` (+nota nslookup si hay NETW) | false | `lynis show warnings` (entre comillas, no ejecutable) | 🟨 genérico |
| HOST-LYN-SUG | todas | `Consultar 'lynis show suggestions' para el detalle.` | false | — | 🟨 genérico |

### `getLynisFixText` — textos por prefijo (todos prosa, isCommand=false)

| Prefijo | Texto |
|---|---|
| NETW | Verificar la configuración de red… (incluye `nslookup google.com` como comprobación de falso positivo) |
| SSH | Revisar la configuración de SSH en /etc/ssh/sshd_config… |
| FIRE | Activar el firewall… |
| AUTH | Revisar la política de contraseñas… |
| KRNL | Revisar los parámetros del kernel (sysctl)… |
| PKGS | `Actualizar paquetes del sistema con el gestor de paquetes correspondiente.` |
| LOGG | Revisar la configuración del sistema de logs en /etc/rsyslog.conf… |
| TIME | Configurar sincronización NTP… |
| CRYP/MAIL/USB/BANN/ACCT/STRG/TOOL | prosa de revisión |
| (fallback) | `Revisar la configuración del sistema relacionada con <id>.` 🟨 |

## HOST — módulo `security-events` (`fromSecurityEvents` / `fromSecurityEventsWin32`)

| ID | Plataforma | fix | isCommand | Sospecha |
|---|---|---|---|---|
| HOST-SEC-SKIP | todas | prosa: cómo dar permiso de lectura de logs | false | — |
| HOST-SEC-SRC | todas | prosa | false | — |
| HOST-SEC-SSH-R-NNN | unix | `SSH_HARDEN_FIX` (prosa: revisar sshd_config, fail2ban, macOS Sesión remota) | false | — |
| HOST-SEC-SSH-NNN | unix | prosa: revisar sshd_config y authorized_keys | false | — |
| HOST-SEC-SSH-EXTRA | unix | `null` | false | — |
| HOST-SEC-SSHF-001 | unix | `SSH_HARDEN_FIX` | false | — |
| HOST-SEC-SUDO-001 | unix | `null` | false | — |
| HOST-SEC-SUDOF-001 | unix | prosa: verificar usuario, visudo | false | — |
| HOST-SEC-SES-NNN | unix | prosa: cerrar sesión manualmente | false | — |
| HOST-SEC-INF | todas | `null` | false | — |
| HOST-SEC-WIN-PERM | win32 | `Para auditar… ejecuta Node-RED como administrador.` | false | — |
| HOST-SEC-WIN-RDP-NNN | win32 | prosa + `RDP_HARDEN_FIX` | false | — |
| HOST-SEC-WIN-RDP-EXTRA | win32 | `null` | false | — |
| HOST-SEC-WIN-LOC | win32 | `null` | false | — |
| HOST-SEC-WINF-001 | win32 | `RDP_HARDEN_FIX` (prosa) | false | — |
| HOST-SEC-WIN-PRIV-NNN | win32 | prosa + `RDP_HARDEN_FIX` | false | — |
| HOST-SEC-WIN-PRIVL | win32 | `null` | false | — |
| HOST-SEC-WIN-UAC | win32 | prosa + `auditpol /set /subcategory:"Creación del proceso" …` | false | 🟧 comando real `auditpol …` embebido en prosa → no se ofrece como copiable; además es dependiente del idioma de Windows |
| HOST-SEC-SES-NNN (win) | win32 | prosa: cerrar desde Administrador de tareas | false | — |
| HOST-SEC-SES-LOC | win32 | `null` | false | — |

## HOST — módulo `trivy-fs` (`fromTrivyJson` con idPrefix `HOST-CVE`, context `host`)

Ver tabla común **CVE / Trivy** más abajo (misma función `getTrivyFixCommand`, context=`host`).

---

## NETWORK — `port-scanner` + `network-utils.getFixForPort` + `process-fix`

`fromPortScanner`/`fromNmap` asignan `fix = processFix || p.fix`, donde
`processFix = getFixForProcess(process, platform)` (si hay proceso conocido) y
`p.fix = getFixForPort(port, platform)`.
**Nota:** el campo `fix` del `PORT_CATALOG` en `port-scanner.js` está **efectivamente muerto**: la línea 273 sobrescribe con `getFixForPort(port)`. Los textos del catálogo (líneas 86-128) no llegan al finding.

### `getFixForPort(port, platform)`

| Puerto | darwin | linux | win32 | isCommand (darwin/linux/win32) | Sospecha |
|---|---|---|---|---|---|
| 22 SSH | `Para deshabilitar: sudo systemsetup…` (prosa multilínea) | `Para deshabilitar: sudo systemctl…` | prosa services.msc | false / false / false | 🟧 contiene `sudo` sin marcarse comando (empieza por "Para") |
| 21 FTP | `sudo launchctl disable system/ftp` | `sudo systemctl stop vsftpd && sudo systemctl disable vsftpd` | prosa | **true** / **true** / false | ✔ comandos con `sudo` → deben mostrar aviso sudo |
| 23 Telnet | `sudo launchctl disable system/telnet` | `sudo systemctl stop telnet && sudo apt remove telnetd` | prosa | **true** / **true** / false | ✔ |
| 80/443 | `Si no necesitas…: sudo systemctl stop nginx…` | idem | `Si no necesitas…: net stop w3svc…` | false / false / false | 🟧 `sudo`/`net stop` embebidos, no copiables |
| 3306 MySQL | `Limita acceso: edita…` | idem | prosa | false | — |
| 5432 Postgres | `Limita acceso: edita…` | idem | prosa | false | — |
| 6379 Redis | `Edita /etc/redis…` | idem | prosa | false | — |
| 27017 Mongo | `Edita /etc/mongod.conf…` | idem | prosa | false | — |
| default | `Identifica el proceso: sudo lsof -i :<port>…` | `…sudo lsof…` / `sudo ufw deny <port>` | `netstat -ano | findstr…` / `netsh advfirewall…` | false | 🟧 comandos (`lsof`, `ufw`, `netsh`) embebidos en prosa, no copiables |

### `process-fix.getFixForProcess(name, platform)` (compartida host-sw / network / image)

| Servicio | darwin | linux | win32 | isCommand (d/l/w) | Sospecha |
|---|---|---|---|---|---|
| sshd | `sudo systemsetup -setremotelogin off` | `sudo systemctl stop ssh && sudo systemctl disable ssh` | prosa services.msc | **true**/**true**/false | ✔ sudo |
| vsftpd/ftpd | `sudo launchctl disable system/ftp` | `sudo systemctl stop vsftpd…` | prosa | **true**/**true**/false | ✔ |
| proftpd/pure-ftpd | (delega vsftpd) | `sudo systemctl stop proftpd…` | prosa | true/true/false | ✔ |
| telnetd | `sudo launchctl disable system/telnet` | `sudo systemctl stop telnet && sudo apt remove telnetd` | prosa | true/true/false | ✔ |
| mysqld/mysql | `Limita acceso: edita…` | idem | prosa | false | — |
| mariadbd/mariadb | `Limita acceso: edita…` | idem | prosa | false | — |
| postgres(ql) | `Edita postgresql.conf…` | idem | prosa | false | — |
| redis(-server) | `Edita /etc/redis…` | idem | prosa | false | — |
| mongod(b)/mongo | `Edita /etc/mongod.conf…` | idem | prosa | false | — |
| nginx | `Si no necesitas nginx: sudo systemctl stop nginx…` | idem | `Si no necesitas nginx: nginx -s stop…` | false | 🟧 sudo embebido |
| apache/apache2/httpd | `sudo apachectl stop && sudo launchctl disable …` | `sudo systemctl stop apache2 && sudo systemctl disable apache2` | `net stop Apache2.4` | **true**/**true**/**false** | 🟧 win32 `net stop Apache2.4` es comando real pero NO se marca (net∉patrones) |
| node/python/ruby/java | prosa (bind 127.0.0.1) | idem | idem | false | — |
| smbd/samba | `sudo launchctl disable system/smbd` | `sudo systemctl stop smbd…` | prosa | true/true/false | ✔ |
| elasticsearch | `Limita Elasticsearch…: edita elasticsearch.yml…` | idem | idem | false | — |
| rabbitmq | `Limita RabbitMQ: edita rabbitmq.conf…` | idem | `Limita RabbitMQ: rabbitmqctl…` | false | 🟧 `rabbitmqctl…` real embebido, no copiable |
| registry | prosa (TLS) | idem | idem | false | — |
| jupyter | `Jupyter expuesto…: jupyter notebook password…` | idem | idem | false | 🟧 `jupyter …` real embebido, no copiable |

### Catálogo de puertos (líneas 86-128 de `port-scanner.js`) — **fix muerto** (no llega al finding)

Textos prosa (`Desactiva…`, `Restringe…`, `Si…`, `Este puerto…`, `Comprueba…`, `API Docker…`, `Panel…`). isCommand irrelevante (no se usan). 🟨 código muerto a limpiar.

---

## IMAGE — `config-audit` (`auditContainer`)

| ID | fix | isCommand | Sospecha |
|---|---|---|---|
| IMG-CFG-001 (root) | `Añadir USER <usuario> no root en el Dockerfile.` | false | — |
| IMG-CFG-002 (env sensibles) | `Usar Docker secrets o variables de entorno en tiempo de ejecución…` | false | — |
| IMG-CFG-003 (0.0.0.0) | `Limitar el binding a 127.0.0.1: -p 127.0.0.1:<puerto>:<puerto>.` (+`imageFix` de `getFixForProcess(image)` si existe) | false | 🟥 el `imageFix` anexado usa fixes de **host** (p.ej. mysql → `edita /etc/mysql/…`, systemctl) para un **contenedor** → rutas/servicios del host, no del contenedor |
| IMG-CFG-004 (docker.sock) | `Evitar montar docker.sock salvo en herramientas de CI/CD…` | false | — |

## IMAGE — `trivy image` (`fromTrivyJson` con idPrefix `IMG-CVE`, context `image`)

Ver tabla común **CVE / Trivy** (context=`image`).

---

## CVE / Trivy — `getTrivyFixCommand(target, pkg, fixedVersion, process.platform, context)`

**Importante:** `platform` que recibe es `process.platform` = **el host que corre Node-RED**, NO el sistema de la imagen escaneada.

| Caso (prioridad) | Rama | fix | isCommand | Sospecha |
|---|---|---|---|---|
| 0. Módulo Go (`github.com/…`) · image | prosa | `…actualizar la imagen base… y reconstruir.` | false | — |
| 0. Módulo Go · host | prosa | `…brew upgrade <herramienta>… o esperar…` | false | — |
| 0b. context=image + target **sin** `/` (OS layer) | prosa | `…actualizar la imagen base (FROM …) en el Dockerfile y reconstruir.` | false | — |
| 1. target `/Cellar/` o `/homebrew/lib/` | cmd | `brew upgrade <pkg>` | **true** | 🟥 si context=image y el target de app empieza por `/` cae aquí → `brew upgrade` para una imagen |
| 1. target `node_modules`/`yarn.lock`/`package-lock.json` | cmd | `npm update <pkg>` | **true** | 🟥 image + `/app/package-lock.json` → `npm update` del host, no arregla la imagen |
| 1. `composer.*` | cmd | `composer update <pkg>` | **true** | 🟥 idem image |
| 1. `go.mod/go.sum` | cmd | `go get -u <pkg>@<ver>` | **true** | 🟥 idem image |
| 1. `requirements.txt`/`Pipfile` | cmd | `pip install --upgrade <pkg>[==ver]` | **true** | 🟥 idem image |
| 1. `Gemfile(.lock)` | cmd | `bundle update <pkg>` | **false** | 🟧 comando real pero `bundle`∉patrones → sin botón; 🟥 idem image |
| 1. `Cargo.toml` | cmd | `cargo update <pkg>` | **false** | 🟧 `cargo`∉patrones → sin botón; 🟥 idem image |
| 1. `pom.xml`/`build.gradle` | prosa | `Actualizar <pkg> a la versión <ver> en tu fichero…` | false | — |
| 2. fallback darwin | cmd | `brew upgrade <pkg>` | **true** | 🟥 se dispara para image si target-path no casó ningún patrón |
| 2. fallback linux (rpm) | cmd | `sudo dnf update <pkg>` | **true** | 🟥 idem image · ✔ sudo |
| 2. fallback linux (apt) | cmd | `sudo apt update && sudo apt install --only-upgrade <pkg>` | **true** | 🟥 idem image · ✔ sudo |
| 2. fallback win32 | cmd | `winget upgrade <pkg>\n(o … choco upgrade <pkg>)` | **true** | 🟥 idem image |
| — sin FixedVersion | prosa | `No hay versión corregida disponible aún para <pkg>. Monitorizar actualizaciones…` | false | 🟨 |
| — medium (resumen) | prosa | `Actualizar los paquetes afectados en <label>` | false | 🟨 genérico |
| — low/info (resumen) | prosa | `Revisar y actualizar paquetes cuando sea posible` | false | 🟨 genérico |

---

## Observaciones transversales

1. **Doble definición de "¿es comando?"** — `lib/finding-schema.js::_isCmd` (fija `isCommand`) y
   `lib/normalizer.js::isExecutableCommand` **no coinciden**: la segunda incluye `netsh` y `net stop`, la primera no.
   Ninguna incluye `bundle`, `cargo`, `rabbitmqctl`, `jupyter`, `auditpol`, `nginx`, `net`. Fuente de los 🟧 "comando real sin botón".
2. **`_isCmd` es ancla-inicio** → cualquier fix que empiece por prosa ("Si no necesitas…: sudo …", "Para deshabilitar: sudo …", "Limita acceso: edita…") nunca es `isCommand`, aunque contenga un comando perfectamente ejecutable. Es conservador (evita falsos positivos) pero deja comandos útiles sin botón copiar.
3. **CVE de imagen (🟥 P1, el más serio)** — `getTrivyFixCommand` sólo redirige a "actualizar imagen base" cuando el target **no** empieza por `/`. Los CVE de dependencias de aplicación dentro de la imagen (`/app/package-lock.json`, `/app/go.mod`, `/src/requirements.txt`, `/Gemfile.lock`…) caen en las reglas por-path o en el fallback por-plataforma → emiten `npm update`/`pip install`/`brew upgrade`/`sudo apt`/`winget` como si se ejecutaran en el host. Ninguno arregla la vulnerabilidad dentro de la imagen (haría falta editar el manifiesto de dependencias y **reconstruir**).
4. **`process.platform` en CVE de imagen** — el fallback por plataforma usa el SO del host, no el de la imagen; un host macOS escaneando una imagen Linux podría sugerir `brew upgrade`.
5. **`getFixForProcess` reutilizada en imagen** (IMG-CFG-003) mezcla remediación de host (systemctl, /etc/…) en el contexto de un contenedor.
6. **Catálogo de puertos con `fix` muerto** en `port-scanner.js` (sobreescrito por `getFixForPort`).

---

## PASO 3 — Informe

- **Fixes distintos catalogados:** ~70 ramas de texto (contando variantes por plataforma de `process-fix`, `getFixForPort`, `getTrivyFixCommand`, security-events, lynis, config-audit).
- **Con comando real ejecutable (independiente de que se marque `isCommand`):** ~30
  (process-fix sshd/ftp/telnet/apache/smbd darwin+linux; getFixForPort 21/23 darwin+linux + default lsof/ufw/netsh; CVE brew/npm/composer/go/pip/bundle/cargo/dnf/apt/winget; auditpol; net stop; rabbitmqctl; jupyter).
- **Marcados `isCommand=true` por `createFinding`:** ~18 (los que empiezan literalmente por un patrón).
- **Sospechosos:**
  - 🟥 **P1 (image → comando de host):** las 8 ramas por-path + 4 fallback de `getTrivyFixCommand` cuando `context=image` y target empieza por `/`; + `imageFix` de host anexado en IMG-CFG-003. **Es el problema de corrección más grave.**
  - 🟧 **P2 (comando real sin botón / sudo sin aviso):** `bundle update`, `cargo update`, `net stop Apache2.4`, `rabbitmqctl…`, `jupyter…`, `auditpol…` (falsos negativos de `_isCmd`); `getFixForPort` 22/80/443/default y `nginx` con `sudo`/`ufw`/`netsh` embebidos en prosa. ~10 casos.
  - 🟨 **P3 (genéricos poco accionables):** `HOST-LYN-SUG`, `HOST-LYN-WARN-EXTRA`, fallback `getLynisFixText`, CVE medium/low/sin-fixedVersion. ~5 casos.
  - 🟧 servicios en `DANGEROUS_SERVICES` sin entrada en `FIXES` (10) → siempre fallback `Desinstala X`.

> **Sin cambios de código.** Pendiente revisar la tabla caso por caso y decidir correcciones.
