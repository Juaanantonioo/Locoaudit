# HANDOFF — deuda conocida y decisiones aplazadas

Cosas detectadas durante un trabajo y dejadas fuera de su alcance a propósito.
No son bugs desconocidos: están localizados, razonados y esperando su turno.

---

## 1. ~~El gate de Lynis es fatal incondicional~~ — RESUELTO

**Fichero:** `nodes/audit-host/audit-host.js` (bloque `if (enableLynis && lynis && lynis.skipped)`)

Mismo defecto de diseño que tenía el gate de Trivy antes de la corrección de
`kind`: **cualquier** `lynis.skipped` aborta la auditoría con `done(err)` antes
del `send(msg)`, así que el dashboard no recibe payload y se queda enseñando la
ejecución anterior.

Trivy ya distingue tres naturalezas (`nodes/audit-host/modules/trivy-fs.js`):

| `kind` | Significado | ¿Fatal? |
|---|---|---|
| `not-installed` | falta la herramienta | sí |
| `unsupported` | esta plataforma/gestor no se puede analizar | **no** |
| `error` | el escaneo se intentó y se rompió | sí |

Lynis necesita lo mismo. El caso `unsupported` existe y está documentado en
`CLAUDE.md`: **Lynis no funciona en Windows sin WSL**. Hoy, si alguien deja el
módulo activado en Windows, no obtiene "Lynis no aplica en esta plataforma" —
obtiene una auditoría abortada.

**Resuelto en la reestructuración de Lynis.** `lynis.js` declara ahora cuatro
naturalezas —`unsupported`, `not-installed`, `timeout`, `error`— y el gate de
`audit-host.js` discrimina por `kind`, nunca por el texto de `reason`. El caso
`unsupported` hubo que **crearlo**: no bastaba con etiquetar las formas que ya
existían, porque en Windows nativo el módulo caía en `commandExists` y reportaba
"no instalado". La comprobación de plataforma va ahora antes que la de
instalación. Fijado en `test/manual/test-lynis-skip-kind.js`.

Se corrigió además una asimetría que no estaba en esta nota: un `throw` de
`runLynis()` dejaba `lynis` a `null` y la auditoría **continuaba**, mientras que
un `skipped` limpio la abortaba. Un fallo es un fallo llegue como llegue; ahora
un `rejected` se trata como `kind: 'error'` en el mismo punto.

Aparecieron dos cosas más al reestructurar, que se dejan anotadas:

- **`lynisIndexSeverity()` ya no existe.** Con el hardening index convertido en
  métrica de cabecera (`scanMeta.lynis`) en vez de finding, desaparece el único
  sitio donde un índice bajo metía un `high` en el riesgo global sin
  corresponder a ningún defecto concreto que el usuario pudiera arreglar. Lo que
  hay que hacer sigue estando en los avisos y sugerencias, cada uno con su
  severidad. El gauge del dashboard lee `scanMeta` y conserva la búsqueda de
  `HOST-LYN-IDX` solo como respaldo para payloads viejos.

- **`primaryUrl` no tenía emisor.** El `ui_template` de host ya pintaba la celda
  "🔗 Advisory" leyendo `f.primaryUrl`, pero ningún módulo lo producía: siempre
  decía "no disponible". El campo 4 del `.dat` de Lynis (`url:…`) es su primer
  emisor real. Si algún día Trivy debe rellenarlo, el campo ya está aceptado en
  `createFinding()`.

---

## 2. `scope` no se sella en los findings sueltos de audit-image

**Fichero:** `nodes/audit-image/audit-image.js`

`normalizeImage()` sella `scope: 'image'` en todo lo que pasa por él, pero el
nodo construye algunos findings directamente con `createFinding()` sin pasar por
el normalizador: `IMG-IMAGE-NONE`, `IMG-TRIVY-OFF`, `IMG-DOCKER-OFF`,
`IMG-SCAN-ERR-*` y los de `config-audit`. Esos llegan sin `scope`.

**Impacto real hoy: ninguno.** Todos son `severity: 'info'` y ninguno lleva
`origin`, así que `isActionable()` (`lib/severity-map.js`) los clasifica igual
con `scope` que sin él, y el riesgo global no cambia. Lo único que queda
descuadrado es el reparto `summary.host` / `summary.image`, que **no lo consume
ningún dashboard** (verificado en los tres `ui_template` y en
`lib/snapshot-body.txt`).

**Cuándo tocarlo:** cuando algo empiece a leer `summary.image`. La corrección es
exportar `sealScope` desde `lib/normalizer.js` y aplicarlo en los puntos donde
`audit-image.js` construye `msg.payload` (son 4 rutas de salida distintas,
incluidas las tempranas).

---

## 3. `summary.host` y `summary.image` siguen sin consumidor

`summarize()` los calcula desde hace tiempo y nadie los lee. Antes ni siquiera
se rellenaban bien, porque `scope` no lo escribía nadie: la rama
`f.scope === 'image'` era código muerto. Ahora el campo existe de verdad
(sellado en los tres puntos de entrada del normalizador), así que los objetos
son correctos para host y red, y correctos para imagen salvo por el punto 2.

Decisión: **no se borran**. Son la base del dashboard combinado si alguna vez se
audita host + imagen en un mismo flujo. Si se descarta esa idea, bórrense junto
con `hostCounts` / `imageCounts`.

---

## 4. ~~El interruptor "Analizar paquetes del sistema" sustituye el escaneo del home~~ — RESUELTO

Los dos escaneos se suman (`mergeScans()` en `trivy-fs.js`), el home va primero
y "Carpeta a auditar" se respeta también con el interruptor activo. Fijado en
`test/manual/test-trivy-merge.js`.

Se arregló además un fallo mayor que apareció al mirarlo: `trivy` **no rellena
`PkgPath` en paquetes del SO** (medido: 0/117 en `rootfs` sobre Debian 12, 0/169
en la imagen `debian:12`), así que la regla `PkgPath ? installed : declared`
marcaba `declared` a openssl y zlib1g instalados por dpkg — los dejaba fuera del
riesgo global y les ponía un paso de resolución que decía "no es software
instalado en tu equipo". Ver `originOf()` en `lib/normalizer.js`, con la
limitación conocida del chroot documentada al lado.

---

## 5. Aviso para quien toque el ui_template de host

`isDeclared(f)` en `examples/dashboard-host-template.html` es **el único punto
del template que replica una condición del backend** (`isActionable()` en
`lib/severity-map.js`). Se replica porque un `ui_template` de Dashboard 2.0 no
puede importar módulos.

Todo lo demás —cifras de accionables e informativos, riesgo global— viene
precalculado en `msg.payload.summary`. Si se cambia la regla de qué es
accionable, hay que tocar **los dos sitios**, y el test que lo detecta es
`test/manual/test-declared-severity.js`.
