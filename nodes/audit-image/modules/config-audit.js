"use strict";

// Configuración insegura de los contenedores, con `docker inspect`.
// high: root y secretos en variables de entorno; medium: puertos en 0.0.0.0 y docker.sock montado.

const { ejecutar }    = require("../../../lib/executor");
const { crearHallazgo }  = require("../../../lib/finding-schema");

const INSPECT_TIMEOUT_MS = 8000;

// Nombres de variable que delatan un secreto.
const SENSITIVE_PATTERNS = ["PASSWORD", "PASSWD", "SECRET", "TOKEN", "CREDENTIAL", "API_KEY", "APIKEY",
  "PRIVATE_KEY", "ACCESS_KEY", "AUTH_KEY"];

// Casan pero no son secretos: claves públicas (GPG_KEYS de las imágenes oficiales) y rutas *_FILE de Docker secrets.
const NOT_SECRET_RE = /^(GPG_KEYS?|.*_KEYRING|.*PUBLIC_KEY.*)$|_FILE$/;

// null si el inspect falla; quien llama lo convierte en hallazgo de comprobación no realizada.
async function inspeccionar(id, format) {
  try {
    const out = await ejecutar(
      `docker inspect ${id} --format "${format}"`,
      INSPECT_TIMEOUT_MS
    );
    return out.trim();
  } catch (_) {
    return null;
  }
}

// JSON de una lista; "null" vale (sin variables o sin montajes).
function esListaJson(out) {
  try {
    const v = JSON.parse(out || "null");
    return v === null || Array.isArray(v);
  } catch (_) {
    return false;
  }
}

// Recibe el ["VAR=value", …] de `{{json .Config.Env}}` y devuelve los nombres sensibles.
function variablesSensibles(envJson) {
  if (!envJson) return [];
  let envList;
  try {
    envList = JSON.parse(envJson);
  } catch (_) {
    return [];
  }
  if (!Array.isArray(envList)) return [];

  return envList
    .map((entry) => {
      const i = String(entry).indexOf("=");
      let nombre;
      let valor;
      if (i < 0) {
        nombre = String(entry);
        valor = "";
      } else {
        nombre = String(entry).slice(0, i);
        valor = String(entry).slice(i + 1);
      }
      return { name: nombre.toUpperCase(), value: valor };
    })
    // Una variable vacía no expone nada.
    .filter(({ name, value }) => value.trim() !== "" && !NOT_SECRET_RE.test(name) &&
      (SENSITIVE_PATTERNS.some((pat) => name.includes(pat)) || /(^|_)PASS$/.test(name)))
    .map(({ name }) => name);
}

// Sufijo correlativo por contenedor: IMG-CFG-001-001, -002…
function idHallazgo(base, n) {
  return `${base}-${String(n + 1).padStart(3, "0")}`;
}

// Comprobación no realizada: se informa, no se da por buena.
function hallazgoInspeccionFallida(name, idx, checks, reason) {
  return crearHallazgo({
    id:        idHallazgo("IMG-CFG-SKIP", idx),
    title:     `Configuración del contenedor ${name}: no se ha podido comprobar`,
    severity:  "info",
    evidence:  `No se ha podido leer la configuración del contenedor (${checks.join(", ")}): ${reason}. ` +
               "Que no aparezcan hallazgos de esa parte no significa que esté bien configurado.",
    fix:       "Vuelve a lanzar la auditoría. Si se repite, comprueba que Docker responde.\n" +
               `$ docker inspect ${name}`,
    category:  "image",
    source:    "native",
    isCommand: false,
    skipped:   true,
    kind:      "error",
  });
}

// Los cuatro chequeos de un contenedor; idx solo numera los IDs.
async function auditarContenedor(container, idx) {
  const findings = [];
  const name = container.name || container.id;

  // En paralelo: son tres `docker inspect` independientes.
  const [userOut, envOut, bindsOut] = await Promise.all([
    inspeccionar(container.id, "{{.Config.User}}"),
    inspeccionar(container.id, "{{json .Config.Env}}"),
    inspeccionar(container.id, "{{json .HostConfig.Binds}}"),
  ]);

  // Sin dato no se afirma nada, ni root ni lo contrario. Un JSON ilegible cuenta como sin dato.
  const fallidas = [];
  if (userOut === null)  fallidas.push("usuario");
  if (envOut === null)   fallidas.push("variables de entorno");
  if (bindsOut === null) fallidas.push("montajes");
  const ilegibles = [];
  if (envOut !== null && !esListaJson(envOut))     ilegibles.push("variables de entorno");
  if (bindsOut !== null && !esListaJson(bindsOut)) ilegibles.push("montajes");
  if (fallidas.length) {
    let motivo;
    if (ilegibles.length) {
      motivo = "docker inspect no respondió o devolvió datos ilegibles";
    } else {
      motivo = "docker inspect no respondió";
    }
    findings.push(hallazgoInspeccionFallida(name, idx, [...fallidas, ...ilegibles],
      motivo));
  } else if (ilegibles.length) {
    findings.push(hallazgoInspeccionFallida(name, idx, ilegibles, "docker inspect devolvió datos que no se pueden leer"));
  }

  const user = userOut ?? "";
  if (userOut !== null && (user === "" || user === "root" || user === "0")) {
    // Parado solo es la configuración con la que volverá a arrancar: por eso baja a medium.
    const enMarcha = container.running === true;
    let titulo;
    let severidad;
    if (enMarcha) {
      titulo = `Contenedor ${name} ejecutándose como root`;
      severidad = "high";
    } else {
      titulo = `Contenedor ${name} configurado para ejecutarse como root (está parado)`;
      severidad = "medium";
    }
    let usuario;
    if (user === "") {
      usuario = "(no definido — default root)";
    } else {
      usuario = user;
    }
    findings.push(crearHallazgo({
      id:       idHallazgo("IMG-CFG-001", idx),
      title:    titulo,
      severity: severidad,
      evidence: `Usuario del contenedor: ${usuario}`,
      // Gramática del fix: "## " rama, "$ " comando, "> " nota, el resto pasos.
      fix:      "Crea un usuario sin privilegios en el Dockerfile y declara USER antes del CMD.\n" +
                "Reconstruye la imagen y vuelve a arrancar el contenedor.\n" +
                "> El usuario tiene que existir dentro de la imagen: un USER que no está creado hace fallar el arranque.",
      category: "image",
      source:   "native",
    }));
  }

  const sensitiveVars = variablesSensibles(envOut);
  if (sensitiveVars.length > 0) {
    findings.push(crearHallazgo({
      id:       idHallazgo("IMG-CFG-002", idx),
      title:    `Variables de entorno sensibles en ${name}: ${sensitiveVars.join(", ")}`,
      severity: "high",
      evidence: `Variables con nombres sensibles detectadas: ${sensitiveVars.join(", ")}`,
      // Dos ramas excluyentes según lo que contenga la variable.
      fix:      "## Si el valor es un secreto\n" +
                "Móntalo con Docker secrets o con un gestor de secretos, y retíralo del Dockerfile.\n" +
                "Rota el valor: el anterior ya está expuesto.\n" +
                "## Si el valor es configuración no sensible\n" +
                "Pásalo en tiempo de ejecución desde un fichero de entorno que no se versione.\n" +
                "$ docker run --env-file .env <imagen>\n" +
                "> Un valor puesto con ENV en el Dockerfile queda grabado en la capa: borrarlo después no lo quita del historial de la imagen.",
      category: "image",
      source:   "native",
    }));
  }

  if (container.ports && container.ports.includes("0.0.0.0:")) {
    // El binding se fija al arrancar el contenedor; por eso no se añade el fix de proceso del host.
    const portsFix =
      "## Si el servicio solo se usa desde el propio equipo\n" +
      "Publica el puerto únicamente en el bucle local y vuelve a arrancar el contenedor.\n" +
      "$ docker run -p 127.0.0.1:<puerto>:<puerto> <imagen>\n" +
      "En Docker Compose, el mapeo equivalente: ports: [\"127.0.0.1:<puerto>:<puerto>\"].\n" +
      "## Si tiene que ser accesible desde fuera\n" +
      "Déjalo publicado y protege el acceso con un cortafuegos o un proxy inverso con autenticación.\n" +
      "> El binding se fija al arrancar el contenedor: no hay comando que lo corrija sobre uno ya en marcha.";
    findings.push(crearHallazgo({
      id:       idHallazgo("IMG-CFG-003", idx),
      title:    `Contenedor ${name} expone puertos en todas las interfaces`,
      severity: "medium",
      evidence: `Puertos publicados: ${container.ports}`,
      fix:      portsFix,
      category: "image",
      source:   "native",
    }));
  }

  let binds = [];
  try { binds = JSON.parse(bindsOut || "[]"); } catch (_) { /* sin montajes legibles */ }
  const hasSock = Array.isArray(binds) &&
    binds.some((b) => typeof b === "string" && b.includes("/var/run/docker.sock"));

  if (hasSock) {
    findings.push(crearHallazgo({
      id:       idHallazgo("IMG-CFG-004", idx),
      title:    `Contenedor ${name} monta el socket de Docker`,
      severity: "medium",
      evidence: `Bind mounts: ${binds.join(", ")}`,
      fix:      "Quita el montaje de /var/run/docker.sock del docker run o del Compose y vuelve a arrancar el contenedor.\n" +
                "Si el contenedor necesita hablar con Docker, ponle delante un proxy de socket que limite la API a lo imprescindible.\n" +
                "> Montar el socket equivale a dar privilegios de root en el host: quien controle el contenedor controla el demonio.",
      category: "image",
      source:   "native",
    }));
  }

  return findings;
}

// Sin Docker devuelve []: el aviso de ausencia lo emite el nodo con IMG-DOCKER-OFF.
async function auditarConfigDocker(dockerInfo) {
  if (!dockerInfo || dockerInfo.skipped) return [];

  const containers = dockerInfo.containers || [];
  if (containers.length === 0) return [];

  const results = await Promise.allSettled(
    containers.map((c, i) => auditarContenedor(c, i))
  );

  return results.flatMap((r, i) => {
    if (r.status === "fulfilled") {
      return r.value;
    } else {
      return [hallazgoInspeccionFallida(containers[i].name || containers[i].id, i, ["usuario", "variables de entorno", "montajes"],
            String((r.reason && r.reason.message) || r.reason || "error inesperado"))];
    }
  });
}

module.exports = { auditarConfigDocker, variablesSensibles };
