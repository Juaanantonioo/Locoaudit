"use strict";

// Configuración insegura de los contenedores, con `docker inspect`.
// high: root y secretos en variables de entorno; medium: puertos en 0.0.0.0 y docker.sock montado.

const { execCommand }    = require("../../../lib/executor");
const { createFinding }  = require("../../../lib/finding-schema");

const INSPECT_TIMEOUT_MS = 8000;

// Nombres de variable que delatan un secreto.
const SENSITIVE_PATTERNS = ["PASSWORD", "PASSWD", "SECRET", "TOKEN", "CREDENTIAL", "API_KEY", "APIKEY",
  "PRIVATE_KEY", "ACCESS_KEY", "AUTH_KEY"];

// Casan pero no son secretos: claves públicas (GPG_KEYS de las imágenes oficiales) y rutas *_FILE de Docker secrets.
const NOT_SECRET_RE = /^(GPG_KEYS?|.*_KEYRING|.*PUBLIC_KEY.*)$|_FILE$/;

// null si el inspect falla; quien llama lo convierte en hallazgo de comprobación no realizada.
async function inspect(id, format) {
  try {
    const out = await execCommand(
      `docker inspect ${id} --format "${format}"`,
      INSPECT_TIMEOUT_MS
    );
    return out.trim();
  } catch (_) {
    return null;
  }
}

// JSON de una lista; "null" vale (sin variables o sin montajes).
function isJsonList(out) {
  try {
    const v = JSON.parse(out || "null");
    return v === null || Array.isArray(v);
  } catch (_) {
    return false;
  }
}

// Recibe el ["VAR=value", …] de `{{json .Config.Env}}` y devuelve los nombres sensibles.
function findSensitiveEnvVars(envJson) {
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
      return { name: (i < 0 ? String(entry) : String(entry).slice(0, i)).toUpperCase(), value: i < 0 ? "" : String(entry).slice(i + 1) };
    })
    // Una variable vacía no expone nada.
    .filter(({ name, value }) => value.trim() !== "" && !NOT_SECRET_RE.test(name) &&
      (SENSITIVE_PATTERNS.some((pat) => name.includes(pat)) || /(^|_)PASS$/.test(name)))
    .map(({ name }) => name);
}

// Sufijo correlativo por contenedor: IMG-CFG-001-001, -002…
function findingId(base, n) {
  return `${base}-${String(n + 1).padStart(3, "0")}`;
}

// Comprobación no realizada: se informa, no se da por buena.
function inspectFailedFinding(name, idx, checks, reason) {
  return createFinding({
    id:        findingId("IMG-CFG-SKIP", idx),
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
async function auditContainer(container, idx) {
  const findings = [];
  const name = container.name || container.id;

  // En paralelo: son tres `docker inspect` independientes.
  const [userOut, envOut, bindsOut] = await Promise.all([
    inspect(container.id, "{{.Config.User}}"),
    inspect(container.id, "{{json .Config.Env}}"),
    inspect(container.id, "{{json .HostConfig.Binds}}"),
  ]);

  // Sin dato no se afirma nada, ni root ni lo contrario. Un JSON ilegible cuenta como sin dato.
  const fallidas = [];
  if (userOut === null)  fallidas.push("usuario");
  if (envOut === null)   fallidas.push("variables de entorno");
  if (bindsOut === null) fallidas.push("montajes");
  const ilegibles = [];
  if (envOut !== null && !isJsonList(envOut))     ilegibles.push("variables de entorno");
  if (bindsOut !== null && !isJsonList(bindsOut)) ilegibles.push("montajes");
  if (fallidas.length) {
    findings.push(inspectFailedFinding(name, idx, [...fallidas, ...ilegibles],
      ilegibles.length ? "docker inspect no respondió o devolvió datos ilegibles" : "docker inspect no respondió"));
  } else if (ilegibles.length) {
    findings.push(inspectFailedFinding(name, idx, ilegibles, "docker inspect devolvió datos que no se pueden leer"));
  }

  const user = userOut ?? "";
  if (userOut !== null && (user === "" || user === "root" || user === "0")) {
    // Parado solo es la configuración con la que volverá a arrancar: por eso baja a medium.
    const enMarcha = container.running === true;
    findings.push(createFinding({
      id:       findingId("IMG-CFG-001", idx),
      title:    enMarcha
        ? `Contenedor ${name} ejecutándose como root`
        : `Contenedor ${name} configurado para ejecutarse como root (está parado)`,
      severity: enMarcha ? "high" : "medium",
      evidence: `Usuario del contenedor: ${user === "" ? "(no definido — default root)" : user}`,
      // Gramática del fix: "## " rama, "$ " comando, "> " nota, el resto pasos.
      fix:      "Crea un usuario sin privilegios en el Dockerfile y declara USER antes del CMD.\n" +
                "Reconstruye la imagen y vuelve a arrancar el contenedor.\n" +
                "> El usuario tiene que existir dentro de la imagen: un USER que no está creado hace fallar el arranque.",
      category: "image",
      source:   "native",
    }));
  }

  const sensitiveVars = findSensitiveEnvVars(envOut);
  if (sensitiveVars.length > 0) {
    findings.push(createFinding({
      id:       findingId("IMG-CFG-002", idx),
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
    findings.push(createFinding({
      id:       findingId("IMG-CFG-003", idx),
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
    findings.push(createFinding({
      id:       findingId("IMG-CFG-004", idx),
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
async function auditDockerConfig(dockerInfo) {
  if (!dockerInfo || dockerInfo.skipped) return [];

  const containers = dockerInfo.containers || [];
  if (containers.length === 0) return [];

  const results = await Promise.allSettled(
    containers.map((c, i) => auditContainer(c, i))
  );

  return results.flatMap((r, i) => (r.status === "fulfilled"
    ? r.value
    : [inspectFailedFinding(containers[i].name || containers[i].id, i, ["usuario", "variables de entorno", "montajes"],
        String((r.reason && r.reason.message) || r.reason || "error inesperado"))]));
}

module.exports = { auditDockerConfig, findSensitiveEnvVars };
