const http = require("node:http");
const fs = require("node:fs");
const path = require("node:path");

const staticRoot = path.join(__dirname, "public");
const host = "127.0.0.1";
const port = Number(process.env.PORT || 4173);
const maxBodyBytes = 16_000;
const staticFiles = new Set([
  "index.html", "login.html", "signup.html", "kernal.html", "omniframe.html", "vm.html", "helpdesk.html",
  "omni-recon.html", "omni-endpoints.html", "omni-terminal.html", "omni-packets.html", "omni-credentials.html",
  "omni-research.html", "omni-samples.html", "omni-incident.html", "omni-specialties.html", "omni-help.html",
  "debugger.html", "target.html", "performance.html", "objects.html", "events.html", "network.html",
  "assessment.html", "registry.html", "services.html", "filesystem.html", "help.html",
  "app.css", "omni.css", "helpdesk.css", "auth.css", "vm.css",
  "app.js", "omni.js", "helpdesk.js", "identity.js", "auth-page.js", "terminal.js", "vm.js",
  "command-index.json", "help-index.json"
]);
const mimeTypes = {
  ".css": "text/css; charset=utf-8",
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".svg": "image/svg+xml",
  ".txt": "text/plain; charset=utf-8"
};

const sendJson = (res, status, data) => {
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff"
  });
  res.end(JSON.stringify(data));
};

const readJsonBody = (req) => new Promise((resolve, reject) => {
  let size = 0;
  const chunks = [];
  req.on("data", (chunk) => {
    size += chunk.length;
    if (size > maxBodyBytes) {
      reject(Object.assign(new Error("Request body exceeds 16 KB."), { status: 413 }));
      req.resume();
      return;
    }
    chunks.push(chunk);
  });
  req.on("end", () => {
    if (size > maxBodyBytes) return;
    try {
      resolve(JSON.parse(Buffer.concat(chunks).toString("utf8")));
    } catch {
      reject(Object.assign(new Error("Request body must be valid JSON."), { status: 400 }));
    }
  });
  req.on("error", reject);
});

const proxyAuth = async (req, res, pathname) => {
  const allowedPaths = new Set([
    "/api/auth/health", "/api/auth/register", "/api/auth/login",
    "/api/auth/session", "/api/auth/logout"
  ]);
  if (!allowedPaths.has(pathname)) {
    sendJson(res, 404, { error: "Account API route not found." });
    return;
  }
  if (!["GET", "POST"].includes(req.method)) {
    res.setHeader("Allow", pathname.endsWith("/session") || pathname.endsWith("/health") ? "GET" : "POST");
    sendJson(res, 405, { error: "Method not allowed." });
    return;
  }
  let body = null;
  if (req.method === "POST" && pathname !== "/api/auth/logout") {
    try {
      body = Buffer.from(JSON.stringify(await readJsonBody(req)));
    } catch (error) {
      sendJson(res, error.status || 400, { error: error.message || "Could not read request body." });
      return;
    }
  }
  const headers = {};
  for (const name of ["content-type", "cookie", "origin"]) {
    if (req.headers[name]) headers[name] = req.headers[name];
  }
  if (body) headers["content-length"] = body.length;
  const upstream = http.request({
    hostname: host,
    port: Number(process.env.AUTH_PORT || 4174),
    path: pathname,
    method: req.method,
    headers,
    timeout: 5000
  }, (response) => {
    res.writeHead(response.statusCode || 502, response.headers);
    response.pipe(res);
  });
  upstream.on("timeout", () => upstream.destroy(new Error("Account service request timed out.")));
  upstream.on("error", (error) => {
    console.error("Local account service request failed:", error.message);
    if (!res.headersSent) sendJson(res, 503, { error: "Account service is unavailable. Start the FastAPI service and retry." });
    else res.destroy(error);
  });
  if (body) upstream.end(body);
  else upstream.end();
};

const hasAccountSession = async (cookie) => {
  if (!cookie) return false;
  try {
    const response = await fetch(`http://${host}:${Number(process.env.AUTH_PORT || 4174)}/api/auth/session`, {
      headers: { Cookie: cookie, Accept: "application/json" },
      signal: AbortSignal.timeout(2500)
    });
    if (!response.ok) return false;
    const account = await response.json();
    return account.authenticated === true;
  } catch (error) {
    console.warn("Could not verify the local account session:", error.message);
    return false;
  }
};

const serveFile = async (req, res, pathname, search = "") => {
  let relative;
  try {
    relative = decodeURIComponent(pathname === "/" ? "/login.html" : pathname);
  } catch {
    sendJson(res, 400, { error: "Invalid URL path." });
    return;
  }
  const file = path.resolve(staticRoot, `.${relative}`);
  if ((!file.startsWith(`${staticRoot}${path.sep}`) && file !== staticRoot) || !staticFiles.has(path.basename(file)) || path.dirname(file) !== staticRoot) {
    sendJson(res, 404, { error: "File not found." });
    return;
  }
  const filename = path.basename(file).toLowerCase();
  if (path.extname(file).toLowerCase() === ".html" && !["login.html", "signup.html"].includes(filename)) {
    const authenticated = await hasAccountSession(req.headers.cookie);
    if (!authenticated) {
      const requested = `${pathname}${search}`;
      res.writeHead(302, {
        Location: `/login.html?next=${encodeURIComponent(requested)}`,
        "Cache-Control": "no-store"
      });
      res.end();
      return;
    }
  }
  fs.stat(file, (statError, stat) => {
    if (statError || !stat.isFile()) {
      sendJson(res, 404, { error: "File not found." });
      return;
    }
    res.writeHead(200, {
      "Content-Type": mimeTypes[path.extname(file).toLowerCase()] || "application/octet-stream",
      "Cache-Control": "no-cache",
      "X-Content-Type-Options": "nosniff",
      "Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'self'; worker-src 'none'; img-src 'self' data:; object-src 'none'; base-uri 'self'; form-action 'self'; frame-src 'none'"
    });
    fs.createReadStream(file).pipe(res);
  });
};

const server = http.createServer((req, res) => {
  const url = new URL(req.url, `http://${host}:${port}`);
  if (url.pathname.startsWith("/api/auth/")) {
    proxyAuth(req, res, url.pathname);
    return;
  }
  if (url.pathname.startsWith("/api/")) {
    sendJson(res, 404, { error: "API route not found." });
    return;
  }
  if (req.method !== "GET" && req.method !== "HEAD") {
    res.setHeader("Allow", "GET, HEAD");
    sendJson(res, 405, { error: "Static application files are read-only." });
    return;
  }
  serveFile(req, res, url.pathname, url.search);
});

server.listen(port, host, () => {
  console.log(`Kernal local workspace: http://${host}:${port}`);
  console.log("App Help Desk uses local keyword matching from public/help-index.json; no AI provider is used.");
  console.log(`Start account storage separately: python -m uvicorn backend.auth_api:app --host ${host} --port ${Number(process.env.AUTH_PORT || 4174)}`);
});
