// Locks for the Node session cache under concurrent handshakes, and for the
// blocking methods it cannot serve.
//
// A sync-mode get callback returned its JS string through a `str` result.
// When the library calls it from one of its own threads, koffi relays the call
// to the JS thread and releases the memory that string was converted into
// before the library copies it, so concurrent lookups read each other's
// values or crashed the process. Sixteen fresh sessions per round resuming
// from one backend crashed within a few rounds. The async-mode backend, which
// hands its result back through a call instead, runs the same load.
//
// The callbacks run on the JS thread, so a method that blocks that thread and
// then needs a handshake used to hang the process for good. Those methods now
// throw on any session that holds such a cache, which a session keeps for its
// whole life, and still work on sessions that have none.
//
// Run from the repo root: node tests/nodejs/test_session_cache_concurrency.js

const assert = require("assert");
const { execFileSync, spawn } = require("child_process");
const fs = require("fs");
const os = require("os");
const path = require("path");

const httpcloak = require(path.join(__dirname, "../../bindings/nodejs/lib/index.js"));

// The server runs in a child process: the blocking methods tested below hold
// this process's JS thread, so a server on it could never answer them.
function httpsServer() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "hc-cache-"));
  const cert = path.join(dir, "c.pem");
  const key = path.join(dir, "k.pem");
  execFileSync("openssl", [
    "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
    "-keyout", key, "-out", cert, "-days", "1", "-nodes", "-subj", "/CN=localhost",
    "-addext", "subjectAltName=IP:127.0.0.1",
  ], { stdio: "ignore" });
  const child = spawn(process.execPath, ["-e", `
    const fs = require("fs");
    const server = require("https").createServer(
      { cert: fs.readFileSync(${JSON.stringify(cert)}), key: fs.readFileSync(${JSON.stringify(key)}) },
      (req, res) => req.resume().on("end", () => res.end("ok")),
    );
    server.listen(0, "127.0.0.1", () => console.log(server.address().port));
  `], { stdio: ["ignore", "pipe", "inherit"] });
  return new Promise((resolve, reject) => {
    child.once("error", reject);
    child.stdout.once("data", (d) => resolve({ child, port: Number(String(d).trim()) }));
  });
}

async function runMode(url, asyncMode) {
  const store = new Map();
  const calls = { get: 0, hit: 0, put: 0 };
  httpcloak.configureSessionCache({
    get: (k) => {
      calls.get++;
      const v = store.get(k) || null;
      if (v) calls.hit++;
      return v;
    },
    put: (k, v) => {
      calls.put++;
      store.set(k, v);
      return 0;
    },
    delete: (k) => {
      store.delete(k);
      return 0;
    },
    async: asyncMode,
  });

  try {
    for (let round = 0; round < 20; round++) {
      await Promise.all(Array.from({ length: 16 }, async () => {
        const s = new httpcloak.Session({ preset: "chrome-latest", verify: false, httpVersion: "h1" });
        try {
          const r = await s.get(url);
          assert.strictEqual(r.statusCode, 200);
        } finally {
          s.close();
        }
      }));
    }
    // Only the first round starts with an empty store, so nearly every later
    // lookup should hit; a value garbled on the way out would show up as a
    // miss here. The slack allows for one more round of misses.
    assert.ok(calls.put > 0, JSON.stringify(calls));
    assert.ok(calls.hit >= calls.get - 2 * 16, JSON.stringify(calls));
    console.log(`ok concurrent cache lookups (async: ${asyncMode})`, JSON.stringify(calls));
  } finally {
    httpcloak.clearSessionCache();
  }
}

// Every method that blocks the JS thread, with a call that would need a fresh
// handshake if it were let through.
const BLOCKING = {
  getSync: (s, url) => s.getSync(url),
  postSync: (s, url) => s.postSync(url, { body: "x" }),
  requestSync: (s, url) => s.requestSync("GET", url),
  getStream: (s, url) => s.getStream(url),
  postStream: (s, url) => s.postStream(url, { body: "x" }),
  requestStream: (s, url) => s.requestStream("GET", url),
  getFast: (s, url) => s.getFast(url),
  postFast: (s, url) => s.postFast(url, { body: "x" }),
  requestFast: (s, url) => s.requestFast("GET", url),
  putFast: (s, url) => s.putFast(url, { body: "x" }),
  deleteFast: (s, url) => s.deleteFast(url),
  patchFast: (s, url) => s.patchFast(url, { body: "x" }),
  warmup: (s, url) => s.warmup(url),
  uploadStream: (s, url) => s.uploadStream("POST", url, [Buffer.from("x")]),
  postUpload: (s, url) => s.postUpload(url, [Buffer.from("x")]),
};

async function assertAllRefused(s, url, label) {
  for (const [name, call] of Object.entries(BLOCKING)) {
    await assert.rejects(
      async () => call(s, url),
      (e) => e instanceof httpcloak.HTTPCloakError && /session's cache/.test(e.message),
      `${label}: ${name}`,
    );
  }
}

async function blockingMethodsRefused(url, asyncMode) {
  const before = new httpcloak.Session({ preset: "chrome-latest", verify: false, httpVersion: "h1" });
  httpcloak.configureSessionCache({
    get: () => null,
    put: () => 0,
    delete: () => 0,
    async: asyncMode,
  });
  const cached = new httpcloak.Session({ preset: "chrome-latest", verify: false, httpVersion: "h1" });
  const [forked] = cached.fork(1);
  try {
    await assertAllRefused(cached, url, "cached session");
    await assertAllRefused(forked, url, "fork of a cached session");
    // A session created before the cache has none, so its handshakes never
    // call into JavaScript and blocking calls are fine.
    assert.strictEqual(before.getSync(url).statusCode, 200);
  } finally {
    httpcloak.clearSessionCache();
  }
  try {
    // The session still holds its cache after clearSessionCache(); letting
    // this through is what used to hang.
    await assertAllRefused(cached, url, "cached session after clear");
    const after = new httpcloak.Session({ preset: "chrome-latest", verify: false, httpVersion: "h1" });
    try {
      assert.strictEqual(after.getSync(url).statusCode, 200);
    } finally {
      after.close();
    }
  } finally {
    for (const s of [before, cached, forked]) s.close();
  }
  console.log(`ok blocking methods refused on a cached session (async: ${asyncMode})`);
}

async function main() {
  const { child, port } = await httpsServer();
  const url = `https://127.0.0.1:${port}/`;
  try {
    await runMode(url, false);
    await runMode(url, true);
    await blockingMethodsRefused(url, false);
    await blockingMethodsRefused(url, true);
  } finally {
    child.kill();
  }
}

main().then(() => process.exit(0), (e) => {
  console.error(e);
  process.exit(1);
});
