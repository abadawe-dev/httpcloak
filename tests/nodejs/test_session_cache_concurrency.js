// Lock for the Node session cache under concurrent handshakes.
//
// A sync-mode get callback returned its JS string through a `str` result.
// When the library calls it from one of its own threads, koffi relays the call
// to the JS thread and releases the memory that string was converted into
// before the library copies it, so concurrent lookups read each other's
// values or crashed the process. Sixteen fresh sessions per round resuming
// from one backend crashed within a few rounds. The async-mode backend, which
// hands its result back through a call instead, runs the same load.
//
// Run from the repo root: node tests/nodejs/test_session_cache_concurrency.js

const assert = require("assert");
const { execFileSync } = require("child_process");
const fs = require("fs");
const https = require("https");
const os = require("os");
const path = require("path");

const httpcloak = require(path.join(__dirname, "../../bindings/nodejs/lib/index.js"));

function httpsServer() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "hc-cache-"));
  const cert = path.join(dir, "c.pem");
  const key = path.join(dir, "k.pem");
  execFileSync("openssl", [
    "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
    "-keyout", key, "-out", cert, "-days", "1", "-nodes", "-subj", "/CN=localhost",
    "-addext", "subjectAltName=IP:127.0.0.1",
  ], { stdio: "ignore" });
  const server = https.createServer(
    { cert: fs.readFileSync(cert), key: fs.readFileSync(key) },
    (req, res) => res.end("ok"),
  );
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => resolve(server));
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

async function main() {
  const server = await httpsServer();
  const url = `https://127.0.0.1:${server.address().port}/`;
  try {
    await runMode(url, false);
    await runMode(url, true);
  } finally {
    server.close();
  }
}

main().then(() => process.exit(0), (e) => {
  console.error(e);
  process.exit(1);
});
