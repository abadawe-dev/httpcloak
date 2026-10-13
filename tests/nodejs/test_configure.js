// Lock for httpcloak.configure().
//
// The typings declare that configure() takes every Session option, but the
// runtime passed on only nine of them, so the rest were dropped without a
// word. The config each session hands the library is captured at creation, so
// nothing here touches the network.
//
// Run from the repo root: node tests/nodejs/test_configure.js

const assert = require("assert");
const path = require("path");

const httpcloak = require(path.join(__dirname, "../../bindings/nodejs/lib/index.js"));

const probe = new httpcloak.Session();
const lib = probe._lib;
probe.close();

const original = lib.httpcloak_session_new;
const seen = [];
lib.httpcloak_session_new = (configJson) => {
  seen.push(JSON.parse(configJson));
  return original(configJson);
};

try {
  httpcloak.configure({
    preset: "chrome-155-windows",
    httpVersion: "h2",
    tlsOnly: true,
    disableHttp3: true,
    echConfigDomain: "ech.example",
    headers: { "X-A": "1" },
  });
  const config = seen[seen.length - 1];
  assert.strictEqual(config.preset, "chrome-155-windows");
  assert.strictEqual(config.http_version, "h2");
  assert.strictEqual(config.tls_only, true);
  assert.strictEqual(config.disable_http3, true);
  assert.strictEqual(config.ech_config_domain, "ech.example");
  console.log("ok configure passes every session option");
} finally {
  lib.httpcloak_session_new = original;
  httpcloak.configure();
}
process.exit(0);
