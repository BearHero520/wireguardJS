const { test } = require("node:test");
const assert = require("node:assert/strict");
const { validate, contains, endpoint, redact } = require("../src/config.cjs");
const privateKey = Buffer.alloc(32, 1).toString("base64");
const publicKey = Buffer.alloc(32, 2).toString("base64");
const valid = `[Interface]\nPrivateKey = ${privateKey}\nAddress = 10.0.0.2/24\nDNS = 1.1.1.1\nLANInterface = br0\n[Peer]\nPublicKey = ${publicKey}\nEndpoint = [2001:db8::1]:51820\nAllowedIPs = 0.0.0.0/0\nPersistentKeepalive = 25\n`;

test("accepts IPv4 tunnel over IPv6 endpoint and normalizes CRLF", () => {
  const result = validate(valid.replaceAll("\n", "\r\n"));
  assert.equal(result.valid, true, result.errors.join("\n"));
  assert.equal(result.normalized, valid);
});
test("rejects IPv6 AllowedIPs, invalid octets and prefixes", () => {
  for (const value of ["::/0", "300.1.1.1/24", "10.0.0.1/33", "010.0.0.1/24", "0.0.0.0/0, ::/0"]) {
    assert.equal(validate(valid.replace("AllowedIPs = 0.0.0.0/0", `AllowedIPs = ${value}`)).valid, false, value);
  }
});
test("rejects DNS outside the tunnel but allows no DNS interception", () => {
  const narrow = valid.replace("AllowedIPs = 0.0.0.0/0", "AllowedIPs = 10.0.0.0/24");
  assert.equal(validate(narrow).valid, false);
  assert.equal(validate(narrow.replace("DNS = 1.1.1.1\n", "")).valid, true);
  assert.equal(contains("10.0.0.9/24", "10.0.0.250"), true);
  assert.equal(contains("10.0.0.0/24", "10.0.1.1"), false);
});
test("rejects ambiguous sections, hooks, duplicate keys, and empty files", () => {
  for (const source of ["", valid + "[Interface]\n", valid.replace("Address =", "PrivateKey = x\nAddress ="), valid.replace("LANInterface = br0", "PostUp = rm -rf /"), valid.replace("[Interface]", "[Other]")]) assert.equal(validate(source).valid, false);
});
test("validates keys and endpoints without exposing private values in errors", () => {
  assert.equal(endpoint("vpn.example.com:51820"), true);
  for (const value of ["-host:80", "host:65536", "host:0", "[::::]:80", "999.1.1.1:80", "2001:db8::1:80"]) assert.equal(endpoint(value), false, value);
  const result = validate(valid.replace(privateKey, "secret"));
  assert.equal(result.valid, false);
  assert.equal(result.errors.join(" ").includes("secret"), false);
  assert.equal(redact(valid).includes(privateKey), false);
});
test("supports multiple peers with distinct routes and keys", () => {
  const source = valid + `[Peer]\nPublicKey = ${Buffer.alloc(32, 3).toString("base64")}\nAllowedIPs = 10.20.0.0/16\n`;
  assert.equal(validate(source).valid, true);
  assert.equal(validate(source.replace("10.20.0.0/16", "0.0.0.0/0")).valid, false);
});

module.exports = { valid };
