const { test } = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const { validate, ipv6, cidr, contains, endpoint, redact } = require("../src/config.cjs");
const privateKey = Buffer.alloc(32, 1).toString("base64");
const publicKey = Buffer.alloc(32, 2).toString("base64");
const valid = `[Interface]\nPrivateKey = ${privateKey}\nAddress = 10.0.0.2/24\nDNS = 1.1.1.1\nLANInterface = br0\n[Peer]\nPublicKey = ${publicKey}\nEndpoint = [2001:db8::1]:51820\nAllowedIPs = 0.0.0.0/0\nPersistentKeepalive = 25\n`;
const dual = valid.replace("10.0.0.2/24", "10.6.0.2/32, fd86:5a72:3ff1:111::2/128").replace("1.1.1.1", "10.6.0.1").replace("AllowedIPs = 0.0.0.0/0", "AllowedIPs = 0.0.0.0/0, ::/0");
const ipv6Only = valid.replace("10.0.0.2/24", "fd00::2/64").replace("1.1.1.1", "fd00::1").replace("AllowedIPs = 0.0.0.0/0", "AllowedIPs = ::/0");

function assertBoth(source, expected, label = "configuration") {
  const frontend = validate(source);
  assert.equal(frontend.valid, expected, `${label}: ${frontend.errors.join("\n")}`);
  const bash = process.platform === "win32" ? "C:/Program Files/Git/bin/bash.exe" : "/bin/bash";
  const backend = spawnSync(bash, ["-c", 'exec awk -f "$WGJS_VALIDATOR"'], {
    input: source, encoding: "utf8", timeout: 10000,
    env: { ...process.env, WGJS_VALIDATOR: path.resolve(__dirname, "../resources/scripts/validate.awk").replaceAll("\\", "/") }
  });
  assert.ifError(backend.error);
  assert.equal(backend.status, expected ? 0 : 1, `${label}: ${backend.stdout}${backend.stderr}`);
}

test("accepts IPv4 tunnel over IPv6 endpoint and normalizes CRLF", () => {
  const result = validate(valid.replaceAll("\n", "\r\n"));
  assert.equal(result.valid, true, result.errors.join("\n"));
  assert.equal(result.normalized, valid);
});
test("rejects invalid octets, prefixes and empty list entries", () => {
  for (const value of ["300.1.1.1/24", "10.0.0.1/33", "010.0.0.1/24", "10.0.0.1/024", "0.0.0.0/0,", "::/129", "::/064", "::/", ""]) {
    assertBoth(dual.replace("AllowedIPs = 0.0.0.0/0, ::/0", `AllowedIPs = ${value}`), false, value);
  }
});
test("accepts dual-stack and IPv6-only tunnel configurations in both validators", () => {
  assertBoth(dual, true, "dual-stack with IPv4 DNS");
  assertBoth(ipv6Only, true, "IPv6-only");
  assertBoth(dual.replace("DNS = 10.6.0.1", "DNS = 10.6.0.1, fd86:5a72:3ff1:111::1"), true, "dual DNS");
  assertBoth("\uFEFF" + dual.replaceAll("\n", "\r\n"), true, "BOM and CRLF");
});
test("NAT6 accepts the same boolean values as NAT and permits IPv6 DNS", () => {
  for (const value of ["true", "false", "0", "1", "yes", "no", "TRUE", "False", "YeS", "NO"]) {
    assertBoth(dual.replace("LANInterface = br0", `LANInterface = br0\nNAT6 = ${value}`), true, `NAT6=${value}`);
  }
  assertBoth(ipv6Only.replace("LANInterface = br0", "LANInterface = br0\nNAT6 = false"), true, "IPv6 DNS with IPv6 NAT disabled");
  assertBoth(valid.replace("LANInterface = br0", "LANInterface = br0\nNAT6 = false"), true, "IPv4-only with unused IPv6 override");
});
test("NAT6 rejects invalid values, duplicate settings, and placement in Peer", () => {
  for (const value of ["", "enabled", "2", "-1", "truefalse", "true,false"]) {
    assertBoth(dual.replace("LANInterface = br0", `LANInterface = br0\nNAT6 = ${value}`), false, `NAT6=${value}`);
  }
  assertBoth(dual.replace("LANInterface = br0", "LANInterface = br0\nNAT6 = true\nNAT6 = false"), false, "duplicate NAT6");
  assertBoth(dual + "NAT6 = false\n", false, "NAT6 in Peer");
});
test("IPv6 routed mode warning follows NAT6 override and NAT inheritance", () => {
  for (const [settings, expected] of [["", false], ["NAT = false\n", true], ["NAT = 0\n", true], ["NAT = false\nNAT6 = true\n", false], ["NAT = true\nNAT6 = false\n", true], ["NAT = no\nNAT6 = YeS\n", false], ["NAT6 = NO\n", true]]) {
    const source = dual.replace("LANInterface = br0", settings + "LANInterface = br0");
    assertBoth(source, true, settings || "defaults");
    const warnings = validate(source).warnings;
    assert.equal(warnings.some((warning) => warning.includes("IPv6 NAT")), expected, settings || "defaults");
    if (expected) assert.match(warnings.join(" "), /AllowedIPs.*LAN IPv6/);
  }
  assert.equal(validate(valid.replace("LANInterface = br0", "NAT6 = false\nLANInterface = br0")).warnings.some((warning) => warning.includes("IPv6 NAT")), false);
});
test("IPv6 parsing accepts compression, expanded words and IPv4 tails", () => {
  for (const value of ["::", "::1", "2001:DB8:0:1::2", "2001:db8:0000:0001:0000:0000:0000:0002", "::ffff:192.0.2.1", "2001:db8:0:0:0:0:192.0.2.1"]) {
    assert.equal(ipv6(value), true, value);
    assert.equal(cidr(`${value}/128`), true, value);
    assertBoth(dual.replace("fd86:5a72:3ff1:111::2/128", `${value}/128`), true, value);
  }
});
test("both validators reject malformed IPv6 addresses", () => {
  for (const value of ["2001:db8::1::2", "1:2:3:4:5:6:7", "1:2:3:4:5:6:7:8:9", ":::1", "::ffff:192.0.2.999", "::ffff:192.168.001.1", "2001:db8::g", "fe80::1%wlan0", "[fd00::1]", "12345::1", ":1:2:3:4:5:6:7"]) {
    assert.equal(ipv6(value), false, value);
    assertBoth(dual.replace("fd86:5a72:3ff1:111::2/128", `${value}/128`), false, value);
  }
});
test("each routed and DNS address family needs an Interface Address", () => {
  assertBoth(valid.replace("AllowedIPs = 0.0.0.0/0", "AllowedIPs = 0.0.0.0/0, ::/0"), false, "IPv6 route without address");
  assertBoth(ipv6Only.replace("AllowedIPs = ::/0", "AllowedIPs = ::/0, 0.0.0.0/0"), false, "IPv4 route without address");
  assertBoth(valid.replace("DNS = 1.1.1.1", "DNS = fd00::1"), false, "IPv6 DNS without address");
  assertBoth(ipv6Only.replace("DNS = fd00::1", "DNS = 1.1.1.1"), false, "IPv4 DNS without address");
});
test("DNS accepts at most one address per family covered by a matching route", () => {
  const narrow = dual.replace("AllowedIPs = 0.0.0.0/0, ::/0", "AllowedIPs = 10.6.0.0/24, fd86:5a72:3ff1:111::/64");
  assertBoth(narrow.replace("DNS = 10.6.0.1", "DNS = 10.6.0.1, fd86:5a72:3ff1:111::1"), true);
  assertBoth(narrow.replace("DNS = 10.6.0.1", "DNS = fd86:5a72:3ff1:112::1"), false);
  assertBoth(dual.replace("DNS = 10.6.0.1", "DNS = 10.6.0.1, 10.6.0.2"), false);
  assertBoth(dual.replace("DNS = 10.6.0.1", "DNS = fd00::1, fd00::2"), false);
  assertBoth(dual.replace("DNS = 10.6.0.1", "DNS = ::ffff:10.6.0.1, fd00::1"), false);
  assertBoth(dual.replace("DNS = 10.6.0.1", "DNS = resolver.example.com"), false);
  assertBoth(dual.replace("DNS = 10.6.0.1", "DNS = "), true);
});
test("IPv6 prefixes compare all bytes and never match IPv4 addresses", () => {
  assert.equal(contains("::/0", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"), true);
  assert.equal(contains("2001:db8::a/127", "2001:db8::b"), true);
  assert.equal(contains("2001:db8::a/127", "2001:db8::c"), false);
  assert.equal(contains("2001:db8::1/128", "2001:0db8:0:0:0:0:0:1"), true);
  assert.equal(contains("2001:db8::1/128", "2001:db8::2"), false);
  assert.equal(contains("::ffff:c000:200/120", "::ffff:192.0.2.99"), true);
  assert.equal(contains("::ffff:0:0/96", "192.0.2.99"), false);
  assert.equal(contains("0.0.0.0/0", "::ffff:192.0.2.99"), false);
  for (const [route, dns, covered] of [["2001:db8::a/127", "2001:db8::b", true], ["2001:db8::a/127", "2001:db8::c", false], ["::ffff:c000:200/120", "::ffff:192.0.2.99", true], ["::ffff:c000:200/120", "::ffff:192.0.3.1", false]]) {
    assertBoth(ipv6Only.replace("DNS = fd00::1", `DNS = ${dns}`).replace("AllowedIPs = ::/0", `AllowedIPs = ${route}`), covered, `${route} contains ${dns}`);
  }
});
test("IPv6 duplicate routes are canonicalized across peers", () => {
  const second = (route) => `[Peer]\nPublicKey = ${Buffer.alloc(32, 3).toString("base64")}\nAllowedIPs = ${route}\n`;
  for (const [first, duplicate] of [["::/0", "0:0:0:0:0:0:0:1/0"], ["2001:db8:abcd:1200::1/57", "2001:0DB8:abcd:127f:ffff::2/57"], ["::ffff:192.0.2.1/120", "::ffff:c000:2ff/120"]]) {
    const source = dual.replace("0.0.0.0/0, ::/0", `0.0.0.0/0, ${first}`);
    assertBoth(source + second(duplicate), false, `${first} equals ${duplicate}`);
  }
  assertBoth(dual + second("2001:db8:1::/64"), true, "overlapping routes with different prefix lengths");
  assertBoth(dual.replace("::/0", "2001:db8:1::/64") + second("2001:db8:2::/64"), true, "different IPv6 subnets");
});
test("both validators reject equivalent routes repeated in a single peer", () => {
  for (const [first, duplicate] of [["::/0", "0:0:0:0:0:0:0:0/0"], ["2001:db8:abcd:1200::1/57", "2001:0DB8:abcd:127f:ffff::2/57"], ["::ffff:192.0.2.1/120", "::ffff:c000:2ff/120"]]) {
    assertBoth(dual.replace("::/0", `${first}, ${duplicate}`), false, `${first} duplicates ${duplicate}`);
  }
  assertBoth(valid.replace("0.0.0.0/0", "0.0.0.0/0, 0.0.0.0/0"), false, "exact IPv4 route duplicate");
  assertBoth(dual.replace("::/0", "2001:db8:1::/64, 2001:db8:2::/64"), true, "distinct same-peer IPv6 routes");
});
test("Address rejects identical hosts and prefixes without rejecting distinct hosts in one subnet", () => {
  for (const addresses of ["fd00::2/64, FD00:0:0:0:0:0:0:0002/64", "::ffff:192.0.2.1/128, ::ffff:c000:201/128", "fd00::2/64, fd00::2/64"]) {
    assertBoth(ipv6Only.replace("Address = fd00::2/64", `Address = ${addresses}`), false, addresses);
  }
  assertBoth(valid.replace("Address = 10.0.0.2/24", "Address = 10.0.0.2/24, 10.0.0.2/24"), false, "duplicate IPv4 address");
  assertBoth(ipv6Only.replace("Address = fd00::2/64", "Address = fd00::2/64, fd00::3/64"), true, "distinct IPv6 hosts in one subnet");
  assertBoth(valid.replace("Address = 10.0.0.2/24", "Address = 10.0.0.2/24, 10.0.0.3/24"), true, "distinct IPv4 hosts in one subnet");
});
test("IPv6 MTU is at least 1280 while IPv4 retains its lower bound", () => {
  for (const value of [576, 1279]) assertBoth(dual.replace("LANInterface = br0", `LANInterface = br0\nMTU = ${value}`), false, `IPv6 MTU ${value}`);
  for (const value of [1280, 1420, 9000]) assertBoth(dual.replace("LANInterface = br0", `MTU = ${value}\nLANInterface = br0`), true, `IPv6 MTU ${value}`);
  assertBoth(valid.replace("Address =", "MTU = 576\nAddress ="), true, "IPv4 MTU 576");
  assertBoth(valid.replace("Address =", "MTU = 575\nAddress ="), false, "IPv4 MTU 575");
  assertBoth(dual.replace("Address =", "MTU = 1279\nAddress ="), false, "MTU before IPv6 address");
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
  for (const value of ["-host:80", "host:65536", "host:0", "[::::]:80", "999.1.1.1:80", "2001:db8::1:80", ":80"]) {
    assert.equal(endpoint(value), false, value);
    assertBoth(valid.replace("[2001:db8::1]:51820", value), false, value);
  }
  assertBoth(valid.replace("[2001:db8::1]:51820", "[::ffff:192.0.2.1]:51820"), true);
  assertBoth(valid.replace("[2001:db8::1]:51820", "vpn.example.com:51820"), true);
  const result = validate(valid.replace(privateKey, "secret"));
  assert.equal(result.valid, false);
  assert.equal(result.errors.join(" ").includes("secret"), false);
  assert.equal(redact(valid).includes(privateKey), false);
});
test("DNS interception rejects port 53 endpoints only when their transport family can conflict", () => {
  for (const value of ["192.0.2.1:53", "192.0.2.1:00053", "vpn.example.com:53"]) {
    assertBoth(valid.replace("[2001:db8::1]:51820", value), false, value);
  }
  assertBoth(valid.replace("[2001:db8::1]:51820", "[2001:db8::1]:53"), true, "IPv6 endpoint with IPv4-only DNS");
  assertBoth(ipv6Only.replace("[2001:db8::1]:51820", "192.0.2.1:53"), true, "IPv4 endpoint with IPv6-only DNS");
  for (const value of ["[2001:db8::1]:53", "[::ffff:192.0.2.1]:53", "vpn.example.com:53"]) {
    assertBoth(ipv6Only.replace("[2001:db8::1]:51820", value), false, value);
  }
  const dualDNS = dual.replace("DNS = 10.6.0.1", "DNS = 10.6.0.1, fd86:5a72:3ff1:111::1");
  for (const value of ["192.0.2.1:53", "[2001:db8::1]:53", "vpn.example.com:53"]) {
    assertBoth(dualDNS.replace("[2001:db8::1]:51820", value), false, `dual DNS ${value}`);
    assertBoth(dual.replace("DNS = 10.6.0.1\n", "").replace("[2001:db8::1]:51820", value), true, `no DNS ${value}`);
  }
});
test("supports multiple peers with distinct routes and keys", () => {
  const source = valid + `[Peer]\nPublicKey = ${Buffer.alloc(32, 3).toString("base64")}\nAllowedIPs = 10.20.0.0/16\n`;
  assert.equal(validate(source).valid, true);
  assert.equal(validate(source.replace("10.20.0.0/16", "0.0.0.0/0")).valid, false);
});

module.exports = { valid };
