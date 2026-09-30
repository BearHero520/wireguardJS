const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const root = path.resolve(__dirname, "..");
const bash = process.platform === "win32" ? "C:/Program Files/Git/bin/bash.exe" : "/bin/bash";
const fixture = `[Interface]\nPrivateKey = ${Buffer.alloc(32, 1).toString("base64")}\nAddress = 10.0.0.2/24\nDNS = 1.1.1.1\nLANInterface = br0\n[Peer]\nPublicKey = ${Buffer.alloc(32, 2).toString("base64")}\nAllowedIPs = 0.0.0.0/0\n`;
const mock = `#!/bin/sh
name="$(basename "$0")"
printf '%s %s\\n' "$name" "$*" >> "$WG_TEST_DIR/trace"
if [ -n "$WG_TEST_FAIL" ]; then
  case "$name $*" in *"$WG_TEST_FAIL"*) exit 1 ;; esac
fi
case "$name $*" in
  'wg --version') echo 'wireguard-tools test'; exit 0 ;;
  'wg show interfaces') [ ! -f "$WG_TEST_DIR/up" ] || echo wg0; exit 0 ;;
  'ip link show wg0') test -f "$WG_TEST_DIR/up"; exit $? ;;
  'ip link add wg0 type wireguard') touch "$WG_TEST_DIR/up"; exit 0 ;;
  'ip link del wg0') rm -f "$WG_TEST_DIR/up"; exit 0 ;;
  'ip route del '*|'ip rule del '*) exit 1 ;;
  iptables*) case " $* " in *' -D '*|*' -C '*) exit 1 ;; esac ;;
  mv*) exec /usr/bin/mv "$@" ;;
esac
exit 0
`;

function sandbox(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "wgjs-test-")).replaceAll("\\", "/");
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  fs.cpSync(path.join(root, "resources"), `${dir}/module`, { recursive: true });
  fs.mkdirSync(`${dir}/mock`);
  for (const tool of ["ip", "iptables", "mv"]) { fs.writeFileSync(`${dir}/mock/${tool}`, mock); fs.chmodSync(`${dir}/mock/${tool}`, 0o755); }
  fs.writeFileSync(`${dir}/module/bin/wg`, mock); fs.chmodSync(`${dir}/module/bin/wg`, 0o755);
  fs.writeFileSync(`${dir}/module/wg0.conf`, fixture);
  const common = `${dir}/module/scripts/common.sh`;
  fs.writeFileSync(common, fs.readFileSync(common, "utf8").replace("/data/local/tmp/kano_wireguard.lock", `${dir}/lock`));
  const run = `${dir}/module/scripts/run.sh`;
  fs.writeFileSync(run, fs.readFileSync(run, "utf8").replace("/proc/sys/net/ipv4/ip_forward", `${dir}/ip_forward`));
  const mockPath = process.platform === "win32" ? `$(cygpath -u '${dir}/mock')` : `${dir}/mock`;
  const invoke = (script, fail = "") => spawnSync(bash, ["-c", `export PATH="${mockPath}:$PATH"; ${script}`], { encoding: "utf8", timeout: 30000, env: { ...process.env, WG_TEST_DIR: dir, WG_TEST_FAIL: fail, KANO_WG_LOCKED: "" } });
  const execute = (command, fail = "", holdLock = false) => invoke(`${holdLock ? `printf '%s\\n' "$$" > '${dir}/lock/pid';` : ""} sh '${run}' ${command}`, fail);
  const manage = `${dir}/module/scripts/manage.sh`;
  fs.writeFileSync(manage, fs.readFileSync(manage, "utf8").replace("/sdcard/ufi_tools_boot.sh", `${dir}/boot.sh`).replace("/data/data/com.minikano.f50_sms/files/", `${dir}/uploads/`));
  fs.mkdirSync(`${dir}/uploads`);
  const executeManage = (command, fail = "") => invoke(`sh '${manage}' ${command}`, fail);
  const trace = () => fs.readFileSync(`${dir}/trace`, "utf8");
  return { dir, execute, executeManage, invoke, trace };
}

test("invalid configuration does not stop an active interface", (t) => {
  const s = sandbox(t);
  fs.writeFileSync(`${s.dir}/up`, "");
  fs.writeFileSync(`${s.dir}/module/wg0.conf`, fixture.replace("0.0.0.0/0", "::/0"));
  const result = s.execute("start");
  assert.notEqual(result.status, 0, result.stdout + result.stderr);
  assert.match(result.stdout, /AllowedIPs/);
  assert.equal(fs.existsSync(`${s.dir}/up`), true);
});
test("stopping uses the active DNS and LAN snapshot after edits", (t) => {
  const s = sandbox(t);
  const started = s.execute("start");
  assert.equal(started.status, 0, started.stdout + started.stderr);
  assert.equal(fs.existsSync(`${s.dir}/module/.state/active.conf`), true);
  fs.writeFileSync(`${s.dir}/module/wg0.conf`, fixture.replace("1.1.1.1", "8.8.8.8").replace("br0", "lan1"));
  fs.writeFileSync(`${s.dir}/trace`, "");
  const stopped = s.execute("stop");
  assert.equal(stopped.status, 0, stopped.stdout + stopped.stderr);
  assert.match(s.trace(), /PREROUTING -i br0.*KANO_DNS_wg0/);
  assert.match(s.trace(), /route del 1\.1\.1\.1\/32/);
  assert.doesNotMatch(s.trace(), /8\.8\.8\.8|lan1/);
  assert.equal(fs.existsSync(`${s.dir}/up`), false);
  assert.equal(fs.existsSync(`${s.dir}/module/.state/active.conf`), false);
});
test("route and firewall failures propagate and roll back the interface", (t) => {
  const s = sandbox(t);
  for (const failure of ["iptables -t mangle -N", "iptables -I FORWARD", "ip route add 10.20.0.0/16"]) {
    fs.writeFileSync(`${s.dir}/module/wg0.conf`, fixture.replace("AllowedIPs = 0.0.0.0/0", "AllowedIPs = 0.0.0.0/0, 10.20.0.0/16"));
    const result = s.execute("start", failure);
    assert.notEqual(result.status, 0, failure + result.stdout + result.stderr);
    assert.equal(fs.existsSync(`${s.dir}/up`), false, failure);
  }
});
test("lock blocks concurrent mutations", (t) => {
  const s = sandbox(t);
  fs.mkdirSync(`${s.dir}/lock`);
  const result = s.execute("start", "", true);
  assert.notEqual(result.status, 0);
  assert.match(result.stdout, /busy/);
});

test("save backs up and replaces config; restore swaps the two versions", (t) => {
  const s = sandbox(t);
  const updated = fixture.replace("10.0.0.2/24", "10.0.0.3/24");
  const upload = `${s.dir}/uploads/config.conf`;
  fs.writeFileSync(upload, updated);
  const saved = s.executeManage(`save '${upload}'`);
  assert.equal(saved.status, 0, saved.stdout + saved.stderr);
  assert.equal(fs.readFileSync(`${s.dir}/module/wg0.conf`, "utf8"), updated);
  assert.equal(fs.readFileSync(`${s.dir}/module/wg0.conf.bak`, "utf8"), fixture);
  assert.equal(fs.existsSync(upload), false);
  const restored = s.executeManage("restore");
  assert.equal(restored.status, 0, restored.stdout + restored.stderr);
  assert.equal(fs.readFileSync(`${s.dir}/module/wg0.conf`, "utf8"), fixture);
  assert.equal(fs.readFileSync(`${s.dir}/module/wg0.conf.bak`, "utf8"), updated);
});
test("failed config move returns failure and keeps the old config", (t) => {
  const s = sandbox(t);
  const upload = `${s.dir}/uploads/config.conf`;
  fs.writeFileSync(upload, fixture.replace("10.0.0.2/24", "10.0.0.3/24"));
  const saved = s.executeManage(`save '${upload}'`, "mv -f");
  assert.notEqual(saved.status, 0);
  assert.doesNotMatch(saved.stdout, /SAVED/);
  assert.equal(fs.readFileSync(`${s.dir}/module/wg0.conf`, "utf8"), fixture);
});
test("boot toggle preserves unrelated entries and is idempotent", (t) => {
  const s = sandbox(t);
  fs.writeFileSync(`${s.dir}/boot.sh`, "#!/system/bin/sh\nsh /data/another/service.sh &\n");
  for (const action of ["boot-on", "boot-on"]) {
    const result = s.executeManage(action);
    assert.equal(result.status, 0, result.stdout + result.stderr);
  }
  const enabled = fs.readFileSync(`${s.dir}/boot.sh`, "utf8");
  assert.equal(enabled.match(/kano_wireguard/g).length, 1);
  assert.equal(s.executeManage("boot-off").status, 0);
  assert.equal(fs.readFileSync(`${s.dir}/boot.sh`, "utf8"), "#!/system/bin/sh\nsh /data/another/service.sh &\n");
});

function prepareInstaller(s) {
  fs.mkdirSync(`${s.dir}/package`);
  fs.cpSync(`${s.dir}/module`, `${s.dir}/package/wg_res`, { recursive: true });
  fs.writeFileSync(`${s.dir}/package/wg_res/VERSION`, "2.0.0\n");
  fs.writeFileSync(`${s.dir}/package/wg_res/service.sh`, '#!/bin/sh\n[ "$WG_TEST_FAIL_RESTART" != 1 ]\n');
  fs.writeFileSync(`${s.dir}/module/service.sh`, '#!/bin/sh\nprintf "old version restarted\\n" >> "$WG_TEST_DIR/trace"\n');
  fs.writeFileSync(`${s.dir}/module/scripts/run.sh`, '#!/bin/sh\nprintf "old version stopped\\n" >> "$WG_TEST_DIR/trace"\nrm -f "$WG_TEST_DIR/up"\n');
  const common = fs.readFileSync(`${s.dir}/module/scripts/common.sh`, "utf8");
  const installer = fs.readFileSync(path.join(root, "resources/install.sh"), "utf8")
    .replace("ROOT=/data/kano_wireguard", `ROOT='${s.dir}/module'`)
    .replace("PREVIOUS=/data/kano_wireguard.previous", `PREVIOUS='${s.dir}/previous'`)
    .replace('/data/.kano_wireguard.stage.$$', `${s.dir}/stage.$$`)
    .replace('chown -R 0:0 "$ROOT"', ': # ownership is verified on-device, not on the test host');
  fs.writeFileSync(`${s.dir}/install.sh`, common + "\n" + installer);
  const packed = s.invoke(`cd '${s.dir}' && tar -czf resources.tar.gz -C package wg_res`);
  assert.equal(packed.status, 0, packed.stderr);
  const digest = require("node:crypto").createHash("sha256").update(fs.readFileSync(`${s.dir}/resources.tar.gz`)).digest("hex");
  const shellDir = process.platform === "win32" ? s.dir.replace(/^([A-Za-z]):/, (_, drive) => `/${drive.toLowerCase()}`) : s.dir;
  return (override = digest, failRestart = false) => s.invoke(`${failRestart ? 'export WG_TEST_FAIL_RESTART=1;' : ""} sh '${s.dir}/install.sh' '${shellDir}/resources.tar.gz' '${override}'`);
}
test("upgrade preserves edited config and keeps a rollback directory", (t) => {
  const s = sandbox(t);
  const install = prepareInstaller(s);
  const edited = fixture.replace("10.0.0.2/24", "10.0.0.99/24");
  fs.writeFileSync(`${s.dir}/module/wg0.conf`, edited);
  const result = install();
  assert.equal(result.status, 0, result.stdout + result.stderr);
  assert.equal(fs.readFileSync(`${s.dir}/module/wg0.conf`, "utf8"), edited);
  assert.equal(fs.existsSync(`${s.dir}/previous`), true);
});
test("digest mismatch leaves the existing install untouched", (t) => {
  const s = sandbox(t);
  const install = prepareInstaller(s);
  const result = install("0".repeat(64));
  assert.notEqual(result.status, 0);
  assert.match(result.stdout, /SHA-256 mismatch/);
  assert.equal(fs.readFileSync(`${s.dir}/module/wg0.conf`, "utf8"), fixture);
  assert.equal(fs.existsSync(`${s.dir}/previous`), false);
});
test("failed restart restores the previous resource version", (t) => {
  const s = sandbox(t);
  const install = prepareInstaller(s);
  fs.writeFileSync(`${s.dir}/up`, "");
  const result = install(undefined, true);
  assert.notEqual(result.status, 0);
  assert.match(fs.readFileSync(`${s.dir}/module/service.sh`, "utf8"), /old version restarted/);
  assert.match(s.trace(), /old version restarted/);
});
