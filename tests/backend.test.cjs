const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const root = path.resolve(__dirname, "..");
const bash = process.platform === "win32" ? "C:/Program Files/Git/bin/bash.exe" : "/bin/bash";
const fixture = `[Interface]\nPrivateKey = ${Buffer.alloc(32, 1).toString("base64")}\nAddress = 10.0.0.2/24\nDNS = 1.1.1.1\nLANInterface = br0\n[Peer]\nPublicKey = ${Buffer.alloc(32, 2).toString("base64")}\nAllowedIPs = 0.0.0.0/0\n`;
const dualStackFixture = fixture
  .replace("Address = 10.0.0.2/24", "Address = 10.6.0.2/32, fd86:5a72:3ff1:111::2/128")
  .replace("DNS = 1.1.1.1", "DNS = 10.6.0.1, fd86:5a72:3ff1:111::1")
  .replace("AllowedIPs = 0.0.0.0/0", "AllowedIPs = 0.0.0.0/0, ::/0")
  .concat("Endpoint = [2001:db8::10]:51820\nPersistentKeepalive = 25\n");
const mock = `#!/bin/sh
name="\${0##*/}"
printf '%s %s\\n' "$name" "$*" >> "$WG_TEST_DIR/trace"
if [ -n "$WG_TEST_FAIL" ]; then
  case "$name $*" in
    *"$WG_TEST_FAIL"*)
      [ -z "$WG_TEST_FAIL_STDERR" ] || printf '%s\\n' "$WG_TEST_FAIL_STDERR" >&2
      exit 1 ;;
  esac
fi
add_record() {
  record_file="$WG_TEST_DIR/$1"
  while IFS= read -r record; do [ "$record" != "$2" ] || return 1; done < "$record_file"
  printf '%s\\n' "$2" >> "$record_file"
}
remove_record() {
  record_file="$WG_TEST_DIR/$1"
  removed=1; contents=''
  while IFS= read -r record; do
    if [ "$record" = "$2" ] && [ "$removed" = 1 ]; then removed=0; else contents="$contents$record
"; fi
  done < "$record_file"
  printf '%s' "$contents" > "$record_file"
  return "$removed"
}
drop_prefix() {
  record_file="$WG_TEST_DIR/$1"
  contents=''
  while IFS= read -r record; do
    case "$record" in "$2"*) ;; *) contents="$contents$record
" ;; esac
  done < "$record_file"
  printf '%s' "$contents" > "$record_file"
}
chain_exists() {
  case "$1" in PREROUTING|INPUT|FORWARD|OUTPUT|POSTROUTING) return 0 ;; esac
  while IFS= read -r record; do [ "$record" != "$name|$table|$1" ] || return 0; done < "$WG_TEST_DIR/chains"
  return 1
}
case "$name $*" in
  'wg --version') echo 'wireguard-tools test'; exit 0 ;;
  'wg show interfaces') [ ! -f "$WG_TEST_DIR/up" ] || echo wg0; exit 0 ;;
  'wg setconf wg0 '*) cp "$3" "$WG_TEST_DIR/setconf"; exit $? ;;
  'ip link show wg0') test -f "$WG_TEST_DIR/up"; exit $? ;;
  'ip link add wg0 type wireguard')
    touch "$WG_TEST_DIR/up"
    mkdir -p "$WG_TEST_DIR/proc/net/ipv6/conf/wg0"
    printf '0\\n' > "$WG_TEST_DIR/proc/net/ipv6/conf/wg0/forwarding"
    printf '1\\n' > "$WG_TEST_DIR/proc/net/ipv6/conf/wg0/accept_ra"
    exit 0 ;;
  'ip link del wg0')
    rm -f "$WG_TEST_DIR/up"
    rm -rf "$WG_TEST_DIR/proc/net/ipv6/conf/wg0"
    for kind in routes addresses; do
      awk '!/ dev wg0( |$)/' "$WG_TEST_DIR/$kind" > "$WG_TEST_DIR/$kind.tmp"
      /usr/bin/mv "$WG_TEST_DIR/$kind.tmp" "$WG_TEST_DIR/$kind"
    done
    exit 0 ;;
  mv*) exec /usr/bin/mv "$@" ;;
esac
case "$name" in
  iptables|ip6tables)
    table=filter
    if [ "$1" = -t ]; then table="$2"; shift 2; fi
    case "$1" in
      -L) exit 0 ;;
      -S)
        shift; query_chain="\${1:-}"
        [ -z "$query_chain" ] || chain_exists "$query_chain" || exit 1
        while IFS='|' read -r record_name record_table record_chain; do
          [ "$record_name|$record_table" = "$name|$table" ] || continue
          [ -z "$query_chain" ] || [ "$query_chain" = "$record_chain" ] || continue
          printf '%s\\n' "-N $record_chain"
        done < "$WG_TEST_DIR/chains"
        while IFS='|' read -r record_name record_table record_chain record_args; do
          [ "$record_name|$record_table" = "$name|$table" ] || continue
          [ -z "$query_chain" ] || [ "$query_chain" = "$record_chain" ] || continue
          printf '%s\\n' "-A $record_chain $record_args"
        done < "$WG_TEST_DIR/rules"
        exit 0 ;;
    esac
    action="$1"; chain="$2"; shift 2
    case "$action" in
      -N) add_record chains "$name|$table|$chain"; exit $? ;;
      -X)
        while IFS='|' read -r record_name record_table record_chain record_args; do
          [ "$record_name|$record_table" = "$name|$table" ] || continue
          [ "$record_chain" != "$chain" ] || exit 1
          case " $record_args " in *" -j $chain "*|*" -g $chain "*) exit 1 ;; esac
        done < "$WG_TEST_DIR/rules"
        remove_record chains "$name|$table|$chain"; exit $? ;;
      -F) drop_prefix rules "$name|$table|$chain|"; exit $? ;;
      -A|-I)
        chain_exists "$chain" || exit 1
        case "$1" in ''|*[!0-9]*) ;; *) shift ;; esac
        printf '%s\\n' "$name|$table|$chain|$*" >> "$WG_TEST_DIR/rules"
        exit 0 ;;
      -D) remove_record rules "$name|$table|$chain|$*"; exit $? ;;
      -C) grep -Fqx -- "$name|$table|$chain|$*" "$WG_TEST_DIR/rules"; exit $? ;;
    esac
    ;;
  ip)
    family=4
    case "$1" in -4) shift ;; -6) family=6; shift ;; esac
    object="$1"; action="$2"; shift 2
    case "$object $action" in
      'rule add') add_record policies "$family|$*"; exit $? ;;
      'rule del') remove_record policies "$family|$*"; exit $? ;;
      'rule show')
        awk -F '[| ]+' -v family="$family" '$1 == family {mark=""; table=""; priority=""; for(i=2;i<=NF;i++) {if($i=="fwmark") mark=$(i+1); if($i=="table") table=$(i+1); if($i=="priority") priority=$(i+1)} print priority ": from all fwmark " mark " lookup " table}' "$WG_TEST_DIR/policies"
        exit 0 ;;
      'route add') add_record routes "$family|$*"; exit $? ;;
      'route del') remove_record routes "$family|$*"; exit $? ;;
      'route flush')
        [ "$*" = cache ] && exit 0
        flush_table=''; flush_dev=''
        while [ "$#" -gt 0 ]; do
          case "$1" in table) flush_table="$2"; shift ;; dev) flush_dev="$2"; shift ;; esac
          shift
        done
        awk -v family="$family|" -v table="$flush_table" -v dev="$flush_dev" '!(index($0, family) == 1 && index($0, " table " table) && index($0, " dev " dev))' "$WG_TEST_DIR/routes" > "$WG_TEST_DIR/routes.tmp"
        /usr/bin/mv "$WG_TEST_DIR/routes.tmp" "$WG_TEST_DIR/routes"
        exit 0 ;;
      'route show')
        awk -v family="$family|" -v query="$*" 'BEGIN {count=split(query, args, " ")} index($0, family) == 1 {line=substr($0, length(family)+1); matches=1; for(i=1;i<=count;i++) if(!index(" " line " ", " " args[i] " ")) matches=0; if(matches) print line}' "$WG_TEST_DIR/routes"
        exit 0 ;;
      'address add') add_record addresses "$family|$*"; exit $? ;;
      'address show')
        if [ "$*" = 'dev br0' ]; then
          if [ "$family" = 6 ]; then
            printf '    inet6 fd42:50::1/64 scope global\\n    inet6 fe80::1/64 scope link\\n'
          else
            printf '    inet 192.168.50.1/24 scope global br0\\n'
          fi
        fi
        exit 0 ;;
    esac
    ;;
esac
exit 0
`;

function sandbox(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "wgjs-test-")).replaceAll("\\", "/");
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  fs.cpSync(path.join(root, "resources"), `${dir}/module`, { recursive: true });
  fs.mkdirSync(`${dir}/mock`);
  for (const tool of ["ip", "iptables", "ip6tables", "mv"]) { fs.writeFileSync(`${dir}/mock/${tool}`, mock); fs.chmodSync(`${dir}/mock/${tool}`, 0o755); }
  // A closed PATH prevents these tests from reaching any host networking tools.
  for (const tool of ["sh", "awk", "basename", "cat", "chmod", "cp", "date", "dirname", "find", "grep", "gzip", "head", "mkdir", "rm", "sed", "sha256sum", "sort", "tail", "tar", "touch", "tr", "wc"]) {
    fs.writeFileSync(`${dir}/mock/${tool}`, `#!/bin/sh\nexec /usr/bin/${tool} "$@"\n`);
    fs.chmodSync(`${dir}/mock/${tool}`, 0o755);
  }
  for (const state of ["trace", "rules", "chains", "policies", "routes", "addresses"]) fs.writeFileSync(`${dir}/${state}`, "");
  fs.writeFileSync(`${dir}/module/bin/wg`, mock); fs.chmodSync(`${dir}/module/bin/wg`, 0o755);
  fs.writeFileSync(`${dir}/module/wg0.conf`, fixture);
  const common = `${dir}/module/scripts/common.sh`;
  fs.writeFileSync(common, fs.readFileSync(common, "utf8").replace("/data/local/tmp/kano_wireguard.lock", `${dir}/lock`));
  const run = `${dir}/module/scripts/run.sh`;
  for (const device of ["all", "default", "br0", "wan0"]) {
    fs.mkdirSync(`${dir}/proc/net/ipv6/conf/${device}`, { recursive: true });
    for (const field of ["forwarding", "disable_ipv6", "accept_ra"]) fs.writeFileSync(`${dir}/proc/net/ipv6/conf/${device}/${field}`, field === "accept_ra" ? "1\n" : "0\n");
  }
  for (const script of [run, `${dir}/module/scripts/network.sh`]) {
    if (fs.existsSync(script)) fs.writeFileSync(script, fs.readFileSync(script, "utf8")
      .replaceAll("/proc/sys/net/ipv4/ip_forward", `${dir}/ip_forward`)
      .replaceAll("/proc/sys/net/ipv6", `${dir}/proc/net/ipv6`));
  }
  const mockPath = process.platform === "win32" ? `$(cygpath -u '${dir}/mock')` : `${dir}/mock`;
  const invoke = (script, fail = "") => {
    const fault = typeof fail === "string" ? { match: fail } : fail;
    return spawnSync(bash, ["-c", `export PATH="${mockPath}"; ${script}`], { encoding: "utf8", timeout: 60000, env: { ...process.env, WG_TEST_DIR: dir, WG_TEST_FAIL: fault.match, WG_TEST_FAIL_STDERR: fault.stderr || "", KANO_WG_LOCKED: "" } });
  };
  const execute = (command, fail = "", holdLock = false) => invoke(`${holdLock ? `printf '%s\\n' "$$" > '${dir}/lock/pid';` : ""} sh '${run}' ${command}`, fail);
  const manage = `${dir}/module/scripts/manage.sh`;
  fs.writeFileSync(manage, fs.readFileSync(manage, "utf8").replace("/sdcard/ufi_tools_boot.sh", `${dir}/boot.sh`).replace("/data/data/com.minikano.f50_sms/files/", `${dir}/uploads/`));
  fs.mkdirSync(`${dir}/uploads`);
  const executeManage = (command, fail = "") => invoke(`sh '${manage}' ${command}`, fail);
  const trace = () => fs.readFileSync(`${dir}/trace`, "utf8");
  const networkState = () => Object.fromEntries(["rules", "chains", "policies", "routes", "addresses"].map((kind) => [kind, fs.readFileSync(`${dir}/${kind}`, "utf8")]));
  return { dir, execute, executeManage, invoke, trace, networkState };
}

function assertNetworkClean(s, preservedRoutes = "") {
  for (const [kind, value] of Object.entries(s.networkState())) assert.equal(value, kind === "routes" ? preservedRoutes : "", `Leftover ${kind}: ${value}`);
  assert.equal(fs.existsSync(`${s.dir}/up`), false);
  assert.equal(fs.existsSync(`${s.dir}/module/.state/active.conf`), false);
}

test("invalid configuration does not stop an active interface", (t) => {
  const s = sandbox(t);
  fs.writeFileSync(`${s.dir}/up`, "");
  fs.writeFileSync(`${s.dir}/module/wg0.conf`, fixture.replace("0.0.0.0/0", "::/129"));
  const result = s.execute("start");
  assert.notEqual(result.status, 0, result.stdout + result.stderr);
  assert.match(result.stdout, /AllowedIPs/);
  assert.equal(fs.existsSync(`${s.dir}/up`), true);
});
test("stopping uses the active DNS and LAN snapshot after edits", (t) => {
  const s = sandbox(t);
  fs.writeFileSync(`${s.dir}/module/wg0.conf`, dualStackFixture);
  const started = s.execute("start");
  assert.equal(started.status, 0, started.stdout + started.stderr);
  assert.equal(fs.existsSync(`${s.dir}/module/.state/active.conf`), true);
  fs.writeFileSync(`${s.dir}/module/wg0.conf`, dualStackFixture
    .replace("DNS = 10.6.0.1, fd86:5a72:3ff1:111::1", "DNS = 8.8.8.8, 2001:4860:4860::8888")
    .replace("br0", "lan1"));
  fs.writeFileSync(`${s.dir}/trace`, "");
  const stopped = s.execute("stop");
  assert.equal(stopped.status, 0, stopped.stdout + stopped.stderr);
  assert.match(s.trace(), /PREROUTING -i br0.*KANO_DNS_wg0/);
  assert.match(s.trace(), /ip route del 10\.6\.0\.1\/32/);
  assert.match(s.trace(), /ip -6 route del fd86:5a72:3ff1:111::1\/128/);
  assert.match(s.trace(), /ip6tables -t nat -D PREROUTING -i br0/);
  assert.doesNotMatch(s.trace(), /8\.8\.8\.8|2001:4860:4860::8888|lan1/);
  assertNetworkClean(s);
});
test("dual-stack routing, DNS and NAT are installed and fully removed", (t) => {
  const s = sandbox(t);
  fs.writeFileSync(`${s.dir}/module/wg0.conf`, dualStackFixture);
  fs.writeFileSync(`${s.dir}/proc/net/ipv6/conf/br0/forwarding`, "1\n");
  fs.writeFileSync(`${s.dir}/proc/net/ipv6/conf/default/accept_ra`, "0\n");
  const started = s.execute("start");
  assert.equal(started.status, 0, started.stdout + started.stderr);
  const state = s.networkState();
  assert.match(state.addresses, /^4\|10\.6\.0\.2\/32 dev wg0$/m);
  assert.match(state.addresses, /^6\|fd86:5a72:3ff1:111::2\/128 dev wg0$/m);
  for (const family of ["4", "6"]) assert.match(state.policies, new RegExp(`^${family}\\|fwmark 2 table 101 priority 100$`, "m"));
  assert.match(state.routes, /^4\|(?:default|0\.0\.0\.0\/0) dev wg0 table 101$/m);
  assert.match(state.routes, /^6\|(?:default|::\/0) dev wg0 table 101$/m);
  assert.ok(state.routes.trim().split("\n").every((route) => route.endsWith(" table 101")), state.routes);
  for (const tool of ["iptables", "ip6tables"]) {
    assert.ok(state.rules.includes(`${tool}|mangle|PREROUTING|-i br0 -j WG_ROUTE_wg0`));
    assert.ok(state.rules.includes(`${tool}|filter|FORWARD|-i br0 -o wg0 -j ACCEPT`));
    assert.ok(state.rules.includes(`${tool}|nat|POSTROUTING|-o wg0 -j MASQUERADE`));
    assert.ok(state.rules.includes(`${tool}|mangle|KANO_DNS_MARK_wg0|-j MARK --set-mark 2`));
    for (const protocol of ["udp", "tcp"]) {
      assert.ok(state.rules.includes(`${tool}|mangle|PREROUTING|-i br0 -p ${protocol} --dport 53 -j KANO_DNS_MARK_wg0`));
      assert.ok(state.rules.includes(`${tool}|mangle|OUTPUT|-p ${protocol} --dport 53 -j KANO_DNS_MARK_wg0`));
    }
  }
  assert.match(state.rules, /iptables\|mangle\|WG_ROUTE_wg0\|-d 0\.0\.0\.0\/0 -j MARK --set-mark 2/);
  assert.match(state.rules, /ip6tables\|mangle\|WG_ROUTE_wg0\|-d ::\/0 -j MARK --set-mark 2/);
  assert.match(state.rules, /iptables\|nat\|KANO_DNS_wg0\|.*--to-destination 10\.6\.0\.1/);
  assert.match(state.rules, /ip6tables\|nat\|KANO_DNS_wg0\|.*--to-destination \[?fd86:5a72:3ff1:111::1/);
  assert.doesNotMatch(state.rules, /^iptables\|.*fd86:|^ip6tables\|.*10\.6\./m);
  assert.equal(fs.readFileSync(`${s.dir}/proc/net/ipv6/conf/all/forwarding`, "utf8").trim(), "1");
  assert.equal(fs.readFileSync(`${s.dir}/proc/net/ipv6/conf/wan0/accept_ra`, "utf8").trim(), "2");
  const unrelatedRoutes = "4|192.0.2.0/24 dev eth0 table 101\n6|2001:db8:ffff::/64 dev eth0 table 101\n";
  fs.appendFileSync(`${s.dir}/routes`, unrelatedRoutes);
  const stopped = s.execute("stop");
  assert.equal(stopped.status, 0, stopped.stdout + stopped.stderr);
  assertNetworkClean(s, unrelatedRoutes);
  for (const device of ["all", "default", "br0", "wan0"]) {
    assert.equal(fs.readFileSync(`${s.dir}/proc/net/ipv6/conf/${device}/forwarding`, "utf8").trim(), device === "br0" ? "1" : "0", device);
    assert.equal(fs.readFileSync(`${s.dir}/proc/net/ipv6/conf/${device}/accept_ra`, "utf8").trim(), device === "default" ? "0" : "1", device);
  }
});
test("IPv6 split-default routes stay in the policy table with local-scope exclusions", (t) => {
  const s = sandbox(t);
  fs.writeFileSync(`${s.dir}/module/wg0.conf`, dualStackFixture.replace("::/0", "::/1, 8000::/1"));
  const result = s.execute("start");
  assert.equal(result.status, 0, result.stdout + result.stderr);
  const { rules, routes } = s.networkState();
  for (const route of ["::/1", "8000::/1"]) assert.ok(routes.includes(`6|${route} dev wg0 table 101\n`));
  assert.ok(routes.trim().split("\n").every((route) => route.endsWith(" table 101")), routes);
  const firstMark = rules.indexOf("ip6tables|mangle|WG_ROUTE_wg0|-d ::/1 -j MARK");
  assert.ok(firstMark >= 0);
  for (const subnet of ["::1/128", "fe80::/10", "ff00::/8", "fd42:50::1/64"]) {
    const exemption = rules.indexOf(`ip6tables|mangle|WG_ROUTE_wg0|-d ${subnet} -j RETURN`);
    assert.ok(exemption >= 0 && exemption < firstMark, subnet);
  }
  assert.equal(s.execute("stop").status, 0);
  assertNetworkClean(s);
});
test("dual-stack config can use only IPv4 DNS without IPv6 DNS translation", (t) => {
  const s = sandbox(t);
  fs.writeFileSync(`${s.dir}/module/wg0.conf`, dualStackFixture.replace("DNS = 10.6.0.1, fd86:5a72:3ff1:111::1", "DNS = 10.6.0.1"));
  const result = s.execute("start");
  assert.equal(result.status, 0, result.stdout + result.stderr);
  assert.match(s.networkState().rules, /iptables\|nat\|KANO_DNS_wg0\|.*DNAT/);
  assert.doesNotMatch(s.networkState().rules, /ip6tables\|nat\|KANO_DNS_wg0\|/);
  assert.match(s.networkState().policies, /^6\|/m);
  assert.equal(s.execute("stop").status, 0);
  assertNetworkClean(s);
});
test("UTF-8 BOM configurations configure both families and sanitize the wg input", (t) => {
  const s = sandbox(t);
  fs.writeFileSync(`${s.dir}/module/wg0.conf`, "\uFEFF" + dualStackFixture);
  const result = s.execute("start");
  assert.equal(result.status, 0, result.stdout + result.stderr);
  assert.match(s.networkState().addresses, /^4\|10\.6\.0\.2\/32 dev wg0$/m);
  assert.match(s.networkState().addresses, /^6\|fd86:5a72:3ff1:111::2\/128 dev wg0$/m);
  const applied = fs.readFileSync(`${s.dir}/setconf`, "utf8");
  assert.ok(applied.startsWith("[Interface]\n"));
  assert.doesNotMatch(applied, /^(Address|DNS|LANInterface|NAT|MTU)\s*=/m);
  assert.equal(s.execute("stop").status, 0);
  assertNetworkClean(s);
});
test("NAT=false limits source NAT to local DNS sockets while preserving forwarding", (t) => {
  const s = sandbox(t);
  fs.writeFileSync(`${s.dir}/module/wg0.conf`, dualStackFixture.replace("LANInterface = br0", "LANInterface = br0\nNAT = false"));
  const result = s.execute("start");
  assert.equal(result.status, 0, result.stdout + result.stderr);
  const { rules } = s.networkState();
  assert.doesNotMatch(rules, /\|nat\|POSTROUTING\|-o wg0 -j MASQUERADE/);
  for (const [tool, dns] of [["iptables", "10.6.0.1"], ["ip6tables", "fd86:5a72:3ff1:111::1"]]) {
    assert.ok(rules.includes(`${tool}|filter|FORWARD|-i br0 -o wg0 -j ACCEPT`));
    assert.ok(rules.includes(`${tool}|filter|FORWARD|-i wg0 -o br0 -j ACCEPT`));
    assert.ok(rules.includes(`${tool}|nat|POSTROUTING|-o wg0 -j KANO_DNS_SRC_wg0`));
    for (const protocol of ["udp", "tcp"]) {
      assert.ok(rules.includes(`${tool}|nat|KANO_DNS_SRC_wg0|-d ${dns} -p ${protocol} --dport 53 -m owner --socket-exists -j MASQUERADE`));
    }
  }
  const sourceNat = rules.trim().split("\n").filter((rule) => rule.includes("MASQUERADE"));
  assert.equal(sourceNat.length, 4);
  assert.ok(sourceNat.every((rule) => rule.includes("--dport 53 -m owner --socket-exists")));
  assert.equal(s.execute("stop").status, 0);
  assertNetworkClean(s);
});
test("NAT=false without DNS does not install any source NAT", (t) => {
  const s = sandbox(t);
  fs.writeFileSync(`${s.dir}/module/wg0.conf`, dualStackFixture
    .replace("LANInterface = br0", "LANInterface = br0\nNAT = false")
    .replace(/^DNS = .*\n/m, ""));
  const result = s.execute("start");
  assert.equal(result.status, 0, result.stdout + result.stderr);
  assert.doesNotMatch(s.networkState().rules, /MASQUERADE|KANO_DNS_SRC/);
  assert.doesNotMatch(s.trace(), / -(?:A|I) [^\n]*-j MASQUERADE\n/);
  assert.equal(s.execute("stop").status, 0);
  assertNetworkClean(s);
});
test("NAT6=false keeps IPv4 NAT and dual-stack routing working without the IPv6 NAT table", (t) => {
  const s = sandbox(t);
  const fault = { match: "ip6tables -t nat", stderr: "ip6tables: cannot initialize nat table: Table does not exist" };
  fs.writeFileSync(`${s.dir}/module/wg0.conf`, dualStackFixture
    .replace("LANInterface = br0", "LANInterface = br0\nNAT = true\nNAT6 = false")
    .replace("DNS = 10.6.0.1, fd86:5a72:3ff1:111::1", "DNS = 10.6.0.1"));
  const result = s.execute("start", fault);
  assert.equal(result.status, 0, result.stdout + result.stderr);
  const state = s.networkState();
  assert.ok(state.rules.includes("iptables|nat|POSTROUTING|-o wg0 -j MASQUERADE"));
  assert.ok(state.rules.includes("ip6tables|filter|FORWARD|-i br0 -o wg0 -j ACCEPT"));
  assert.match(state.policies, /^6\|fwmark 2 table 101 priority 100$/m);
  assert.match(state.routes, /^6\|::\/0 dev wg0 table 101$/m);
  assert.doesNotMatch(state.rules + state.chains, /^ip6tables\|nat\|/m);
  assert.doesNotMatch(fs.readFileSync(`${s.dir}/setconf`, "utf8"), /^(NAT|NAT6)\s*=/m);
  const stopped = s.execute("stop", fault);
  assert.equal(stopped.status, 0, stopped.stdout + stopped.stderr);
  assertNetworkClean(s);
});
test("NAT6=false with IPv6 DNS still requires IPv6 NAT and preserves the active tunnel on failure", (t) => {
  const s = sandbox(t);
  assert.equal(s.execute("start").status, 0);
  const activeState = s.networkState();
  fs.writeFileSync(`${s.dir}/module/wg0.conf`, dualStackFixture.replace("LANInterface = br0", "LANInterface = br0\nNAT = true\nNAT6 = false"));
  fs.writeFileSync(`${s.dir}/trace`, "");
  const result = s.execute("restart", {
    match: "ip6tables -t nat",
    stderr: "ip6tables: cannot initialize nat table: Table does not exist\n" + "x".repeat(8192)
  });
  assert.notEqual(result.status, 0, result.stdout + result.stderr);
  assert.match(result.stdout, /Table does not exist/);
  assert.match(result.stdout, /DNS/);
  assert.doesNotMatch(result.stdout + result.stderr, /x{2048}/);
  assert.deepEqual(s.networkState(), activeState);
  assert.equal(fs.existsSync(`${s.dir}/up`), true);
  assert.equal(fs.readFileSync(`${s.dir}/module/.state/active.conf`, "utf8"), fixture);
  assert.doesNotMatch(s.trace(), /ip link del wg0/);
});
test("NAT6=true overrides NAT=false for IPv6 only", (t) => {
  const s = sandbox(t);
  fs.writeFileSync(`${s.dir}/module/wg0.conf`, dualStackFixture
    .replace("LANInterface = br0", "LANInterface = br0\nNAT = false\nNAT6 = true")
    .replace(/^DNS = .*\n/m, ""));
  const result = s.execute("start");
  assert.equal(result.status, 0, result.stdout + result.stderr);
  const { rules } = s.networkState();
  assert.ok(rules.includes("ip6tables|nat|POSTROUTING|-o wg0 -j MASQUERADE"));
  assert.doesNotMatch(rules, /^iptables\|.*MASQUERADE/m);
  assert.ok(rules.includes("iptables|filter|FORWARD|-i br0 -o wg0 -j ACCEPT"));
  assert.equal(s.execute("stop").status, 0);
  assertNetworkClean(s);
});
test("unsupported local DNS source NAT fails before replacing an active tunnel", (t) => {
  const s = sandbox(t);
  assert.equal(s.execute("start").status, 0);
  const activeState = s.networkState();
  fs.writeFileSync(`${s.dir}/module/wg0.conf`, dualStackFixture.replace("LANInterface = br0", "LANInterface = br0\nNAT = false"));
  fs.writeFileSync(`${s.dir}/trace`, "");
  const result = s.execute("restart", "-m owner --socket-exists -j MASQUERADE");
  assert.notEqual(result.status, 0, result.stdout + result.stderr);
  assert.deepEqual(s.networkState(), activeState);
  assert.equal(fs.existsSync(`${s.dir}/up`), true);
  assert.equal(fs.readFileSync(`${s.dir}/module/.state/active.conf`, "utf8"), fixture);
  assert.doesNotMatch(s.trace(), /ip link del wg0/);
});
test("cleanup failures keep the active snapshot and a retry removes residual state", (t) => {
  const s = sandbox(t);
  for (const failure of ["ip6tables -t nat -D PREROUTING", "ip6tables -t mangle -F WG_ROUTE_wg0", "ip -6 rule del fwmark", "ip6tables -t nat -S"]) {
    fs.mkdirSync(`${s.dir}/module/.state`, { recursive: true });
    fs.writeFileSync(`${s.dir}/module/.state/active.conf`, dualStackFixture);
    fs.writeFileSync(`${s.dir}/module/wg0.conf`, dualStackFixture.replace("br0", "lan1"));
    fs.writeFileSync(`${s.dir}/up`, "");
    fs.writeFileSync(`${s.dir}/chains`, ["iptables", "ip6tables"].flatMap((tool) => [`${tool}|nat|KANO_DNS_wg0`, `${tool}|mangle|WG_ROUTE_wg0`]).join("\n") + "\n");
    fs.writeFileSync(`${s.dir}/rules`, [["iptables", "0.0.0.0/0", "10.6.0.1"], ["ip6tables", "::/0", "fd86:5a72:3ff1:111::1"]].flatMap(([tool, route, dns]) => [
      `${tool}|nat|PREROUTING|-i br0 -p udp --dport 53 -j KANO_DNS_wg0`,
      `${tool}|nat|KANO_DNS_wg0|-p udp --dport 53 -j DNAT --to-destination ${dns}`,
      `${tool}|mangle|PREROUTING|-i br0 -j WG_ROUTE_wg0`,
      `${tool}|mangle|WG_ROUTE_wg0|-d ${route} -j MARK --set-mark 2`,
      `${tool}|filter|FORWARD|-i br0 -o wg0 -j ACCEPT`,
      `${tool}|nat|POSTROUTING|-o wg0 -j MASQUERADE`
    ]).join("\n") + "\n");
    fs.writeFileSync(`${s.dir}/policies`, "4|fwmark 2 table 101 priority 100\n6|fwmark 2 table 101 priority 100\n");
    fs.writeFileSync(`${s.dir}/routes`, "4|0.0.0.0/0 dev wg0 table 101\n6|::/0 dev wg0 table 101\n");
    fs.writeFileSync(`${s.dir}/module/.state/ipv6-sysctl`, "all/forwarding 0\ndefault/forwarding 0\ndefault/accept_ra 1\nbr0/forwarding 0\nbr0/accept_ra 1\nwan0/forwarding 0\nwan0/accept_ra 1\n");
    fs.writeFileSync(`${s.dir}/proc/net/ipv6/conf/all/forwarding`, "1\n");
    fs.writeFileSync(`${s.dir}/proc/net/ipv6/conf/wan0/accept_ra`, "2\n");
    const stopped = s.execute("stop", failure);
    assert.notEqual(stopped.status, 0, failure + stopped.stdout + stopped.stderr);
    assert.equal(fs.readFileSync(`${s.dir}/module/.state/active.conf`, "utf8"), dualStackFixture, failure);
    assert.equal(fs.existsSync(`${s.dir}/up`), false, failure);
    assert.doesNotMatch(s.networkState().rules, /^iptables\|/m);
    assert.equal(fs.readFileSync(`${s.dir}/proc/net/ipv6/conf/all/forwarding`, "utf8").trim(), "0", failure);
    assert.equal(fs.readFileSync(`${s.dir}/proc/net/ipv6/conf/wan0/accept_ra`, "utf8").trim(), "1", failure);
    fs.writeFileSync(`${s.dir}/trace`, "");
    const retried = s.execute("stop");
    assert.equal(retried.status, 0, failure + retried.stdout + retried.stderr);
    assert.doesNotMatch(s.trace(), /lan1/);
    assertNetworkClean(s);
  }
});
test("stopping preserves unrelated firewall rules that mention the tunnel interface", (t) => {
  const s = sandbox(t);
  fs.mkdirSync(`${s.dir}/module/.state`, { recursive: true });
  fs.writeFileSync(`${s.dir}/module/.state/active.conf`, dualStackFixture);
  fs.writeFileSync(`${s.dir}/up`, "");
  const unrelatedRules = "iptables|filter|FORWARD|-i wg0 -j LOG\nip6tables|filter|FORWARD|-i wg0 -j LOG\n";
  fs.writeFileSync(`${s.dir}/rules`, unrelatedRules);
  const result = s.execute("stop");
  assert.equal(result.status, 0, result.stdout + result.stderr);
  for (const [kind, value] of Object.entries(s.networkState())) assert.equal(value, kind === "rules" ? unrelatedRules : "", kind);
  assert.equal(fs.existsSync(`${s.dir}/up`), false);
  assert.equal(fs.existsSync(`${s.dir}/module/.state/active.conf`), false);
});
test("IPv4-only operation does not require ip6tables", (t) => {
  const s = sandbox(t);
  fs.rmSync(`${s.dir}/mock/ip6tables`);
  const result = s.execute("start");
  assert.equal(result.status, 0, result.stdout + result.stderr);
  assert.doesNotMatch(s.trace(), /ip6tables|ip -6 /);
  assert.equal(s.execute("stop").status, 0);
  assertNetworkClean(s);
});
test("IPv6-only operation does not require IPv4 firewall support", (t) => {
  const s = sandbox(t);
  fs.writeFileSync(`${s.dir}/module/wg0.conf`, dualStackFixture
    .replace("Address = 10.6.0.2/32, ", "Address = ")
    .replace("DNS = 10.6.0.1, ", "DNS = ")
    .replace("AllowedIPs = 0.0.0.0/0, ", "AllowedIPs = "));
  fs.rmSync(`${s.dir}/mock/iptables`);
  const result = s.execute("start");
  assert.equal(result.status, 0, result.stdout + result.stderr);
  const state = s.networkState();
  assert.doesNotMatch(state.addresses + state.policies + state.routes, /^4\|/m);
  assert.doesNotMatch(state.rules, /^iptables\|/m);
  assert.match(state.rules, /ip6tables\|nat\|POSTROUTING\|.*MASQUERADE/);
  assert.equal(s.execute("stop").status, 0);
  assertNetworkClean(s);
});
test("missing ip6tables leaves an active IPv4 configuration untouched", (t) => {
  const s = sandbox(t);
  assert.equal(s.execute("start").status, 0);
  const activeState = s.networkState();
  fs.writeFileSync(`${s.dir}/module/wg0.conf`, dualStackFixture);
  fs.rmSync(`${s.dir}/mock/ip6tables`);
  fs.writeFileSync(`${s.dir}/trace`, "");
  const result = s.execute("restart");
  assert.notEqual(result.status, 0, result.stdout + result.stderr);
  assert.match(result.stdout, /ip6tables/);
  assert.deepEqual(s.networkState(), activeState);
  assert.equal(fs.existsSync(`${s.dir}/up`), true);
  assert.equal(fs.readFileSync(`${s.dir}/module/.state/active.conf`, "utf8"), fixture);
  assert.doesNotMatch(s.trace(), /ip link del wg0|route flush table| -D /);
});
test("unsupported IPv6 firewall tables fail before stopping the active tunnel", (t) => {
  const s = sandbox(t);
  assert.equal(s.execute("start").status, 0);
  const activeState = s.networkState();
  fs.writeFileSync(`${s.dir}/module/wg0.conf`, dualStackFixture);
  fs.writeFileSync(`${s.dir}/trace`, "");
  const result = s.execute("restart", "ip6tables -t mangle -L");
  assert.notEqual(result.status, 0, result.stdout + result.stderr);
  assert.deepEqual(s.networkState(), activeState);
  assert.equal(fs.existsSync(`${s.dir}/up`), true);
  assert.doesNotMatch(s.trace(), /ip link del wg0/);
});
test("failed IPv6 NAT capability probe removes its temporary chain without disturbing active rules", (t) => {
  const s = sandbox(t);
  assert.equal(s.execute("start").status, 0);
  const activeState = s.networkState();
  fs.writeFileSync(`${s.dir}/module/wg0.conf`, dualStackFixture);
  fs.writeFileSync(`${s.dir}/trace`, "");
  const result = s.execute("restart", "ip6tables -t nat -A KANO_TEST_");
  assert.notEqual(result.status, 0, result.stdout + result.stderr);
  assert.deepEqual(s.networkState(), activeState);
  assert.equal(fs.existsSync(`${s.dir}/up`), true);
  assert.doesNotMatch(s.trace(), /ip link del wg0/);
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
test("IPv6 route and firewall failures roll back both address families", (t) => {
  const s = sandbox(t);
  fs.writeFileSync(`${s.dir}/module/wg0.conf`, dualStackFixture.replace("::/0", "::/0, 2001:db8:20::/64"));
  for (const failure of ["ip -6 route add 2001:db8:20::/64", "ip6tables -I FORWARD", "ip6tables -t nat -I POSTROUTING", "ip6tables -t nat -A KANO_DNS_wg0", "ip6tables -t mangle -A WG_ROUTE_wg0"]) {
    const result = s.execute("start", failure);
    assert.notEqual(result.status, 0, failure + result.stdout + result.stderr);
    assertNetworkClean(s);
    assert.equal(fs.readFileSync(`${s.dir}/proc/net/ipv6/conf/all/forwarding`, "utf8").trim(), "0", failure);
    assert.equal(fs.readFileSync(`${s.dir}/proc/net/ipv6/conf/wan0/accept_ra`, "utf8").trim(), "1", failure);
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

function prepareInstaller(s, customizePackage = () => {}) {
  fs.mkdirSync(`${s.dir}/package`);
  fs.cpSync(`${s.dir}/module`, `${s.dir}/package/wg_res`, { recursive: true });
  fs.writeFileSync(`${s.dir}/package/wg_res/VERSION`, "2.0.0\n");
  fs.writeFileSync(`${s.dir}/package/wg_res/service.sh`, '#!/bin/sh\n[ "$WG_TEST_FAIL_RESTART" != 1 ]\n');
  fs.writeFileSync(`${s.dir}/module/service.sh`, '#!/bin/sh\nprintf "old version restarted\\n" >> "$WG_TEST_DIR/trace"\n');
  fs.writeFileSync(`${s.dir}/module/scripts/run.sh`, '#!/bin/sh\nprintf "old version stopped\\n" >> "$WG_TEST_DIR/trace"\nrm -f "$WG_TEST_DIR/up"\n');
  const common = fs.readFileSync(`${s.dir}/module/scripts/common.sh`, "utf8");
  customizePackage(`${s.dir}/package/wg_res`);
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
test("failed upgrade cleanup retains both versions and does not restart the previous service", (t) => {
  const s = sandbox(t);
  const install = prepareInstaller(s, (packageDir) => {
    fs.writeFileSync(`${packageDir}/scripts/run.sh`, '#!/bin/sh\nprintf "new resource cleanup failed\\n" >> "$WG_TEST_DIR/trace"\nexit 1\n');
  });
  fs.writeFileSync(`${s.dir}/up`, "");
  const result = install(undefined, true);
  assert.notEqual(result.status, 0, result.stdout + result.stderr);
  assert.match(s.trace(), /new resource cleanup failed/);
  assert.doesNotMatch(s.trace(), /old version restarted/);
  assert.match(fs.readFileSync(`${s.dir}/module/scripts/run.sh`, "utf8"), /new resource cleanup failed/);
  assert.match(fs.readFileSync(`${s.dir}/previous/service.sh`, "utf8"), /old version restarted/);
});
