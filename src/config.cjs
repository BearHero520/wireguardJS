"use strict";

function ipv4(value) {
  const parts = value.split(".");
  return parts.length === 4 && parts.every((part) => /^(0|[1-9]\d{0,2})$/.test(part) && Number(part) <= 255);
}

function cidr(value) {
  const parts = value.split("/");
  return parts.length === 2 && ipv4(parts[0]) && /^(0|[1-9]\d?)$/.test(parts[1]) && Number(parts[1]) <= 32;
}

function contains(network, address) {
  if (!cidr(network) || !ipv4(address)) return false;
  const number = (ip) => ip.split(".").reduce((sum, part) => sum * 256 + Number(part), 0);
  const [ip, prefix] = network.split("/");
  const size = 2 ** (32 - Number(prefix));
  return Math.floor(number(ip) / size) === Math.floor(number(address) / size);
}

function key(value) {
  // The final base64 digit must have two zero padding bits (a 32-byte key).
  return /^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=$/.test(value) && value !== "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
}

function endpoint(value) {
  const match = /^(\[[0-9a-fA-F:.]+\]|[a-zA-Z0-9](?:[a-zA-Z0-9.-]*[a-zA-Z0-9])?):(\d{1,5})$/.exec(value);
  if (!match || Number(match[2]) < 1 || Number(match[2]) > 65535) return false;
  const host = match[1];
  if (host.startsWith("[")) {
    try { return new URL(`http://${host}/`).hostname.startsWith("["); } catch { return false; }
  }
  if (/^[\d.]+$/.test(host)) return ipv4(host);
  return host.length <= 253 && host.split(".").every((label) => /^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$/.test(label));
}

const interfaceKeys = new Set(["PrivateKey", "Address", "ListenPort", "DNS", "MTU", "NAT", "LANInterface"]);
const peerKeys = new Set(["PublicKey", "PresharedKey", "AllowedIPs", "Endpoint", "PersistentKeepalive"]);
const list = (value = "") => value.split(",").map((item) => item.trim()).filter(Boolean);

function validate(source) {
  const errors = [];
  const warnings = [];
  const sections = [];
  let current = null;
  const normalized = String(source).replace(/^\uFEFF/, "").replace(/\r\n?/g, "\n");
  if (normalized.length > 65536) errors.push("配置文件不能超过 64 KiB。");
  normalized.split("\n").forEach((line, index) => {
    const text = line.replace(/[;#].*$/, "").trim();
    if (!text) return;
    if (/^\[(Interface|Peer)\]$/.test(text)) {
      current = { type: text.slice(1, -1), values: {}, line: index + 1 };
      sections.push(current);
      return;
    }
    const match = /^([A-Za-z]+)\s*=\s*(.*)$/.exec(text);
    if (!match || !current) { errors.push(`第 ${index + 1} 行：无法识别的配置格式。`); return; }
    const [, name, value] = match;
    const supported = current.type === "Interface" ? interfaceKeys : peerKeys;
    if (!supported.has(name)) errors.push(`第 ${index + 1} 行：不支持 ${name}。`);
    if (Object.prototype.hasOwnProperty.call(current.values, name)) errors.push(`第 ${index + 1} 行：${name} 重复。`);
    current.values[name] = value.trim();
  });
  const interfaces = sections.filter((section) => section.type === "Interface");
  const peers = sections.filter((section) => section.type === "Peer");
  if (interfaces.length !== 1 || sections[0]?.type !== "Interface") errors.push("必须以唯一的 [Interface] 段开始。");
  const settings = interfaces[0]?.values || {};
  if (!key(settings.PrivateKey || "")) errors.push("PrivateKey 必须是有效的 32 字节 Base64 密钥。");
  if (!list(settings.Address).length || !list(settings.Address).every(cidr)) errors.push("Address 必须填写 IPv4 地址和前缀，例如 10.0.0.2/24。");
  if (settings.ListenPort !== undefined && !/^(0|[1-9]\d{0,4})$/.test(settings.ListenPort)) errors.push("ListenPort 必须是 0 到 65535 的整数。");
  else if (Number(settings.ListenPort) > 65535) errors.push("ListenPort 不能超过 65535。");
  if (settings.MTU !== undefined && (!/^\d+$/.test(settings.MTU) || Number(settings.MTU) < 576 || Number(settings.MTU) > 9000)) errors.push("MTU 必须是 576 到 9000 的整数。");
  if (settings.NAT !== undefined && !/^(true|false|0|1|yes|no)$/i.test(settings.NAT)) errors.push("NAT 必须是 true 或 false。");
  if (settings.LANInterface !== undefined && !/^[a-zA-Z0-9_][a-zA-Z0-9_.-]{0,14}$/.test(settings.LANInterface)) errors.push("LANInterface 必须是有效的网卡名，最长 15 个字符。");
  if (!peers.length) errors.push("至少需要一个 [Peer]。");
  const seen = new Set();
  peers.forEach(({ values }, index) => {
    const name = `Peer ${index + 1}`;
    if (!key(values.PublicKey || "")) errors.push(`${name}：PublicKey 无效。`);
    if (values.PresharedKey && !key(values.PresharedKey)) errors.push(`${name}：PresharedKey 无效。`);
    if (seen.has(values.PublicKey)) errors.push(`${name}：PublicKey 与其他节点重复。`);
    seen.add(values.PublicKey);
    if (!list(values.AllowedIPs).length || !list(values.AllowedIPs).every(cidr)) errors.push(`${name}：AllowedIPs 仅支持 IPv4 CIDR，不能包含 ::/0。`);
    if (values.Endpoint && !endpoint(values.Endpoint)) errors.push(`${name}：Endpoint 格式错误，例如 host:51820 或 [IPv6]:51820。`);
    if (values.PersistentKeepalive !== undefined && (!/^\d+$/.test(values.PersistentKeepalive) || Number(values.PersistentKeepalive) > 65535)) errors.push(`${name}：PersistentKeepalive 必须是 0 到 65535 的整数。`);
  });
  const dns = list(settings.DNS);
  if (!dns.every(ipv4)) errors.push("DNS 仅支持 IPv4 地址；留空则不接管 DNS。");
  if (dns.length > 1) errors.push("DNS 目前只支持一个地址，请保留一个或留空。");
  const routes = peers.flatMap(({ values }) => list(values.AllowedIPs));
  if (dns.some((address) => ipv4(address) && !routes.some((route) => contains(route, address)))) errors.push("DNS 地址必须包含在某个 Peer 的 AllowedIPs 中，否则会导致 DNS 断网。");
  const routeOwners = new Map();
  peers.forEach(({ values }, index) => list(values.AllowedIPs).filter(cidr).forEach((route) => {
    const [address, prefix] = route.split("/");
    const size = 2 ** (32 - Number(prefix));
    const numeric = address.split(".").reduce((sum, part) => sum * 256 + Number(part), 0);
    const canonical = `${Math.floor(numeric / size)}/${prefix}`;
    if (routeOwners.has(canonical) && routeOwners.get(canonical) !== index) errors.push("不同 Peer 不能配置相同的 AllowedIPs 网段。");
    routeOwners.set(canonical, index);
  }));
  if (!settings.LANInterface) warnings.push("LAN 网卡使用默认值 br0。");
  return { valid: errors.length === 0, errors: [...new Set(errors)], warnings, normalized: normalized.trim() + "\n", peers: peers.length };
}

function redact(text) {
  return String(text).replace(/^(\s*(?:PrivateKey|PresharedKey)\s*=).*$/gim, "$1 [REDACTED]");
}

module.exports = { ipv4, cidr, contains, endpoint, validate, redact };
