"use strict";

function ipv4(value) {
  const parts = value.split(".");
  return parts.length === 4 && parts.every((part) => /^(0|[1-9]\d{0,2})$/.test(part) && Number(part) <= 255);
}

function address(value) {
  if (typeof value !== "string") return null;
  if (ipv4(value)) return { family: 4, bytes: value.split(".").map(Number) };
  if (!value.includes(":") || !/^[0-9a-fA-F:.]+$/.test(value)) return null;
  try {
    // URL supplies the browser's IPv6 parser, including embedded IPv4 tails.
    const canonical = new URL(`http://[${value}]/`).hostname.slice(1, -1);
    const halves = canonical.split("::");
    const left = halves[0] ? halves[0].split(":") : [];
    const right = halves[1] ? halves[1].split(":") : [];
    const words = halves.length === 2 ? [...left, ...Array(8 - left.length - right.length).fill("0"), ...right] : left;
    return { family: 6, bytes: words.flatMap((word) => { const number = parseInt(word, 16); return [number >>> 8, number & 255]; }) };
  } catch { return null; }
}

function ipv6(value) { return address(value)?.family === 6; }

function network(value) {
  const parts = value.split("/");
  if (parts.length !== 2 || !/^(0|[1-9]\d{0,2})$/.test(parts[1])) return null;
  const parsed = address(parts[0]);
  const prefix = Number(parts[1]);
  return parsed && prefix <= parsed.bytes.length * 8 ? { ...parsed, prefix } : null;
}

function cidr(value) { return network(value) !== null; }

function prefixBytes(bytes, prefix) {
  return bytes.map((byte, index) => {
    const size = 2 ** (8 - Math.max(0, Math.min(8, prefix - index * 8)));
    return Math.floor(byte / size) * size;
  });
}

function contains(route, value) {
  const parsed = network(route);
  const target = address(value);
  if (!parsed || !target || parsed.family !== target.family) return false;
  const expected = prefixBytes(parsed.bytes, parsed.prefix);
  return prefixBytes(target.bytes, parsed.prefix).every((byte, index) => byte === expected[index]);
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

const interfaceKeys = new Set(["PrivateKey", "Address", "ListenPort", "DNS", "MTU", "NAT", "NAT6", "LANInterface"]);
const peerKeys = new Set(["PublicKey", "PresharedKey", "AllowedIPs", "Endpoint", "PersistentKeepalive"]);
const list = (value = "") => value.trim() ? value.split(",").map((item) => item.trim()) : [];

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
    const match = /^([A-Za-z][A-Za-z0-9]*)\s*=\s*(.*)$/.exec(text);
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
  const addresses = list(settings.Address);
  const families = new Set(addresses.map(network).filter(Boolean).map((item) => item.family));
  if (!addresses.length || !addresses.every(cidr)) errors.push("Address 必须填写有效的 IPv4 或 IPv6 地址和前缀，例如 10.0.0.2/24、fd00::2/64。");
  const seenAddresses = new Set();
  addresses.map(network).filter(Boolean).forEach((parsed) => {
    const canonical = `${parsed.family}:${parsed.bytes.join(".")}/${parsed.prefix}`;
    if (seenAddresses.has(canonical)) errors.push("Address 不能重复配置相同的地址和前缀。");
    seenAddresses.add(canonical);
  });
  if (settings.ListenPort !== undefined && !/^(0|[1-9]\d{0,4})$/.test(settings.ListenPort)) errors.push("ListenPort 必须是 0 到 65535 的整数。");
  else if (Number(settings.ListenPort) > 65535) errors.push("ListenPort 不能超过 65535。");
  const minimumMTU = families.has(6) ? 1280 : 576;
  if (settings.MTU !== undefined && (!/^\d+$/.test(settings.MTU) || Number(settings.MTU) < minimumMTU || Number(settings.MTU) > 9000)) errors.push(`MTU 必须是 ${minimumMTU} 到 9000 的整数${families.has(6) ? "（IPv6 最低为 1280）" : ""}。`);
  for (const name of ["NAT", "NAT6"]) {
    if (settings[name] !== undefined && !/^(true|false|0|1|yes|no)$/i.test(settings[name])) errors.push(`${name} 必须是 true 或 false。`);
  }
  if (settings.LANInterface !== undefined && !/^[a-zA-Z0-9_][a-zA-Z0-9_.-]{0,14}$/.test(settings.LANInterface)) errors.push("LANInterface 必须是有效的网卡名，最长 15 个字符。");
  if (!peers.length) errors.push("至少需要一个 [Peer]。");
  const seen = new Set();
  peers.forEach(({ values }, index) => {
    const name = `Peer ${index + 1}`;
    if (!key(values.PublicKey || "")) errors.push(`${name}：PublicKey 无效。`);
    if (values.PresharedKey !== undefined && !key(values.PresharedKey)) errors.push(`${name}：PresharedKey 无效。`);
    if (seen.has(values.PublicKey)) errors.push(`${name}：PublicKey 与其他节点重复。`);
    seen.add(values.PublicKey);
    const allowed = list(values.AllowedIPs);
    if (!allowed.length || !allowed.every(cidr)) errors.push(`${name}：AllowedIPs 必须填写有效的 IPv4 或 IPv6 CIDR。`);
    allowed.map(network).filter(Boolean).forEach((route) => {
      if (!families.has(route.family)) errors.push(`${name}：AllowedIPs 包含 IPv${route.family} 网段，Address 中必须配置 IPv${route.family} 地址。`);
    });
    if (values.Endpoint && !endpoint(values.Endpoint)) errors.push(`${name}：Endpoint 格式错误，例如 host:51820 或 [IPv6]:51820。`);
    if (values.PersistentKeepalive !== undefined && (!/^\d+$/.test(values.PersistentKeepalive) || Number(values.PersistentKeepalive) > 65535)) errors.push(`${name}：PersistentKeepalive 必须是 0 到 65535 的整数。`);
  });
  const dns = list(settings.DNS);
  if (!dns.every((value) => address(value))) errors.push("DNS 必须是有效的 IPv4 或 IPv6 地址；留空则不接管 DNS。");
  for (const family of [4, 6]) {
    const count = dns.filter((value) => address(value)?.family === family).length;
    if (count > 1) errors.push(`DNS 最多支持一个 IPv${family} 地址。`);
    if (count && !families.has(family)) errors.push(`DNS 使用 IPv${family}，Address 中必须配置 IPv${family} 地址。`);
  }
  peers.forEach(({ values }, index) => {
    if (!values.Endpoint || !endpoint(values.Endpoint)) return;
    const separator = values.Endpoint.lastIndexOf(":");
    if (Number(values.Endpoint.slice(separator + 1)) !== 53) return;
    const host = values.Endpoint.slice(0, separator);
    const family = host.startsWith("[") ? 6 : ipv4(host) ? 4 : 0;
    if (family ? dns.some((value) => address(value)?.family === family) : dns.length) errors.push(`Peer ${index + 1}：Endpoint 的 UDP 53 端口与 DNS 接管冲突，请删除 DNS 或更换 Endpoint 端口。`);
  });
  const routes = peers.flatMap(({ values }) => list(values.AllowedIPs));
  if (dns.some((value) => address(value) && !routes.some((route) => contains(route, value)))) errors.push("DNS 地址必须包含在某个 Peer 的同地址族 AllowedIPs 中，否则会导致 DNS 断网。");
  const routeOwners = new Map();
  peers.forEach(({ values }, index) => list(values.AllowedIPs).filter(cidr).forEach((route) => {
    const parsed = network(route);
    const canonical = `${parsed.family}:${prefixBytes(parsed.bytes, parsed.prefix).join(".")}/${parsed.prefix}`;
    if (routeOwners.has(canonical)) errors.push(routeOwners.get(canonical) === index ? `Peer ${index + 1}：AllowedIPs 不能重复配置相同的网段。` : "不同 Peer 不能配置相同的 AllowedIPs 网段。");
    routeOwners.set(canonical, index);
  }));
  if (/^(false|0|no)$/i.test(settings.NAT6 ?? settings.NAT ?? "true") && routes.some((route) => network(route)?.family === 6)) warnings.push("IPv6 NAT 已关闭：服务器对应 Peer 的 AllowedIPs 和回程路由必须包含 LAN IPv6 前缀。");
  if (!settings.LANInterface) warnings.push("LAN 网卡使用默认值 br0。");
  return { valid: errors.length === 0, errors: [...new Set(errors)], warnings, normalized: normalized.trim() + "\n", peers: peers.length };
}

function redact(text) {
  return String(text).replace(/^(\s*(?:PrivateKey|PresharedKey)\s*=).*$/gim, "$1 [REDACTED]");
}

module.exports = { ipv4, ipv6, cidr, contains, endpoint, validate, redact };
