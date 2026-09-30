function fail(message) { print "line " NR ": " message; invalid = 1 }
function trim(value) { gsub(/^[ \t]+|[ \t\r]+$/, "", value); return value }
function ip(value, parts, count, i) {
    count = split(value, parts, ".")
    if (count != 4) return 0
    for (i = 1; i <= 4; i++) if (parts[i] !~ /^[0-9]+$/ || parts[i] + 0 > 255 || (length(parts[i]) > 1 && substr(parts[i], 1, 1) == "0")) return 0
    return 1
}
function hex_number(value, number, i) {
    number = 0
    for (i = 1; i <= length(value); i++) number = number * 16 + index("0123456789abcdef", tolower(substr(value, i, 1))) - 1
    return number
}
# Keep IPv6 as bytes: portable awk numbers cannot exactly represent 128 bits.
function parse_ip(value, bytes, parts, tailparts, left, right, lcount, rcount, compression, tail, i, j, word, position) {
    for (i in bytes) delete bytes[i]
    if (ip(value)) { split(value, bytes, "."); return 4 }
    if (value !~ /^[0-9A-Fa-f:.]+$/ || !index(value, ":")) return 0
    if (index(value, ".")) {
        for (j = length(value); j > 0; j--) if (substr(value, j, 1) == ":") break
        tail = substr(value, j + 1)
        if (!ip(tail)) return 0
        split(tail, parts, ".")
        value = substr(value, 1, j) sprintf("%x:%x", parts[1] * 256 + parts[2], parts[3] * 256 + parts[4])
    }
    compression = index(value, "::")
    if (compression) {
        left = substr(value, 1, compression - 1)
        right = substr(value, compression + 2)
        if (index(right, "::")) return 0
        lcount = left == "" ? 0 : split(left, parts, ":")
        rcount = right == "" ? 0 : split(right, tailparts, ":")
        if (lcount + rcount >= 8) return 0
    } else {
        lcount = split(value, parts, ":")
        rcount = 0
        if (lcount != 8) return 0
    }
    position = 0
    for (i = 1; i <= lcount; i++) {
        if (length(parts[i]) > 4 || parts[i] !~ /^[0-9A-Fa-f]+$/) return 0
        word = hex_number(parts[i]); bytes[++position] = int(word / 256); bytes[++position] = word % 256
    }
    if (compression) for (i = 1; i <= 8 - lcount - rcount; i++) { bytes[++position] = 0; bytes[++position] = 0 }
    for (i = 1; i <= rcount; i++) {
        if (length(tailparts[i]) > 4 || tailparts[i] !~ /^[0-9A-Fa-f]+$/) return 0
        word = hex_number(tailparts[i]); bytes[++position] = int(word / 256); bytes[++position] = word % 256
    }
    return 6
}
function cidr(value, parts, bytes, count, family) {
    count = split(value, parts, "/")
    family = parse_ip(parts[1], bytes)
    return count == 2 && family && parts[2] ~ /^(0|[1-9][0-9]*)$/ && parts[2] + 0 <= (family == 4 ? 32 : 128)
}
function route_family(value, parts, bytes) { split(value, parts, "/"); return parse_ip(parts[1], bytes) }
function key(value) { return length(value) == 44 && value ~ /^[A-Za-z0-9+\/]+=$/ && substr(value, 43, 1) ~ /^[AEIMQUYcgkosw048]$/ && value != "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" }
function masked_byte(value, prefix, position, bits, size) {
    bits = prefix - (position - 1) * 8
    if (bits < 0) bits = 0
    if (bits > 8) bits = 8
    size = 2 ^ (8 - bits)
    return int(value / size) * size
}
function canonical(value, host_address, parts, bytes, family, result, i) {
    split(value, parts, "/")
    family = parse_ip(parts[1], bytes)
    result = family ":"
    for (i = 1; i <= (family == 4 ? 4 : 16); i++) result = result sprintf("%02x", host_address ? bytes[i] : masked_byte(bytes[i], parts[2] + 0, i))
    return result "/" (parts[2] + 0)
}
function inside(network, address, parts, network_bytes, address_bytes, family, i) {
    if (!cidr(network)) return 0
    split(network, parts, "/")
    family = parse_ip(parts[1], network_bytes)
    if (parse_ip(address, address_bytes) != family) return 0
    for (i = 1; i <= (family == 4 ? 4 : 16); i++) if (masked_byte(network_bytes[i], parts[2] + 0, i) != masked_byte(address_bytes[i], parts[2] + 0, i)) return 0
    return 1
}
function endpoint(value, parts, bytes, host, port, closing, count, i) {
    if (value == "") return 1
    if (substr(value, 1, 1) == "[") {
        closing = index(value, "]")
        if (!closing || substr(value, closing + 1, 1) != ":" || parse_ip(substr(value, 2, closing - 2), bytes) != 6) return 0
        port = substr(value, closing + 2)
    } else {
        if (split(value, parts, ":") != 2) return 0
        host = parts[1]; port = parts[2]
        if (host ~ /^[0-9.]+$/) { if (!ip(host)) return 0 }
        else {
            if (!length(host) || length(host) > 253) return 0
            count = split(host, parts, ".")
            for (i = 1; i <= count; i++) if (length(parts[i]) > 63 || parts[i] !~ /^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?$/) return 0
        }
    }
    return port ~ /^[0-9]+$/ && length(port) <= 5 && port + 0 >= 1 && port + 0 <= 65535
}
{
    if (NR == 1) sub(/^\357\273\277/, "")
    sub(/[;#].*$/, "")
    line = trim($0)
    if (line == "") next
    if (line == "[Interface]") { if (interfaces++ || peers) fail("Interface must be first and unique"); section = "Interface"; next }
    if (line == "[Peer]") { peers++; section = "Peer"; next }
    if (!section || index(line, "=") == 0) { fail("invalid configuration syntax"); next }
    name = trim(substr(line, 1, index(line, "=") - 1))
    value = trim(substr(line, index(line, "=") + 1))
    identity = section ":" peers ":" name
    if (seen[identity]++) fail("duplicate field " name)
    if (section == "Interface") {
        if (name == "PrivateKey") { private_key = key(value); if (!private_key) fail("invalid PrivateKey") }
        else if (name == "Address") {
            addresses = split(value, items, ",")
            for (i = 1; i <= addresses; i++) {
                item = trim(items[i])
                if (!cidr(item)) fail("Address requires IPv4 or IPv6 CIDR")
                else {
                    address_families[route_family(item)] = 1
                    if (address_seen[canonical(item, 1)]++) fail("duplicate Address and prefix")
                }
            }
        }
        else if (name == "DNS") {
            dns_count = value == "" ? 0 : split(value, dns, ",")
            for (i = 1; i <= dns_count; i++) {
                dns[i] = trim(dns[i])
                family = parse_ip(dns[i], bytes)
                if (!family) fail("DNS requires IPv4 or IPv6 addresses")
                else if (++dns_families[family] > 1) fail("DNS supports at most one address per IP family")
            }
        }
        else if (name == "LANInterface") { if (length(value) > 15 || value !~ /^[A-Za-z0-9_][A-Za-z0-9_.-]*$/) fail("invalid LANInterface") }
        else if (name == "MTU") { mtu = value; mtu_set = 1; if (value !~ /^[0-9]+$/ || value + 0 < 576 || value + 0 > 9000) fail("invalid MTU") }
        else if (name == "ListenPort") { if (value !~ /^(0|[1-9][0-9]*)$/ || value + 0 > 65535) fail("invalid ListenPort") }
        else if (name == "NAT" || name == "NAT6") { if (tolower(value) !~ /^(true|false|0|1|yes|no)$/) fail("invalid " name) }
        else fail("unsupported Interface field " name)
    } else {
        if (name == "PublicKey") {
            public_key[peers] = key(value)
            if (!public_key[peers]) fail("invalid PublicKey")
            if (public_seen[value]++) fail("duplicate PublicKey")
        }
        else if (name == "PresharedKey") { if (!key(value)) fail("invalid PresharedKey") }
        else if (name == "AllowedIPs") {
            allowed[peers] = split(value, items, ",")
            for (i = 1; i <= allowed[peers]; i++) {
                item = trim(items[i])
                if (!cidr(item)) fail("AllowedIPs requires IPv4 or IPv6 CIDR")
                else {
                    routes[++route_count] = item
                    route_families[route_family(item)] = 1
                    route_id = canonical(item)
                    if (route_owners[route_id]) fail(route_owners[route_id] == peers ? "duplicate AllowedIPs subnet in Peer" : "different Peers cannot share the same AllowedIPs subnet")
                    route_owners[route_id] = peers
                }
            }
        }
        else if (name == "Endpoint") { endpoint_values[peers] = value; if (!endpoint(value)) fail("invalid Endpoint") }
        else if (name == "PersistentKeepalive") { if (value !~ /^[0-9]+$/ || value + 0 > 65535) fail("invalid PersistentKeepalive") }
        else fail("unsupported Peer field " name)
    }
}
END {
    if (interfaces != 1 || !private_key || !addresses || !peers) fail("missing Interface, PrivateKey, Address or Peer")
    for (p = 1; p <= peers; p++) if (!public_key[p] || !allowed[p]) fail("Peer requires PublicKey and AllowedIPs")
    if (address_families[6] && mtu_set && mtu + 0 < 1280) fail("IPv6 requires MTU of at least 1280")
    for (family in route_families) if (!address_families[family]) fail("AllowedIPs requires an Interface Address of the same IP family")
    for (family in dns_families) if (!address_families[family]) fail("DNS requires an Interface Address of the same IP family")
    for (p = 1; p <= peers; p++) if (endpoint_values[p] != "" && endpoint(endpoint_values[p])) {
        match(endpoint_values[p], /:[0-9]+$/)
        port = substr(endpoint_values[p], RSTART + 1) + 0
        host = substr(endpoint_values[p], 1, RSTART - 1)
        family = substr(host, 1, 1) == "[" ? 6 : ip(host) ? 4 : 0
        if (port == 53 && (family ? dns_families[family] : dns_count)) fail("Endpoint UDP port 53 conflicts with DNS interception; omit DNS or use another Endpoint port")
    }
    for (d = 1; d <= dns_count; d++) if (parse_ip(dns[d], bytes)) {
        covered = 0
        for (r = 1; r <= route_count; r++) if (inside(routes[r], dns[d])) covered = 1
        if (!covered) fail("DNS must be covered by AllowedIPs of the same IP family")
    }
    exit invalid ? 1 : 0
}
