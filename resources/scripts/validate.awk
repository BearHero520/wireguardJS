function fail(message) { print "line " NR ": " message; invalid = 1 }
function trim(value) { gsub(/^[ \t]+|[ \t\r]+$/, "", value); return value }
function ip(value, parts, count, i) {
    count = split(value, parts, ".")
    if (count != 4) return 0
    for (i = 1; i <= 4; i++) if (parts[i] !~ /^[0-9]+$/ || parts[i] + 0 > 255 || (length(parts[i]) > 1 && substr(parts[i], 1, 1) == "0")) return 0
    return 1
}
function cidr(value, parts, count) {
    count = split(value, parts, "/")
    return count == 2 && ip(parts[1]) && parts[2] ~ /^[0-9]+$/ && parts[2] + 0 <= 32
}
function key(value) { return length(value) == 44 && value ~ /^[A-Za-z0-9+\/]+=$/ && value != "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" }
function ip_number(value, parts) {
    split(value, parts, ".")
    return ((parts[1] * 256 + parts[2]) * 256 + parts[3]) * 256 + parts[4]
}
function inside(network, address, parts, size) {
    split(network, parts, "/")
    size = 2 ^ (32 - parts[2])
    return int(ip_number(parts[1]) / size) == int(ip_number(address) / size)
}
{
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
            for (i = 1; i <= addresses; i++) if (!cidr(trim(items[i]))) fail("Address requires IPv4 CIDR")
        }
        else if (name == "DNS") { dns = value; if (dns != "" && !ip(dns)) fail("DNS requires one IPv4 address") }
        else if (name == "LANInterface") { if (length(value) > 15 || value !~ /^[A-Za-z0-9_][A-Za-z0-9_.-]*$/) fail("invalid LANInterface") }
        else if (name == "MTU") { if (value !~ /^[0-9]+$/ || value + 0 < 576 || value + 0 > 9000) fail("invalid MTU") }
        else if (name == "ListenPort") { if (value !~ /^[0-9]+$/ || value + 0 > 65535) fail("invalid ListenPort") }
        else if (name == "NAT") { if (tolower(value) !~ /^(true|false|0|1|yes|no)$/) fail("invalid NAT") }
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
                if (!cidr(item)) fail("AllowedIPs requires IPv4 CIDR; IPv6 tunnel traffic is unsupported")
                else routes[++route_count] = item
            }
        }
        else if (name == "Endpoint") { if (value !~ /:[0-9]+$/ || value ~ /[ \t]/) fail("invalid Endpoint") }
        else if (name == "PersistentKeepalive") { if (value !~ /^[0-9]+$/ || value + 0 > 65535) fail("invalid PersistentKeepalive") }
        else fail("unsupported Peer field " name)
    }
}
END {
    if (interfaces != 1 || !private_key || !addresses || !peers) fail("missing Interface, PrivateKey, Address or Peer")
    for (p = 1; p <= peers; p++) if (!public_key[p] || !allowed[p]) fail("Peer requires PublicKey and AllowedIPs")
    if (dns != "" && ip(dns)) {
        covered = 0
        for (r = 1; r <= route_count; r++) if (inside(routes[r], dns)) covered = 1
        if (!covered) fail("DNS must be covered by AllowedIPs")
    }
    exit invalid ? 1 : 0
}
