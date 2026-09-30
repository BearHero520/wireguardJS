# Changelog

## 2.1.0

- Support IPv4, IPv6, and mixed Address / AllowedIPs configurations, including ::/0 and IPv6-only tunnels.
- Validate IPv6 prefixes, equivalent duplicate routes, per-family address requirements, and the IPv6 minimum MTU in both UI and device scripts.
- Add IPv6 LAN policy routing, forwarding, optional NAT66, and one DNS server per address family.
- Keep AllowedIPs routes in separate policy tables and mark DNS traffic, preserving the gateway's transport/default routes.
- Check kernel/firewall capabilities before stopping an existing connection; clean up both families on failure.
- Keep local DNS source addresses valid with NAT=false without masquerading LAN traffic.
- Retain cleanup snapshots and previous resources when stop or upgrade rollback cannot finish safely.
- Preserve upstream router-advertisement behavior while enabling IPv6 forwarding and restore modified sysctls on stop.
- Add IPv6 diagnostics, a dual-stack example, upgrade reminders, and dual-stack regression tests.

## 2.0.0

- Split the original embedded plugin into maintainable UI, validation, device scripts, and reproducible release assets.
- Preserve configuration during upgrades, verify resource hashes, and restore the previous install when upgrade startup fails.
- Restrict filesystem permissions; protect mutations with a shared lock.
- Save atomically with a backup, propagate command failures, and preserve editor contents on failed reads.
- Add import/export, backup/restore, validation, configurable LAN interface, and diagnostics.
- Track active configuration for cleanup; isolate DNS rules and report route/firewall failures.
- Correct the template to IPv4-only AllowedIPs; support IPv4 or IPv6 peer endpoints.
- Add mobile layout, guarded actions, visibility-aware polling, and automated regression tests.
- Retain the original ARM64 wg binary; its build provenance remains unverified.
