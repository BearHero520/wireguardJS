# Changelog

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
