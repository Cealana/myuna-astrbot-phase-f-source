# ADR-036: Server BU daily encrypted backup v1

Status: candidate

## Decision

The `Server BU` USB drive remains exFAT without BitLocker. Every backup payload is encrypted before publication with an independently generated OpenPGP symmetric AES-256 key. The key is never stored on the USB drive. A recovery copy is kept in a locked-down directory on the BitLocker-protected C volume and should later be exported to an off-server password manager or trusted device.

The Windows launcher validates drive letter, label, filesystem, volume identifier, physical serial number, disk size, health, and an on-device identity marker. Any mismatch fails closed. WSL then creates five allowlisted encrypted artifacts: PostgreSQL, Myuna control plane, channel runtime, project documents, and the latest application-consistent Minecraft backup.

Snapshots are staged on the BitLocker-protected D volume, encrypted, copied to an on-device incoming directory, decrypted and structurally verified from the USB copy, and only then atomically published. Retention is the union of 14 daily, 8 weekly, and 6 monthly recovery points. The only known-good snapshot is never deleted.

## Consistency boundaries

- PostgreSQL uses a custom-format logical dump and `pg_restore --list` verification.
- AstrBot SQLite databases use the online SQLite backup API and `integrity_check`.
- Minecraft runs the existing backup service first and consumes only a completed non-partial archive.
- NapCat configuration and bounded session state are best-effort recovery aids; QR re-login remains the authoritative fallback.
- Secrets, chat databases, memory, archives, and all other sensitive classes are always inside encrypted payloads.

## Deliberate exclusions

The backup does not copy arbitrary user profiles, browser data, cookies, unrelated personal files, model caches, QQ program binaries, crash dumps, logs, temporary data, or old quarantined account sessions.
