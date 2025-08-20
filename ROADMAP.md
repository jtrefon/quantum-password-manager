# Password Manager Roadmap

This roadmap tracks the vision, security principles, milestones, and concrete tasks for the quantum‑resistant, offline‑first password manager.

## Vision
- Provide an ultra-secure, offline password manager with zero leakage of secrets to screens, logs, or shell history.
- Single encrypted database file. No network access. No telemetry. Reproducible and auditable builds.
- Great CLI UX without exposing sensitive data.

## Security Principles
- No secrets on stdout/stderr, logs, or prompts. Never echo secrets.
- Clipboard by default for secrets; auto-clear when possible.
- Memory hygiene: zeroize secrets, minimize lifetime, prefer stack over heap.
- Strong KDF (Argon2id), authenticated encryption (AEAD), secure random.
- Local-only: never send data over the network.
- Defense-in-depth: reproducible builds, dependency audit, code scanning, fuzzing.

## Milestones

### M1 — Secret-safe CLI UX (high priority)
- [ ] Copy credentials to clipboard instead of printing: username, password, OTP
- [ ] Auto-clear clipboard after N seconds (best-effort, platform-specific)
- [ ] Secure prompts: hidden password input, double-entry confirmation for new secrets
- [ ] Redact secrets from errors/logs; no debug prints of buffers
- [ ] Add `--show` override (off by default) for advanced/debug use
 - [ ] Password generator: presets `normal`/`strong`/`insane` and advanced numeric strength `1..10`
 - [ ] Generator options: length override, exclude ambiguous chars, allow/disallow specials to satisfy site policies
 - [ ] "Regenerate-and-copy" loop: generate -> copy to clipboard -> retry without saving until confirmed
 - [ ] `pm add` wizard: choose manual (double-entry) or generator path; never echo secrets
 - [ ] `pm regenerate` for existing records with clipboard-first flow; write only on confirm

### M2 — Records, Search, and Navigation
- [ ] Record model: name, username, password, URL, notes, tags, created/updated
- [ ] Efficient search: substring, tag filter, fuzzy match (opt)
- [ ] Paginated listing and interactive selection (arrow keys / numbers)
- [ ] Favorites and recent items
- [ ] Import from minimal CSV (no secrets echo during import)
 - [ ] Per-record password policy (allowed char classes, min/max length, ambiguous-char rules)
 - [ ] Optional passphrase mode (Diceware-style) for services disallowing special chars

### M3 — Attachments (keys, certificates, documents)
- [ ] Encrypted attachments storage (streaming encryption to avoid memory spikes)
- [ ] CLI commands: `attach`, `attachments ls`, `attachments export` (writes to file; never prints content)
- [ ] Metadata: original filename, size, content-type (no content on screen)
- [ ] Export with secure file permissions (0600) and safety warnings

### M4 — Crypto and Key Management
- [ ] Master key derivation via Argon2id with tunable params (secure defaults)
- [ ] File format versioning and key rotation command
- [ ] Hardware-backed secrets (exploration): Secure Enclave/TPM/YubiKey for key wrapping
- [ ] PQC exploration for key-wrapping/handshake (e.g., ML-KEM/Kyber via Rust crates) — research, benchmarks, and threat model notes
 - [ ] Password history with timestamps and ability to rollback (hidden by default; copy-only display)

### M5 — Reliability, Tests, and Tooling
- [ ] Cross-platform CI builds (Linux/macOS/Windows) with deterministic artifacts
- [ ] Unit, integration, and end-to-end tests for CLI flows (no secrets on stdout)
- [ ] Fuzz critical parsers and crypto wrappers
- [ ] Dependency audit in CI (cargo-audit), linting (clippy), formatting
- [ ] Threat model and SECURITY.md

### M6 — UX Polish and Docs
- [ ] Guided CLI wizards for common flows (add, edit, rotate)
- [ ] Clear errors and actionable help
- [ ] Man pages and `--help` examples without secrets
- [ ] README quickstart + CLI reference; add docs/ folder as needed

### M7 — Storage Privacy Hardening (design + implementation)
- [ ] Encrypted metadata only: ensure flags/indices/timestamps are inside AEAD; nothing leaks in plaintext
- [ ] Secure deletion semantics: tombstone records first; compact/vacuum to re-encrypt DB and drop deleted payloads
- [ ] DB padding: add randomized padding/chaff to hinder size-based inference (configurable target sizes)
- [ ] Optional decoy records/noise: encrypted indistinguishable entries; adjustable ratio; only helpful for size obfuscation
- [ ] Design note: With Argon2id + AEAD, ciphertext is indistinguishable; decoys do not materially increase brute-force cost versus strengthening KDF params. Prefer strong KDF, unique nonces, and padding over decoys. Avoid relying on flags for plausible deniability; the model is public and flags are encrypted anyway.

## Proposed CLI Commands
- `pm add` — interactive wizard: name, username, URL (shown). Choose: manual (hidden + confirm) or generator.
- `pm list [--search <q>] [--tag <tag>] [--page N]` — lists records (names only)
- `pm copy --name <record> [--field username|password|otp] [--timeout 30]` — copies to clipboard; no stdout
- `pm show --name <record> [--safe]` — metadata only unless `--show` is passed
- `pm edit --name <record>` — wizard; no secrets echoed
- `pm gen [--strength normal|strong|insane|<1..10>] [--length N] [--no-special] [--no-ambiguous] [--copy] [--preview]` — generate without saving; copy-only flow
- `pm regenerate --name <record> [--strength ...] [--length N] [--no-special] [--no-ambiguous] [--copy]` — update on confirm; clipboard-first
- `pm attach add --name <record> --file <path>` — encrypt and attach
- `pm attach ls --name <record>` — list attachments (names only)
- `pm attach export --name <record> --attachment <id> --out <path>` — decrypt to file; secure permissions
- `pm rotate [--all|--name <record>]` — rotate keys/rehash passwords
- `pm import csv --file <path>` — import with safe prompts

## Clipboard Strategy (cross-platform)
- Windows: PowerShell Set-Clipboard; fallback to clip.exe
- macOS: pbcopy
- Linux: xclip/xsel if available (document optional dep) or use a cross-platform clipboard crate
- Auto-clear: background task/sleep to restore previous clipboard after N seconds where feasible

## Database File
- Single file with header (version, KDF params), encrypted payload (AEAD)
- Optional per-record random nonces; streaming for attachments
- File locking to prevent concurrent writes; graceful errors
- Backups: `pm backup` (encrypted) and `pm restore`

## Security Docs
- SECURITY.md: report policy, scope, supported versions
- THREAT_MODEL.md: assets, adversaries, assumptions, mitigations
- REPRODUCIBLE_BUILDS.md: steps to reproduce release binaries

## Issue Breakdown (initial)
- [ ] UX: Implement clipboard helpers per OS
- [ ] UX: Secure prompts and double-entry
- [ ] CLI: `copy` command (username/password/otp)
- [ ] CLI: `gen` command with presets and advanced numeric strength
- [ ] CLI: `regenerate` flow for existing records (clipboard-first)
- [ ] CLI: `list` with pagination and search
- [ ] Model: records + tags schema
- [ ] Model: password policy per record
- [ ] Attachments: encrypt, list, export to file
- [ ] Crypto: Argon2id config + file format v1
- [ ] Tests: E2E flows without secrets on stdout
- [ ] Docs: SECURITY.md, THREAT_MODEL.md

## Notes
- Binaries are distributed via GitHub Releases; crates.io hosts source for `cargo install`.
- Keep offline-first promise: no network calls in the app.
- Respect license: non‑commercial use; contributions accepted under the same terms.
