# Changelog

All notable changes to this project are documented here. The format is based
on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-05-29

Initial release.

### Added
- **Daemon mode** (no arguments): holds a persistent PC/SC session to the
  YubiKey, caches PIN verification for the lifetime of the session, and serves
  ECDH requests over a Unix socket in `$XDG_RUNTIME_DIR`. Touch is still
  required for every decryption (hardware-enforced).
- **age plugin mode** (`--age-plugin=identity-v1`): speaks the C2SP age-plugin
  protocol on stdin/stdout and proxies ECDH to the daemon, prompting for the
  PIN only after a `probe_key` confirms the right YubiKey is connected.
- **Identity conversion**: any non-`--age-plugin=` argument is treated as the
  path to an identity file whose `AGE-PLUGIN-YUBIKEY-` entries are re-encoded
  as `AGE-PLUGIN-YUBIKEY-AGENT-` (atomic write, `.bak` backup).
- **systemd integration**: socket-activated user service (`.socket` + `.service`)
  with hardening (`RestrictAddressFamilies=AF_UNIX`, `SystemCallFilter`,
  `NoNewPrivileges`, `UMask=0177`, etc.).
- Typed tarpc/bincode RPC between plugin and daemon (`probe_key`, `ecdh`).

### Security
- The PIN is never persistently cached; the daemon's owned copy is zeroized
  after use (transport serialization buffers excepted).
- Access control rides on the `0700` `$XDG_RUNTIME_DIR`; the socket is `0600`
  under the systemd unit.

[0.1.0]: https://github.com/brongan/age-plugin-yubikey-agent/releases/tag/v0.1.0
