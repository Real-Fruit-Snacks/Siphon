# Changelog

All notable changes to Siphon will be documented in this file.

Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-04-04

### Added
- HTTPS beacon transport with cookie-based check-in
- ECDH P-256 ephemeral key exchange with per-session forward secrecy
- AES-256-GCM authenticated encryption for all payloads
- HMAC-SHA256 pre-shared token authentication
- uTLS Chrome fingerprinting (HelloChrome_Auto)
- Command execution via cmd.exe (Windows) and /bin/sh (Linux)
- File upload (exfiltration) with 512 KB chunking and AES-GCM at-rest encryption
- File download (deployment) to target with 0600 permissions
- ETW and AMSI runtime patching on Windows
- PPID spoofing under explorer.exe with CREATE_NO_WINDOW
- Persistence via registry run keys, scheduled tasks, and startup folder
- Self-destruct with binary rename and detached cleanup process
- Exponential backoff with cryptographic jitter (crypto/rand)
- Adjustable beacon interval from operator console (capped at 24h)
- Interactive operator CLI with Catppuccin Mocha theming
- Prefix-match implant selection and task queuing
- Resource limits: 1000 implants, 1000 results, 512 KB chunks
- Input limits: 64 KB cookie, 1 MB response, 10 MB submit body
- Integration test suite covering ECDH, AES-GCM, Envelope, and HTTP flow
- Cross-compilation support (Linux server, Windows implant)
- Build-time configuration via ldflags (C2_HOST, SLEEP_SEC, SERVER_PK, AUTH_TOKEN)
