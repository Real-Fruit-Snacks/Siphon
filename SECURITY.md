# Security Policy

## Supported Versions

Only the latest release of Siphon is supported with security updates.

| Version | Supported          |
| ------- | ------------------ |
| latest  | :white_check_mark: |
| < latest | :x:               |

## Reporting a Vulnerability

**Do NOT open public issues for security vulnerabilities.**

If you discover a security vulnerability in Siphon, please report it responsibly:

1. **Preferred:** Use [GitHub Security Advisories](https://github.com/Real-Fruit-Snacks/Siphon/security/advisories/new) to create a private report.
2. **Alternative:** Email the maintainers directly with details of the vulnerability.

### What to Include

- Description of the vulnerability
- Steps to reproduce
- Affected versions
- Potential impact
- Suggested fix (if any)

### Response Timeline

- **Acknowledgment:** Within 48 hours of receipt
- **Assessment:** Within 7 days
- **Fix & Disclosure:** Within 90 days (coordinated responsible disclosure)

We follow a 90-day responsible disclosure timeline. If a fix is not released within 90 days, the reporter may disclose the vulnerability publicly.

## What is NOT a Vulnerability

Siphon is a C2 framework designed for authorized red team operations. The following behaviors are **features, not bugs**:

- ECDH key exchange and encrypted communications
- Command execution on target systems
- File exfiltration and download capabilities
- ETW and AMSI patching for runtime evasion
- PPID spoofing and process creation flags
- Persistence mechanisms (registry, scheduled tasks, startup folder)
- Self-destruct and binary removal capability
- Cookie-based beacon transport with uTLS fingerprinting

These capabilities exist by design for legitimate security testing. Reports that simply describe Siphon working as intended will be closed.

## Responsible Use

Siphon is intended for authorized penetration testing, red team engagements, and security research only. Users are responsible for ensuring they have proper authorization before using this tool against any systems.
