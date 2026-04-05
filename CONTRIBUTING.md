# Contributing to Siphon

Thank you for your interest in contributing to Siphon! This document provides guidelines and instructions for contributing.

## Development Environment Setup

### Prerequisites

- **Go:** 1.24.9+ via [golang.org](https://go.dev/dl/)
- **Make:** For build automation
- **Git:** For version control

### Getting Started

```bash
# Fork and clone the repository
git clone https://github.com/<your-username>/Siphon.git
cd Siphon

# Generate keys and certificates
make setup

# Build the server
make server

# Run tests with race detector
go test ./... -v -race
```

## Code Style

All code must pass the following checks before submission:

- **Vetting:** `go vet ./...` — all code must pass vet checks
- **Linting:** `staticcheck ./...` — zero warnings allowed
- **Tests:** `go test ./... -race` — all tests must pass with race detector

Run all three before submitting a PR:

```bash
go vet ./...
staticcheck ./...
go test ./... -v -race
```

## Project Structure

Siphon has a clean separation between server and implant:

- `shared/` — Protocol types shared between server and implant
- `server/` — C2 server, crypto, HTTP handlers, operator CLI
- `implant/` — Implant binary with platform-specific evasion and persistence
- `Makefile` — Build system with cross-compilation support

When adding a new feature:

1. **Determine scope** — Does it affect the server, implant, or both?
2. **Follow platform conventions** — Use `_windows.go` / `_other.go` build tags for platform-specific code
3. **Update tests** — Add test coverage in `server/server_test.go`
4. **Document the feature** in the README if it adds user-facing functionality

## Testing Requirements

- All existing tests must continue to pass: `go test ./... -race`
- New features must include tests
- Integration tests go in `server/server_test.go`
- Use the race detector (`-race`) for all test runs

## Pull Request Process

1. **Fork** the repository and create a feature branch:
   ```bash
   git checkout -b feat/my-feature
   ```

2. **Make your changes** with clear, focused commits.

3. **Test thoroughly:**
   ```bash
   go vet ./...
   staticcheck ./...
   go test ./... -v -race
   ```

4. **Push** your branch and open a Pull Request against `main`.

5. **Describe your changes** in the PR using the provided template.

6. **Respond to review feedback** promptly.

## Commit Message Format

This project follows [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<optional scope>): <description>

[optional body]

[optional footer(s)]
```

### Types

| Type       | Description                          |
| ---------- | ------------------------------------ |
| `feat`     | New feature                          |
| `fix`      | Bug fix                              |
| `docs`     | Documentation changes                |
| `style`    | Formatting, no code change           |
| `refactor` | Code restructuring, no behavior change |
| `test`     | Adding or updating tests             |
| `ci`       | CI/CD changes                        |
| `chore`    | Maintenance, dependencies            |
| `perf`     | Performance improvements             |

### Examples

```
feat(implant): add kill-date expiration support
fix(server): handle concurrent beacon race condition
docs: update build instructions for cross-compilation
ci: add Windows cross-compilation job
```

### Important

- Do **not** include AI co-author signatures in commits.
- Keep commits focused on a single logical change.

## Questions?

If you have questions about contributing, feel free to open a discussion or issue on GitHub.
