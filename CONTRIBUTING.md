# Contributing to StructuredID

Thank you for your interest in contributing to StructuredID!

## Contributor License Agreement

All contributions require signing our [CLA](CLA.md). The CLA bot will prompt you on your first pull request.

## Development Setup

```bash
# Clone
git clone --recursive https://github.com/structured-id/sid.git
cd sid

# Build
cargo build

# Run tests (requires PostgreSQL on port 54399)
docker compose -f docker-compose.test.yml up -d
cargo nextest run --workspace

# Lint
cargo clippy --all-targets --all-features -- -D warnings
cargo fmt --check
```

## Pull Request Guidelines

1. **One concern per PR** -- don't mix features with refactoring
2. **Tests required** -- every function needs unit tests, every API endpoint needs integration tests
3. **Clippy clean** -- zero warnings (`-D warnings`)
4. **Conventional commits** -- `feat(auth): add passkey enrollment`, `fix(storage): handle null timestamps`

## Code Style

- `pub(crate)` by default, explicit `pub` only for trait APIs
- `Result<T, E>` everywhere, no `unwrap()` on I/O paths
- `Secret<T>` for credentials (zeroize on drop)
- `ct_eq()` for secret comparisons (constant-time)

## Architecture

See [ARCH.md](ARCH.md) for the full architecture overview.

Key principles:
- Architecture docs (`arch/`) are the source of truth. Code must converge to architecture.
- Profile IS the user (no separate User entity in CE)
- CE instance IS the organization (implicit)
- Proto-first development: define `.proto` first, then implement

## Reporting Issues

Use [GitHub Issues](https://github.com/structured-id/sid/issues). Include:
- Steps to reproduce
- Expected vs actual behavior
- Version (`sid --version`)
- Relevant logs (redact credentials)

## Security Vulnerabilities

**Do not report security vulnerabilities through public issues.** Email security@structured.id with details. See [SECURITY.md](SECURITY.md) if it exists, or the security policy in the repo settings.
