# Contributing to StructuredID

Thank you for your interest in contributing to StructuredID!

## Contributor License Agreement

Before a first pull request can be merged, you sign the Structured World Contributor License Agreement once, at <https://sw.foundation/cla>. It covers every repository of the organisation and takes a minute: sign in with GitHub, confirm your e-mail address, sign. The `CLA` status on your pull request then turns green by itself.

You keep the copyright in your contribution. If you contribute as part of your job, your employer may also need to sign the corporate agreement; the page above explains when.

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

Key principles:
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

**Do not report security vulnerabilities through public issues.** Report them privately at <https://github.com/structured-id/sid/security/advisories/new>; see [SECURITY.md](SECURITY.md).
