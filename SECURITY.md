# Security Policy

## Reporting a Vulnerability

**Please do NOT report security vulnerabilities through public GitHub issues.**

If you discover a security vulnerability in StructuredID, report it through [private vulnerability reporting](https://github.com/structured-id/sid/security/advisories/new). The report stays confidential until an advisory is published.

### What to Include

- Description of the vulnerability and its impact
- Steps to reproduce or a proof-of-concept
- Affected version(s)
- Any suggested fix (optional)

### Response Timeline

| Severity | Acknowledgement | Patch Target |
|----------|----------------|--------------|
| Critical | 24 hours | 72 hours |
| High | 48 hours | 7 days |
| Medium | 7 days | Next release |
| Low | 7 days | Next release |

### Scope

This policy applies to:
- `sid` (CE binary)
- `zkpp` (zero-knowledge password-policy proofs)
- `proto` (Protobuf definitions)
- `opaque` (OPAQUE client library)
- `sid-client-vue` (Vue 3 gRPC-web client)
- `sid-test` (test fixtures)

### Safe Harbor

We consider security research conducted in good faith to be authorized. We will not pursue legal action against researchers who:

- Make a good faith effort to avoid privacy violations, data destruction, and service disruption
- Only interact with accounts you own or with explicit permission
- Report vulnerabilities promptly and do not exploit them beyond verification

## Supported Versions

| Version | Supported |
|---------|-----------|
| Latest release | Yes |
| Previous minor | Security fixes only |
| Older | No |

## Security Updates

Security advisories are published via [GitHub Security Advisories](https://github.com/structured-id/sid/security/advisories).
