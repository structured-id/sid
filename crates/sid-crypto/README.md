# sid-crypto

Host-selected cryptographic primitives and independent rustls/jsonwebtoken
adapters. This library does not provide an identity service, certificate
authority, JWT processing engine, claim policy or key manager.

The base operation contract uses `no_std + alloc`. Standard-library and backend
dependencies are selected through features:

| Feature | Capability |
| --- | --- |
| `alloc` | Allocation support without choosing a backend |
| `std` | Standard-library support |
| `primitives` | RustCrypto AES-256-GCM, HMAC-SHA256, HKDF-SHA256, PBKDF2-SHA256 and SHA-256 |
| `aws-lc` | AWS-LC implementation of the same primitive contract |
| `tls-rustcrypto` | RustCrypto provider for rustls |
| `tls-aws-lc` | AWS-LC provider for rustls |
| `tls12` | TLS 1.2 suites for an enabled TLS adapter |
| `jwt-rustcrypto` | RustCrypto adapter for jsonwebtoken's extension traits |
| `jwt` | Explicit AWS-LC JWT provider installer |
| `fips` | AWS-LC FIPS module build, not deployment certification |

Defaults select `std`, AWS-LC primitives, AWS-LC TLS and the AWS-LC JWT installer.
Use `default-features = false` to consume only the required capabilities. In
particular, TLS-only RustCrypto does not require JWT, AWS-LC or SID services;
JWT-only RustCrypto does not require the TLS stack.

## TLS

```toml
sid-crypto = { version = "0.1", default-features = false, features = ["std", "tls-rustcrypto", "tls12"] }
```

`sid_crypto::tls::rustcrypto::provider()` and
`sid_crypto::tls::aws_lc::provider()` return a rustls `CryptoProvider` without
installing it. Pass the selected provider to rustls configuration builders.
The host selects trust anchors, peer identities, protocol versions and any
process-global installation.

Consumers that use rustls' process default require explicit host initialization
before their clients are constructed. Treat an already selected provider as a
startup conflict, rather than ignoring the error or trying another backend.
The TLS module's executable example demonstrates this initialization with the
existing rustls API. A library constructor or HTTP builder does not install a
provider on behalf of its embedding host. TLS and JWT initialization are
independent; selecting either one does not initialize the other.

The RustCrypto adapter supports X25519, P-256 and P-384 key exchange, AES-GCM
and ChaCha20-Poly1305 suites, and P-256/P-384 ECDSA or Ed25519 local identities.
RSA public verification remains available; RSA private operations are refused.
TLS 1.2 is optional. Both TLS profiles retain rustls certificate validation,
AEAD usage bounds and record-length checks.

The RustCrypto TLS dependency closure supports Rust 1.92 and `no_std + alloc`.
On targets without an OS entropy source, configure getrandom's supported custom
backend and supply secure host entropy. A compile check with that backend is
not evidence that a particular device supplies qualified entropy. These target
and compiler guarantees do not extend automatically to optional JWT or AWS-LC
dependencies.

## JWT

`sid_crypto::jwt::rustcrypto::provider()` returns a static jsonwebtoken
`CryptoProvider` without installing it. The host may install this provider
explicitly before the first JWT operation. Parsing, serialization, algorithm
selection and claim validation remain with jsonwebtoken and the application.
Applications using PEM constructors enable jsonwebtoken's `use_pem` feature;
the provider adapter does not select key serialization formats.

RustCrypto signing supports HS256/384/512, ES256/384 and EdDSA. Verification also
supports RS256/384/512 and PS256/384/512 with bounded 2048 to 8192-bit public RSA
keys. RSA signing and private-key extraction are refused. The AWS-LC capability
retains `sid_crypto::jwt::install_jwt_provider()`, an explicit host operation
that reports a conflict if another process provider has already been selected.

## Primitive operations

`CryptoPrimitives` is the common operation boundary. `RustCryptoPrimitives`
and `AwsLcPrimitives` are stateless implementations; the caller owns keys,
nonces, contexts and their lifetimes. HKDF output is limited to 8160 bytes
before allocation. PBKDF2 requires positive iterations and nonempty output,
rejecting invalid parameters before mutation. Entropy failure is returned as
`CryptoError::Entropy`; it never supplies replacement nonce bytes.

`is_fips()` describes a selected module build. It does not certify an
application, runtime environment or deployment.

## License

Apache-2.0. See `NOTICES` for the retained notices of adapted TLS code.
Independent TLS implementations are test oracles, not RustCrypto product
dependencies.
