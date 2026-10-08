## sid-opaque-ke: the OPAQUE key exchange protocol

[OPAQUE](https://eprint.iacr.org/2018/163.pdf) is an augmented password-authenticated key exchange protocol. It allows a client to authenticate to a server using a password, without ever having to expose the plaintext password to the server.

This implementation is based on [RFC 9807](https://datatracker.ietf.org/doc/rfc9807/).

This crate is the [opaque-ke](https://github.com/facebook/opaque-ke) implementation, kept on the current RustCrypto releases (`digest` 0.11, `elliptic-curve` 0.14, `rand_core` 0.10, `curve25519-dalek` 5) and published by StructuredID. Its OPRF is [sid-voprf](https://crates.io/crates/sid-voprf). The protocol and its byte encoding are unchanged: the RFC 9807 test vectors pass.

Background
----------

Augmented Password Authenticated Key Exchange (aPAKE) protocols are designed to provide password authentication and mutually authenticated key exchange without relying on PKI (except during user/password registration) and without disclosing passwords to servers or other entities other than the client machine.

OPAQUE is a PKI-free aPAKE that is secure against pre-computation attacks and capable of using a secret salt.

Documentation
-------------

The API can be found [here](https://docs.rs/sid-opaque-ke/) along with an example for usage. More examples can be found in the [examples](./examples) directory.

Installation
------------

Add the following line to the dependencies of your `Cargo.toml`:

```
sid-opaque-ke = "4.1"
```

### Minimum Supported Rust Version

Rust **1.87** or higher.

Audit
-----

The upstream opaque-ke library was audited by NCC Group in June of 2021. The audit was sponsored by WhatsApp for its use in [enabling end-to-end encrypted backups](https://engineering.fb.com/2021/09/10/security/whatsapp-e2ee-backups/).

The audit found issues in release `v0.5.0`, and the fixes were subsequently incorporated into release `v1.2.0`. See the [full audit report here](https://research.nccgroup.com/2021/12/13/public-report-whatsapp-opaque-ke-cryptographic-implementation-review/).

Resources
---------

- [OPAQUE academic publication](https://eprint.iacr.org/2018/163.pdf), including formal definitions and a proof of security
- [RFC 9807](https://datatracker.ietf.org/doc/rfc9807/), containing a detailed (byte-level) specification for OPAQUE
- ["Let's talk about PAKE"](https://blog.cryptographyengineering.com/2018/10/19/lets-talk-about-pake/), an introductory blog post written by Matthew Green that covers OPAQUE

Contributors
------------

The authors of the upstream code are Kevin Lewi
([@kevinlewi](https://github.com/kevinlewi)) and François Garillot ([@huitseeker](https://github.com/huitseeker)).

#### Acknowledgments

Special thanks go to Hugo Krawczyk and Chris Wood for helping to clarify discrepancies and making suggestions for improving
this implementation. Additional credit goes to @daxpedda for adding no_std support, p256 support, and making other general
improvements to the library.

License
-------

This project is dual-licensed under either the [MIT license](./LICENSE-MIT)
or the [Apache License, Version 2.0](./LICENSE-APACHE).
You may select, at your option, one of the above-listed licenses.
