# sid-voprf
An implementation of a (verifiable) oblivious pseudorandom function (VOPRF)

A VOPRF is a verifiable oblivious pseudorandom function, a protocol between a client and a server. The regular (non-verifiable) OPRF is also supported in this implementation.

This implementation is based on [RFC 9497](https://www.rfc-editor.org/rfc/rfc9497).

This crate is the [voprf](https://github.com/facebook/voprf) implementation, kept on the current RustCrypto releases (`digest` 0.11, `elliptic-curve` 0.14, `hash2curve` 0.14, `rand_core` 0.10, `curve25519-dalek` 5) and published by StructuredID. The protocol and its byte encoding are unchanged: the RFC 9497 test vectors pass.

Documentation
-------------

The API can be found [here](https://docs.rs/sid-voprf/) along with an example for usage.

Installation
------------

Add the following line to the dependencies of your `Cargo.toml`:

```
sid-voprf = "0.6"
```

### Minimum Supported Rust Version

Rust **1.85** or higher.

Contributors
------------

The author of the upstream code is Kevin Lewi ([@kevinlewi](https://github.com/kevinlewi)).

License
-------

This project is dual-licensed under either the [MIT license](./LICENSE-MIT)
or the [Apache License, Version 2.0](./LICENSE-APACHE).
You may select, at your option, one of the above-listed licenses.
