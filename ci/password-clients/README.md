# Published password client conformance

This consumer installs the released public package with its npm integrity hash,
not a local source checkout. The Rust integration test serves real gRPC on an
ephemeral loopback port and drives the installed client in Node and headless
Chromium through registration,
login, retained-password refusal, password change and authorized reset. It also
rejects omitted proofs, forged evaluator replies and a valid proof submitted to
another real operation; retrying an accepted registration returns its durable
result, and a refused password change preserves the current login. Crypto
messages on that connection are protobuf bytes; JSON byte arrays are confined
to the test-process adapter.

```sh
npm ci --ignore-scripts --prefix ci/password-clients
ci/password-clients/node_modules/.bin/playwright install chromium
cargo nextest run --locked -p sid-server --features client-conformance \
  --test packaged_password_client
```

Node 24, Chromium and the locked dependency set are used in CI. The test requires actual
proofs and client Argon2 parameters; unavailable packages fail rather than skip.
It uses the CE co-located evaluator and test storage. It does not establish
UI/BFF or browser HTTP transport, private-kernel delivery, private process isolation, database crash
recovery or weak-device performance.

The browser bundles only the installed public SDK and the shared test command
adapter, served on an ephemeral loopback origin with cross-origin isolation.
It performs the cryptography in Chromium; the Rust driver transmits the resulting
bytes over real gRPC. This isolates browser KSF/prover conformance from the
separate sign-in/account UI and BFF acceptance.
