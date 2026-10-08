#!/usr/bin/env bash
# Dependency isolation checks for the SID workspace.
#
# Cargo unifies features across every package built together, so a successful
# workspace build can hide a package that never declared a feature it uses: a
# neighbour enabled it. These checks build and resolve packages on their own.
#
#   closure     client-facing packages: no server/storage crate in their normal
#               dependency graph, for each supported feature set and target
#   combos      each supported feature combination of each package, built alone
#   each        every feature of every package on its own (cargo-hack), in a
#               copy of the checkout because cargo-hack rewrites manifests
#   consumers   sid-proto, sid-core and both together as dependencies of
#               projects outside this workspace
#   all         everything above
#
# Server and storage packages keep their database, broker and cache
# dependencies; only the client-facing closure is restricted.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# Targets a client-facing package is consumed on.
CLIENT_TARGETS=(
  x86_64-unknown-linux-gnu
  aarch64-unknown-linux-gnu
  x86_64-apple-darwin
  aarch64-apple-darwin
  x86_64-pc-windows-msvc
  aarch64-apple-ios
  aarch64-linux-android
)

# Crates that belong to the server, its storage or its infrastructure.
SERVER_ONLY='^(sqlx|sqlx-core|sqlx-postgres|sqlx-sqlite|sqlx-macros|sqlx-macros-core|libsqlite3-sys|sid-storage|sid-server|sid-authn|sid-infra|sid-notify|async-nats|fred|coordinode[a-z0-9_-]*) '

# Client-facing packages and their supported feature sets ("pkg|flags").
CLIENT_SETS=(
  "sid-keys|"
  "sid-core|"
  "sid-core|--no-default-features"
  "sid-core|--features grpc"
  "sid-proto|"
)

# Supported feature combinations of every package ("pkg|flags"), as named in
# the package manifests.
COMBOS=(
  "sid-keys|"
  "sid-core|"
  "sid-core|--no-default-features"
  "sid-core|--features grpc"
  "sid-core|--no-default-features --features grpc"
  "sid-proto|"
  "sid-plugin|"
  "sid-crypto|"
  "sid-crypto|--no-default-features --features primitives"
  "sid-storage|"
  "sid-storage|--no-default-features --features storage-sqlite"
  "sid-storage|--features storage-sqlite"
  "sid-authn|"
  "sid-authn|--features grpc"
  "sid-authz|"
  "sid-authz|--no-default-features"
  "sid-authz|--features standalone"
  "sid-admin|"
  "sid-fed|"
  "sid-i18n|"
  "sid-i18n|--no-default-features --features i18n-en"
  "sid-infra|"
  "sid-infra|--features http"
  "sid-org-crypto|"
  "sid-org-crypto|--features k8s"
  "sid-webtransport|"
  "sid-scim|"
  "sid-notify|"
  "sid-attestation|"
  "sid-auth|"
  "sid-auth|--no-default-features"
  "sid-auth-proxy|"
  "sid-migrate|"
  "sid-migrate|--no-default-features --features storage-pg"
  "sid-migrate|--no-default-features --features storage-sqlite"
  "sid-server|"
  "sid-server|--no-default-features --features embedded-dev"
  "sid-server|--features webtransport"
)

fail=0

check_closure() {
  local entry pkg flags target found
  for entry in "${CLIENT_SETS[@]}"; do
    pkg="${entry%%|*}"
    flags="${entry#*|}"
    for target in "${CLIENT_TARGETS[@]}"; do
      # shellcheck disable=SC2086
      found="$(cargo tree --locked -p "$pkg" $flags -e normal --target "$target" \
        --prefix none -f '{p}' | grep -E "$SERVER_ONLY" | sort -u || true)"
      if [[ -n "$found" ]]; then
        echo "FAIL closure $pkg [$flags] on $target pulls server-only crates:"
        echo "$found" | sed 's/^/    /'
        fail=1
      else
        echo "ok   closure $pkg [$flags] on $target"
      fi
    done
  done
}

check_combos() {
  local entry pkg flags targets
  for entry in "${COMBOS[@]}"; do
    pkg="${entry%%|*}"
    flags="${entry#*|}"
    # Tests and benches are written for the default features, so they are
    # built there; other combinations build the library and binaries.
    targets=""
    [[ -z "$flags" ]] && targets="--all-targets"
    # shellcheck disable=SC2086
    if cargo check --locked -p "$pkg" $flags $targets; then
      echo "ok   combo $pkg [$flags]"
    else
      echo "FAIL combo $pkg [$flags]"
      fail=1
    fi
  done
}

check_each() {
  command -v cargo-hack >/dev/null || { echo "cargo-hack is required"; exit 2; }
  local copy
  copy="$(mktemp -d)"
  trap 'rm -rf "$copy"' RETURN
  # A copy, not the checkout: --no-dev-deps rewrites manifests while it runs.
  rsync -a --exclude target --exclude .git "$ROOT/" "$copy/"
  (
    cd "$copy"
    export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target}/isolation-each"
    # Dropping dev-dependencies rewrites the copy's lockfile, so no --locked;
    # --offline keeps the versions the checkout already locked.
    cargo hack check --offline --workspace --each-feature --no-dev-deps \
      --exclude sid-server --exclude sid-migrate
    # A server or migration build without a storage backend is not a product:
    # every other feature is checked together with one of the backends.
    cargo hack check --offline -p sid-server --feature-powerset --depth 2 \
      --no-dev-deps --at-least-one-of storage-pg,embedded-dev
    cargo hack check --offline -p sid-migrate --feature-powerset --depth 2 \
      --no-dev-deps --at-least-one-of storage-pg,storage-sqlite
  ) || fail=1
}

check_consumers() {
  local work name flags
  work="$(mktemp -d)"
  trap 'rm -rf "$work"' RETURN
  # Each consumer resolves outside the workspace with the workspace's pinned
  # versions; the lockfile is trimmed to the consumer's own graph.
  for name in sid-proto sid-core combined; do
    cp -R "$ROOT/ci/external-consumers/$name" "$work/$name"
    sed -i.bak "s|@SID@|$ROOT|g" "$work/$name/Cargo.toml"
    rm "$work/$name/Cargo.toml.bak"
    cp "$ROOT/Cargo.lock" "$work/$name/Cargo.lock"
  done
  local sets=(
    "sid-proto|"
    "sid-core|"
    "sid-core|--features recovery"
    "sid-core|--features grpc"
    "sid-core|--features recovery,grpc"
    "combined|"
  )
  local entry found
  for entry in "${sets[@]}"; do
    name="${entry%%|*}"
    flags="${entry#*|}"
    # shellcheck disable=SC2086
    if (cd "$work/$name" && CARGO_TARGET_DIR="$work/target" cargo run --offline $flags); then
      echo "ok   consumer $name [$flags]"
    else
      echo "FAIL consumer $name [$flags]"
      fail=1
    fi
    # shellcheck disable=SC2086
    found="$(cd "$work/$name" && cargo tree --offline $flags -e normal --target all \
      --prefix none -f '{p}' | grep -E "$SERVER_ONLY" | sort -u || true)"
    if [[ -n "$found" ]]; then
      echo "FAIL consumer $name [$flags] pulls server-only crates:"
      echo "$found" | sed 's/^/    /'
      fail=1
    fi
  done
}

case "${1:-all}" in
  closure) check_closure ;;
  combos) check_combos ;;
  each) check_each ;;
  consumers) check_consumers ;;
  all) check_closure; check_combos; check_each; check_consumers ;;
  *) echo "usage: $0 [closure|combos|each|consumers|all]"; exit 2 ;;
esac

exit "$fail"
