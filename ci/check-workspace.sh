#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Run the canonical workspace tests on an otherwise idle native Linux host.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."
[[ $(uname -s) == Linux ]] || { echo 'Native Linux is required' >&2; exit 1; }
docker info >/dev/null
compose=(docker compose --project-name sid-workspace-qualification -f docker-compose.test.yml)
for name in sid-test-postgres sid-test-redis sid-test-nats; do
    if docker container inspect "$name" >/dev/null 2>&1; then
        echo "Existing container must remain untouched: $name" >&2
        exit 1
    fi
done
if [[ -e ci/password-clients/node_modules ]]; then
    echo 'Use a clean qualification checkout, preserving existing node_modules' >&2
    exit 1
fi

scratch=$(mktemp -d /var/tmp/sid-workspace-qualification.XXXXXX)
export CARGO_TARGET_DIR="$scratch/target"
export PLAYWRIGHT_BROWSERS_PATH="$scratch/browsers"
export PATH="$scratch/bin:$PATH"
donor=""
services_started=false
# shellcheck disable=SC2329 # Invoked by the exit trap.
cleanup() {
    result=$?
    trap - EXIT
    if [[ -n "$donor" ]]; then
        if ! docker rm "$donor"; then result=1; fi
    fi
    if [[ "$services_started" == true ]]; then
        if ! "${compose[@]}" down --volumes; then result=1; fi
    fi
    if [[ "$result" == 0 ]]; then
        if cargo clean; then
            rm -rf -- "$scratch" ci/password-clients/node_modules
        else
            result=1
        fi
    fi
    if [[ "$result" != 0 ]]; then
        echo "Qualification failed; build evidence retained at $scratch" >&2
    fi
    exit "$result"
}
trap cleanup EXIT

mkdir "$scratch/bin"
protoc --version
node --version
npm --version
# The image supplies the same NATS executable used by the canonical CI job.
donor=$(docker create nats:2.15-alpine)
docker cp "$donor:/usr/local/bin/nats-server" "$scratch/bin/nats-server"
docker rm "$donor"
donor=""
nats-server --version
services_started=true
"${compose[@]}" up -d --wait
npm ci --ignore-scripts --prefix ci/password-clients
ci/password-clients/node_modules/.bin/playwright install chromium
cargo nextest run --locked --workspace --all-features --profile ci
cargo test --locked --doc --workspace --all-features
