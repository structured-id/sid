#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# Runs inside the check container on the Linux machine, started by check.sh:
# unpacks the uploaded working tree snapshot and runs one task, preparation as
# root and the build as an ordinary account.
#
#   remote.sh musl [target...]   release build of the server for musl targets
#                                (default: x86_64 and aarch64), with zig as the
#                                C cross compiler for the native dependencies
set -euo pipefail

task="${1:?task: musl [target...]}"
shift
upload=/check
repo=/home/builder/sid
export CARGO_TERM_COLOR=never DEBIAN_FRONTEND=noninteractive

apt-get update -qq
apt-get install -y -qq --no-install-recommends protobuf-compiler libprotobuf-dev cmake xz-utils >/dev/null
useradd --create-home builder

as_builder() {
    runuser -u builder -- env CARGO_HOME=/home/builder/.cargo \
        RUSTUP_HOME=/usr/local/rustup PATH="/home/builder/.cargo/bin:/usr/local/cargo/bin:/opt/zig:$PATH" \
        CARGO_TERM_COLOR=never "$@"
}

as_builder git init --quiet "$repo"
as_builder git -C "$repo" fetch --quiet --no-tags "$upload/snapshot.bundle" refs/remote-check/snapshot
as_builder git -C "$repo" -c advice.detachedHead=false checkout --quiet --detach FETCH_HEAD
# The submodules come as archives of the commits they are pinned to: the
# container reaches no repository it would need credentials for.
for archive in "$upload"/submodules/*.tar; do
    [[ -e "$archive" ]] || continue
    path=$(basename "$archive" .tar | tr '%' '/')
    as_builder mkdir -p "$repo/$path"
    as_builder tar -xf "$archive" -C "$repo/$path"
done
cd "$repo"
echo "snapshot $(as_builder git -C "$repo" rev-parse --short HEAD) as $(as_builder id -un)"

case "$task" in
    musl)
        targets=("$@")
        [[ ${#targets[@]} -gt 0 ]] || targets=(x86_64-unknown-linux-musl aarch64-unknown-linux-musl)
        # zig compiles the C of ring, SQLite, aws-lc and anything else the
        # server links, for any target, without a per-target GCC.
        zig_version=0.14.1
        curl -fsSL "https://ziglang.org/download/$zig_version/zig-x86_64-linux-$zig_version.tar.xz" \
            | tar -xJ -C /opt
        mv "/opt/zig-x86_64-linux-$zig_version" /opt/zig
        chmod -R a+rX /opt/zig
        chmod -R a+w /usr/local/rustup
        as_builder rustup target add "${targets[@]}"
        as_builder cargo install --locked --quiet cargo-zigbuild
        status=0
        for target in "${targets[@]}"; do
            echo "===== $target ====="
            # --keep-going: every crate that cannot build for the target is
            # reported, not only the first.
            if as_builder cargo zigbuild --locked --release --keep-going -p sid-server --target "$target"; then
                echo "ok   $target"
            else
                echo "FAIL $target"
                status=1
            fi
        done
        [[ "$status" == 0 ]] || exit "$status"
        ;;
    *)
        echo "unknown task: $task" >&2
        exit 2
        ;;
esac
echo "===== passed ====="
