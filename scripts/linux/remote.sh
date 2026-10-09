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
#   remote.sh history-checker ['<options>'...]
#                                load measurement of the password-history
#                                checker, one run per argument (the options of
#                                the history_checker_load example; none = one
#                                run with its defaults), one JSON line each
set -euo pipefail

task="${1:?task: musl [target...] | history-checker ['<options>'...]}"
shift
export CARGO_TERM_COLOR=never DEBIAN_FRONTEND=noninteractive

if [[ -n "${SID_CHECK_UPLOAD:-}" ]]; then
    # On the host itself (no container): the host's rustup with the pinned
    # toolchain, building inside the upload, which check.sh removes.
    upload="$SID_CHECK_UPLOAD"
    repo="$upload/sid"
    as_builder() {
        RUSTUP_TOOLCHAIN="$SID_CHECK_TOOLCHAIN" CARGO_TARGET_DIR="$upload/target" "$@"
    }
else
    upload=/check
    repo=/home/builder/sid
    apt-get update -qq
    apt-get install -y -qq --no-install-recommends protobuf-compiler libprotobuf-dev cmake xz-utils >/dev/null
    useradd --create-home builder
    as_builder() {
        runuser -u builder -- env CARGO_HOME=/home/builder/.cargo \
            RUSTUP_HOME=/usr/local/rustup PATH="/home/builder/.cargo/bin:/usr/local/cargo/bin:/opt/zig:$PATH" \
            CARGO_TERM_COLOR=never "$@"
    }
fi

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
    history-checker)
        echo "cpus $(nproc), memory $(free -m | awk '/^Mem:/ {print $2}') MiB"
        runs=("$@")
        [[ ${#runs[@]} -gt 0 ]] || runs=("")
        for run in "${runs[@]}"; do
            # shellcheck disable=SC2086 # a run is a list of options
            as_builder cargo run --locked --release --quiet -p sid-authn \
                --example history_checker_load -- $run
        done
        ;;
    *)
        echo "unknown task: $task" >&2
        exit 2
        ;;
esac
echo "===== passed ====="
