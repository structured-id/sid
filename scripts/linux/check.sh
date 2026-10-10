#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# Runs checks on a Linux machine against the exact state of this working tree,
# committed or not, without touching the index, HEAD or any branch here.
#
#   SID_LINUX=<ssh destination> scripts/linux/check.sh musl
#   SID_LINUX=<ssh destination> scripts/linux/check.sh musl aarch64-unknown-linux-musl
#   SID_LINUX=<ssh destination> scripts/linux/check.sh history-checker '--domains 2 --entries 24'
#
# `musl` builds the server for the given musl targets (by default x86_64 and
# aarch64), which exercises every native dependency the server links.
# `history-checker` measures the password-history checker under concurrent
# load, one run per argument.
#
# SID_REV names a commit or branch to check instead of the working tree.
#
# The checks run in the pinned toolchain image as an ordinary account.
# Everything they build lives in the container and goes with it, and the
# upload goes too, whatever the outcome: the machine is shared with other work.
#
# SID_LINUX_RUNTIME=host runs on a machine without a container runtime: the
# host's rustup with the pinned toolchain, building inside the upload, which
# is removed with everything built there.
set -euo pipefail

destination="${SID_LINUX:?set SID_LINUX to the SSH destination of the Linux machine}"
task="${1:?task: musl [target...] | history-checker ['<options>'...]}"
shift
# The version rust-toolchain.toml pins.
image="rust:1.99.0"

ssh_options=(-o BatchMode=yes -o LogLevel=ERROR)

root=$(git rev-parse --show-toplevel)
work=$(mktemp -d)
snapshot_ref=refs/remote-check/snapshot
remote=""
container="sid-check-$(date +%s)-$$"
# shellcheck disable=SC2329 # called by the EXIT trap
cleanup() {
    git -C "$root" update-ref -d "$snapshot_ref" 2>/dev/null || true
    rm -rf "$work"
    if [[ -n "$remote" ]]; then
        # shellcheck disable=SC2029 # the names are meant to be expanded here
        ssh "${ssh_options[@]}" "$destination" \
            "docker rm -f $container >/dev/null 2>&1; rm -rf -- '$remote'" || true
    fi
}
trap cleanup EXIT

if [[ -n "${SID_REV:-}" ]]; then
    commit=$(git -C "$root" rev-parse --verify "${SID_REV}^{commit}")
else
    # The snapshot is built in a separate index: tracked and untracked files
    # as they are now, ignored files left out.
    GIT_INDEX_FILE="$work/index" git -C "$root" read-tree HEAD
    GIT_INDEX_FILE="$work/index" git -C "$root" add --all
    tree=$(GIT_INDEX_FILE="$work/index" git -C "$root" write-tree)
    commit=$(git -C "$root" commit-tree "$tree" -p HEAD -m "working tree snapshot")
fi
git -C "$root" update-ref "$snapshot_ref" "$commit"
git -C "$root" bundle create --quiet "$work/snapshot.bundle" "$snapshot_ref"
git -C "$root" update-ref -d "$snapshot_ref"

# Each submodule travels as an archive of the commit the snapshot pins, named
# by its path with '/' written as '%'.
mkdir "$work/submodules"
while read -r _ type pinned path; do
    [[ "$type" == commit ]] || continue
    git -C "$root/$path" archive --format=tar "$pinned" >"$work/submodules/${path//\//%}.tar"
done < <(git -C "$root" ls-tree -r "$commit")
cp "$root/scripts/linux/remote.sh" "$work/remote.sh"

remote=$(ssh "${ssh_options[@]}" "$destination" 'mktemp -d /tmp/sid-check.XXXXXX')
# The checks read the upload as an ordinary account.
# shellcheck disable=SC2029
ssh "${ssh_options[@]}" "$destination" "chmod 755 '$remote'"
scp "${ssh_options[@]}" -q -r "$work/snapshot.bundle" "$work/submodules" "$work/remote.sh" \
    "$destination:$remote/"

arguments=""
for argument in "$task" "$@"; do
    arguments+=" '${argument//\'/\'\\\'\'}'"
done
status=0
if [[ "${SID_LINUX_RUNTIME:-container}" == host ]]; then
    # shellcheck disable=SC2029
    ssh "${ssh_options[@]}" "$destination" \
        "SID_CHECK_UPLOAD='$remote' SID_CHECK_TOOLCHAIN='${image#rust:}' bash '$remote/remote.sh'$arguments" \
        || status=$?
else
    # shellcheck disable=SC2029
    ssh "${ssh_options[@]}" "$destination" \
        "docker run -d --name $container -v '$remote':/check:ro $image tail -f /dev/null >/dev/null"
    # shellcheck disable=SC2029
    ssh "${ssh_options[@]}" "$destination" "docker exec $container bash /check/remote.sh$arguments" \
        || status=$?
fi
exit "$status"
