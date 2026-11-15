#!/bin/sh
# Durable delivery benchmark on a measurement host: PostgreSQL and NATS run
# as attempt-owned service containers whose loopback ports arrive in
# CXBR_SERVICE_PG and CXBR_SERVICE_NATS. Their cgroups are named to the
# benchmark (SID_BENCH_CGROUPS) when the container runtime can be asked;
# otherwise their usage is reported as unattributed, never guessed.
set -eu

git rev-parse HEAD
nproc

cargo bench --locked -p sid-notify --features bench --bench durable_delivery --no-run

export SID_BENCH_POSTGRES_URL="postgres://sid:sid_dev@127.0.0.1:${CXBR_SERVICE_PG}"
export SID_TEST_NATS_URL="nats://127.0.0.1:${CXBR_SERVICE_NATS}"

# The cgroup of the service container publishing host port $1, as
# /sys/fs/cgroup/<path>; nothing when it cannot be determined.
cgroup_of() {
    command -v podman >/dev/null 2>&1 || return 0
    for id in $(podman ps -q 2>/dev/null); do
        if podman port "$id" 2>/dev/null | grep -q ":$1\$"; then
            path=$(podman inspect --format '{{.State.CgroupPath}}' "$id" 2>/dev/null) || return 0
            [ -n "$path" ] && [ -r "/sys/fs/cgroup${path}/cpu.stat" ] && echo "/sys/fs/cgroup${path}"
            return 0
        fi
    done
}

pg=$(cgroup_of "$CXBR_SERVICE_PG")
nats=$(cgroup_of "$CXBR_SERVICE_NATS")
cgroups=""
[ -n "$pg" ] && cgroups="postgres=$pg"
[ -n "$nats" ] && cgroups="${cgroups:+$cgroups,}nats=$nats"
if [ -n "$cgroups" ]; then
    export SID_BENCH_CGROUPS="$cgroups"
    echo "attributed cgroups: $cgroups"
else
    echo "server cgroups unavailable: server usage is reported unattributed"
fi

exec cargo bench --locked -p sid-notify --features bench --bench durable_delivery
