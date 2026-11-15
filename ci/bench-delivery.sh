#!/bin/sh
# Durable delivery benchmark on a measurement host: PostgreSQL and NATS run
# as attempt-owned service containers whose loopback ports arrive in
# CXBR_SERVICE_PG and CXBR_SERVICE_NATS. Their cgroup is named to the
# benchmark (SID_BENCH_CGROUPS) when it can be found; otherwise their usage
# is reported as unattributed, never guessed.
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

# The attempt's own service containers share one cgroup, `services`, beside
# an ancestor of this script's cgroup; nothing when there is none.
services_cgroup() {
    own=$(cat /proc/self/cgroup 2>/dev/null) || return 0
    path=${own#0::}
    while [ -n "$path" ] && [ "$path" != / ]; do
        path=${path%/*}
        if [ -r "/sys/fs/cgroup${path}/services/cpu.stat" ]; then
            echo "/sys/fs/cgroup${path}/services"
            return 0
        fi
    done
}

cgroups=""
services=$(services_cgroup)
if [ -n "$services" ]; then
    cgroups="services=$services"
else
    pg=$(cgroup_of "$CXBR_SERVICE_PG")
    nats=$(cgroup_of "$CXBR_SERVICE_NATS")
    [ -n "$pg" ] && cgroups="postgres=$pg"
    [ -n "$nats" ] && cgroups="${cgroups:+$cgroups,}nats=$nats"
fi
if [ -n "$cgroups" ]; then
    export SID_BENCH_CGROUPS="$cgroups"
    echo "attributed cgroups: $cgroups"
else
    echo "server cgroups unavailable: server usage is reported unattributed"
fi

exec cargo bench --locked -p sid-notify --features bench --bench durable_delivery
