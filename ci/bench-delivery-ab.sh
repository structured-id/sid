#!/bin/sh
# Durable delivery benchmark, A/B on one measurement host: the baseline tree
# (CXBR_BASE_CHECKOUT) against the primary tree (the current directory),
# over the same attempt-owned PostgreSQL and NATS services. Both are built
# first; the measurement phase then runs them in the order base, primary,
# primary, base, so host drift does not fall on one side.
set -eu

base="$CXBR_BASE_CHECKOUT"
echo "primary $(git rev-parse HEAD)"
echo "base    $(git -C "$base" rev-parse HEAD)"
nproc

# The phase spans the whole A/B group below, so each run of the benchmark,
# which would otherwise open and close it itself, is started without it.
bench() {
    env -u CXBR_BENCHMARK_PHASE \
        cargo bench --locked -p sid-notify --features bench --bench durable_delivery "$@"
}

bench --no-run
(cd "$base" && bench --no-run)

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

"$CXBR_BENCHMARK_PHASE" begin
for side in base primary primary base; do
    echo "=== $side ==="
    if [ "$side" = base ]; then
        (cd "$base" && bench)
    else
        bench
    fi
done
"$CXBR_BENCHMARK_PHASE" end
