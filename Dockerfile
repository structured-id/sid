# syntax=docker/dockerfile:1.7
# StructuredID CE: PostgreSQL storage, bundled NATS, REST beside gRPC, the
# account pages and the administration console.
#
# Build: docker build -t sid .
#
# The binary compiles in a Debian build stage of the release the runtime
# runs: it then needs the runtime's glibc and the baseline x86-64 ISA, never
# what the machine running the build happens to have. Cache mounts are the
# same as in Dockerfile.embedded, under their own ids.

# ── Stage 1: Build ──────────────────────────────────────────────
FROM docker.io/library/rust:trixie AS builder

WORKDIR /build

# protobuf-compiler brings protoc; libprotobuf-dev the well-known types the
# service definitions import.
RUN apt-get update && apt-get install -y --no-install-recommends \
    protobuf-compiler libprotobuf-dev \
    && rm -rf /var/lib/apt/lists/*

COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates/ crates/
# The storage crate compiles its schema migrations in from here.
COPY migrations/ migrations/
COPY proto/ proto/
# The ZKPP crate comes from the zkpp submodule by path.
COPY zkpp/ zkpp/

# The platform the build is made for, compiled into the binary with that
# platform's CA set: the build that publishes the image names the platform
# and fetches the set into the context as platform-cas.json (empty while the
# platform publishes none). Without a platform the binary names none.
ARG SID_BUILD_PLATFORM
ENV SID_BUILD_PLATFORM=${SID_BUILD_PLATFORM}
ENV SID_BUILD_PLATFORM_CAS=${SID_BUILD_PLATFORM:+/build/platform-cas.json}
# The bracket makes the copy match nothing, and succeed, when no set was
# fetched.
COPY platform-cas.jso[n] ./

RUN --mount=type=cache,id=sid-cargo-registry,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,id=sid-cargo-git,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,id=sid-target-ce,target=/build/target,sharing=locked \
    cargo build --locked --release -p sid-server \
    && strip target/release/sid \
    && install -D target/release/sid /out/sid

# The account pages and the administration console, built from the ui-core
# submodule the way its own CI builds them.
FROM docker.io/library/node:26-trixie AS ui

WORKDIR /ui
COPY ui-core/ ./
# Node no longer ships corepack; it is installed from npm, then fetches the
# Yarn the workspace's packageManager names.
RUN npm install -g corepack && corepack enable && corepack install
RUN --mount=type=cache,id=sid-yarn-cache,target=/root/.yarn/berry/cache,sharing=locked \
    cd apps/ui-profile && yarn install --immutable && yarn build
RUN --mount=type=cache,id=sid-yarn-cache,target=/root/.yarn/berry/cache,sharing=locked \
    cd apps/ui-admin && yarn install --immutable && yarn build

# The bundled event bus: with SID_NATS_URL unset the server runs this
# nats-server as a child process (JetStream under SID_DATA_DIR/nats).
FROM docker.io/library/nats:2.15-alpine AS nats

# ── Stage 2: Runtime ────────────────────────────────────────────
FROM docker.io/library/debian:trixie-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates wget \
    && rm -rf /var/lib/apt/lists/*

COPY --from=nats /usr/local/bin/nats-server /usr/local/bin/nats-server
COPY --from=builder /out/sid /usr/local/bin/sid
# The bundles the server serves: account pages at /account/, the console
# where the installation settings place it (/admin/ by default).
COPY --from=ui /ui/apps/ui-profile/dist/spa /usr/share/sid/ui/account
COPY --from=ui /ui/apps/ui-admin/dist/spa /usr/share/sid/ui/admin

# Data directory for auto-generated keys and runtime state
RUN mkdir -p /var/lib/sid && chown nobody:nogroup /var/lib/sid
VOLUME /var/lib/sid

ENV SID_BIND=0.0.0.0:8080
ENV SID_GRPC_BIND=0.0.0.0:50051
ENV SID_DATA_DIR=/var/lib/sid
ENV SID_UI_DIR=/usr/share/sid/ui
EXPOSE 8080 50051

HEALTHCHECK --interval=10s --timeout=5s --retries=3 \
    CMD wget -qO- http://127.0.0.1:8080/health || exit 1

USER nobody
CMD ["sid"]
