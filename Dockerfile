# StructuredID CE — Runtime image
# Binary is pre-built by CI (build job) and passed via artifact.
# Local build: cargo build --release -p sid-server && docker build -t sid .
# The bundled event bus: with SID_NATS_URL unset the server runs this
# nats-server as a child process (JetStream under SID_DATA_DIR/nats).
FROM nats:2.15-alpine AS nats

FROM debian:trixie-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates openssl wget \
    && rm -rf /var/lib/apt/lists/*

COPY --from=nats /usr/local/bin/nats-server /usr/local/bin/nats-server
COPY target/release/sid /usr/local/bin/sid

# Data directory for auto-generated JWT keys and runtime state
RUN mkdir -p /var/lib/sid && chown nobody:nogroup /var/lib/sid
VOLUME /var/lib/sid

ENV SID_BIND=0.0.0.0:8080
ENV SID_GRPC_BIND=0.0.0.0:50051
ENV SID_DATA_DIR=/var/lib/sid
EXPOSE 8080 50051

HEALTHCHECK --interval=10s --timeout=5s --retries=3 \
    CMD wget -qO- http://127.0.0.1:8080/health || exit 1

USER nobody
CMD ["sid"]
