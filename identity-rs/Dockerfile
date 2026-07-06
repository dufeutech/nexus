# One workspace build, three runtime images (selected via compose `target:`):
# the identity sidecar (hot path), the authz-admin authoring surface, and the
# membership-sync projection worker.
# protoc is needed for the sidecar's native-histogram (protobuf) metrics export.
FROM rust:1-bookworm AS build
WORKDIR /app
RUN apt-get update \
    && apt-get install -y --no-install-recommends protobuf-compiler libprotobuf-dev \
    && rm -rf /var/lib/apt/lists/*
COPY . .
RUN cargo build --release

# --- identity sidecar (hot path: ext_proc 50051, profile 9200, metrics 9202) ---
# wget is installed for the container HEALTHCHECK (GET /healthz); the slim base
# ships neither wget nor curl. Runs as a non-root numeric UID so Kubernetes
# `runAsNonRoot` can verify it without a separate runAsUser.
FROM debian:bookworm-slim AS sidecar
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates wget \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -r -u 10001 app
COPY --from=build /app/target/release/identity-sidecar /usr/local/bin/identity-sidecar
USER 10001
EXPOSE 50051 9200 9202
CMD ["identity-sidecar"]

# --- authz-admin (nexus-native authorization authoring surface + healthz on 9300) ---
# The identity-plane admin API that authors roles/entitlements/suspension
# (nexus-native-authorization). wget is installed for the HEALTHCHECK (GET /healthz).
FROM debian:bookworm-slim AS authz-admin
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates wget \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -r -u 10001 app
COPY --from=build /app/target/release/authz-admin /usr/local/bin/authz-admin
USER 10001
EXPOSE 9300
CMD ["authz-admin"]

# --- membership-sync (routing membership NOTIFY -> Profile projection; metrics 9000) ---
FROM debian:bookworm-slim AS membership-sync
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -r -u 10001 app
COPY --from=build /app/target/release/membership-sync /usr/local/bin/membership-sync
USER 10001
EXPOSE 9000
CMD ["membership-sync"]
