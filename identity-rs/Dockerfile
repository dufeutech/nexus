# One workspace build, three runtime images (selected via compose `target:`).
# protoc is needed for the sidecar's native-histogram (protobuf) metrics export.
FROM rust:1-bookworm AS build
WORKDIR /app
RUN apt-get update \
    && apt-get install -y --no-install-recommends protobuf-compiler libprotobuf-dev \
    && rm -rf /var/lib/apt/lists/*
COPY . .
RUN cargo build --release

# --- identity sidecar (hot path: ext_proc 50051, profile 9200, metrics 9202) ---
FROM debian:bookworm-slim AS sidecar
COPY --from=build /app/target/release/identity-sidecar /usr/local/bin/identity-sidecar
EXPOSE 50051 9200 9202
CMD ["identity-sidecar"]

# --- sync-worker (webhook + metrics + healthz on 8080) ---
FROM debian:bookworm-slim AS sync-worker
COPY --from=build /app/target/release/sync-worker /usr/local/bin/sync-worker
EXPOSE 8080
CMD ["sync-worker"]

# --- reconciler (metrics on 9000) ---
FROM debian:bookworm-slim AS reconciler
COPY --from=build /app/target/release/reconciler /usr/local/bin/reconciler
EXPOSE 9000
CMD ["reconciler"]
