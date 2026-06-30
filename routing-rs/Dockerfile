# One workspace build, two runtime images (selected via compose `target:`).
# No protoc needed: envoy-types ships pre-generated ext_proc code, and the
# metrics exporter is built without its protobuf feature.
FROM rust:1-bookworm AS build
WORKDIR /app
COPY . .
RUN cargo build --release

# --- tenant-router (hot path: ext_proc 50052, resolve 9300, metrics 9302) ---
# wget is installed for the container HEALTHCHECK (GET /healthz); the slim base
# ships neither wget nor curl. Runs as a non-root numeric UID so Kubernetes
# `runAsNonRoot` can verify it without a separate runAsUser.
FROM debian:bookworm-slim AS tenant-router
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates wget \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -r -u 10001 app
COPY --from=build /app/target/release/tenant-router /usr/local/bin/tenant-router
USER 10001
EXPOSE 50052 9300 9302
CMD ["tenant-router"]

# --- control-plane (admin API on 9400; ops /metrics + /healthz on 9401) ---
# /metrics is on a SEPARATE port from the admin API so a NetworkPolicy can allow
# scrapers/kubelet to ops WITHOUT granting them the broker-only admin API (RFC C16).
FROM debian:bookworm-slim AS control-plane
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates wget \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -r -u 10001 app
COPY --from=build /app/target/release/control-plane /usr/local/bin/control-plane
USER 10001
EXPOSE 9400 9401
CMD ["control-plane"]
