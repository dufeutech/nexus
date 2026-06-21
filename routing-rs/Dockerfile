# One workspace build, two runtime images (selected via compose `target:`).
# No protoc needed: envoy-types ships pre-generated ext_proc code, and the
# metrics exporter is built without its protobuf feature.
FROM rust:1-bookworm AS build
WORKDIR /app
COPY . .
RUN cargo build --release

# --- tenant-router (hot path: ext_proc 50052, resolve 9300, metrics 9302) ---
FROM debian:bookworm-slim AS tenant-router
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /app/target/release/tenant-router /usr/local/bin/tenant-router
EXPOSE 50052 9300 9302
CMD ["tenant-router"]

# --- control-plane (admin API + metrics on 9400) ---
FROM debian:bookworm-slim AS control-plane
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /app/target/release/control-plane /usr/local/bin/control-plane
EXPOSE 9400
CMD ["control-plane"]
