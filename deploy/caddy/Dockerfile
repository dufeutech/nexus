# Customer-domain TLS front tier image: stock Caddy + the Postgres CertMagic storage
# module (not in stock Caddy). Caddy 2.8+ so ARI (renewal rate-limit exemption) is
# automatic. Pin CADDY_VERSION and the storage module commit deliberately; re-verify
# the module still tracks current CertMagic before bumping (design D3).
ARG CADDY_VERSION=2.8

FROM caddy:${CADDY_VERSION}-builder AS build
# Pinned to a commit for reproducible builds (infra N13 / design D3). This is the module
# HEAD that introduced the optional-DDL flag — the exact feature the Caddyfile's
# `storage postgres { disable_ddl true }` relies on, so the DML-only-role posture stays
# verified against a known module. Re-verify it still tracks current CertMagic before bumping.
RUN xcaddy build --with github.com/yroc92/postgres-storage@276797aefe401b738781692d278a158c53b99208

FROM caddy:${CADDY_VERSION} AS caddy
COPY --from=build /usr/bin/caddy /usr/bin/caddy
# The Caddyfile is MOUNTED read-only by the orchestrator (native config, not baked),
# so a config change never rebuilds the image.
