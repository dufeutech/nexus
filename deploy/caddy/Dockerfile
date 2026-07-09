# Customer-domain TLS front tier image: stock Caddy + the Postgres CertMagic storage
# module (not in stock Caddy). Caddy 2.8+ so ARI (renewal rate-limit exemption) is
# automatic. Pin CADDY_VERSION and the storage module commit deliberately; re-verify
# the module still tracks current CertMagic before bumping (design D3).
ARG CADDY_VERSION=2.8

FROM caddy:${CADDY_VERSION}-builder AS build
# Pin the module to a commit in real builds: --with github.com/yroc92/postgres-storage@<sha>
RUN xcaddy build --with github.com/yroc92/postgres-storage

FROM caddy:${CADDY_VERSION}
COPY --from=build /usr/bin/caddy /usr/bin/caddy
# The Caddyfile is MOUNTED read-only by the orchestrator (native config, not baked),
# so a config change never rebuilds the image.
