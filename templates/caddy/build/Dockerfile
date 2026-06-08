# syntax=docker/dockerfile:1.7

FROM caddy:2-builder AS builder
COPY plugins.txt /tmp/plugins.txt
RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg/mod \
    xcaddy build \
      $(awk 'NF && $1 !~ /^#/ {printf "--with %s ", $1}' /tmp/plugins.txt)

FROM caddy:2
COPY --from=builder /usr/bin/caddy /usr/bin/caddy
