# Caddy with the Cloudflare DNS module, for certificates by the DNS challenge.
# The stock caddy image has no DNS modules. Build recipe: Caddy's Docker Hub
# page ("Adding custom Caddy modules"). Module: github.com/caddy-dns/cloudflare.
FROM caddy:2-builder AS builder
RUN xcaddy build --with github.com/caddy-dns/cloudflare

FROM caddy:2-alpine
COPY --from=builder /usr/bin/caddy /usr/bin/caddy
