# ╭──────────────────────────────────────────────────────────────────╮
# │  ┌●───●───●───●───●───●───●───●───●───●───●───●───●───●───●───┐  │
# │  │                                                            │  │
# │  ●   ██╗  ██╗    ██╗    ██╗                                   ●  │
# │  │   ██║  ██║    ██║    ██║           herbiewalker            │  │
# │  │   ███████║    ██║ █╗ ██║──●──●──●──┐                       │  │
# │  │   ██╔══██║    ██║███╗██║           │                       │  │
# │  ●   ██║  ██║    ╚███╔███╔╝           ●───⏣  code · tools     ●  │
# │  │   ╚═╝  ╚═╝     ╚══╝╚══╝                    homelab         │  │
# │  │                                                            │  │
# │  └●───●───●───●───●───●───●───●───●───●───●───●───●───●───●───┘  │
# ╰──────────────────────────────────────────────────────────────────╯
# Sanctum — multi-stage build to a distroless, non-root, static image.
#
# Hard constraint 6 (CLAUDE.md): non-root, read-only rootfs, all capabilities
# dropped, base images pinned BY DIGEST. The `guard-digest-pin` CI step fails
# the build if any FROM line below loses its @sha256: — a floating base tag is
# an unreviewed change to what ships (principle 1).
#
# To update a pin, resolve the new digest deliberately and record why in the
# changelog; never replace a digest with a bare tag "temporarily".

# --- build stage -------------------------------------------------------------
FROM golang:1.26-bookworm@sha256:5de7c99eb78ca5e515a4c340235d0955ec5964a5071c492c15503d7c267da473 AS build

WORKDIR /src

# Dependency layer first, so source edits do not re-download the module graph.
COPY go.mod go.sum* ./
RUN go mod download

COPY . .

# CGO_ENABLED=0 is load-bearing, not an optimization: it is what keeps the
# binary static so the runtime stage can be distroless/static. It is also why
# ADR D-5 chose a tmpfs SQLite + Tink seal over SQLCipher, which would have
# required cgo and forfeited all of this.
ARG VERSION=0.0.0-dev
RUN CGO_ENABLED=0 GOOS=linux go build \
      -trimpath \
      -ldflags="-s -w -X main.version=${VERSION}" \
      -o /out/sanctum ./cmd/sanctum

# --- runtime stage -----------------------------------------------------------
FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab

# distroless :nonroot is uid/gid 65532. Stated explicitly so `docker inspect`
# can assert it in CI rather than trusting the base image's default.
USER 65532:65532

COPY --from=build /out/sanctum /usr/local/bin/sanctum

# Only the HTTP surface. LAN-only in v1 (ADR D-12) — publishing this port to
# the internet is a hard-constraint violation, not a deployment choice.
EXPOSE 8080

# In the image (not just compose) so the Unraid template and any other runtime
# get the same health signal. distroless has no shell/curl; the binary probes itself.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ["/usr/local/bin/sanctum", "-healthcheck"]

ENTRYPOINT ["/usr/local/bin/sanctum"]

# ⏣ HW ⏣ · code · tools · homelab · ⏣ HW ⏣
