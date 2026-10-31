# syntax=docker/dockerfile:1.7
# labd, the maclab controller, as a container (docs/https.md, deploy/k8s/).
#
#   docker build -t ghcr.io/iconidentify/maclab:<tag> .                      (the cluster's own architecture)
#   docker buildx build --platform linux/amd64 -t ghcr.io/iconidentify/maclab:<tag> .
#
# The image holds labd and, next to it, lab-agent for the Macs (linux/arm64), which labd hands out to invited Macs.
# What labd itself runs or reads at run time (the calls it can reach; docs/https.md, "The container"):
#   git ls-remote        resolving a build's source ref (internal/server/sources.go)      -> git, ca-certificates
#   time.LoadLocation    Availability windows' IANA zones (internal/window)               -> tzdata, and -tags timetzdata
#   outbound https       ntfy, omarchy-m-testing.org publishing, GitHub                   -> ca-certificates
#   sh -c                only with --notify-cmd (not used in the pod)                     -> debian's /bin/sh
#   tailscale            only with --tailscale (never in the pod)                         -> not installed
# No secrets go in the image: admin.token and builder.token are made in /data on the first start, or come with
# migrated data. Data: /data (the PVC), owned by uid 10001. Plain HTTP inside the pod only; TLS ends at the Ingress.

FROM --platform=$BUILDPLATFORM golang:1.27.1-bookworm AS build
ARG TARGETOS=linux
ARG TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN set -eux; \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -tags timetzdata -ldflags '-s -w' -o /out/labd ./cmd/labd; \
    CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags '-s -w' -o /out/lab-agent-linux-arm64 ./cmd/lab-agent

FROM debian:bookworm-slim
RUN set -eux; apt-get update; apt-get install -y --no-install-recommends git ca-certificates tzdata tini; \
    rm -rf /var/lib/apt/lists/*; \
    groupadd --gid 10001 labd; \
    useradd --uid 10001 --gid 10001 --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin labd; \
    install -d -o 10001 -g 10001 -m 0700 /data
COPY --from=build /out/labd /out/lab-agent-linux-arm64 /usr/local/bin/
USER 10001:10001
# git wants a HOME; /tmp is the pod's emptyDir (the root filesystem is read-only)
ENV HOME=/tmp
EXPOSE 7770
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/labd"]
# the Deployment gives the real arguments; alone, the image serves this machine only
CMD ["--listen", "127.0.0.1:7770", "--data", "/data"]
