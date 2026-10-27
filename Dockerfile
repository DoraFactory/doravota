# syntax=docker/dockerfile:1
ARG GO_VERSION="1.26.5"
ARG RUNNER_IMAGE="gcr.io/distroless/static-debian11"
# --------------------------------------------------------
# Builder
# --------------------------------------------------------
FROM golang:${GO_VERSION}-alpine AS builder
ARG GIT_VERSION=""
ARG GIT_COMMIT="unknown"
ARG COMMIT_SHA=""
ARG ALLOW_PRERELEASE="false"
RUN apk add --no-cache \
    ca-certificates \
    build-base \
    linux-headers \
    bash binutils curl git xz
# Download go dependencies
WORKDIR /dora
ENV GOPROXY=https://proxy.golang.org,direct
COPY go.mod go.sum ./
COPY third_party/ ./third_party/
RUN go mod download
# Copy the remaining files
COPY . .
# Share dependency checks and artifact smoke tests with release CI.
RUN export VERSION="${GIT_VERSION:-$(cat VERSION)}" && \
    COMMIT_SHA="${COMMIT_SHA:-${GIT_COMMIT}}" ALLOW_PRERELEASE="${ALLOW_PRERELEASE}" \
    bash scripts/build-bridge-release.sh && \
    mkdir -p /dora/build && \
    case "$(go env GOARCH)" in amd64) suffix=amd64 ;; arm64) suffix=arm64 ;; *) exit 1 ;; esac && \
    cp "release/dorad-${VERSION}-linux-${suffix}" /dora/build/dorad
# --------------------------------------------------------
# Runner
# --------------------------------------------------------
FROM ${RUNNER_IMAGE}
COPY --from=builder /dora/build/dorad /bin/dorad
ENV HOME=/dora
WORKDIR $HOME
EXPOSE 26656
EXPOSE 26657
EXPOSE 1317
# Note: uncomment the line below if you need pprof in localdora
# We disable it by default in out main Dockerfile for security reasons
# EXPOSE 6060
ENTRYPOINT ["dorad"]
