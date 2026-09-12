# syntax=docker/dockerfile:1
ARG GO_VERSION="1.24.7"
ARG RUNNER_IMAGE="gcr.io/distroless/static-debian11"
# --------------------------------------------------------
# Builder
# --------------------------------------------------------
FROM golang:${GO_VERSION}-alpine as builder
ARG GIT_VERSION="v0.5.0-rc.1"
ARG GIT_COMMIT="unknown"
ARG COMMIT_SHA=""
RUN apk add --no-cache \
    ca-certificates \
    build-base \
    linux-headers \
    bash binutils curl git
# Download go dependencies
WORKDIR /dora
COPY go.mod go.sum ./
RUN go mod download
# Copy the remaining files
COPY . .
# Share dependency checks, musl flags and artifact smoke tests with release CI.
RUN VERSION="${GIT_VERSION}" COMMIT_SHA="${COMMIT_SHA:-${GIT_COMMIT}}" \
    BUILD_TAGS="muslc,netgo,osusergo,static_build,ledger" bash scripts/build-bridge-release.sh && \
    mkdir -p /dora/build && \
    case "$(go env GOARCH)" in amd64) suffix=amd ;; arm64) suffix=arm64 ;; *) exit 1 ;; esac && \
    cp "release/dorad-${GIT_VERSION}-linux-${suffix}" /dora/build/dorad
# --------------------------------------------------------
# Runner
# --------------------------------------------------------
FROM ${RUNNER_IMAGE}
COPY --from=builder /dora/build/dorad /bin/dorad
ENV HOME /dora
WORKDIR $HOME
EXPOSE 26656
EXPOSE 26657
EXPOSE 1317
# Note: uncomment the line below if you need pprof in localdora
# We disable it by default in out main Dockerfile for security reasons
# EXPOSE 6060
ENTRYPOINT ["dorad"]