# syntax=docker/dockerfile:1
ARG GO_VERSION="1.24.7"
ARG RUNNER_IMAGE="gcr.io/distroless/static-debian11"
FROM golang:${GO_VERSION}-alpine AS builder
ARG GIT_VERSION="v0.5.0-rc.1"
ARG COMMIT_SHA="unknown"
RUN apk add --no-cache ca-certificates bash build-base binutils curl git
WORKDIR /dora
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# Share dependency checks, musl flags and artifact smoke tests with release CI.
RUN VERSION="${GIT_VERSION}" COMMIT_SHA="${COMMIT_SHA}" bash scripts/build-bridge-release.sh && \
    mkdir -p /dora/build && \
    case "$(go env GOARCH)" in amd64) suffix=amd ;; arm64) suffix=arm64 ;; *) exit 1 ;; esac && \
    cp "release/dorad-${GIT_VERSION}-linux-${suffix}" /dora/build/dorad
FROM ${RUNNER_IMAGE}
COPY --from=builder /dora/build/dorad /bin/dorad
ENV HOME=/dora
WORKDIR /dora
EXPOSE 26656 26657 1317
ENTRYPOINT ["dorad"]
