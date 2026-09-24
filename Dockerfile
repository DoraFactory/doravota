# syntax=docker/dockerfile:1
ARG GO_VERSION=1.24.7
ARG RUNNER_IMAGE=gcr.io/distroless/static-debian11
FROM golang:${GO_VERSION}-alpine AS builder
RUN apk add --no-cache bash ca-certificates build-base linux-headers binutils curl git
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG EMERGENCY_HEIGHT
ARG EMERGENCY_CHAIN_ID
ARG COMMIT_SHA
RUN EMERGENCY_HEIGHT="${EMERGENCY_HEIGHT}" EMERGENCY_CHAIN_ID="${EMERGENCY_CHAIN_ID}" \
    COMMIT_SHA="${COMMIT_SHA}" OUTPUT=/out/dorad bash scripts/build-emergency-044.sh

FROM scratch AS artifacts
COPY --from=builder /out/ /

FROM ${RUNNER_IMAGE} AS runtime
COPY --from=builder /out/dorad /bin/dorad
ENV HOME=/dora
WORKDIR /dora
EXPOSE 26656 26657 1317
ENTRYPOINT ["dorad"]
