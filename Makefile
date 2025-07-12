#!/usr/bin/make -f

DOCKER := $(shell which docker)
BUILDDIR ?= $(CURDIR)/build
HTTPS_GIT := https://github.com/DoraFactory/doravota.git
DOCKER_BUF := $(DOCKER) run --rm -v $(CURDIR):/workspace --workdir /workspace bufbuild/buf:1.28.1

###############################################################################
###                                  Build                                 ###
###############################################################################

build: go.sum
	CGO_ENABLED=1 go build -mod=readonly  -o build/dorad ./cmd/dorad

install: go.sum
	CGO_ENABLED=1 go install -mod=readonly  ./cmd/dorad

go.sum: go.mod
	echo "Ensure dependencies have not been modified ..." >&2
	go mod verify
	go mod download

###############################################################################
###                                Protobuf                                ###
###############################################################################

protoVer=0.12.0
protoImageName=ghcr.io/cosmos/proto-builder:$(protoVer)
protoImage=$(DOCKER) run --rm -v $(CURDIR):/workspace --workdir /workspace $(protoImageName)

# ------
# NOTE: If you are experiencing problems running these commands, try deleting
#       the docker image and execute the desired command again.
# ------

proto-all: proto-format proto-lint proto-gen

proto-gen:
	@echo "Generating Protobuf files"
	@if docker ps -a --format '{{.Names}}' | grep -Eq "^${protoImageName}$$"; then docker start -a $(protoImageName); else $(protoImage) sh ./scripts/protocgen.sh; fi

proto-format:
	@echo "Formatting Protobuf files"
	@$(protoImage) find ./ -name "*.proto" -exec clang-format -i {} \;

proto-lint:
	@echo "Linting Protobuf files"
	@$(protoImage) buf lint --error-format=json

proto-check-breaking:
	@echo "Checking Protobuf breaking changes"
	@$(protoImage) buf breaking --against $(HTTPS_GIT)#branch=main

proto-update-deps:
	@echo "Updating Protobuf dependencies"
	@$(protoImage) buf mod update

# Use buf to generate protobuf files (alternative method)
proto-gen-buf:
	@echo "Generating Protobuf files with buf"
	@$(DOCKER_BUF) generate

proto-lint-buf:
	@echo "Linting Protobuf files with buf"
	@$(DOCKER_BUF) lint

proto-format-buf:
	@echo "Formatting Protobuf files with buf"
	@$(DOCKER_BUF) format -w

proto-breaking-buf:
	@echo "Checking Protobuf breaking changes with buf"
	@$(DOCKER_BUF) breaking --against '.git#branch=main'

###############################################################################
###                                Tools                                   ###
###############################################################################

tools-install:
	@echo "Installing tools..."
	@go install github.com/bufbuild/buf/cmd/buf@latest
	@go install github.com/grpc-ecosystem/grpc-gateway/v2/protoc-gen-grpc-gateway@latest
	@go install github.com/grpc-ecosystem/grpc-gateway/v2/protoc-gen-openapiv2@latest
	@go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
	@go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
	@go install cosmossdk.io/tools/cosmovisor/cmd/cosmovisor@latest

tools-clean:
	@echo "Cleaning tools..."
	@go clean -cache
	@go clean -modcache

###############################################################################
###                                Tests                                   ###
###############################################################################

test:
	@echo "Running tests..."
	@go test -v ./...

test-cover:
	@echo "Running tests with coverage..."
	@go test -v -coverprofile=coverage.out ./...
	@go tool cover -html=coverage.out -o coverage.html

###############################################################################
###                                Linting                                 ###
###############################################################################

lint:
	@echo "Running linter..."
	@golangci-lint run --timeout=10m

lint-fix:
	@echo "Running linter with fixes..."
	@golangci-lint run --fix --timeout=10m

format:
	@echo "Formatting code..."
	@find . -name '*.go' -type f -not -path "./vendor*" -not -path "*.git*" -not -path "./client/docs/statik/statik.go" | xargs gofmt -w -s
	@find . -name '*.go' -type f -not -path "./vendor*" -not -path "*.git*" -not -path "./client/docs/statik/statik.go" | xargs misspell -w
	@find . -name '*.go' -type f -not -path "./vendor*" -not -path "*.git*" -not -path "./client/docs/statik/statik.go" | xargs goimports -w -local github.com/DoraFactory/doravota

###############################################################################
###                                Docker                                  ###
###############################################################################

docker-build:
	@echo "Building Docker image..."
	@docker build -t doravota:latest .

docker-run:
	@echo "Running Docker container..."
	@docker run --rm -it doravota:latest

###############################################################################
###                                Clean                                   ###
###############################################################################

clean:
	@echo "Cleaning build artifacts..."
	@rm -rf $(BUILDDIR)
	@rm -rf coverage.out coverage.html

.PHONY: build install go.sum proto-all proto-gen proto-format proto-lint proto-check-breaking proto-update-deps proto-gen-buf proto-lint-buf proto-format-buf proto-breaking-buf tools-install tools-clean test test-cover lint lint-fix format docker-build docker-run clean