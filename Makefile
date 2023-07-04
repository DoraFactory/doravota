#!/usr/bin/make -f

build: go.sum
ifeq ($(OS),Windows_NT)
	$(error wasmd server not supported. Use "make build-windows-client" for client)
	exit 1
else
	go build -mod=readonly $(BUILD_FLAGS) -o build/doravota-testnetd ./cmd/doravota-testnetd
endif

install: go.sum
	go install -mod=readonly $(BUILD_FLAGS) ./cmd/doravota-testnetd