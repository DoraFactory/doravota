#!/usr/bin/make -f

.PHONY: build install

build: go.sum
	CGO_ENABLED=1 go build -mod=readonly  -o build/dorad ./cmd/dorad

install: go.sum
	CGO_ENABLED=1 go install -mod=readonly  ./cmd/dorad