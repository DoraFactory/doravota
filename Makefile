#!/usr/bin/make -f

.PHONY: build install

build: go.sum
	CGO_ENABLED=0 go build -mod=readonly  -o build/dorad ./cmd/dorad

install: go.sum
	CGO_ENABLED=0 go install -mod=readonly  ./cmd/dorad