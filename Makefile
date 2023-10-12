#!/usr/bin/make -f

build: go.sum
	go build -mod=readonly CGO_ENABLED=1 -o build/dorad ./cmd/dorad

install: go.sum
	go install -mod=readonly CGO_ENABLED=1 ./cmd/dorad