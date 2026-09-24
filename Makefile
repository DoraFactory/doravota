#!/usr/bin/make -f

build: go.sum
	bash scripts/build-maintenance.sh

install: build
	install -d "$$(go env GOPATH)/bin"
	install -m 0755 build/dorad "$$(go env GOPATH)/bin/dorad"
