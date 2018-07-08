.PHONY: test deps all

all: test docker

test: deps
	go test -cover ./cmd/...
	go test -cover ./pkg/...

vendor: Gopkg.lock
	dep ensure -vendor-only

deps: vendor
	go get -u github.com/hashicorp/vault/api

docker:
	docker build -t polargeospatialcenter/approle-secret-server -f Dockerfile.approle-secret-server .
	docker build -t polargeospatialcenter/credmanager -f Dockerfile.credmanager .
