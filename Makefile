.PHONY: test deps all

all: test docker

test: deps
	go test -cover ./cmd/...
	go test -cover ./pkg/...

vendor: Gopkg.lock
	dep ensure -vendor-only

deps: vendor

docker:
	docker build -t polargeospatialcenter/approle-secret-server -f Dockerfile.approle-secret-server .
	docker build -t polargeospatialcenter/credmanager -f Dockerfile.credmanager .
