.PHONY: test deps all

all: test docker

test: 
	go test -mod=readonly -cover ./cmd/...
	go test -mod=readonly -cover ./pkg/...

docker:
	docker build -t polargeospatialcenter/credmanager -f Dockerfile.credmanager .
