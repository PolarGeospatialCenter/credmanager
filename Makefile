.PHONY: test deps

test: deps
	$(MAKE) -C cmd/credmanager test
	$(MAKE) -C cmd/credmanager-api test
	go test ./pkg/...

deps: vendor
	go get github.com/hashicorp/vault/api
	go get github.com/hashicorp/consul/api

vendor: Gopkg.toml
	dep ensure
