.PHONY: test deps

test: deps
	$(MAKE) -C cmd/credmanager test
	$(MAKE) -C cmd/credmanager-api test
	go test ./pkg/...

vendor: Gopkg.lock
	dep ensure -vendor-only

deps: vendor
	go get -u github.com/hashicorp/vault/api
	go get -u github.com/hashicorp/consul/api
