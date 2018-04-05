.PHONY: test deps

test: deps
	go test -cover ./{cmd,pkg}/...

vendor: Gopkg.lock
	dep ensure -vendor-only

deps: vendor
	go get -u github.com/hashicorp/vault/api
	go get -u github.com/hashicorp/consul/api
