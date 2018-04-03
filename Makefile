.PHONY: test

test:
	$(MAKE) -C cmd/credmanager test
	$(MAKE) -C cmd/credmanager-api test
	go test ./pkg/...
