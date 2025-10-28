.PHONY: build
build:
	go build -o huntsuite ./cmd/huntsuite

.PHONY: clean
clean:
	rm -f huntsuite
