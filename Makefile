.PHONY: build clean dist

BINARY := blocknet-miner

build:
	go build -o $(BINARY) ./cmd/blocknet-miner

clean:
	rm -f $(BINARY)
	rm -rf dist

# Create dist/ with the launcher + a bundled blocknet daemon binary.
# Usage:
#   make dist BLOCKNET_BIN=/path/to/blocknet
# or if you have the blocknet repo checked out next to this one:
#   make dist

BLOCKNET_BIN ?= ../blocknet/blocknet

dist: build
	@mkdir -p dist
	@cp -f $(BINARY) dist/$(BINARY)
	@chmod 755 dist/$(BINARY)
	@if [ ! -f "$(BLOCKNET_BIN)" ]; then \
		echo "Error: blocknet binary not found at '$(BLOCKNET_BIN)'"; \
		echo "Set BLOCKNET_BIN=/path/to/blocknetd"; \
		exit 1; \
	fi; \
	cp -f "$(BLOCKNET_BIN)" dist/blocknetd; \
	chmod 755 dist/blocknetd
	@echo "Built dist/ with $(BINARY) + blocknetd"
