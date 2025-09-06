.PHONY: install test run build deploy clean

# Variables
BINARY_NAME=kopia_verify
FREEBSD_BINARY=$(BINARY_NAME)_freebsd_amd64
GO_FILES=*.go

# Install dependencies
install:
	go mod init kopia_verify || true
	go mod tidy

# Format code and run tests
test:
	go fmt ./...
	go test ./...

# Run locally (requires GCS auth)
run:
	go run verify.go

# Build FreeBSD binary for server deployment
build:
	GOOS=freebsd GOARCH=amd64 go build -o $(FREEBSD_BINARY) verify.go

# Deploy binary to server
deploy: build
	scp $(FREEBSD_BINARY) server:/tmp/$(BINARY_NAME)
	ssh server "sudo mv /tmp/$(BINARY_NAME) /usr/local/bin/$(BINARY_NAME) && sudo chmod +x /usr/local/bin/$(BINARY_NAME)"

# Clean build artifacts
clean:
	rm -f $(FREEBSD_BINARY) $(BINARY_NAME)

# Show help
help:
	@echo "Available targets:"
	@echo "  install - Initialize go module and install dependencies"
	@echo "  test    - Format code and run tests"
	@echo "  run     - Run verification locally (requires GCS auth)"
	@echo "  build   - Cross-compile FreeBSD binary for server"
	@echo "  deploy  - Build and deploy binary to server"
	@echo "  clean   - Remove build artifacts"