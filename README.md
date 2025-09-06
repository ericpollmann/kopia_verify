# Kopia Verification Tool

Cryptographically verifies that a Kopia repository stored in Google Cloud Storage is identical to the local repository.

## Features

- **Perfect Verification**: Compares MD5 hashes of all blobs between local and GCS repositories
- **Intelligent Caching**: Uses mtime-based cache to achieve sub-second performance on repeated runs
- **Thread-Safe**: Concurrent processing with proper mutex protection
- **Progress Reporting**: Shows progress every 100 blobs processed
- **Cross-Platform**: Builds FreeBSD binaries for server deployment

## Quick Start

```bash
# Install dependencies
make install

# Build and deploy to server
make deploy

# Run verification from macbook
kopia-verify
```

## Available Make Targets

- `make install` - Initialize go module and install dependencies
- `make test` - Format code and run tests
- `make run` - Run verification locally (requires GCS auth)
- `make build` - Cross-compile FreeBSD binary for server
- `make deploy` - Build and deploy binary to server
- `make clean` - Remove build artifacts

## Architecture

The tool maps different Kopia blob types to their local filesystem paths:
- Standard blobs (`p*`, `q*`, `s*`) → `/var/kopia/repository/{prefix}/{blob}`
- Special files (`xw*`, `xn0*`) → `/var/kopia/repository/{blob}`
- Log files (`_log*.f`) → `/var/kopia/repository/{blob}`

## Cache Performance

- **Cold Run**: ~47 seconds for 520 blobs
- **Warm Run**: <1 second with intelligent caching
- **Cache Location**: `/var/kopia/.cache/kopia_md5_cache.json`
- **Cache Invalidation**: Based on file mtime and size changes

## Alias Usage

After deployment, use the shell alias from anywhere:
```bash
kopia-verify  # Runs: ssh server "sudo -u kopia /usr/local/bin/kopia_verify"
```

Perfect for daily automated verification of repository integrity.