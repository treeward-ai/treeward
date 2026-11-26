# Contributing to Treeward

Thanks for your interest in contributing to Treeward!

## Prerequisites

- **Quickstart / demo only:** `docker`, `kind`, `kubectl` (`make quickstart`)
- **Development:** Go matching `go.mod` (`go test ./...`, `go build ./...`)

## Workflow

1. Fork the repository and create a branch from `main`.
2. Make your changes and add or update unit tests.
3. Verify locally:
   ```bash
   go vet ./...
   go test -race -count=1 ./...
   go build ./...
   bash -n scripts/*.sh
   ```
4. Open a Pull Request with a clear description of what changed and why.

## License

By contributing, you agree that your contributions will be licensed under the [Apache License 2.0](LICENSE).
