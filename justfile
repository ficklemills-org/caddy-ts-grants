# List available commands
default:
    @just --list

# Check formatting, vet and run tests
test:
    test -z "$(gofmt -l .)"
    go vet ./...
    go test ./...

# Tidy dependencies (run after go version/dep changes)
tidy:
    go mod tidy
