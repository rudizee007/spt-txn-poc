#!/bin/sh
# scripts/m0-bootstrap.sh
#
# Run this once on a fresh OpenBSD host after completing
# docs/OPENBSD-SETUP.md steps 0-8.
#
# Brings the Go module up to date and runs the unit tests.
# If this passes, you've completed Milestone 0.

set -eu

cd "$(dirname "$0")/.."

echo "==> go version"
go version

echo "==> go mod tidy"
go mod tidy

echo "==> go vet ./..."
go vet ./...

echo "==> go test ./..."
go test -v ./...

echo ""
echo "==> Milestone 0 PASSED"
echo ""
echo "Next: read docs/BUILD-ORDER.md and start on Milestone 1"
echo "(the Trust Registry HTTP service)."
