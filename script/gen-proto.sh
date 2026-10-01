#!/bin/sh
# Regenerate the Main <-> agent protobuf code.
#
# Needs protoc plus the two Go plugins:
#   go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
#   go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
set -e
cd "$(dirname "$0")/.."

PATH="$PATH:$(go env GOPATH)/bin"
command -v protoc >/dev/null || { echo "protoc not found" >&2; exit 1; }
command -v protoc-gen-go >/dev/null || { echo "protoc-gen-go not found; see the comment at the top of this script" >&2; exit 1; }
command -v protoc-gen-go-grpc >/dev/null || { echo "protoc-gen-go-grpc not found; see the comment at the top of this script" >&2; exit 1; }

protoc -I api/proto \
  --go_out=. --go_opt=module=github.com/thehavlok/whitenet \
  --go-grpc_out=. --go-grpc_opt=module=github.com/thehavlok/whitenet \
  api/proto/whitenet/node/v1/*.proto

echo "generated into internal/nodepb/"
