#!/bin/bash
set -e

if [ -z "$1" ]; then
    echo "Usage: ./patch_core.sh <path_to_olcrtc_repo>"
    echo "Example: ./patch_core.sh /Users/havlok/Downloads/test/orig/olcrtc"
    exit 1
fi

SOURCE_DIR="$1"
# Target dir is the parent of the patch folder
TARGET_DIR="$(cd "$(dirname "$0")/.." && pwd)"

echo "Copying source files from $SOURCE_DIR to $TARGET_DIR..."
# Copy all files from upstream, ignoring .git and our custom patch directory
rsync -a --exclude='.git' --exclude='build' --exclude='vendor' --exclude='patch' --exclude='*.xcframework' "$SOURCE_DIR/" "$TARGET_DIR/"

echo "Renaming olcrtc to whitenet..."
cd "$TARGET_DIR"

# Rename file contents (skip patch folder and .git)
find . -path ./patch -prune -o -path ./.git -prune -o -type f \( -name '*.go' -o -name 'go.mod' -o -name 'magefile.go' -o -name '*.md' -o -name '*.yaml' \) -print0 | xargs -0 perl -pi -e 's/github\.com\/openlibrecommunity\/olcrtc/github\.com\/thehavlok\/whitenet/g'
find . -path ./patch -prune -o -path ./.git -prune -o -type f \( -name '*.go' -o -name 'go.mod' -o -name 'magefile.go' -o -name '*.md' -o -name '*.yaml' \) -print0 | xargs -0 perl -pi -e 's/olcrtc/whitenet/g'
find . -path ./patch -prune -o -path ./.git -prune -o -type f \( -name '*.go' -o -name 'go.mod' -o -name 'magefile.go' -o -name '*.md' -o -name '*.yaml' \) -print0 | xargs -0 perl -pi -e 's/OLCRTC/WHITENET/g'
find . -path ./patch -prune -o -path ./.git -prune -o -type f \( -name '*.go' -o -name 'go.mod' -o -name 'magefile.go' -o -name '*.md' -o -name '*.yaml' \) -print0 | xargs -0 perl -pi -e 's/Olcrtc/Whitenet/g'
find . -path ./patch -prune -o -path ./.git -prune -o -type f \( -name '*.go' -o -name 'go.mod' -o -name 'magefile.go' -o -name '*.md' -o -name '*.yaml' \) -print0 | xargs -0 perl -pi -e 's/olcRTC/WhiteNet/g'

# Rename files and directories named olcrtc
find . -path ./patch -prune -o -path ./.git -prune -o -depth -name '*olcrtc*' -execdir bash -c 'mv "$1" "${1//olcrtc/whitenet}"' _ {} \;

echo "Running go mod tidy..."
go mod tidy

echo "Done! The repository at $TARGET_DIR is successfully synchronized with upstream and patched."
