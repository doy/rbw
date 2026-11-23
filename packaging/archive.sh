#!/bin/sh
# Packs a release build into dist/rbw-ng-VERSION-TARGET.tar.gz, with shell
# completions, and writes its SHA-256 next to it.
#
# usage: packaging/archive.sh TARGET
# Run from the repository root after `cargo build --release --target TARGET`.
set -eu

target="$1"
version="$(cargo pkgid | sed 's/.*[#@]//')"
name="rbw-ng-$version-$target"
release="target/$target/release"

# The completion files also go where the cargo-deb assets expect them.
mkdir -p "$release/completion"
for shell in bash zsh fish; do
    "$release/rbw" gen-completions "$shell" > "$release/completion/$shell"
done

stage="$(mktemp -d)"
trap 'rm -rf "$stage"' EXIT
mkdir "$stage/$name"
cp "$release/rbw" "$release/rbw-agent" README.md LICENSE CHANGELOG.md "$stage/$name/"
cp -R "$release/completion" "$stage/$name/"

mkdir -p dist
tar -czf "dist/$name.tar.gz" -C "$stage" "$name"
(cd dist && shasum -a 256 "$name.tar.gz" > "$name.tar.gz.sha256")
echo "dist/$name.tar.gz"
