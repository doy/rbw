#!/bin/sh
# Prints the CHANGELOG.md section of a version, without its heading.
#
# usage: packaging/release-notes.sh VERSION
set -eu

awk -v version="$1" '
    index($0, "## [" version "]") == 1 { found = 1; next }
    found && /^## \[/ { exit }
    found { print }
' CHANGELOG.md | sed -e '/./,$!d' | sed -e :a -e '/^\n*$/{$d;N;ba' -e '}'
