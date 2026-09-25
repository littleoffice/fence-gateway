#!/usr/bin/env bash
# Regenerate the interop test vectors from mcp-searxng-relay's own fence.go.
#
#   interop/regen.sh [out-dir]
#
# The relay commit is pinned in interop/testdata/relay/RELAY_COMMIT. Its
# fence.go is compiled unmodified next to interop/relaygen, which calls
# wrapFence and wrapFenceCDATA under both preamble layouts. With no argument
# the committed vectors are overwritten; CI passes a scratch directory instead
# and runs the interop tests against fresh output (INTEROP_VECTORS).
#
# To move to a newer relay: put its commit in RELAY_COMMIT, run this script,
# run `go test ./...`, and commit the result. Signatures, nonces and
# timestamps change on every run; the key and the contents do not.

set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/.." && pwd)"
out="${1:-$here/testdata/relay}"
mkdir -p "$out"
out="$(cd "$out" && pwd)"

repo="${RELAY_REPO:-https://github.com/littleoffice/mcp-searxng-relay}"
commit="$(tr -d '[:space:]' < "$here/testdata/relay/RELAY_COMMIT")"
go_version="$(awk '$1 == "go" { print $2; exit }' "$root/go.mod")"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

git init -q "$work/relay"
git -C "$work/relay" fetch -q --depth 1 "$repo" "$commit"
git -C "$work/relay" checkout -q FETCH_HEAD

mkdir "$work/gen"
cp "$here"/relaygen/*.go "$work/relay/fence.go" "$work/gen/"
printf 'module relaygen\n\ngo %s\n' "$go_version" > "$work/gen/go.mod"

(cd "$work/gen" && GOFLAGS=-mod=mod go run -tags relaygen . "$out")
echo "wrote vectors from $repo@$commit to $out"
