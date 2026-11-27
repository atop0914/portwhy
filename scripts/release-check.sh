#!/usr/bin/env bash
#
# The release is consistent, or this says which part is not.
#
# Everything asserted here is a claim that only becomes false on a release day,
# which is why none of it lives in CI: a tag exists only after the fact. The
# failures this catches are the ones that cannot be seen from inside the tree —
# a tag that points at a different commit than HEAD says, a CHANGELOG whose top
# section is the previous release, a binary that reports "dev" because it was
# built by the one command that ignores the Makefile.
#
# It does not fetch, push or install. `go install ...@v1.0.0` is the user's
# command and it is run by hand, on the release day, from a clean shell.
#
# Usage: scripts/release-check.sh [tag]     (default: the tag exactly at HEAD)
set -uo pipefail

pkg=github.com/atop0914/portwhy
changelog=CHANGELOG.md

fail() { printf 'FAIL: %s\n' "$*"; exit 1; }
ok()   { printf 'ok   %s\n' "$*"; }

git rev-parse --is-inside-work-tree >/dev/null 2>&1 || fail "not a git checkout"

# A dirty tree means the tagged commit is not the code that ran the gates.
if [ -n "$(git status --porcelain)" ]; then
	git status --short >&2
	fail "the working tree is not clean; a tag on a dirty tree describes code nobody reviewed"
fi
ok "working tree is clean"

tag=${1:-}
if [ -z "$tag" ]; then
	tag=$(git describe --tags --exact-match 2>/dev/null) ||
		fail "HEAD is not at a tag, and no tag was given"
fi

head=$(git rev-parse HEAD) || fail "cannot read HEAD"
tagged=$(git rev-parse "$tag^{commit}" 2>/dev/null) ||
	fail "tag $tag does not exist"
[ "$head" = "$tagged" ] || fail "tag $tag points at ${tagged:0:12}, HEAD is ${head:0:12}"
ok "tag $tag is at HEAD (${head:0:12})"

# The changelog is the release note. Its first version heading has to be this
# tag: an entry left at the previous version is how a release ships describing
# something else.
top=$(grep -m1 -E '^## v[0-9]' "$changelog" | awk '{print $2}')
[ -n "$top" ] || fail "$changelog has no version heading"
[ "$top" = "$tag" ] || fail "$changelog starts at $top, not at $tag"
ok "$changelog starts at $top"
grep -q "^## $tag" "$changelog" || fail "$changelog has no section for $tag"
ok "$changelog has a section for $tag"

# Version identity, checked the way a user meets it: build once with the tag
# injected, then read the line it prints. Comparing struct fields would pass for
# a binary whose CLI prints something else entirely.
tmp=$(mktemp -d) || fail "cannot create a temporary directory"
trap 'rm -rf "$tmp"' EXIT
go build -trimpath \
	-ldflags "-X $pkg/internal/version.Version=$tag" \
	-o "$tmp/portwhy" ./cmd/portwhy 2>"$tmp/build.err" ||
	{ cat "$tmp/build.err" >&2; fail "go build failed"; }
line=$("$tmp/portwhy" version 2>&1) || fail "portwhy version exited non-zero: $line"
case $line in
"portwhy $tag" | "portwhy $tag "*) ok "a binary built at this tag reports $tag" ;;
*) fail "the binary reports '$line', want it to start with 'portwhy $tag'" ;;
esac

# dev and main are the two refs this project keeps; a release is the moment they
# have to agree, because main is what a reader lands on.
for ref in dev main; do
	if git rev-parse --verify --quiet "refs/heads/$ref" >/dev/null; then
		r=$(git rev-parse "refs/heads/$ref")
		[ "$r" = "$head" ] || fail "$ref is ${r:0:12}, tag $tag is ${head:0:12}"
		ok "$ref == $tag"
	else
		ok "$ref does not exist yet (nothing to compare)"
	fi
done

# Zero dependencies is a promise to the host this runs on, and a release is a
# bad time to discover it grew one.
n=$(go list -m all | wc -l)
[ "$n" -eq 1 ] || fail "go list -m all has $n modules; runtime dependencies are not allowed"
ok "modules=1"

printf '\n%s is consistent.\n' "$tag"
