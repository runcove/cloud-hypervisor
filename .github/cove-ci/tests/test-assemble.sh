#!/usr/bin/env bash
# test-assemble.sh -- assemble.sh against a small temp repo: an upstream tag,
# topic branches on it (one stacked), and order files that make it pass,
# conflict, miss a ref, and match or miss a --check ref.
#
# The temp repo asks for signed commits with a gpg program that always fails,
# so any commit assemble.sh tried to sign would fail its case. Every case also
# checks that no ref moved and no worktree was left behind.
#
# Usage: bash .github/cove-ci/tests/test-assemble.sh   (exit 0: all passed)
set -uo pipefail
export LC_ALL=C

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ASSEMBLE="$(cd "$HERE/.." && pwd)/assemble.sh"
T=$(mktemp -d)
trap 'rm -rf -- "$T"' EXIT
export TMPDIR="$T/tmp" GIT_CONFIG_NOSYSTEM=1 HOME="$T/home"
mkdir -p "$TMPDIR" "$HOME"
unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE

pass=0 failed=0
ok() { pass=$((pass + 1)); echo "ok   $1"; }
bad() { failed=$((failed + 1)); echo "FAIL $1"; shift; printf '     %s\n' "$@"; }

R="$T/repo"
g() { git -C "$R" -c commit.gpgsign=false "$@"; }
commit() { # commit FILE TEXT MESSAGE: write FILE and commit it on the current branch
  printf '%s\n' "$2" > "$R/$1"; g add "$1"; g commit -q -m "$3"
}

git init -q -b main "$R"
g config user.name test; g config user.email test@localhost
commit a.txt "upstream a" "upstream a"
commit b.txt "upstream b" "upstream b"
g tag v1.0
g switch -q -c topic/one v1.0;   commit one.txt "one" "one"
g switch -q -c topic/two v1.0;   commit two.txt "two" "two"
g switch -q -c topic/three topic/two; commit three.txt "three" "three"   # stacked on two
g switch -q -c topic/clash v1.0; commit one.txt "not one" "clash with one"
g switch -q -c topic/loose v1.0; commit loose.txt "loose" "loose"        # not on two
g switch -q --orphan topic/stray; commit stray.txt "stray" "no upstream history"
g switch -q main
# Expected tree: one, two, three on v1.0, merged by hand.
g switch -q --detach v1.0
for t in one two three; do g merge -q --no-ff --no-edit "topic/$t"; done
WANT=$(g rev-parse 'HEAD^{tree}')
g branch -q want HEAD
g switch -q main
g update-ref refs/remotes/fork/topic/one topic/one
g update-ref refs/remotes/fork/topic/two topic/two
g update-ref refs/remotes/fork/topic/three topic/three
# From here on, a commit that is signed fails, and rerere would record.
g config commit.gpgsign true; g config gpg.program false; g config rerere.enabled true

order() { # order NAME LINE...: write an order file
  local f="$T/$1.txt"; shift
  printf '%s\n' "$@" > "$f"; echo "$f"
}
GOOD=$(order good "# comment" "@upstream v1.0" "" "topic/one never-upstream  # fork-only" \
  "topic/two" "topic/three base=topic/two")

# run NAME ARGS...: assemble.sh in the repo. Sets RC, OUT (stdout), ERR.
run() {
  local name=$1; shift
  local before after
  before=$(g for-each-ref --format='%(refname) %(objectname)'; g worktree list --porcelain; ls "$TMPDIR")
  OUT=$(cd "$R" && bash "$ASSEMBLE" "$@" 2> "$T/$name.err")
  RC=$?
  ERR=$(cat "$T/$name.err")
  after=$(g for-each-ref --format='%(refname) %(objectname)'; g worktree list --porcelain; ls "$TMPDIR")
  [ "$before" = "$after" ] || bad "$name: no ref moved, no worktree or temp dir left" "$(diff <(echo "$before") <(echo "$after"))"
}
# expect NAME WANT_RC PATTERN...: fixed strings that stdout+stderr must hold.
expect() {
  local name=$1 want=$2; shift 2
  local why=() p
  [ "$RC" = "$want" ] || why+=("exit $RC, want $want")
  for p in "$@"; do grep -qF -- "$p" <<<"$OUT"$'\n'"$ERR" || why+=("no '$p' in the output"); done
  if [ ${#why[@]} -eq 0 ]; then ok "$name"; else bad "$name" "${why[@]}" "stdout: $OUT" "stderr: $ERR"; fi
}

run happy --topics "$GOOD"
expect "happy path: exit 0, prints the hand-merged tree" 0 "$WANT"
if [ "$OUT" = "$WANT" ]; then ok "happy path: stdout is the tree id alone"
else bad "happy path: stdout is the tree id alone" "$OUT"; fi

run prefix --topics "$GOOD" --prefix fork/
expect "--prefix fork/: the remote refs give the same tree" 0 "$WANT"

run check-match --topics "$GOOD" --check want
expect "--check on an equal tree: exit 0" 0 "$WANT" "equals want's tree"

run check-mismatch --topics "$GOOD" --check topic/one
expect "--check on another tree: exit 1, with the diff stat" 1 "differs from topic/one's tree" \
  "three.txt | 1 +" "two.txt   | 1 +"

run conflict --topics "$(order conflict "@upstream v1.0" topic/one topic/clash topic/two)"
expect "conflict: exit 2, names the topic and the file" 2 \
  "CONFLICT merging topic topic/clash (merge 2 of 3)" "one.txt"

run missing --topics "$(order missing "@upstream v1.0" topic/one topic/nope topic/two)"
expect "missing ref: exit 93, names it" 93 "topic topic/nope is missing"

run missing-prefix --topics "$GOOD" --prefix nowhere/
expect "missing ref under a prefix: exit 93, names it" 93 "topic nowhere/topic/one is missing"

run bad-base --topics "$(order bad-base "@upstream v1.0" topic/two "topic/loose base=topic/two")"
expect "stacked topic whose base is not its ancestor: exit 93" 93 \
  "topic topic/loose says base=topic/two, but topic/two is not its ancestor"

run late-base --topics "$(order late-base "@upstream v1.0" "topic/three base=topic/two" topic/two)"
expect "base listed after the topic: exit 93" 93 "base=topic/two is not a topic listed above it"

run off-tag --topics "$(order off-tag "@upstream v1.0" topic/one topic/stray)"
expect "topic not based on the tag: exit 93" 93 "topic topic/stray is not based on v1.0"

run no-tag --topics "$(order no-tag topic/one)"
expect "no @upstream and no --base: exit 93" 93 "no upstream tag"

run base-arg --topics "$(order base-arg topic/one topic/two "topic/three base=topic/two")" --base v1.0
expect "--base gives the tag: exit 0, same tree" 0 "$WANT"

run bad-field --topics "$(order bad-field "@upstream v1.0" "topic/one upstream")"
expect "unknown field: exit 93, names the line" 93 "bad-field.txt:2: unknown field 'upstream'"

run twice --topics "$(order twice "@upstream v1.0" topic/one topic/one)"
expect "a topic listed twice: exit 93" 93 "topic/one is listed twice"

g switch -q --detach topic/one
run detached --topics "$GOOD"
expect "runs with the repo's HEAD detached elsewhere, same tree" 0 "$WANT"
g switch -q main

echo "$pass passed, $failed failed"
[ "$failed" = 0 ]
