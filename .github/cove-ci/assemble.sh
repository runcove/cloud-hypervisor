#!/usr/bin/env bash
# assemble.sh -- rebuild a cove-patches line from its topic branches, locally,
# and print the tree it comes to. It never pushes, never signs, and never
# moves a branch: the merges happen on a detached HEAD in a throwaway worktree
# that is removed on every exit.
#
# Usage: assemble.sh [--topics FILE] [--base TAG] [--prefix PREFIX] [--check REF]
#   --topics  the order file (default: topics.txt next to this script; its
#             syntax is described at the top of that file)
#   --base    the upstream tag to build on (default: the file's @upstream)
#   --prefix  put in front of each topic name to find its ref, e.g. origin/
#             (default: empty, the local branches)
#   --check   compare the assembled tree with REF's tree
#
# Before merging anything it refuses (exit 93) a listed topic whose ref is
# missing, a topic that does not contain the upstream tag's commit, and a
# stacked topic whose base= is not listed above it or is not its ancestor.
# Then, from the tag's commit, it merges each topic in order with
# `git merge --no-ff --no-edit`. rerere is off, so a conflict cannot be
# resolved silently by a recorded resolution.
#
# Run it from inside a clone of the fork. Output: the assembled tree id on
# stdout (and, with --check on a mismatch, the diff stat from REF to it);
# progress and refusals on stderr.
#
# Exit: 0 assembled (with --check: the trees are equal); 1 --check: the trees
#       differ; 2 a topic conflicted (named on stderr); 93 refused to run
#       (usage, the order file, or a ref check above).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TOPICS="$HERE/topics.txt" BASE="" PREFIX="" CHECK=""

cannot() { echo "assemble: CANNOT RUN -- $* (exit 93)" >&2; exit 93; }
say() { echo "assemble: $*" >&2; }

while [ $# -gt 0 ]; do
  case "$1" in
    --topics|--base|--prefix|--check)
      [ $# -ge 2 ] || cannot "$1 needs a value"
      case "$1" in
        --topics) TOPICS=$2 ;; --base) BASE=$2 ;; --prefix) PREFIX=$2 ;; --check) CHECK=$2 ;;
      esac
      shift 2 ;;
    -h|--help) sed -n '2,/^set -euo/{/^set -euo/d;s/^# \{0,1\}//;p}' "${BASH_SOURCE[0]}"; exit 0 ;;
    *) cannot "unknown argument '$1'" ;;
  esac
done

git rev-parse --git-dir >/dev/null 2>&1 || cannot "not inside a git repository"
[ -f "$TOPICS" ] || cannot "no order file at $TOPICS"

# --- read the order file -------------------------------------------------------
names=() bases=() file_base="" n=0
declare -A index=()
while IFS= read -r line || [ -n "$line" ]; do
  n=$((n + 1))
  line=${line%%#*}
  read -r -a f <<<"$line"
  [ ${#f[@]} -gt 0 ] || continue
  if [ "${f[0]}" = "@upstream" ]; then
    [ ${#f[@]} -eq 2 ] || cannot "$TOPICS:$n: @upstream takes one tag"
    [ -z "$file_base" ] || cannot "$TOPICS:$n: a second @upstream line"
    file_base=${f[1]}
    continue
  fi
  name=${f[0]}
  case "$name" in -*|*=*|@*) cannot "$TOPICS:$n: '$name' is not a branch name" ;; esac
  [ -z "${index[$name]:-}" ] || cannot "$TOPICS:$n: $name is listed twice"
  b=""
  for tok in "${f[@]:1}"; do
    case "$tok" in
      never-upstream) ;;
      base=?*)
        [ -n "${index[${tok#base=}]:-}" ] ||
          cannot "$TOPICS:$n: $name's ${tok} is not a topic listed above it"
        b="$b ${tok#base=}" ;;
      *) cannot "$TOPICS:$n: unknown field '$tok' on $name" ;;
    esac
  done
  names+=("$name") bases+=("$b")
  index[$name]=${#names[@]}
done < "$TOPICS"

[ ${#names[@]} -gt 0 ] || cannot "$TOPICS lists no topic"
BASE=${BASE:-$file_base}
[ -n "$BASE" ] || cannot "no upstream tag: give --base or an @upstream line in $TOPICS"

# --- check every ref before merging anything -----------------------------------
base_commit=$(git rev-parse --verify --quiet "$BASE^{commit}") ||
  cannot "upstream tag $BASE does not resolve to a commit"
if [ -n "$CHECK" ]; then
  check_tree=$(git rev-parse --verify --quiet "$CHECK^{tree}") ||
    cannot "--check ref $CHECK does not resolve to a tree"
fi
refs=()
for i in "${!names[@]}"; do
  ref=$PREFIX${names[$i]}
  c=$(git rev-parse --verify --quiet "$ref^{commit}") || cannot "topic $ref is missing"
  git merge-base --is-ancestor "$base_commit" "$c" ||
    cannot "topic $ref is not based on $BASE ($base_commit is not its ancestor)"
  read -r -a stacked <<<"${bases[$i]}"
  for b in ${stacked[@]+"${stacked[@]}"}; do
    git merge-base --is-ancestor "$PREFIX$b" "$c" ||
      cannot "topic $ref says base=$b, but $PREFIX$b is not its ancestor"
  done
  refs+=("$c")
done

# --- merge, in a throwaway worktree ------------------------------------------------
# No signing, no hooks, no rerere; a fixed identity so it runs where none is set.
G=(git -c commit.gpgsign=false -c rerere.enabled=false -c core.hooksPath=/dev/null
   -c merge.verifySignatures=false)
export GIT_AUTHOR_NAME=assemble.sh GIT_AUTHOR_EMAIL=assemble@localhost
export GIT_COMMITTER_NAME=assemble.sh GIT_COMMITTER_EMAIL=assemble@localhost

WT=$(mktemp -d "${TMPDIR:-/tmp}/assemble.XXXXXX")
cleanup() {
  git worktree remove --force "$WT" >/dev/null 2>&1 || rm -rf -- "$WT"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

"${G[@]}" worktree add --quiet --detach "$WT" "$base_commit" >/dev/null 2>&1 ||
  cannot "could not create a worktree at $WT"

say "on $BASE ($base_commit), ${#names[@]} topics from $TOPICS"
for i in "${!names[@]}"; do
  ref=$PREFIX${names[$i]}
  say "merge $((i + 1))/${#names[@]} $ref (${refs[$i]})"
  if ! out=$("${G[@]}" -C "$WT" merge --no-ff --no-edit -m "Merge $ref" "${refs[$i]}" 2>&1); then
    echo "assemble: CONFLICT merging topic $ref (merge $((i + 1)) of ${#names[@]}); refusing (exit 2)" >&2
    printf '%s\n' "$out" | sed 's/^/  /' >&2
    exit 2
  fi
done

tree=$(git -C "$WT" rev-parse 'HEAD^{tree}')
echo "$tree"
if [ -n "$CHECK" ]; then
  if [ "$tree" = "$check_tree" ]; then
    say "check: the assembled tree equals $CHECK's tree"
  else
    say "check: the assembled tree differs from $CHECK's tree ($check_tree); diff stat from $CHECK:"
    git diff --stat "$check_tree" "$tree"
    exit 1
  fi
fi
