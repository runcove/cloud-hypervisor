#!/usr/bin/env bash
# test-release-workflow.sh -- cove-release.yml's triggers and its check of the
# previous release's checkpoint attestation, without GitHub.
#
# Reads the workflow with python3's yaml. Checks that only a v*-cove.* tag push
# and workflow_dispatch start it, and that every gh attestation verify pins
# the signer workflow, a GitHub-hosted runner and a source ref, and every one
# that decides pins the source and signer digest. Then runs the smoke job's
# "Fetch the previous release's checkpoint" step against a temp repo (GitHub's
# URL rewritten to it) and a stub gh whose one attestation has a given source
# ref and digest: the push shape and the dispatch shape pass, anything else
# fails. A refused case also has to have reached gh attestation verify and the
# step's own refusal text, so a step that stops earlier (a missing helper, a
# failed fetch) is not counted as a refusal.
#
# Usage: bash .github/cove-ci/tests/test-release-workflow.sh   (exit 0: all passed)
set -uo pipefail
export LC_ALL=C

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
WF="$ROOT/.github/workflows/cove-release.yml"
T=$(mktemp -d)
trap 'rm -rf -- "$T"' EXIT
export HOME="$T/home" GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL="$T/home/.gitconfig"
mkdir -p "$HOME"
unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE

pass=0 failed=0
ok() { pass=$((pass + 1)); echo "ok   $1"; }
bad() { failed=$((failed + 1)); echo "FAIL $1"; shift; printf '     %s\n' "$@"; }

# --- static checks -----------------------------------------------------------
STEP="$T/step.sh"
if out=$(python3 -I - "$WF" "$STEP" <<'EOF' 2>&1
import re, sys, yaml
wf = yaml.safe_load(open(sys.argv[1]))
on = wf.get("on", wf.get(True))
errs = []
if sorted(on) != ["push", "workflow_dispatch"]:
    errs.append(f"triggers are {sorted(on)}, not push and workflow_dispatch")
if on["push"] != {"tags": ["v*-cove.*"]}:
    errs.append(f"push trigger is {on['push']}, not tags: [v*-cove.*]")
if "ci-test" in yaml.safe_dump(on):
    errs.append("a trigger names ci-test")
if wf.get("permissions") != {}:
    errs.append("workflow-level permissions are not {}")
for name, job in wf["jobs"].items():
    perms = job.get("permissions") or {}
    writes = sorted(k for k, v in perms.items() if v == "write")
    if writes and name != "release":
        errs.append(f"job {name} holds {writes}")
rel = wf["jobs"]["release"]["if"]
if "startsWith(github.ref, 'refs/tags/v')" not in rel or "startsWith(inputs.tag, 'v')" not in rel:
    errs.append(f"release job condition is {rel!r}")
step = [s for s in wf["jobs"]["smoke"]["steps"] if s.get("name") == "Fetch the previous release's checkpoint"]
if len(step) != 1:
    errs.append("no single smoke step fetching the previous checkpoint")
else:
    run = step[0]["run"]
    open(sys.argv[2], "w").write(run)
    joined = re.sub(r"\\\n\s*", " ", run)
    pin = re.search(r"pin=\(([^)]*)\)", joined, re.S)
    pin = pin.group(1) if pin else ""
    for flag in ("--repo", "--signer-workflow", "--deny-self-hosted-runners"):
        if flag not in pin:
            errs.append(f"pin lacks {flag}")
    if '.github/workflows/cove-release.yml"' not in pin:
        errs.append("pin's --signer-workflow is not this workflow")
    calls = [l for l in joined.splitlines() if "gh attestation verify" in l]
    if len(calls) < 2:
        errs.append(f"{len(calls)} gh attestation verify calls")
    for c in calls:
        if '"${pin[@]}"' not in c or "--source-ref" not in c:
            errs.append(f"unpinned call: {c.strip()}")
        if "--format json" not in c and not ("--source-digest" in c and "--signer-digest" in c):
            errs.append(f"call without both digests: {c.strip()}")
text = open(sys.argv[1]).read()
other = [l for l in text.splitlines() if "ci-test" in l and "git tag -l 'ci-test-*'" not in l and not l.lstrip().startswith("#")]
if other:
    errs.append(f"ci-test outside comments and the tag drop: {other}")
print("\n".join(errs))
sys.exit(1 if errs else 0)
EOF
); then
  ok "triggers are a v*-cove.* tag push and dispatch; only release writes; every verify is pinned"
else
  bad "static checks of cove-release.yml" "$out"
fi
[ -s "$STEP" ] || { echo "no step to run"; echo "passed $pass, failed $((failed + 1))"; exit 1; }

# --- the step, run --------------------------------------------------------------
# History: c0 - c1 (tag v54.1-cove.5) - c2 (cove-patches-v54.1); c3 on c1 off the
# branch, with tag v54.1-cove.7 on c3 (a tag whose commit is not on the branch).
R="$T/gh-repo"
g() { git -C "$R" -c commit.gpgsign=false -c tag.gpgsign=false -c user.name=t -c user.email=t@t "$@"; }
git init -q -b cove-patches-v54.1 "$R"
step_commit() { echo "$1" > "$R/f"; g add f; g commit -q -m "c$1"; g rev-parse HEAD; }
c0=$(step_commit 0)
c1=$(step_commit 1)
g tag -a -m v54.1-cove.5 v54.1-cove.5
c2=$(step_commit 2)
g checkout -q -b other "$c1"; echo 3 > "$R/f"; g commit -q -am c3; c3=$(g rev-parse HEAD)
g tag -a -m v54.1-cove.7 v54.1-cove.7
g checkout -q cove-patches-v54.1
git config --global url."file://$R".insteadOf "https://github.com/runcove/cloud-hypervisor.git"

# The stub gh: one release below (REL_TAG), its checkpoint, and one attestation whose
# certificate has source ref ATT_REF and source and signer digest ATT_DIGEST.
mkdir -p "$T/bin" "$T/assets"
printf 'checkpoint\n' > "$T/assets/ch-smoke-checkpoint.tar.gz"
(cd "$T/assets" && sha256sum ch-smoke-checkpoint.tar.gz > ch-smoke-checkpoint.tar.gz.sha256)
cat > "$T/bin/gh" <<'EOF'
#!/usr/bin/env bash
echo "gh $*" >> "$GH_LOG"
case "$1 $2" in
  "release list") echo "$REL_TAG"; exit 0 ;;
  "release view") printf '%s\n' ch-smoke-checkpoint.tar.gz ch-smoke-checkpoint.tar.gz.sha256; exit 0 ;;
  "release download")
    shift 3; dir=''
    while [ $# -gt 0 ]; do case "$1" in --dir) dir=$2; shift 2 ;; *) shift ;; esac; done
    cp "$ASSETS"/* "$dir"/; exit 0 ;;
  "attestation verify")
    shift 3; json=false
    while [ $# -gt 0 ]; do
      case "$1" in
        --repo) [ "$2" = runcove/cloud-hypervisor ] || exit 1; shift 2 ;;
        --signer-workflow) [ "$2" = runcove/cloud-hypervisor/.github/workflows/cove-release.yml ] || exit 1; shift 2 ;;
        --source-ref) [ "$2" = "$ATT_REF" ] || { echo "ref mismatch" >&2; exit 1; }; shift 2 ;;
        --source-digest|--signer-digest) [ "$2" = "$ATT_DIGEST" ] || { echo "digest mismatch" >&2; exit 1; }; shift 2 ;;
        --deny-self-hosted-runners) shift ;;
        --format) json=true; shift 2 ;;
        --jq) shift 2 ;;
        *) echo "unknown $1" >&2; exit 2 ;;
      esac
    done
    if $json; then echo "$ATT_DIGEST"; fi
    exit 0 ;;
esac
exit 2
EOF
chmod +x "$T/bin/gh"

# case NAME WANT(pass|fail) ATT_REF ATT_DIGEST [RELEASE_TAG [VERSION]]
run_case() {
  local name=$1 want=$2 d="$T/case-$1" rel=${5:-v54.1-cove.5} ver=${6:-v54.1-cove.6}
  mkdir -p "$d/rt/smoke/in" "$d/wd"
  ln -s "$ROOT" "$d/wd/src"
  local rc=0
  (cd "$d/wd" && env PATH="$T/bin:$PATH" GH_LOG="$d/gh.log" ASSETS="$T/assets" ATT_REF="$3" ATT_DIGEST="$4" \
    REL_TAG="$rel" VERSION="$ver" GH_TOKEN=x GH_REPO=runcove/cloud-hypervisor GITHUB_REPOSITORY=runcove/cloud-hypervisor \
    RUNNER_TEMP="$d/rt" bash -e "$STEP") > "$d/out" 2>&1 || rc=$?
  local got=fail
  [ "$rc" = 0 ] && [ -f "$d/rt/smoke/in/previous.tar.gz" ] && got=pass
  local unpinned
  unpinned=$(grep '^gh attestation verify' "$d/gh.log" | grep -v -- '--deny-self-hosted-runners' || true)
  # A refusal counts only if the stub gh was asked to verify an attestation and
  # the step then said it found none it accepts.
  local why=''
  if [ "$want" = fail ]; then
    grep -q '^gh attestation verify' "$d/gh.log" 2>/dev/null || why="the stub gh was never asked to verify an attestation"
    grep -qF "has no attestation from its tag's push or its branch's dispatch" "$d/out" || why="${why:+$why; }the step did not end in its attestation refusal"
  fi
  if [ "$got" = "$want" ] && [ -z "$unpinned" ] && [ -z "$why" ]; then
    ok "$name: $want"
  else
    bad "$name: want $want, got $got (rc $rc)" "$(tail -n 8 "$d/out")" ${why:+"not a real refusal: $why"} ${unpinned:+"unpinned: $unpinned"}
  fi
}

run_case push-shape            pass refs/tags/v54.1-cove.5      "$c1"
run_case dispatch-shape        pass refs/heads/cove-patches-v54.1 "$c2"
run_case dispatch-at-tag       pass refs/heads/cove-patches-v54.1 "$c1"
run_case tag-ref-other-digest  fail refs/tags/v54.1-cove.5      "$c2"
run_case other-branch          fail refs/heads/other            "$c3"
run_case other-ref-tag-digest  fail refs/heads/other            "$c1"
run_case dispatch-off-branch   fail refs/heads/cove-patches-v54.1 "$c3"
run_case dispatch-before-tag   fail refs/heads/cove-patches-v54.1 "$c0"
run_case other-tag             fail refs/tags/ci-test-1         "$c1"
# A push-shape attestation for a tag whose commit is not on the release branch.
run_case push-shape-off-branch fail refs/tags/v54.1-cove.7      "$c3" v54.1-cove.7 v54.1-cove.8

echo "passed $pass, failed $failed"
[ "$failed" -eq 0 ]
