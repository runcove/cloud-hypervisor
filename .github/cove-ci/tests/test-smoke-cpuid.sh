#!/usr/bin/env bash
# test-smoke-cpuid.sh -- smoke.sh's step 5 CPUID-refusal skip, without KVM.
#
# Sources smoke.sh (which then defines its helpers and returns) and drives its
# fail() as step 5 would, against fake d.chlog / d.out contents, and checks
# smoke_tool.py pack carries HOST_CPU_FLAGS through unpack. Each case runs in
# a subshell, since fail() exits. A last group runs smoke.sh itself with a
# stub cloud-hypervisor that refuses the checkpoint's CPUID.
#
# Usage: bash .github/cove-ci/tests/test-smoke-cpuid.sh   (exit 0: all passed)
set -uo pipefail
export LC_ALL=C

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CI="$(cd "$HERE/.." && pwd)"
T=$(mktemp -d)
trap 'rm -rf -- "$T"' EXIT

pass=0 failed=0
ok() { pass=$((pass + 1)); echo "ok   $1"; }
bad() { failed=$((failed + 1)); echo "FAIL $1"; shift; printf '     %s\n' "$@"; }

# Lines in CH v54's shapes (arch/src/x86_64/mod.rs's error!, vmm/src/lib.rs's context).
REFUSAL_CHLOG='cloud-hypervisor: 12.345678s: <vmm> ERROR:arch/src/x86_64/mod.rs:663 -- Detected incompatible CPUID entry: leaf=0x07 (subleaf=0x00), register='"'"'EBX'"'"', compatible_check='"'"'BitwiseSubset'"'"', source VM feature='"'"'0xd19f4fbb'"'"', destination VM feature='"'"'0xc19f4fbb'"'"'.
cloud-hypervisor: 12.345700s: <vmm> ERROR:arch/src/x86_64/mod.rs:663 -- Detected incompatible CPUID entry: leaf=0x07 (subleaf=0x00), register='"'"'ECX'"'"', compatible_check='"'"'BitwiseSubset'"'"', source VM feature='"'"'0x40405f4e'"'"', destination VM feature='"'"'0x00405f4e'"'"'.'
REFUSAL_OUT='Error booting VM: VmRestore(CpuManager(...))
Error checking cpu feature compatibility'
OTHER_CHLOG='cloud-hypervisor: 1.0s: <vmm> ERROR:vmm/src/lib.rs:2100 -- Error restoring VM: memory-ranges: No such file or directory (os error 2)'

# case NAME CODE CHLOG OUT SAVED_FLAGS HERE_FLAGS [WAKE [RAW]]: one fail CODE call.
# Sets RC, STDOUT, STDERR and OUTPUT (both). SAVED_FLAGS empty: the checkpoint
# has no HOST_CPU_FLAGS. WAKE=no: step 5 has not reached the wake (WAKE_CKPT unset).
# RAW: the whole HOST_CPU_FLAGS file, verbatim (instead of a flags line of SAVED_FLAGS).
run_case() {
  local name=$1 code=$2 chlog=$3 out=$4 saved=$5 here=$6 wake=${7:-yes} raw=${8:-}
  local d="$T/$name"
  mkdir -p "$d/work" "$d/ckpt"
  [ -z "$chlog" ] || printf '%s\n' "$chlog" > "$d/work/d.chlog"
  [ -z "$out" ] || printf '%s\n' "$out" > "$d/work/d.out"
  [ -z "$saved" ] || printf 'flags\t\t: %s\n' "$saved" > "$d/ckpt/HOST_CPU_FLAGS"
  [ -z "$raw" ] || printf '%s\n' "$raw" > "$d/ckpt/HOST_CPU_FLAGS"
  printf 'processor\t: 0\nflags\t\t: %s\nbugs\t\t: spectre_v1\nprocessor\t: 1\nflags\t\t: other\n' "$here" > "$d/cpuinfo"
  STDOUT=$(
    exec 2> "$d/stderr"
    # shellcheck source=SCRIPTDIR/../smoke.sh
    source "$CI/smoke.sh"
    WORK="$d/work" CPUINFO="$d/cpuinfo" STEP="5 (previous release's checkpoint)"
    VERSION=v54.0-cove.12 PREV_VERSION=v54.0-cove.11 MODE=wake
    [ "$wake" = no ] || WAKE_CKPT="$d/ckpt"
    fail "$code" "the d process exited before its API socket appeared"
  )
  RC=$?
  STDERR=$(cat "$d/stderr")
  OUTPUT=$STDOUT$'\n'$STDERR
}

# expect NAME WANT_RC PATTERN...: each PATTERN is a fixed string that the output
# must hold; '!PATTERN' must not be there. 'out:' / 'err:' after the '!' limits
# the search to stdout / stderr (stdout is what the workflow's wake.log keeps).
expect() {
  local name=$1 want=$2; shift 2
  local why=() re neg hay
  [ "$RC" = "$want" ] || why+=("exit $RC, want $want")
  for re in "$@"; do
    neg=no hay=$OUTPUT
    case "$re" in '!'*) neg=yes re=${re#!} ;; esac
    case "$re" in out:*) hay=$STDOUT re=${re#out:} ;; err:*) hay=$STDERR re=${re#err:} ;; esac
    if [ "$neg" = yes ]; then
      ! grep -qF -- "$re" <<<"$hay" || why+=("output has '$re'")
    else
      grep -qF -- "$re" <<<"$hay" || why+=("output lacks '$re'")
    fi
  done
  if [ "${#why[@]}" = 0 ]; then ok "$name"; else bad "$name" "${why[@]}" "stdout: $STDOUT" "stderr: $STDERR"; fi
}

SKIP="ch-smoke: step 5 (previous release's checkpoint) SKIPPED -- this runner's CPU lacks features the checkpoint was saved with: "
TAIL="--- last lines of d.chlog ---"

# flags absent (older checkpoints, cove.11's shape): skip, as before.
run_case cpuid-no-flags-file 15 "$REFUSAL_CHLOG" "$REFUSAL_OUT" "" "fpu sse avx2"
expect "CPUID refusal, checkpoint without HOST_CPU_FLAGS: SKIPPED with CH's CPUID lines, exit 0" 0 \
  "out:$SKIP""Detected incompatible CPUID entry: leaf=0x07 (subleaf=0x00), register='EBX'" \
  "register='ECX'" "; this is not a pass" "out:::warning title=ch-smoke step 5 skipped::" \
  "out:step5=skipped-cpuid (not PASSED)" "!FAILED" "!PASSED version"

# flags present and differing: skip, naming what this host lacks.
run_case cpuid-missing-flags 15 "$REFUSAL_CHLOG" "" "fpu sse avx2 avx512f avx512bw avx512vl" "fpu sse avx2"
expect "CPUID refusal with HOST_CPU_FLAGS missing here: SKIPPED naming the missing flags, exit 0" 0 \
  "out:$SKIP""avx512bw avx512f avx512vl (in the checkpoint's HOST_CPU_FLAGS, not in this host's); this is not a pass" \
  "!out:Detected incompatible" "!FAILED"

# flags present and equal: not a runner difference, so a failure.
run_case cpuid-same-flags 15 "$REFUSAL_CHLOG" "" "fpu sse avx2" "fpu sse avx2"
expect "CPUID refusal, HOST_CPU_FLAGS equal to this host's: FAILED, exit 15, no skip" 15 \
  "err:a change in what Cloud Hypervisor reports, not a runner difference: Detected incompatible CPUID entry: leaf=0x07" \
  "err:ch-smoke: FAILED at step 5 (previous release's checkpoint) -- the d process exited before its API socket appeared (exit 15)" \
  "!SKIPPED" "!::warning" "!skipped-cpuid" "!PASSED"

run_case cpuid-fewer-flags 15 "$REFUSAL_CHLOG" "" "fpu sse" "fpu sse avx2 avx512f"
expect "CPUID refusal, this host has every saved flag and more: FAILED, exit 15" 15 \
  "err:not a runner difference" "err:(exit 15)" "!SKIPPED" "!::warning"

run_case cpuid-empty-flags 15 "$REFUSAL_CHLOG" "" "" "fpu" yes $'processor\t: 0'
expect "CPUID refusal, HOST_CPU_FLAGS without a flags line (nothing to compare): SKIPPED, exit 0" 0 \
  "out:$SKIP""Detected incompatible CPUID entry" "!FAILED"

run_case cpuid-only-in-out 15 "" "$REFUSAL_OUT" "" "fpu"
expect "CPUID refusal only on CH's stderr: SKIPPED, exit 0" 0 \
  "out:$SKIP""Error checking cpu feature compatibility; this is not a pass"

# A skip prints the tail of the VMM logs that a failure prints (log_tails).
run_case skip-tail 15 "$(seq 1 20 | sed 's/^/chlog line /'; printf '%s\n' "$REFUSAL_CHLOG")" "$REFUSAL_OUT" "" "fpu"
want_tail=$(
  exec 2>&1
  # shellcheck source=SCRIPTDIR/../smoke.sh
  source "$CI/smoke.sh"
  log_tails "$T/skip-tail/work"
)
if [ "$RC" = 0 ] && [ -n "$want_tail" ] && [[ "$STDERR" == *"$want_tail"* ]] \
   && grep -qxF -- "$TAIL" <<<"$STDERR" && grep -qxF 'chlog line 8' <<<"$STDERR" \
   && ! grep -qxF 'chlog line 7' <<<"$STDERR" && ! grep -qF -- "$TAIL" <<<"$STDOUT"; then
  ok "a CPUID skip prints the same log tail a failure prints, on stderr, last 15 lines of each log"
else
  bad "a CPUID skip prints the same log tail a failure prints, on stderr, last 15 lines of each log" \
    "rc $RC" "stderr: $STDERR"
fi

# shellcheck disable=SC2016  # the \$(id) is data, never expanded
run_case hostile-flags 15 "$REFUSAL_CHLOG" "" 'avx512f ::error::x $(id) a/b' "fpu"
expect "HOST_CPU_FLAGS words outside [a-z0-9_] are dropped" 0 \
  "$SKIP""avx512f (in the checkpoint" "!::error::" "!\$(id)" "!a/b"

run_case other-error 15 "$OTHER_CHLOG" "Error booting VM: VmRestore(...)" "fpu avx512f" "fpu"
expect "other restore error: FAILED, exit 15" 15 \
  "ch-smoke: FAILED at step 5 (previous release's checkpoint) -- the d process exited before its API socket appeared (exit 15)" \
  "!SKIPPED" "!::warning"

run_case no-logs 15 "" "" "" "fpu"
expect "no VMM logs at all: FAILED, exit 15" 15 "(exit 15)" "!SKIPPED"

run_case before-wake 15 "$REFUSAL_CHLOG" "" "" "fpu" no
expect "refusal text but step 5 never reached the wake: FAILED, exit 15" 15 "(exit 15)" "!SKIPPED"

run_case other-step 12 "$REFUSAL_CHLOG" "" "" "fpu"
expect "a CPUID refusal in another step's failure is not skipped: exit 12" 12 "(exit 12)" "!SKIPPED"

# --- pack carries HOST_CPU_FLAGS, unpack accepts it ------------------------------
p="$T/pack"
mkdir -p "$p/snap" "$p/out" "$p/dest"
echo '{}' > "$p/snap/config.json"
head -c 4096 /dev/zero > "$p/disk.raw"
printf 'flags\t\t: fpu sse avx512f\n' > "$p/HOST_CPU_FLAGS"
sha=$(printf '%064d' 0)
if python3 "$CI/smoke_tool.py" pack "$p/out" --snapshot "$p/snap" --disk "$p/disk.raw" --version v54.0-cove.12 \
     --hb 3 --kernel-sha256 "$sha" --initramfs-sha256 "$sha" --host-cpu-flags "$p/HOST_CPU_FLAGS" > /dev/null \
   && python3 "$CI/smoke_tool.py" unpack "$p/out/ch-smoke-checkpoint.tar.gz" "$p/dest" \
   && cmp -s "$p/HOST_CPU_FLAGS" "$p/dest/checkpoint/HOST_CPU_FLAGS"; then
  ok "pack writes checkpoint/HOST_CPU_FLAGS and unpack gives it back"
else
  bad "pack writes checkpoint/HOST_CPU_FLAGS and unpack gives it back"
fi
mkdir -p "$p/out2" "$p/dest2"
if python3 "$CI/smoke_tool.py" pack "$p/out2" --snapshot "$p/snap" --disk "$p/disk.raw" --version v54.0-cove.11 \
     --hb 3 --kernel-sha256 "$sha" --initramfs-sha256 "$sha" > /dev/null \
   && python3 "$CI/smoke_tool.py" unpack "$p/out2/ch-smoke-checkpoint.tar.gz" "$p/dest2" \
   && [ ! -e "$p/dest2/checkpoint/HOST_CPU_FLAGS" ]; then
  ok "a checkpoint packed without --host-cpu-flags (cove.11's shape) still unpacks"
else
  bad "a checkpoint packed without --host-cpu-flags (cove.11's shape) still unpacks"
fi

# --- smoke.sh itself, --wake-only, with a stub cloud-hypervisor that refuses ------
# the wake for CPUID: the whole path from launch() through fail() and the exit
# trap, for a checkpoint with equal flags, with differing flags and with none.
e2e="$T/e2e"
mkdir -p "$e2e/in" "$e2e/snap"
cat > "$e2e/in/cloud-hypervisor" <<'STUB'
#!/usr/bin/env bash
if [ "${1:-}" = --version ]; then echo "cloud-hypervisor v54.0-cove.12"; exit 0; fi
log=""
while [ $# -gt 0 ]; do [ "$1" = --log-file ] && log=${2:-}; shift; done
printf '%s\n' "cloud-hypervisor: 1.0s: <vmm> ERROR:arch/src/x86_64/mod.rs:663 -- Detected incompatible CPUID entry: leaf=0x07 (subleaf=0x00), register='EBX'" > "$log"
echo "Error checking cpu feature compatibility"
exit 1
STUB
chmod +x "$e2e/in/cloud-hypervisor"
echo kernel > "$e2e/in/vmlinux"; echo initramfs > "$e2e/in/initramfs.cpio.gz"
echo v54.0-cove.12 > "$e2e/in/VERSION"
echo '{"disks":[{}],"serial":{},"console":{}}' > "$e2e/snap/config.json"
head -c 4096 /dev/zero > "$e2e/disk.raw"
sha=$(printf '%064d' 0)
# e2e_case NAME FLAGSFILE|"": pack a previous checkpoint (with that HOST_CPU_FLAGS,
# or none), run the wake against it. Sets RC, STDOUT, STDERR and OUTPUT.
e2e_case() {
  local name=$1 flags=$2 d="$T/e2e/$1"
  mkdir -p "$d/in" "$d/out"
  cp -f "$e2e"/in/* "$d/in/"
  python3 "$CI/smoke_tool.py" pack "$d/out" --snapshot "$e2e/snap" --disk "$e2e/disk.raw" --version v54.0-cove.11 \
    --hb 3 --kernel-sha256 "$sha" --initramfs-sha256 "$sha" ${flags:+--host-cpu-flags "$flags"} > /dev/null \
    || { bad "$name: could not pack the previous checkpoint"; return 1; }
  cp -f "$d/out/ch-smoke-checkpoint.tar.gz" "$d/in/previous.tar.gz"
  STDOUT=$(SMOKE_KVM_DEVICE=/dev/null bash "$CI/smoke.sh" --wake-only --in "$d/in" --work "$d/work" 2> "$d/stderr")
  RC=$?
  STDERR=$(cat "$d/stderr")
  OUTPUT=$STDOUT$'\n'$STDERR
}
if grep -q '^flags' /proc/cpuinfo 2>/dev/null; then
  grep -m1 '^flags' /proc/cpuinfo > "$e2e/same-flags"
  { tr -d '\n' < "$e2e/same-flags"; echo " zz_not_a_real_cpu_flag"; } > "$e2e/more-flags"

  if e2e_case e2e-equal "$e2e/same-flags"; then
    expect "smoke.sh --wake-only, checkpoint flags equal to this host's: exit 15, log tail, no skip" 15 \
      "err:not a runner difference" \
      "err:ch-smoke: FAILED at step 5 (previous release's checkpoint) -- the d process exited before its API socket appeared (exit 15)" \
      "err:--- last lines of d.chlog ---" "!SKIPPED" "!skipped-cpuid" "!PASSED"
  fi
  if e2e_case e2e-differing "$e2e/more-flags"; then
    expect "smoke.sh --wake-only, checkpoint flags this host lacks: SKIPPED naming them, exit 0, log tail" 0 \
      "out:$SKIP""zz_not_a_real_cpu_flag (in the checkpoint's HOST_CPU_FLAGS, not in this host's); this is not a pass" \
      "out:step5=skipped-cpuid (not PASSED)" "err:--- last lines of d.chlog ---" "!FAILED"
  fi
  if e2e_case e2e-absent ""; then
    expect "smoke.sh --wake-only, checkpoint without HOST_CPU_FLAGS: SKIPPED with CH's CPUID lines, exit 0, log tail" 0 \
      "out:$SKIP""Detected incompatible CPUID entry: leaf=0x07" "err:--- last lines of d.chlog ---" "!FAILED"
  fi
else
  echo "note: no flags line in /proc/cpuinfo, so the smoke.sh --wake-only cases are not run"
fi

# --- the workflow raises its warning on exactly smoke.sh's line -------------------
wf="$CI/../workflows/cove-release.yml"
if grep -qF "grep -q \"^${SKIP%% the checkpoint*}\"" "$wf"; then
  ok "cove-release.yml's wake step looks for smoke.sh's SKIPPED line"
else
  bad "cove-release.yml's wake step looks for smoke.sh's SKIPPED line"
fi

echo "$pass passed, $failed failed"
[ "$failed" = 0 ]
