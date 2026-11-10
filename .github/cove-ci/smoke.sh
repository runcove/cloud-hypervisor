#!/usr/bin/env bash
# smoke.sh -- the Cloud Hypervisor release smoke: what cove relies on, on KVM.
#
# Runs directly on a Linux host with /dev/kvm (cove-release.yml's `smoke` job),
# against one build's static x86_64 binary. Not in Docker: its default seccomp
# profile refuses io_uring.
#
# WHAT IT PROVES, in order, each step its own exit code:
#   0. the binary prints `cloud-hypervisor <VERSION>` as its first line;   (10)
#   1. BOOT: a guest boots by direct kernel boot (the pinned vmlinux and the
#      busybox initramfs of smoke_tool.py) with 2 vCPUs (max 4), 256 MiB
#      (+256 MiB ACPI hotplug), one virtio-blk disk with num_queues=2, a
#      serial log and a virtio-console log; its init prints CH-SMOKE-BOOTED
#      after writing and reading back the disk's first sector, then a
#      heartbeat line every second (smoke_tool.py's INIT). The guest must see
#      2 blk-mq queues on the disk, the host must find its mark in the disk
#      image, and the running VMM must hold an io_uring ring: a link to
#      anon_inode:[io_uring] in /proc/<pid>/fd;                              (11)
#   2. SNAPSHOT AND RESTORE: pause, snapshot to a local directory (and copy
#      the disk while paused: that pair is the checkpoint step 6 packs), stop
#      the process, restore into a NEW process and resume. The heartbeat must reach two
#      beats past the number it had reached (one may have been queued before
#      the pause), with no second CH-SMOKE-BOOTED (resumed, not rebooted),
#      the disk still taking writes and still 2 queues;                      (12)
#   3. CLONE: pause the restored VM, snapshot it, copy its disk, restore the
#      copy into a second process beside it. The clone must run while the
#      source stays paused (vm.info says Paused and its heartbeat does not
#      move); then the source resumes and both run at once;                 (13)
#   4. RESIZE: on the source, vCPUs up to max and back to the boot count, and
#      memory up by the hotplug size it was booted with (vm.info must show
#      it). The guest must see each change in its heartbeat and keep
#      beating;                                                             (14)
#   5. WAKE THE PREVIOUS RELEASE'S CHECKPOINT: when IN/previous.tar.gz is
#      there (the workflow fetched it from the previous GitHub Release and
#      checked its attestation and sha256), restore it with this binary: its
#      heartbeat must reach two beats past the number it was saved at, with no
#      reboot and 2 disk queues. That proves this binary still restores what
#      the last release saved. With no previous.tar.gz the step says SKIPPED
#      and why, and proves nothing: there was no earlier checkpoint to wake.
#      It also says SKIPPED, exit 0, when the wake fails because Cloud
#      Hypervisor refused the checkpoint for CPUID: its log says "Error
#      checking cpu feature compatibility" / "Detected incompatible CPUID
#      entry", because the host that saved it had CPU features this one lacks
#      (a hosted runner's CPU model cannot be chosen, and CH v54 has no
#      portable CPU profile). That skip names the missing flags (from the
#      checkpoint's HOST_CPU_FLAGS against this host's /proc/cpuinfo) or,
#      for a checkpoint without HOST_CPU_FLAGS, CH's CPUID lines, prints a
#      ::warning:: line, and says it is not a pass: it proves nothing about
#      waking that checkpoint. The forge's ch-smoke, which saves and wakes on
#      one host, is the cross-version gate that cannot skip this way. Any
#      other failure of the wake fails the step;                           (15)
#   6. PACK, run right after step 2, before anything is woken: the step 2
#      checkpoint (snapshot + the disk as it was at that moment + CHECKPOINT
#      + HOST_CPU_FLAGS, this host's /proc/cpuinfo flags line, so the next
#      release can say what a CPUID refusal lacked) becomes
#      OUT/ch-smoke-checkpoint.tar.gz and
#      OUT/ch-smoke-checkpoint.tar.gz.sha256, which the release publishes for
#      the next release's step 5. This script never publishes anything.    (16)
#
# Usage: smoke.sh [--pack-only | --wake-only] --in DIR --work DIR [--out DIR]
#   --pack-only  steps 0-4 and 6;  --wake-only  steps 0 and 5, no --out.
#                The workflow runs the two apart, recording the sha256 between.
#   --in    holds cloud-hypervisor (the candidate, executable), vmlinux,
#           initramfs.cpio.gz, VERSION (what the binary prints, one line) and,
#           optionally, previous.tar.gz
#   --work  scratch: created (it must not exist, or be empty) and removed on
#           exit, success or failure, after every process this started is gone
#   --out   an existing empty directory for the checkpoint and its sha256
#
# Env (all optional; the defaults are the real run's):
#   SMOKE_BOOT_TIMEOUT    seconds to wait for CH-SMOKE-BOOTED (90)
#   SMOKE_HB_TIMEOUT      seconds to wait for a heartbeat to move (30)
#   SMOKE_RESIZE_TIMEOUT  seconds to wait for the guest to see a resize (60)
#   SMOKE_SETTLE          seconds a paused VM is watched for not moving (3)
#   SMOKE_KVM_DEVICE      the device checked before anything starts
#                         (/dev/kvm). Only the tests change it, to run with a
#                         stub cloud-hypervisor; the real binary opens
#                         /dev/kvm itself whatever this says, so it cannot
#                         make a run without KVM pass.
#   SMOKE_DISK_OPTS       extra --disk options, comma separated. Cloud
#                         Hypervisor's _disable_io_uring=on puts the disk on
#                         another backend, so step 1's ring check must fail.
#
# Exit: 0 every step passed, or step 5 said SKIPPED (no previous checkpoint,
#       or CH refused it for CPUID: this runner's CPU lacks features the
#       saving host had; the output says which, and that it is not a pass);
#       10-16 the step above failed, naming what it saw (15: any wake
#       failure other than that CPUID refusal); 93 could not run safely (an
#       argument or input missing or malformed, no usable KVM device, a work or out
#       directory that is not empty, a previous checkpoint that is not what
#       step 6 writes, a tool missing).
set -euo pipefail
export LC_ALL=C

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TOOL="$HERE/smoke_tool.py"
STEP=preflight
# Set by step 5 to the unpacked checkpoint it wakes; while set, a step 5
# failure is first checked for Cloud Hypervisor's CPUID refusal.
WAKE_CKPT=""
# Where this host's CPU flags are read; only the tests change it.
CPUINFO=/proc/cpuinfo
# What Cloud Hypervisor logs when a snapshot's CPUID is not a subset of this
# host's (vmm/src/lib.rs's context, arch/src/x86_64/mod.rs's error! per entry).
CPUID_REFUSAL_RE='Error checking cpu feature compatibility|Detected incompatible CPUID entry'

cannot() { echo "ch-smoke: CANNOT RUN -- $* (exit 93)" >&2; exit 93; }
say() { echo "ch-smoke: $*"; }

# cpu_flags FILE: the words of FILE's first `flags :` line (a /proc/cpuinfo, or
# a checkpoint's HOST_CPU_FLAGS), one per line, sorted. Only [a-z0-9_] words:
# HOST_CPU_FLAGS comes from a published release.
cpu_flags() {
  { sed -n '/^flags[[:space:]]*:/{s/^[^:]*://;p;q;}' "$1" 2>/dev/null \
      | tr -s '[:blank:]' '\n' | grep -E '^[a-z0-9_]{1,64}$' | LC_ALL=C sort -u; } || true
}

# cpuid_refused WORKDIR CHECKPOINTDIR: true when the wake's VMM (d) logged
# Cloud Hypervisor's CPUID refusal. Prints what this host lacks: the flags in
# CHECKPOINTDIR/HOST_CPU_FLAGS missing from this host's, or, when there is no
# such file or no flag differs (CPUID holds more than /proc/cpuinfo names),
# CH's own CPUID lines, printable characters only, on one line.
cpuid_refused() {
  local work=$1 ckpt=$2 lines missing=""
  lines=$(cat "$work/d.chlog" "$work/d.out" 2>/dev/null | tr -d '\r' | grep -a -E "$CPUID_REFUSAL_RE" || true)
  [ -n "$lines" ] || return 1
  if [ -f "$ckpt/HOST_CPU_FLAGS" ] && [ ! -L "$ckpt/HOST_CPU_FLAGS" ]; then
    missing=$(comm -23 <(cpu_flags "$ckpt/HOST_CPU_FLAGS") <(cpu_flags "$CPUINFO") | tr '\n' ' ')
    missing=${missing% }
  fi
  if [ -n "$missing" ]; then
    echo "$missing (in the checkpoint's HOST_CPU_FLAGS, not in this host's)"
  else
    lines=$({ grep -a -o 'Detected incompatible CPUID entry.*' <<<"$lines" || echo "$lines"; } \
      | head -n 16 | tr '\n' ' ' | tr -cd '[:print:]' | cut -c1-3000)
    echo "${lines% }"
  fi
}

fail() {
  local code=$1 missing; shift
  if [ "$code" = 15 ] && [ -n "$WAKE_CKPT" ] && missing=$(cpuid_refused "$WORK" "$WAKE_CKPT"); then
    say "step 5 (previous release's checkpoint) SKIPPED -- this runner's CPU lacks features the checkpoint was saved with: $missing; this is not a pass"
    say "step 5: the wake of ${PREV_VERSION:-the previous release}'s checkpoint ended with: $*"
    echo "::warning title=ch-smoke step 5 skipped::this runner's CPU lacks features ${PREV_VERSION:-the previous release}'s checkpoint was saved with; step 5 is not a pass"
    say "DONE version=${VERSION:-} previous=${PREV_VERSION:-none} mode=${MODE:-} step5=skipped-cpuid (not PASSED)"
    exit 0
  fi
  echo "ch-smoke: FAILED at step $STEP -- $* (exit $code)" >&2
  exit "$code"
}

# Sourced (the tests): the helpers above only.
[ "${BASH_SOURCE[0]}" = "$0" ] || return 0

IN="" WORK="" OUT="" MODE=all
while [ $# -gt 0 ]; do
  case "$1" in
    --in|--work|--out)
      [ $# -ge 2 ] && [ -n "$2" ] || cannot "$1 needs a value"
      case "$1" in --in) IN=$2 ;; --work) WORK=$2 ;; --out) OUT=$2 ;; esac
      shift 2 ;;
    --pack-only|--wake-only)
      [ "$MODE" = all ] || cannot "--pack-only and --wake-only exclude each other"
      MODE=${1#--}; MODE=${MODE%-only}; shift ;;
    *) cannot "unknown argument '$1' (usage: smoke.sh --in DIR --work DIR --out DIR)" ;;
  esac
done
[ -n "$IN" ] && [ -n "$WORK" ] || cannot "--in and --work are required"
[ "$MODE" = wake ] || [ -n "$OUT" ] || cannot "--out is required unless --wake-only"

num() { case "$2" in ''|*[!0-9.]*|*.*.*|.*) cannot "$1='$2' is not a number of seconds" ;; esac; }
BOOT_TIMEOUT=${SMOKE_BOOT_TIMEOUT:-90};     num SMOKE_BOOT_TIMEOUT "$BOOT_TIMEOUT"
HB_TIMEOUT=${SMOKE_HB_TIMEOUT:-30};         num SMOKE_HB_TIMEOUT "$HB_TIMEOUT"
RESIZE_TIMEOUT=${SMOKE_RESIZE_TIMEOUT:-60}; num SMOKE_RESIZE_TIMEOUT "$RESIZE_TIMEOUT"
SETTLE=${SMOKE_SETTLE:-3};                  num SMOKE_SETTLE "$SETTLE"
KVM=${SMOKE_KVM_DEVICE:-/dev/kvm}
DISK_OPTS=${SMOKE_DISK_OPTS:-}

for t in python3 sha256sum cp grep sed tail awk comm sort tr; do
  command -v "$t" >/dev/null 2>&1 || cannot "no $t on PATH"
done
[ -f "$TOOL" ] || cannot "no smoke_tool.py beside this script"

CH="$IN/cloud-hypervisor"
KERNEL="$IN/vmlinux"
INITRAMFS="$IN/initramfs.cpio.gz"
PREVIOUS="$IN/previous.tar.gz"
[ -f "$CH" ] && [ -x "$CH" ] || cannot "no executable $CH"
[ -s "$KERNEL" ] || cannot "no kernel at $KERNEL"
[ -s "$INITRAMFS" ] || cannot "no initramfs at $INITRAMFS"
[ -f "$IN/VERSION" ] || cannot "no $IN/VERSION"
VERSION=$(cat "$IN/VERSION")
[[ "$VERSION" =~ ^v[0-9]+\.[0-9]+(\.[0-9]+)?(-[A-Za-z0-9._-]+)?$ ]] || cannot "VERSION '$VERSION' is not a release tag or git describe output"
if [ "$MODE" != wake ]; then
  [ -d "$OUT" ] || cannot "--out $OUT is not a directory"
  [ -z "$(ls -A "$OUT")" ] || cannot "--out $OUT is not empty"
fi
[ -c "$KVM" ] && [ -r "$KVM" ] && [ -w "$KVM" ] || cannot "$KVM is not a character device this user can read and write"
# Each VMM's API socket is $WORK/<name>.sock, and a unix socket path has room
# for 107 bytes.
case "$WORK" in /*) ;; *) WORK="$PWD/$WORK" ;; esac
[ "${#WORK}" -le 96 ] || cannot "--work $WORK is too long a path for the VMMs' unix sockets (96 bytes at most)"
if [ -e "$WORK" ]; then
  [ -d "$WORK" ] && [ -z "$(ls -A "$WORK")" ] || cannot "--work $WORK exists and is not an empty directory"
else
  mkdir -p "$WORK" || cannot "cannot create --work $WORK"
fi
WORK=$(cd "$WORK" && pwd)

# --- every process this starts dies with it, and the scratch goes -------------
PIDS=()
cleanup() {
  local rc=$?
  trap - EXIT
  local pid n
  for pid in "${PIDS[@]}"; do kill -TERM "$pid" 2>/dev/null || true; done
  for pid in "${PIDS[@]}"; do
    n=0
    while kill -0 "$pid" 2>/dev/null && [ "$n" -lt 50 ]; do sleep 0.1; n=$((n + 1)); done
    kill -KILL "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
  done
  if [ "$rc" -ne 0 ] && [ -d "$WORK" ]; then
    local f
    for f in "$WORK"/*.console "$WORK"/*.serial "$WORK"/*.chlog "$WORK"/*.out; do
      [ -f "$f" ] || continue
      echo "--- last lines of ${f##*/} ---" >&2
      tail -n 15 "$f" >&2 || true
    done
  fi
  rm -rf -- "$WORK"
  exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# --- helpers --------------------------------------------------------------------
declare -A PID_OF
api() { python3 "$TOOL" api "$WORK/$1.sock" "$2" "$3" ${4:+"$4"}; }
alive() { kill -0 "${PID_OF[$1]}" 2>/dev/null; }

# launch NAME CODE ARGS...: start a VMM with its API socket and log file, wait
# for the socket. A process that dies first, or no socket in time, fails CODE.
launch() {
  local name=$1 code=$2; shift 2
  "$CH" --api-socket "path=$WORK/$name.sock" --log-file "$WORK/$name.chlog" "$@" \
    > "$WORK/$name.out" 2>&1 &
  PID_OF[$name]=$!
  PIDS+=("$!")
  local n=0
  while [ ! -S "$WORK/$name.sock" ]; do
    alive "$name" || fail "$code" "the $name process exited before its API socket appeared"
    [ "$n" -lt 100 ] || fail "$code" "no API socket for $name after 20 s"
    sleep 0.2; n=$((n + 1))
  done
}

stop() {
  local name=$1 n=0
  api "$name" PUT vmm.shutdown > /dev/null 2>&1 || true
  while alive "$name" && [ "$n" -lt 50 ]; do sleep 0.2; n=$((n + 1)); done
  kill -KILL "${PID_OF[$name]}" 2>/dev/null || true
  wait "${PID_OF[$name]}" 2>/dev/null || true
}

# The guest's heartbeat, read from NAME's virtio-console log:
#   CH-SMOKE-HB <n> cpus=<online list> mem_kb=<MemTotal> queues=<blk-mq queues> disk=<ok|err>
# Only COMPLETE lines count: the log is read while the guest writes it, so its
# last line can be half there. The console is a tty, so lines end in \r\n.
HB_RE='^CH-SMOKE-HB [0-9][0-9]* cpus=[0-9,-][0-9,-]* mem_kb=[0-9][0-9]* queues=[0-9][0-9]* disk=(ok|err)$'
hb_line() { { tr -d '\r' < "$WORK/$1.console" 2>/dev/null | grep -a -E "$HB_RE" || true; } | tail -n 1; }
hb_of() { local n; n=$(hb_line "$1" | sed -n 's/.*CH-SMOKE-HB \([0-9][0-9]*\).*/\1/p'); echo "${n:-0}"; }
hb_field() { hb_line "$1" | sed -n "s/.* $2=\([^ ]*\).*/\1/p"; }
booted_count() { local n; n=$({ grep -a -c 'CH-SMOKE-BOOTED' "$WORK/$1.console" 2>/dev/null || true; } | head -n 1); echo "${n:-0}"; }
info() { api "$1" GET vm.info | python3 "$TOOL" field - "$2"; }

# deadline SECONDS -> sets DEADLINE (epoch seconds, rounded up)
deadline() { DEADLINE=$(( $(date +%s) + ${1%.*} + 1 )); }
expired() { [ "$(date +%s)" -ge "$DEADLINE" ]; }

# wait_hb NAME ABOVE CODE WHAT: the heartbeat of NAME passes ABOVE, and that
# line (one written after ABOVE) says disk=ok. A VM that resumed from a pause
# or a snapshot is waited on with ABOVE = the beat it stopped at + 1: one beat
# may already sit in the virtio-console's ring from before the pause, so only
# the second beat past it proves the guest is running again.
wait_hb() {
  local name=$1 above=$2 code=$3 what=$4
  deadline "$HB_TIMEOUT"
  until [ "$(hb_of "$name")" -gt "$above" ]; do
    alive "$name" || fail "$code" "$what: the $name process exited"
    expired && fail "$code" "$what: the heartbeat of $name did not pass $above within ${HB_TIMEOUT}s (last: '$(hb_line "$name")')"
    sleep 0.2
  done
  [ "$(hb_field "$name" disk)" = ok ] || fail "$code" "$what: $name's disk stopped taking writes: '$(hb_line "$name")'"
}

# queues_ok NAME CODE WHAT: the guest's virtio-blk disk has the 2 blk-mq
# queues it was given (num_queues=2); one would mean the setting was lost.
queues_ok() {
  local q; q=$(hb_field "$1" queues)
  [ "$q" = 2 ] || fail "$2" "$3: the guest sees $q blk-mq queue(s) on its disk, not 2: '$(hb_line "$1")'"
}

# wait_field NAME FIELD VALUE CODE WHAT: the guest's own heartbeat shows it.
wait_field() {
  local name=$1 field=$2 want=$3 code=$4 what=$5
  deadline "$RESIZE_TIMEOUT"
  until [ "$(hb_field "$name" "$field")" = "$want" ]; do
    alive "$name" || fail "$code" "$what: the $name process exited"
    expired && fail "$code" "$what: the guest never showed $field=$want within ${RESIZE_TIMEOUT}s (last: '$(hb_line "$name")')"
    sleep 0.2
  done
}

# What /sys/devices/system/cpu/online says with N vCPUs: 0, or 0-(N-1).
online_list() { if [ "$1" -eq 1 ]; then echo 0; else echo "0-$(($1 - 1))"; fi; }

not_rebooted() {
  [ "$(booted_count "$1")" = 0 ] || fail "$2" "$3: $1 printed CH-SMOKE-BOOTED: it booted again instead of resuming"
}

snapshot() {
  local name=$1 dir=$2 code=$3
  mkdir -p "$dir" || fail "$code" "cannot create $dir"
  api "$name" PUT vm.snapshot "{\"destination_url\":\"file://$dir\"}" > /dev/null \
    || fail "$code" "vm.snapshot of $name to $dir was refused"
  [ -s "$dir/config.json" ] || fail "$code" "the snapshot of $name wrote no config.json"
}

restore() {
  local name=$1 dir=$2 disk=$3 code=$4
  python3 "$TOOL" rewrite-config "$dir" --disk "$disk" --serial "$WORK/$name.serial" \
    --console "$WORK/$name.console" --kernel "$KERNEL" --initramfs "$INITRAMFS" \
    || fail "$code" "the snapshot in $dir could not be pointed at $name's files"
  launch "$name" "$code" --restore "source_url=file://$dir"
  api "$name" PUT vm.resume > /dev/null || fail "$code" "vm.resume of the restored $name was refused"
}

# holds_io_uring PID: PID's descriptor table has a live io_uring ring. The
# start-up probe's ring is closed by now, so this one is a disk's. An unreadable
# table has no link to find and counts as none.
holds_io_uring() {
  local fd
  for fd in "/proc/$1/fd/"*; do
    [ "$(readlink "$fd" 2>/dev/null)" = "anon_inode:[io_uring]" ] && return 0
  done
  return 1
}

passed() { say "step $1 $2: passed${3:+ ($3)}"; }

# --- 0. the binary is the candidate ------------------------------------------
STEP="0 (version)"
first=$("$CH" --version 2>&1 | head -n 1) || true
[ "$first" = "cloud-hypervisor $VERSION" ] || fail 10 "the binary prints '$first', not 'cloud-hypervisor $VERSION'"
passed 0 version "$first"

KSHA=$(sha256sum "$KERNEL" | cut -d' ' -f1) || cannot "cannot hash $KERNEL"
ISHA=$(sha256sum "$INITRAMFS" | cut -d' ' -f1) || cannot "cannot hash $INITRAMFS"

# Steps 1-4 and 6 (not indented): skipped with --wake-only.
if [ "$MODE" != wake ]; then
# --- 1. boot -------------------------------------------------------------------
STEP="1 (boot)"
DISK="$WORK/disk.raw"
truncate -s 64M "$DISK" 2>/dev/null || dd if=/dev/zero of="$DISK" bs=1M count=0 seek=64 2>/dev/null \
  || cannot "cannot create the guest disk in $WORK"
launch a 11 \
  --kernel "$KERNEL" --initramfs "$INITRAMFS" \
  --cmdline "console=ttyS0 reboot=k panic=1 rdinit=/init" \
  --cpus boot=2,max=4 \
  --memory size=256M,hotplug_method=acpi,hotplug_size=256M \
  --disk "path=$DISK,image_type=raw,num_queues=2,queue_size=128${DISK_OPTS:+,$DISK_OPTS}" \
  --serial "file=$WORK/a.serial" --console "file=$WORK/a.console"
deadline "$BOOT_TIMEOUT"
until [ "$(booted_count a)" != 0 ]; do
  alive a || fail 11 "the VMM exited before the guest printed CH-SMOKE-BOOTED"
  expired && fail 11 "no CH-SMOKE-BOOTED on the virtio-console within ${BOOT_TIMEOUT}s"
  sleep 0.2
done
grep -a -q 'CH-SMOKE-DISK-OK' "$WORK/a.console" || fail 11 "the guest could not write and read back its virtio-blk disk"
wait_hb a 1 11 "after boot"
queues_ok a 11 "after boot"
# The guest's own readback (CH-SMOKE-DISK-OK) can come from its page cache;
# the mark found in the image on the host is what proves the write reached
# the device.
head -c 13 "$DISK" | grep -q '^CH-SMOKE-DISK' || fail 11 "the guest's disk mark is not in the disk image on the host"
holds_io_uring "${PID_OF[a]}" \
  || fail 11 "the running VMM (pid ${PID_OF[a]}) holds no io_uring ring: no anon_inode:[io_uring] link in /proc/${PID_OF[a]}/fd, so its disk is not on the io_uring backend"
passed 1 boot "heartbeat $(hb_of a), $(hb_field a cpus) online"

# --- 2. snapshot and restore -------------------------------------------------
STEP="2 (snapshot and restore)"
api a PUT vm.pause > /dev/null || fail 12 "vm.pause was refused"
HB_SAVED=$(hb_of a)
snapshot a "$WORK/snap1" 12
cp --sparse=always "$DISK" "$WORK/snap1-disk.raw" || fail 12 "cannot copy the paused VM's disk"
stop a
# restore rewrites config.json, so it gets a copy: snap1 stays as taken, for step 6.
cp -r "$WORK/snap1" "$WORK/run1" || fail 12 "cannot copy the snapshot"
restore b "$WORK/run1" "$DISK" 12
wait_hb b "$((HB_SAVED + 1))" 12 "after restore"
queues_ok b 12 "after restore"
not_rebooted b 12 "after restore"
passed 2 "snapshot and restore" "saved at heartbeat $HB_SAVED, restored to $(hb_of b)"

# --- 6. pack this build's checkpoint, before step 5 wakes anything -------------
STEP="6 (pack)"
# Where it was made: a later wake refused for CPUID can then name what it lacks.
grep -m1 '^flags' "$CPUINFO" > "$WORK/HOST_CPU_FLAGS" || fail 16 "no flags line in $CPUINFO"
python3 "$TOOL" pack "$OUT" --snapshot "$WORK/snap1" --disk "$WORK/snap1-disk.raw" --version "$VERSION" \
  --hb "$HB_SAVED" --kernel-sha256 "$KSHA" --initramfs-sha256 "$ISHA" \
  --host-cpu-flags "$WORK/HOST_CPU_FLAGS" \
  || fail 16 "the checkpoint could not be packed"
passed 6 pack "$(cut -d' ' -f1 "$OUT/ch-smoke-checkpoint.tar.gz.sha256")"

# --- 3. clone -------------------------------------------------------------------
STEP="3 (clone)"
api b PUT vm.pause > /dev/null || fail 13 "vm.pause of the source was refused"
HB_SRC=$(hb_of b)
snapshot b "$WORK/snap2" 13
cp --sparse=always "$DISK" "$WORK/clone.raw" || fail 13 "cannot copy the source's disk"
restore c "$WORK/snap2" "$WORK/clone.raw" 13
wait_hb c "$((HB_SRC + 1))" 13 "the clone"
queues_ok c 13 "the clone"
not_rebooted c 13 "the clone"
state=$(info b state) || fail 13 "vm.info of the source was refused"
[ "$state" = Paused ] || fail 13 "the source is '$state' while its clone runs, not Paused"
sleep "$SETTLE"
[ "$(hb_of b)" = "$HB_SRC" ] || fail 13 "the paused source's heartbeat moved ($HB_SRC -> $(hb_of b))"
api b PUT vm.resume > /dev/null || fail 13 "vm.resume of the source was refused"
HB_C=$(hb_of c)
wait_hb b "$((HB_SRC + 1))" 13 "the source beside its clone"
wait_hb c "$HB_C" 13 "the clone beside its source"
stop c
passed 3 clone "source paused at $HB_SRC while the clone ran; both then ran"

# --- 4. resize --------------------------------------------------------------------
STEP="4 (resize)"
BOOT_CPUS=$(info b config.cpus.boot_vcpus) || fail 14 "vm.info gave no cpus.boot_vcpus"
MAX_CPUS=$(info b config.cpus.max_vcpus) || fail 14 "vm.info gave no cpus.max_vcpus"
[ "$MAX_CPUS" -gt "$BOOT_CPUS" ] || fail 14 "max_vcpus $MAX_CPUS leaves no room above boot_vcpus $BOOT_CPUS"
api b PUT vm.resize "{\"desired_vcpus\":$MAX_CPUS}" > /dev/null || fail 14 "vm.resize to $MAX_CPUS vCPUs was refused"
wait_field b cpus "$(online_list "$MAX_CPUS")" 14 "vCPUs up to $MAX_CPUS"
api b PUT vm.resize "{\"desired_vcpus\":$BOOT_CPUS}" > /dev/null || fail 14 "vm.resize back to $BOOT_CPUS vCPUs was refused"
wait_field b cpus "$(online_list "$BOOT_CPUS")" 14 "vCPUs back to $BOOT_CPUS"
# Step 1 booted with hotplug_size=256M, so vm.info must show it.
HOTPLUG=$(info b config.memory.hotplug_size 2>/dev/null || echo "")
case "$HOTPLUG" in ''|*[!0-9]*|0) fail 14 "vm.info shows memory.hotplug_size '$HOTPLUG', but the VM was booted with 256M of hotplug" ;; esac
SIZE=$(info b config.memory.size) || fail 14 "vm.info gave no memory.size"
MEM_BEFORE=$(hb_field b mem_kb)
case "$MEM_BEFORE" in ''|*[!0-9]*) fail 14 "the guest's heartbeat shows no mem_kb: '$(hb_line b)'" ;; esac
api b PUT vm.resize "{\"desired_ram\":$((SIZE + HOTPLUG))}" > /dev/null \
  || fail 14 "vm.resize of memory to $((SIZE + HOTPLUG)) bytes was refused"
deadline "$RESIZE_TIMEOUT"
until [ "$(hb_field b mem_kb)" -gt $((MEM_BEFORE + HOTPLUG / 2048)) ]; do
  alive b || fail 14 "the VMM exited after the memory resize"
  expired && fail 14 "the guest's MemTotal did not grow by half of $HOTPLUG bytes within ${RESIZE_TIMEOUT}s (before ${MEM_BEFORE} kB, last '$(hb_line b)')"
  sleep 0.2
done
mem_note="memory $MEM_BEFORE -> $(hb_field b mem_kb) kB"
wait_hb b "$(hb_of b)" 14 "after the resizes"
passed 4 resize "vCPUs $BOOT_CPUS -> $MAX_CPUS -> $BOOT_CPUS; $mem_note"
stop b
fi  # steps 1-4 and 6

# --- 5. wake the previous release's checkpoint ----------------------------------
STEP="5 (previous release's checkpoint)"
PREV_VERSION=none
if [ "$MODE" = pack ]; then
  say "step 5 previous release's checkpoint: not run here (--pack-only)"
elif [ -f "$PREVIOUS" ]; then
  mkdir -p "$WORK/prev" || cannot "cannot create $WORK/prev"
  python3 "$TOOL" unpack "$PREVIOUS" "$WORK/prev" || cannot "the previous checkpoint is not one this smoke writes"
  P="$WORK/prev/checkpoint"
  PREV_VERSION=$(python3 "$TOOL" info "$P/CHECKPOINT" version) || cannot "the previous checkpoint has no version"
  PREV_HB=$(python3 "$TOOL" info "$P/CHECKPOINT" hb) || cannot "the previous checkpoint has no heartbeat"
  [ "$PREV_VERSION" != "$VERSION" ] || cannot "the previous checkpoint is this build's own ($VERSION)"
  # From here a failure is first checked for CH's CPUID refusal (fail above).
  WAKE_CKPT=$P
  restore d "$P/snapshot" "$P/disk.raw" 15
  wait_hb d "$((PREV_HB + 1))" 15 "waking $PREV_VERSION's checkpoint"
  queues_ok d 15 "waking $PREV_VERSION's checkpoint"
  not_rebooted d 15 "waking $PREV_VERSION's checkpoint"
  stop d
  WAKE_CKPT=""
  passed 5 "previous release's checkpoint" "$PREV_VERSION's, saved at heartbeat $PREV_HB, woke at $(hb_of d)"
else
  say "step 5 previous release's checkpoint: SKIPPED (no $PREVIOUS: no earlier release published a checkpoint to wake)"
fi

say "PASSED version=$VERSION previous=$PREV_VERSION mode=$MODE"
