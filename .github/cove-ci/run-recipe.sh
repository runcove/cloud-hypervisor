#!/usr/bin/env bash
# run-recipe.sh <build|block-tests|test> -- run one phase of build-static.sh in
# a fresh container on the GitHub-hosted runner, from cove-release.yml and
# cove-test.yml. It holds the build image and the tool pins, once.
#
# The tree is copied in, never mounted, and no token goes in. Nothing the
# container leaves behind is trusted until it has been checked here.
#
# Env: SRC (the clean checkout), VERSION, IS_RELEASE, FORK_SHA, REF, RUN_ID. The
#      build phase's files land in $RUNNER_TEMP/out.
# Exit: the phase's own exit code; 93 when this script cannot run it, or when
#       something other than a plain file comes out of the container.
set -euo pipefail

# The official image of the toolchain the fork builds with (Cargo.toml
# rust-version), by its multi-arch index digest. The pins are the published
# release files, each checked against its sha256 before it is unpacked.
export BUILD_IMAGE=rust:1.89.0-bookworm@sha256:948f9b08a66e7fe01b03a98ef1c7568292e07ec2e4fe90d88c07bb14563c84ff
export ZIG_VERSION=0.16.0
export ZIG_SHA256=70e49664a74374b48b51e6f3fdfbf437f6395d42509050588bd49abe52ba3d00
export CARGO_ZIGBUILD_VERSION=0.23.3
export CARGO_ZIGBUILD_SHA256=75c94b3f0d12d39270106852c747284521184b2f816a895576f3399e61b35af5
export CARGO_DENY_VERSION=0.18.9
export CARGO_DENY_SHA256=491d04e4c05d7c92582e3d40ec94126c52472a546326a6d29473a5a4e73babd2
export CARGO_ABOUT_VERSION=0.9.2
export CARGO_ABOUT_SHA256=9099a59e820c38a68b9d65f300662a567d56562f9a10f6aa4c7e86c17c2566af

cannot() { echo "run-recipe: CANNOT RUN -- $* (exit 93)" >&2; exit 93; }

export BUILD_PHASE=${1:-}
for v in SRC VERSION IS_RELEASE FORK_SHA REF RUN_ID RUNNER_TEMP; do
  [ -n "${!v:-}" ] || cannot "$v is not set"
done
CI_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
OUT="$RUNNER_TEMP/out"
BLOCK_OUT="$RUNNER_TEMP/block-tests"
JOBS=$(nproc)

case "$BUILD_PHASE" in
  build)
    OPTS=(--network bridge --memory 10g --memory-swap 10g)
    ;;
  # A runner is a throwaway VM holding no secret, so the phases that need
  # io_uring drop Docker's seccomp profile rather than carry a copy of it.
  block-tests)
    [ -r "$BLOCK_OUT/MANIFEST" ] || cannot "no block test executables came out of the build phase"
    OPTS=(--network none --memory 10g --memory-swap 10g --security-opt seccomp=unconfined)
    ;;
  # The arguments upstream's scripts/dev_cli.sh gives its unit tests.
  test)
    OPTS=(--network bridge --memory 14g --memory-swap 14g --security-opt seccomp=unconfined
          --device /dev/kvm --device /dev/net/tun --cap-add net_admin)
    ;;
  *) cannot "phase '$BUILD_PHASE' is not build, block-tests or test" ;;
esac

NAME="cove-${BUILD_PHASE}-${RUN_ID}"
remove() { docker rm -f "$NAME" >/dev/null 2>&1 || true; }
remove
trap remove EXIT
docker create --name "$NAME" "${OPTS[@]}" --cpus "$JOBS" \
  --ulimit nofile=65536:65536 \
  -e CARGO_BUILD_JOBS="$JOBS" -e SOURCE_DATE_EPOCH=0 -e BUILD_PHASE \
  -e VERSION -e IS_RELEASE -e FORK_SHA -e REF -e RUN_ID -e BUILD_IMAGE \
  -e ZIG_VERSION -e ZIG_SHA256 -e CARGO_ZIGBUILD_VERSION -e CARGO_ZIGBUILD_SHA256 \
  -e CARGO_DENY_VERSION -e CARGO_DENY_SHA256 \
  -e CARGO_ABOUT_VERSION -e CARGO_ABOUT_SHA256 \
  -w / "$BUILD_IMAGE" bash /build-static.sh >/dev/null
docker cp -q "$CI_DIR/build-static.sh" "$NAME":/build-static.sh
if [ "$BUILD_PHASE" = block-tests ]; then
  docker cp -q "$BLOCK_OUT/." "$NAME":/block-tests
else
  docker cp -q "$CI_DIR/third-party-notices.py" "$NAME":/third-party-notices.py
  docker cp -q "$SRC/." "$NAME":/src
fi

# What the container prints reaches this log until the resume line: none of it
# runs as a workflow command.
tok=$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')
echo "::stop-commands::$tok"
rc=0
docker start -a "$NAME" || rc=$?
printf '\n::%s::\n' "$tok"
[ "$rc" -eq 0 ] || { echo "::error::phase $BUILD_PHASE failed (exit $rc); the error is above."; exit "$rc"; }
[ "$BUILD_PHASE" = build ] || exit 0

# docker cp copies a symlink as a symlink, and upload-artifact follows links,
# so a link left behind by the tree's code could upload a file of this runner.
# Nothing reads what came out until it is known to be plain files. The refusal
# names no path, because the names are the container's.
copy_out() { # <path in the container> <new directory here>
  mkdir -p "$2"
  docker cp -q "$NAME:$1/." "$2" || cannot "could not copy $1 out of the container"
  if [ -n "$(find "$2" -mindepth 1 ! -type f ! -type d -print -quit)" ]; then
    find "$2" -mindepth 1 -delete
    cannot "$1 held something other than plain files and directories"
  fi
}
copy_out /out "$OUT"
copy_out /block-tests "$BLOCK_OUT"
ls -la "$OUT"
# --status and no stderr, for the same reason.
( cd "$OUT" && sha256sum --strict --status -c SHA256SUMS 2>/dev/null ) \
  || { echo "::error::the build's SHA256SUMS does not match the files in its output"; exit 1; }
