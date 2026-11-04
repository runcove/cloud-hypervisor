#!/usr/bin/env bash
# build-static.sh -- THE static Cloud Hypervisor recipe.
#
# Runs INSIDE a compile container, started by run-recipe.sh (beside this file)
# from .github/workflows/cove-release.yml and cove-test.yml.
#
# THREE PHASES, one container each, chosen by BUILD_PHASE:
#   build        steps 1-9 below, under Docker's default seccomp profile.
#                It compiles block's test executables but does not run them;
#   block-tests  runs those executables and nothing else: no cargo, no rustc,
#                no build script or proc macro, so nothing is compiled there.
#                33 of block's tests open real io_uring rings, which Docker's
#                default profile refuses, so this phase runs in a container
#                that allows io_uring, with no network;
#   test         steps 1-4, then block's clippy and tests, the workspace's
#                unit tests, and virtio-devices' `virtio_block_filter` seccomp
#                tests on x86_64-unknown-linux-musl (the target we ship; the
#                workspace tests run on the gnu host, where a syscall only
#                musl's libc makes, such as legacy open or stat, goes unseen),
#                in a container that allows io_uring and has
#                /dev/kvm and /dev/net/tun. It builds no release binary.
#
# WHAT THE BUILD PHASE DOES, in order, all in /src (the fork's tree, .git included --
# CH's cloud-hypervisor/build.rs runs `git describe --dirty` for the version
# the binary prints, so a tree without .git builds a binary that lies):
#   1. installs zig, cargo-zigbuild, cargo-deny and cargo-about at pinned
#      versions, each checked against a pinned sha256 before it is unpacked;
#   2. refuses a tree that could choose what cargo, rustc or rustup RUN: any
#      `.cargo` entry (cargo reads .cargo/config.toml from where it is run and
#      every directory above, and cargo-about runs it from the manifest's own
#      directory: `[build] rustc`, a wrapper, a credential provider or source
#      replacement there is the fork's choice of program) or rust-toolchain
#      file (rustup would fetch and run the toolchain it names) anywhere in
#      /src or above it, or a config in CARGO_HOME (which defaults to $HOME/.cargo, as cargo's
#      own does); and unsets every CARGO* and RUST* environment variable
#      but the few the build needs. Steps 4 and 5 rest on this: with it, they
#      run cargo's own code and ours, and none the fork chose;
#   3. on a release, checks the release tag $VERSION is already at HEAD and
#      ANNOTATED -- CI never mints or pushes a tag. Annotated, because build.rs
#      calls `git describe` WITHOUT --tags, which ignores lightweight tags:
#      a lightweight one would build `v53.0-1-g4ddc0fcd7`;
#   4. `cargo deny check advisories`, BLOCKING, before any of the fork's
#      code runs (its build scripts, from step 6 on): a vulnerability, unsound or unmaintained advisory fails the
#      build and the failure names its RUSTSEC ids; a yanked crate is a
#      warning. The config is written by this file into a fresh private
#      directory, never a deny.toml in the tree (none today), so an ignore
#      can only be added here, in plain view.
#      Only `advisories` runs; bans, licenses and sources never did;
#   5. THIRD-PARTY-NOTICES.txt, also before any of the fork's code runs:
#      `cargo about` reads this commit's Cargo.lock for the SAME two targets
#      and feature set step 7 builds (one list each, used by both), leaving
#      out crates that are only build- or dev-dependencies, and
#      third-party-notices.py (beside this file) checks its answer is whole
#      and writes the file: Cloud Hypervisor's own licences and credits,
#      every linked crate with its licence and the licence's text, the
#      licence files of native code crates bundle, and the Rust standard
#      library's and the C library's notices from this container's own
#      toolchain. A crate with no licence it can determine, no text, a
#      licence not on OUR accepted list, or native code nobody has looked at
#      fails the build; a partial file is never written;
#   6. `cargo clippy -D warnings` of the one crate we patch (block), on the
#      host target, with its io_uring feature (the patched io_uring engine and
#      its tests only compile with it), then `cargo test --no-run` of the same:
#      its test executables, with a sha256 MANIFEST, go to $BLOCK_TESTS for
#      the block-tests phase to run;
#   7. `cargo zigbuild --release --locked` of the cloud-hypervisor bin for
#      x86_64- and aarch64-unknown-linux-musl, features io_uring,kvm only;
#   8. the smoke: the first line of the x86_64 binary's `--version` must be
#      EXACTLY `cloud-hypervisor <expected>` (never -dirty; the second line is
#      "Migration Protocol Versions: ..."), and `file` + readelf must
#      show each binary is a statically linked ELF of the right machine with
#      no program interpreter and no NEEDED entries;
#   9. $OUT/cloud-hypervisor-static-{x86_64,aarch64}, BUILDINFO,
#      THIRD-PARTY-NOTICES.txt and SHA256SUMS (covering all four). The
#      notices' digest was recorded in step 5; the copy in $OUT and, last of
#      all, its line in SHA256SUMS must still be that digest, because the
#      fork's build scripts ran in between as this same user.
#
# REPRODUCIBILITY INPUTS, not a promise: SOURCE_DATE_EPOCH=0 comes from the
# caller; RUSTFLAGS remaps /src and CARGO_HOME out of every embedded path, so
# the bytes do not depend on where the tree was copied.
#
# Env (all required unless noted; nothing is a default, so a workflow edit
# that drops one refuses here instead of building something else):
#   BUILD_PHASE              build | block-tests | test
#   VERSION                  the version the binary must print, e.g.
#                            v53.0-cove.1 (release) or v53.0-1-g4ddc0fcd7:
#                            always equal to `git describe --dirty` here
#   IS_RELEASE               true | false
#   FORK_SHA                 the 40-hex commit HEAD must be
#   ZIG_VERSION ZIG_SHA256
#   CARGO_ZIGBUILD_VERSION CARGO_ZIGBUILD_SHA256
#   CARGO_DENY_VERSION CARGO_DENY_SHA256
#   CARGO_ABOUT_VERSION CARGO_ABOUT_SHA256
#   BUILD_IMAGE              the image reference (with digest), for BUILDINFO
#   REF RUN_ID               for BUILDINFO (optional: "local" when unset)
#   OUT                      optional, default /out
#   BLOCK_TESTS              optional, default /block-tests: block's test
#                            executables and their MANIFEST (written by the
#                            build phase, read by the block-tests phase)
#
# Exit: 0 built and smoked (block-tests: every executable passed); 1 a step
#       failed (compile, test, clippy, an advisory, the notices, smoke);
#       93 could not build what was asked (an input missing or malformed, no
#       third-party-notices.py beside this file in the build phase, no or a
#       mismatched block-tests MANIFEST, neither CARGO_HOME nor HOME
#       set, a tree with a .cargo entry or a rust-toolchain file, a HEAD that is not FORK_SHA, a tree that is not clean, a release tag
#       that is missing, lightweight or names another commit).
set -euo pipefail
export LC_ALL=C

cannot() { echo "build-static: CANNOT BUILD -- $* (exit 93)" >&2; exit 93; }
fail()   { echo "build-static: FAILED -- $*" >&2; exit 1; }

for v in VERSION IS_RELEASE FORK_SHA ZIG_VERSION ZIG_SHA256 CARGO_ZIGBUILD_VERSION \
         CARGO_ZIGBUILD_SHA256 CARGO_DENY_VERSION CARGO_DENY_SHA256 \
         CARGO_ABOUT_VERSION CARGO_ABOUT_SHA256 BUILD_IMAGE; do
  [ -n "${!v:-}" ] || cannot "$v is not set"
done
case "$IS_RELEASE" in true|false) ;; *) cannot "IS_RELEASE is '$IS_RELEASE', not true or false" ;; esac
case "${BUILD_PHASE:-}" in build|block-tests|test) ;; *) cannot "BUILD_PHASE is '${BUILD_PHASE:-}', not build, block-tests or test" ;; esac
[[ "$VERSION" =~ ^v[0-9A-Za-z._-]+$ ]] || cannot "VERSION '$VERSION' is not a plain v-name"
[[ "$FORK_SHA" =~ ^[0-9a-f]{40}$ ]]   || cannot "FORK_SHA '$FORK_SHA' is not a full lowercase commit id"
for s in ZIG_SHA256 CARGO_ZIGBUILD_SHA256 CARGO_DENY_SHA256 CARGO_ABOUT_SHA256; do
  [[ "${!s}" =~ ^[0-9a-f]{64}$ ]] || cannot "$s is not a 64-hex sha256"
done
# The notices writer travels with this file (run-recipe.sh copies both into
# the build container's root).
HERE=${BASH_SOURCE[0]%/*}
[ "$HERE" != "${BASH_SOURCE[0]}" ] || HERE=.
# Absolute, because it is used after `cd /src`. Run as /build-static.sh (the
# container), the directory part is empty and means /.
HERE=$(cd "${HERE:-/}" && pwd) || cannot "cannot resolve the directory of ${BASH_SOURCE[0]}"
NOTICES_PY="${HERE%/}/third-party-notices.py"
[ -r "$NOTICES_PY" ] || [ "$BUILD_PHASE" = block-tests ] || cannot "no third-party-notices.py beside ${BASH_SOURCE[0]}"
# What is built, said once: the zigbuild loop and the notices both read these,
# so the notices cannot describe another binary than the one that ships.
TARGETS=(x86_64-unknown-linux-musl aarch64-unknown-linux-musl)
FEATURES=io_uring,kvm
# The block crate's own feature for its tests and lint: our patch lives in its
# io_uring engine, which only compiles with it.
BLOCK_FEATURES=io_uring
OUT="${OUT:-/out}"
BLOCK_TESTS="${BLOCK_TESTS:-/block-tests}"
REF="${REF:-local}"
RUN_ID="${RUN_ID:-local}"
# build.rs appends CH_EXTRA_VERSION to the version when it is set; nothing of
# ours sets it, and nothing from outside may.
unset CH_EXTRA_VERSION
# >>> cargo-env: what the environment may not choose.
# Nor may the environment choose the compiler, a wrapper around it, cargo
# itself, the toolchain, the target, the profile, a linker or a credential
# provider: each CARGO* and RUST* variable is a program or a setting cargo or
# rustup honours, so every one is unset, not only the ones known to name a
# program, except these, which this build needs, each for the reason given.
# Nothing else of ours sets one (cargo-zigbuild sets what it
# needs for its own child; RUSTFLAGS and CARGO_INCREMENTAL are exported by
# the recipe itself, below this block); the tree's side of the same door is
# tree_guard, below.
#   CARGO_HOME, RUSTUP_HOME      where the image keeps cargo and rustup (and
#                                what tree_guard looks in for a config)
#   CARGO_BUILD_JOBS             the caller's parallelism cap
#   *_VERSION, *_SHA256 of       the pinned tools' inputs, read above
#   CARGO_ZIGBUILD, CARGO_DENY,  and in BUILDINFO
#   CARGO_ABOUT
KEEP_ENV=" CARGO_HOME RUSTUP_HOME CARGO_BUILD_JOBS CARGO_ZIGBUILD_VERSION CARGO_ZIGBUILD_SHA256 CARGO_DENY_VERSION CARGO_DENY_SHA256 CARGO_ABOUT_VERSION CARGO_ABOUT_SHA256 "
while IFS= read -r env_name; do
  # bash cannot unset a name that is not a valid identifier (older bash errors,
  # and set -e would end the build); skip it, cargo reads only valid names.
  [[ "$env_name" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] || continue
  case "$env_name" in
    CARGO*|RUST*) case "$KEEP_ENV" in *" $env_name "*) ;; *) unset "$env_name" ;; esac ;;
  esac
done < <(compgen -e)
# Always a path, so tree_guard always has a config to look for: unset, cargo
# itself uses $HOME/.cargo, and the later steps (and RUSTFLAGS) must say the
# same place. With neither CARGO_HOME nor HOME there is no such path, so the
# build refuses (as it does for any input it cannot build from) instead of
# dying on an unbound variable.
if [ -z "${CARGO_HOME:-}" ]; then
  [ -n "${HOME:-}" ] || cannot "neither CARGO_HOME nor HOME is set, so there is no CARGO_HOME for the tree guard to check"
  CARGO_HOME="$HOME/.cargo"
fi
export CARGO_HOME
# <<< cargo-env

T_START=$(date +%s)
phase() { echo; echo "==== $* ($(( $(date +%s) - T_START ))s) ===="; }

if [ "$BUILD_PHASE" = block-tests ]; then
  # A container whose seccomp profile allows io_uring runs block's test
  # executables, which the build phase compiled under Docker's default
  # profile, and nothing else: no cargo, rustc or rustup is called here, so
  # no build script or proc macro runs and nothing can be compiled. Each runs
  # from an empty directory of its own (block's tests read no file of the
  # tree), its stdin closed.
  phase "block tests (the build phase's executables; nothing is compiled here)"
  [ -r "$BLOCK_TESTS/MANIFEST" ] || cannot "no $BLOCK_TESTS/MANIFEST: the build phase wrote no block test executables"
  ( cd "$BLOCK_TESTS" && sha256sum --strict -c MANIFEST ) \
    || cannot "$BLOCK_TESTS does not match its MANIFEST"
  ran=0
  while read -r _ name <&3; do
    [[ "$name" =~ ^[A-Za-z0-9_][A-Za-z0-9_-]*$ ]] || cannot "MANIFEST names '$name', not a plain executable name"
    work=$(mktemp -d) || cannot "mktemp -d failed"
    echo "---- $name"
    ( cd "$work" && "$BLOCK_TESTS/$name" </dev/null ) || fail "block test executable $name failed"
    ran=$((ran + 1))
  done 3< "$BLOCK_TESTS/MANIFEST"
  [ "$ran" -ge 1 ] || cannot "$BLOCK_TESTS/MANIFEST lists no executable"
  echo "build-static: OK block tests of $VERSION ($ran executables) in $(( $(date +%s) - T_START ))s"
  exit 0
fi

phase "tools"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq --no-install-recommends file binutils xz-utils >/dev/null
mkdir -p /tmp/dl
fetch() { # <url> <sha256> <dest>
  curl -fsSL --retry 5 -o "$3" "$1"
  echo "$2  $3" | sha256sum -c - || fail "sha256 of $1 is not the pinned $2"
}
fetch "https://ziglang.org/download/${ZIG_VERSION}/zig-x86_64-linux-${ZIG_VERSION}.tar.xz" "$ZIG_SHA256" /tmp/dl/zig.tar.xz
tar -xJf /tmp/dl/zig.tar.xz -C /opt
ln -sf "/opt/zig-x86_64-linux-${ZIG_VERSION}/zig" /usr/local/bin/zig
fetch "https://github.com/rust-cross/cargo-zigbuild/releases/download/v${CARGO_ZIGBUILD_VERSION}/cargo-zigbuild-x86_64-unknown-linux-musl.tar.xz" "$CARGO_ZIGBUILD_SHA256" /tmp/dl/czb.tar.xz
tar -xJf /tmp/dl/czb.tar.xz -C /usr/local/bin --strip-components=1 cargo-zigbuild-x86_64-unknown-linux-musl/cargo-zigbuild
fetch "https://github.com/EmbarkStudios/cargo-deny/releases/download/${CARGO_DENY_VERSION}/cargo-deny-${CARGO_DENY_VERSION}-x86_64-unknown-linux-musl.tar.gz" "$CARGO_DENY_SHA256" /tmp/dl/deny.tar.gz
tar -xzf /tmp/dl/deny.tar.gz -C /usr/local/bin --strip-components=1 "cargo-deny-${CARGO_DENY_VERSION}-x86_64-unknown-linux-musl/cargo-deny"
fetch "https://github.com/EmbarkStudios/cargo-about/releases/download/${CARGO_ABOUT_VERSION}/cargo-about-${CARGO_ABOUT_VERSION}-x86_64-unknown-linux-musl.tar.gz" "$CARGO_ABOUT_SHA256" /tmp/dl/about.tar.gz
tar -xzf /tmp/dl/about.tar.gz -C /usr/local/bin --strip-components=1 "cargo-about-${CARGO_ABOUT_VERSION}-x86_64-unknown-linux-musl/cargo-about"
rm -rf /tmp/dl
command -v python3 >/dev/null || cannot "the build image has no python3 (third-party-notices.py needs it)"
ZIG_DIR="/opt/zig-x86_64-linux-${ZIG_VERSION}"
echo "zig $(zig version); $(cargo-zigbuild --version); $(cargo-deny --version); $(cargo-about --version); $(python3 --version)"

phase "source"
# >>> tree-guard: what in a source tree could choose a program for cargo,
# rustc or rustup to run.
tree_guard() { # <tree root, absolute> <CARGO_HOME> <highest directory above the tree to check>
  # 0 clean; 1 and the reasons on stderr. The recipe's ceiling is /, so every
  # directory cargo and rustup would walk through is checked; only the tests
  # pass another, to keep the runner's own directories out of their verdict.
  local root=$1 home=$2 top=${3%/} hits d
  # Any entry NAMED .cargo, of any type and at any depth: cargo reads
  # <dir>/.cargo/config.toml (and config) for the directory it runs in and
  # every one above, cargo-about runs it in the manifest's directory, and a
  # symlink called .cargo is followed. .git is skipped: nothing runs cargo in it.
  hits=$(find "$root" -path "$root/.git" -prune -o \
           \( -name .cargo -o -name rust-toolchain -o -name rust-toolchain.toml \) -print | sort | head -20) \
    || { echo "build-static: could not search $root for cargo configuration" >&2; return 1; }
  d=${root%/*}
  while :; do
    for f in .cargo rust-toolchain rust-toolchain.toml; do
      if [ -e "${d:-/}/$f" ] || [ -L "${d:-/}/$f" ]; then hits+=${hits:+$'\n'}${d}/$f; fi
    done
    [ -n "$d" ] && [ "$d" != "$top" ] || break
    d=${d%/*}
  done
  for f in config config.toml; do
    if [ -e "$home/$f" ] || [ -L "$home/$f" ]; then hits+=${hits:+$'\n'}$home/$f; fi
  done
  [ -z "$hits" ] && return 0
  printf 'build-static: %s\n' "REFUSING a tree that can choose what cargo, rustc or rustup run:" >&2
  printf '  %s\n' "$hits" >&2
  return 1
}
# <<< tree-guard
# FIRST, before git, rustup, rustc or cargo is run here: rustup reads a
# rust-toolchain file for every one of its proxies, cargo among them.
tree_guard /src "$CARGO_HOME" / \
  || cannot "the source tree (or a directory above it, or CARGO_HOME) carries cargo configuration or a rust-toolchain file, listed above; none is expected, and one could run a program of the fork's choosing before the advisories gate and the notices"
cd /src
# The tree was docker-cp'd in, so its owner is not this user; without this git
# refuses the repository and build.rs silently falls back to Cargo.toml's
# version -- which the smoke would catch, but only after the whole build.
git config --global --add safe.directory '*'
HEAD_SHA=$(git rev-parse HEAD) || cannot "/src is not a git checkout"
[ "$HEAD_SHA" = "$FORK_SHA" ] || cannot "HEAD is $HEAD_SHA, the build was decided on $FORK_SHA"
# Clean, including untracked files: anything here that is not the commit
# would be built into a binary labelled as the commit.
dirt=$(git status --porcelain --untracked-files=all) || cannot "git status failed"
[ -z "$dirt" ] || { printf '%s\n' "$dirt" | head -20 >&2; cannot "the tree is not the clean commit $FORK_SHA"; }

if [ "$IS_RELEASE" = true ]; then
  # The release tag is ALREADY on the commit: it was pushed to the fork, and
  # cove-release.yml's decide step proved it the one v<up>-cove.<n> tag at HEAD.
  # Nothing here creates a tag. It must name HEAD and be ANNOTATED: build.rs
  # calls `git describe` WITHOUT --tags, which ignores lightweight tags, so a
  # lightweight one would build `v53.0-1-g4ddc0fcd7` under the release name.
  existing=$(git rev-parse -q --verify "refs/tags/$VERSION^{commit}") \
    || cannot "release $VERSION has no tag of that name in /src"
  [ "$existing" = "$HEAD_SHA" ] || cannot "tag $VERSION names $existing, not HEAD $HEAD_SHA"
  [ "$(git cat-file -t "refs/tags/$VERSION")" = tag ] \
    || cannot "tag $VERSION is lightweight; build.rs's plain \`git describe\` cannot see it (release tags are annotated)"
fi
# EVERY build, release or not: what build.rs will embed is `git describe
# --dirty` (its exact form -- no --tags, no --long), and it must be the
# VERSION the build was decided on, which names the artefact. So the file name
# and what the binary prints are always one string.
EXPECT=$(git describe --dirty) || cannot "git describe found no annotated tag"
case "$EXPECT" in *-dirty) cannot "git describe says the tree is dirty ($EXPECT)" ;; esac
[ "$EXPECT" = "$VERSION" ] || cannot "git describe --dirty says '$EXPECT', but the build was decided as '$VERSION'"
echo "the binary must print: cloud-hypervisor $EXPECT"

phase "toolchain"
rustup component add clippy
rustup target add "${TARGETS[@]}"
rustc -Vv
cargo -V

export RUSTFLAGS="--remap-path-prefix=/src=/cloud-hypervisor --remap-path-prefix=${CARGO_HOME}=/cargo"
export CARGO_INCREMENTAL=0

phase "cargo deny check advisories (BLOCKING; yanked crates warn)"
# OUR policy, passed with --config so a deny.toml in the tree (if it ever grows
# one) is never read: its `ignore`, `db-urls` or `yanked` cannot steer this
# gate. Everything not set here is cargo-deny's default, under which
# vulnerability, unsound and unmaintained advisories are errors.
# It runs BEFORE any of the fork's code does (its build scripts run from the
# first cargo test/build on), and its config and log live in a fresh private
# directory, so nothing the fork builds can touch the gate. cargo-deny reads
# only `cargo metadata` and the lockfile; it builds nothing.
DENY_DIR=$(mktemp -d) || cannot "mktemp -d failed"
DENY_CONFIG="$DENY_DIR/ch-advisory-deny.toml"
cat >"$DENY_CONFIG" <<'TOML'
[advisories]
yanked = "warn"
ignore = []
TOML
# >>> deny-verdict: the gate's reading of cargo-deny's output.
deny_verdict() { # <cargo-deny exit> <its combined output, --color never>
  local rc=$1 log=$2 ids
  ids=$(awk '/^(error|warning|note|help)(\[[^]]*\])?:/ { err = ($0 ~ /^error/) }
             err && match($0, /ID: [A-Z]+-[0-9]+-[0-9]+/) { print substr($0, RSTART + 4, RLENGTH - 4) }' \
          "$log" | sort -u | tr '\n' ' ')
  ids=${ids% }
  if [ "$rc" -eq 0 ] && [ -z "$ids" ]; then
    echo "cargo deny check advisories: clean (exit 0); yanked crates, if any, are the warnings above."
    return 0
  fi
  if [ -n "$ids" ]; then
    echo "build-static: FAILED -- cargo deny check advisories found: $ids (exit $rc). Bump the crate in the fork; yanked crates alone never fail this." >&2
  else
    echo "build-static: FAILED -- cargo deny check advisories exited $rc without naming an advisory: it could not run (database fetch, config, lockfile). Read the lines above." >&2
  fi
  return 1
}
# <<< deny-verdict
deny_rc=0
cargo deny --log-level warn --color never check --config "$DENY_CONFIG" advisories \
  >"$DENY_DIR/deny.log" 2>&1 || deny_rc=$?
cat "$DENY_DIR/deny.log"
deny_verdict "$deny_rc" "$DENY_DIR/deny.log" || exit 1

if [ "$BUILD_PHASE" = test ]; then
  # What cove-test.yml runs. The guard and the gate above came first, so none
  # of the tree's code has run yet. The workspace's two commands are upstream's
  # scripts/run_unit_tests.sh, with --locked.
  HOST_TARGET=$(rustc -vV | sed -n 's/^host: //p')
  [ -n "$HOST_TARGET" ] || cannot "rustc -vV names no host target"
  export RUST_BACKTRACE=1
  phase "cargo clippy -p block"
  cargo clippy --locked -p block --features "$BLOCK_FEATURES" --all-targets -- -D warnings
  phase "block tests"
  cargo test --locked -p block --features "$BLOCK_FEATURES"
  phase "workspace unit tests"
  cargo test --locked --lib --bins --target "$HOST_TARGET" --release --workspace
  phase "virtio-block seccomp filter tests (x86_64 musl)"
  # Every test whose name contains virtio_block_filter, so later ones run too.
  RUST_BACKTRACE=1 cargo zigbuild test --locked -p virtio-devices --lib --features kvm \
    --target x86_64-unknown-linux-musl virtio_block_filter
  phase "workspace doc tests"
  cargo test --locked --doc --target "$HOST_TARGET" --release --workspace
  echo "build-static: OK tests of $VERSION in $(( $(date +%s) - T_START ))s"
  exit 0
fi

phase "third-party notices (cargo about; a crate without a licence or its text fails)"
# The crates LINKED INTO the two binaries, from this commit's Cargo.lock: the
# zigbuild's own targets and features, without crates that are only build- or
# dev-dependencies. OUR config, passed with --config, so an about.toml in the
# tree is never read: `accepted` is the list of licences a release may
# carry, in the order one is chosen when a crate offers several, and a crate
# under anything else fails the build until it is added here.
# Like the gate above it runs before any of the fork's code, in its own fresh
# private directory; cargo-about reads `cargo metadata` and the crates'
# files, and builds nothing (tree_guard, above, is why `cargo metadata` runs
# no program the tree names). The standard library's and the C library's
# notices come from this container's own toolchain: rustc's share/doc/rust and
# the zig unpacked above. It runs WITHOUT --fail because Cloud Hypervisor's
# own crates mostly declare no licence (they are the project's code, under the
# project's licences); third-party-notices.py is what refuses, for every
# other crate, a missing licence or text.
NOTICES_DIR=$(mktemp -d) || cannot "mktemp -d failed"
cat >"$NOTICES_DIR/ch-about.toml" <<'TOML'
accepted = ["Apache-2.0", "MIT", "BSD-3-Clause", "ISC", "MPL-2.0", "Unicode-3.0"]
ignore-build-dependencies = true
ignore-dev-dependencies = true
TOML
about_targets=()
for target in "${TARGETS[@]}"; do about_targets+=(--target "$target"); done
cargo about generate --config "$NOTICES_DIR/ch-about.toml" --format json --locked \
  --manifest-path /src/cloud-hypervisor/Cargo.toml "${about_targets[@]}" \
  --no-default-features --features "$FEATURES" --output-file "$NOTICES_DIR/about.json" \
  || fail "cargo about could not list the linked crates and their licences (the error is above)"
RUSTC_NAME=$(rustc -V | cut -d' ' -f1,2) || fail "rustc -V failed"
python3 -I "$NOTICES_PY" --about-json "$NOTICES_DIR/about.json" --src /src \
  --rust-doc "$(rustc --print sysroot)/share/doc/rust" --rustc-version "$RUSTC_NAME" \
  --zig-dir "$ZIG_DIR" --zig-version "$(zig version)" \
  --out "$NOTICES_DIR/THIRD-PARTY-NOTICES.txt" \
  || fail "THIRD-PARTY-NOTICES.txt was not written; every reason is named above"
[ -s "$NOTICES_DIR/THIRD-PARTY-NOTICES.txt" ] || fail "THIRD-PARTY-NOTICES.txt is empty"
# Its digest now, checked again when it is copied out: the fork's build
# scripts run between here and there, as this same user.
NOTICES_SHA256=$(sha256sum < "$NOTICES_DIR/THIRD-PARTY-NOTICES.txt" | cut -d' ' -f1)
[[ "$NOTICES_SHA256" =~ ^[0-9a-f]{64}$ ]] || fail "could not take THIRD-PARTY-NOTICES.txt's sha256"

phase "cargo clippy -p block"
cargo clippy --locked -p block --features "$BLOCK_FEATURES" --all-targets -- -D warnings
phase "block test executables (built here, run by the block-tests phase)"
# Built here, under Docker's default profile, so every build script and proc
# macro runs here; the block-tests container only runs what this leaves.
BLOCK_JSON_DIR=$(mktemp -d) || cannot "mktemp -d failed"
cargo test --locked -p block --features "$BLOCK_FEATURES" --no-run --message-format=json \
  >"$BLOCK_JSON_DIR/messages.json" || fail "block's tests did not compile (the error is above)"
# >>> block-test-exes: which of cargo's artefacts are test executables.
block_test_exes() { # <cargo --message-format=json output> <directory to fill>
  python3 -I -c '
import hashlib, json, os, shutil, sys
src, dest = sys.argv[1], sys.argv[2]
exes = []
for line in open(src, encoding="utf-8"):
    try:
        m = json.loads(line)
    except ValueError:
        continue
    if (isinstance(m, dict) and m.get("reason") == "compiler-artifact"
            and (m.get("profile") or {}).get("test") is True and m.get("executable")):
        exes.append(m["executable"])
names = [os.path.basename(e) for e in exes]
if not exes or len(set(names)) != len(names):
    sys.exit(f"block_test_exes: {len(exes)} test executables, names {names}: want at least one, each named once")
os.makedirs(dest)
with open(os.path.join(dest, "MANIFEST"), "w") as man:
    for e, n in zip(exes, names):
        shutil.copyfile(e, os.path.join(dest, n))
        os.chmod(os.path.join(dest, n), 0o755)
        with open(os.path.join(dest, n), "rb") as f:
            man.write(f"{hashlib.sha256(f.read()).hexdigest()}  {n}\n")
        print(f"block test executable: {n}")
' "$1" "$2"
}
# <<< block-test-exes
block_test_exes "$BLOCK_JSON_DIR/messages.json" "$BLOCK_TESTS" \
  || fail "could not collect block's test executables into $BLOCK_TESTS"

declare -A TIMES
for target in "${TARGETS[@]}"; do
  phase "cargo zigbuild $target"
  t0=$(date +%s)
  cargo zigbuild --release --locked --target "$target" \
    --bin cloud-hypervisor --no-default-features --features "$FEATURES"
  TIMES[$target]=$(( $(date +%s) - t0 ))
done

phase "smoke"
X86="target/x86_64-unknown-linux-musl/release/cloud-hypervisor"
ARM="target/aarch64-unknown-linux-musl/release/cloud-hypervisor"
# `--version` prints the name line, then "Migration Protocol Versions: ..."
# (measured, v53.0). The NAME LINE is the one that must match exactly; the
# rest is recorded in BUILDINFO.
version_out=$("$X86" --version) || fail "$X86 --version exited non-zero"
got=${version_out%%$'\n'*}
[ "$got" = "cloud-hypervisor $EXPECT" ] \
  || fail "x86_64 --version's first line is '$got', wanted exactly 'cloud-hypervisor $EXPECT'"
printf 'x86_64 --version:\n%s\n' "$version_out"
static_elf() { # <file> <file-machine-word> <readelf-machine>
  local f=$1 fm=$2 rm=$3 desc
  desc=$(file -b "$f")
  echo "file $f: $desc"
  [[ "$desc" == "ELF 64-bit LSB"* ]] || fail "$f is not a 64-bit little-endian ELF: $desc"
  [[ "$desc" == *"$fm"* ]]           || fail "$f is not $fm: $desc"
  [[ "$desc" == *"statically linked"* || "$desc" == *"static-pie linked"* ]] || fail "$f is not statically linked: $desc"
  readelf -h "$f" | grep -Eq "^ +Machine: +$rm\$" || fail "$f's ELF header machine is not $rm"
  ! readelf -lW "$f" | grep -q 'INTERP'            || fail "$f has a program interpreter"
  ! readelf -dW "$f" 2>/dev/null | grep -q '(NEEDED)' || fail "$f has NEEDED shared libraries"
}
static_elf "$X86" "x86-64" "Advanced Micro Devices X86-64"
static_elf "$ARM" "ARM aarch64" "AArch64"

phase "out"
mkdir -p "$OUT"
cp "$X86" "$OUT/cloud-hypervisor-static-x86_64"
cp "$ARM" "$OUT/cloud-hypervisor-static-aarch64"
cp "$NOTICES_DIR/THIRD-PARTY-NOTICES.txt" "$OUT/THIRD-PARTY-NOTICES.txt"
[ "$(sha256sum < "$OUT/THIRD-PARTY-NOTICES.txt" | cut -d' ' -f1)" = "$NOTICES_SHA256" ] \
  || fail "THIRD-PARTY-NOTICES.txt changed after it was written, during the build"
{
  echo "cloud-hypervisor-static $VERSION"
  echo "release: $IS_RELEASE"
  echo "fork: runcove/cloud-hypervisor"
  echo "fork sha: $HEAD_SHA"
  echo "ref: $REF"
  echo "run id: $RUN_ID"
  echo "version printed: $got"
  echo "--version, whole: $(printf '%s' "$version_out" | tr '\n' '|')"
  echo "build image: $BUILD_IMAGE"
  echo "zig: $(zig version) (pinned $ZIG_VERSION, sha256 $ZIG_SHA256)"
  echo "cargo-zigbuild: $CARGO_ZIGBUILD_VERSION (sha256 $CARGO_ZIGBUILD_SHA256)"
  echo "cargo-deny: $CARGO_DENY_VERSION (sha256 $CARGO_DENY_SHA256); advisories clean (blocking; yanked crates warn)"
  echo "cargo-about: $CARGO_ABOUT_VERSION (sha256 $CARGO_ABOUT_SHA256); THIRD-PARTY-NOTICES.txt written from it, describing $RUSTC_NAME and zig $(zig version)"
  echo "cargo: $(cargo -V)"
  echo "features: $FEATURES (no default features); profile: release, --locked"
  echo "RUSTFLAGS: $RUSTFLAGS"
  echo "SOURCE_DATE_EPOCH: ${SOURCE_DATE_EPOCH:-unset}"
  echo "zigbuild seconds: x86_64 ${TIMES[x86_64-unknown-linux-musl]} aarch64 ${TIMES[aarch64-unknown-linux-musl]}; whole script $(( $(date +%s) - T_START ))"
  echo "file x86_64: $(file -b "$OUT/cloud-hypervisor-static-x86_64")"
  echo "file aarch64: $(file -b "$OUT/cloud-hypervisor-static-aarch64")"
  echo "---- rustc -Vv ----"
  rustc -Vv
} > "$OUT/BUILDINFO"
( cd "$OUT" && sha256sum cloud-hypervisor-static-x86_64 cloud-hypervisor-static-aarch64 BUILDINFO \
    THIRD-PARTY-NOTICES.txt > SHA256SUMS )
ls -l "$OUT"
cat "$OUT/BUILDINFO" "$OUT/SHA256SUMS"
# LAST: the notices line SHA256SUMS ships is the digest taken when the file was
# written, before the fork's build scripts ran.
grep -qxF "$NOTICES_SHA256  THIRD-PARTY-NOTICES.txt" "$OUT/SHA256SUMS" \
  || fail "SHA256SUMS does not list THIRD-PARTY-NOTICES.txt with the digest it had when it was written ($NOTICES_SHA256)"
# ... and it is the ONLY line naming the file: a reader that takes the first
# line for a name and one that takes the last must find the same digest.
[ "$(grep -cF 'THIRD-PARTY-NOTICES.txt' "$OUT/SHA256SUMS")" = 1 ] \
  || fail "SHA256SUMS names THIRD-PARTY-NOTICES.txt on more than one line"
echo "build-static: OK $VERSION in $(( $(date +%s) - T_START ))s"
