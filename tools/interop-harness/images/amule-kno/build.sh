#!/usr/bin/env bash
# Build the kno/amule **Fork Pin** counterparty image (ADR-0092).
#
#   tools/interop-harness/images/amule-kno/build.sh                 # default variant
#   tools/interop-harness/images/amule-kno/build.sh --quic          # NAT-traversal variant
#   tools/interop-harness/images/amule-kno/build.sh --runtime-only  # reuse an existing compile-stage image
#   tools/interop-harness/images/amule-kno/build.sh --check-only    # verify the pin only, run no docker build
#
# Verifies the reference source sits at the pinned commit, then runs the two
# builds: the compile stage against the pinned source tree, and the runtime
# image against this directory.
#
# `--runtime-only` skips the compile stage and rebuilds only the runtime image
# against an already-built compile-stage image (`AMULE_KNO_BUILD_IMAGE`, or the
# default compile-stage tag). Setting `AMULE_KNO_BUILD_IMAGE` implies it. A fresh git
# worktree does not carry the vendored source tree at
# `docs/reference/amule-kno/amule` (it is git-ignored), so a rebuild there reuses a
# compile-stage image built once on the host instead of recompiling.
#
# The pin is still verified even in `--runtime-only` mode: when the in-tree
# source is absent, the check falls back to `AMULE_KNO_SRC`, a pinned clone
# elsewhere on the host (e.g. the main checkout's, when building from a worktree). The
# clone must be clean, and in `--runtime-only` mode the reused compile image
# must carry the `org.rmule.amule_kno.commit` / `.quic` labels this script's
# compile build stamps, matching the verified pin and variant; a compile image
# built before those labels existed is refused and must be rebuilt once.
#
# The pin is checked HERE and not inside the Dockerfile because the build context
# is a checkout whose `.git` the context may not carry. The verified SHA and the
# upstream base ride in as build args and land on the image as
# `org.rmule.amule_kno.*` labels, so `docker inspect` can always name the source
# a captured row came from — the **Fork Pin** discipline of ADR-0045 as amended.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)"
IMAGE_DIR="$REPO_ROOT/tools/interop-harness/images/amule-kno"
IN_TREE_SOURCE_DIR="$REPO_ROOT/docs/reference/amule-kno/amule"
# Worktrees do not carry the vendored source tree; AMULE_KNO_SRC points the pin
# check at a pinned clone elsewhere instead.
FALLBACK_SOURCE_DIR="${AMULE_KNO_SRC:-$IN_TREE_SOURCE_DIR}"
META="$REPO_ROOT/docs/reference/amule-kno/amule-kno.meta.toml"

ENABLE_QUIC=NO
RUNTIME_ONLY=NO
CHECK_ONLY=NO

for arg in "$@"; do
  case "$arg" in
    --quic) ENABLE_QUIC=YES ;;
    --runtime-only) RUNTIME_ONLY=YES ;;
    --check-only) CHECK_ONLY=YES ;;
    *)
      echo "usage: $0 [--quic] [--runtime-only] [--check-only]" >&2
      exit 1
      ;;
  esac
done

BUILD_TAG_DEFAULT="rmule/interop-amule-kno-build:local"
RUNTIME_TAG_DEFAULT="rmule/interop-amule-kno:local"
if [[ "$ENABLE_QUIC" == YES ]]; then
  BUILD_TAG_DEFAULT="rmule/interop-amule-kno-build:quic"
  RUNTIME_TAG_DEFAULT="rmule/interop-amule-kno:quic"
fi

# AMULE_KNO_BUILD_IMAGE names an existing compile-stage image to reuse instead
# of compiling one; setting it is enough to select --runtime-only on its own.
if [[ -n "${AMULE_KNO_BUILD_IMAGE:-}" ]]; then
  RUNTIME_ONLY=YES
  BUILD_TAG="$AMULE_KNO_BUILD_IMAGE"
else
  BUILD_TAG="${AMULE_KNO_BUILD_TAG:-$BUILD_TAG_DEFAULT}"
fi
RUNTIME_TAG="${AMULE_KNO_RUNTIME_TAG:-$RUNTIME_TAG_DEFAULT}"

# The pin of record lives in the reference sidecar; read it rather than restating
# it, so there is one place to change when ADR-0092 re-pins.
PINNED_COMMIT="$(sed -nE 's/^commit[[:space:]]*=[[:space:]]*"([0-9a-f]+)".*/\1/p' "$META" | head -1)"
if [[ -z "$PINNED_COMMIT" ]]; then
  echo "could not read the pinned commit from $META" >&2
  exit 1
fi
UPSTREAM_BASE="$(sed -nE 's/.*merge-base `([0-9a-f]{40})`.*/\1/p' "$META" | head -1)"
UPSTREAM_BASE="${UPSTREAM_BASE:-unknown}"

SOURCE_DIR="$IN_TREE_SOURCE_DIR"
if [[ ! -d "$SOURCE_DIR/.git" ]]; then
  SOURCE_DIR="$FALLBACK_SOURCE_DIR"
fi
if [[ ! -d "$SOURCE_DIR/.git" ]]; then
  echo "reference cache missing at both $IN_TREE_SOURCE_DIR and $FALLBACK_SOURCE_DIR" >&2
  echo "clone the source_url of $META into $IN_TREE_SOURCE_DIR and check out $PINNED_COMMIT" >&2
  echo "(docs/reference/README.md, Filling the cache), or point AMULE_KNO_SRC at an existing clone" >&2
  exit 1
fi

HEAD_COMMIT="$(git -C "$SOURCE_DIR" rev-parse HEAD)"
if [[ "$HEAD_COMMIT" != "$PINNED_COMMIT" ]]; then
  echo "reference cache at $SOURCE_DIR is at $HEAD_COMMIT, expected $PINNED_COMMIT" >&2
  echo "run: git -C $SOURCE_DIR fetch && git -C $SOURCE_DIR checkout $PINNED_COMMIT" >&2
  echo "or point AMULE_KNO_SRC elsewhere" >&2
  exit 1
fi
# A dirty clone would build modified bytes under the pin's label.
if [[ -n "$(git -C "$SOURCE_DIR" status --porcelain)" ]]; then
  echo "reference cache at $SOURCE_DIR has local changes; the Fork Pin names the commit's bytes only" >&2
  exit 1
fi
echo "kno/amule pin verified: $HEAD_COMMIT (source $SOURCE_DIR, upstream base $UPSTREAM_BASE, quic=$ENABLE_QUIC, runtime-only=$RUNTIME_ONLY)"

if [[ "$CHECK_ONLY" == YES ]]; then
  echo "check-only: pin verified, no docker build run"
  exit 0
fi

if [[ "$RUNTIME_ONLY" == YES ]]; then
  if ! docker image inspect "$BUILD_TAG" >/dev/null 2>&1; then
    echo "--runtime-only needs an existing compile-stage image at $BUILD_TAG" >&2
    echo "build it first without --runtime-only, or set AMULE_KNO_BUILD_IMAGE to one that already exists" >&2
    exit 1
  fi
  # The runtime image stamps the verified commit, so the compile image it
  # copies from must have been built from that same commit and variant.
  label() {
    docker image inspect -f "{{ index .Config.Labels \"$1\" }}" "$BUILD_TAG"
  }
  BUILT_COMMIT="$(label org.rmule.amule_kno.commit)"
  BUILT_QUIC="$(label org.rmule.amule_kno.quic)"
  if [[ "$BUILT_COMMIT" != "$HEAD_COMMIT" || "$BUILT_QUIC" != "$ENABLE_QUIC" ]]; then
    echo "compile-stage image $BUILD_TAG was built from commit '$BUILT_COMMIT' quic='$BUILT_QUIC'," >&2
    echo "expected $HEAD_COMMIT quic=$ENABLE_QUIC; rebuild it without --runtime-only" >&2
    exit 1
  fi
else
  docker build \
    --build-arg "ENABLE_QUIC=$ENABLE_QUIC" \
    --label "org.rmule.amule_kno.commit=$HEAD_COMMIT" \
    --label "org.rmule.amule_kno.quic=$ENABLE_QUIC" \
    -t "$BUILD_TAG" \
    -f "$IMAGE_DIR/Dockerfile.build" \
    "$SOURCE_DIR"
fi

# The runtime stage's context is `images/`, not this directory: it lifts the
# stock `amule` image's scenario entrypoint beside its own (see Dockerfile).
docker build \
  -f "$IMAGE_DIR/Dockerfile" \
  --build-arg "AMULE_KNO_BUILD_IMAGE=$BUILD_TAG" \
  --build-arg "AMULE_KNO_COMMIT=$HEAD_COMMIT" \
  --build-arg "AMULE_KNO_UPSTREAM_BASE=$UPSTREAM_BASE" \
  --build-arg "ENABLE_QUIC=$ENABLE_QUIC" \
  -t "$RUNTIME_TAG" \
  "$IMAGE_DIR/.."

echo "built $RUNTIME_TAG from $HEAD_COMMIT (quic=$ENABLE_QUIC, runtime-only=$RUNTIME_ONLY)"
