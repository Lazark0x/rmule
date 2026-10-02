#!/usr/bin/env bash
# Build the emulecored counterparty image (ADR-0082 Stimulus Counterparty).
#
#   tools/interop-harness/images/emuleqt/build.sh
#
# Verifies the reference cache is at the pinned commit, then runs the two
# builds: the compile stage against the pinned source tree, and the runtime
# image against this directory.
#
# The pin is checked HERE and not inside the Dockerfile because the upstream
# tree ships its own .dockerignore excluding `.git/`, so the build context is a
# checkout with no repository attached. The verified SHA is passed in and lands
# on the image as `org.rmule.emuleqt.commit`.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)"
IMAGE_DIR="$REPO_ROOT/tools/interop-harness/images/emuleqt"
SOURCE_DIR="$REPO_ROOT/docs/reference/emule-qt/emule-qt"

# The pin of record lives in the reference sidecar; read it rather than
# restating it, so there is one place to change when ADR-0082 re-pins.
META="$REPO_ROOT/docs/reference/emule-qt/emule-qt.meta.toml"
PINNED_COMMIT="$(sed -nE 's/^commit[[:space:]]*=[[:space:]]*"([0-9a-f]+)".*/\1/p' "$META" | head -1)"
if [[ -z "$PINNED_COMMIT" ]]; then
  echo "could not read the pinned commit from $META" >&2
  exit 1
fi

if [[ ! -d "$SOURCE_DIR/.git" ]]; then
  echo "reference cache missing at $SOURCE_DIR" >&2
  echo "clone the source_url of $META into $SOURCE_DIR and check out $PINNED_COMMIT" >&2
  echo "(docs/reference/README.md, Filling the cache)" >&2
  exit 1
fi

HEAD_COMMIT="$(git -C "$SOURCE_DIR" rev-parse HEAD)"
if [[ "$HEAD_COMMIT" != "$PINNED_COMMIT" ]]; then
  echo "reference cache is at $HEAD_COMMIT, expected $PINNED_COMMIT" >&2
  echo "run: git -C $SOURCE_DIR fetch && git -C $SOURCE_DIR checkout $PINNED_COMMIT" >&2
  exit 1
fi
# A dirty clone would build modified bytes under the pin's label.
if [[ -n "$(git -C "$SOURCE_DIR" status --porcelain)" ]]; then
  echo "reference cache at $SOURCE_DIR has local changes; the pin names the commit's bytes only" >&2
  exit 1
fi
echo "emule-qt pin verified: $HEAD_COMMIT"

BUILD_TAG="${EMULEQT_BUILD_TAG:-rmule/interop-emuleqt-build:local}"
RUNTIME_TAG="${EMULEQT_RUNTIME_TAG:-rmule/interop-emuleqt:local}"

docker build \
  --build-arg "EMULEQT_COMMIT=$HEAD_COMMIT" \
  -t "$BUILD_TAG" \
  -f "$IMAGE_DIR/Dockerfile.build" \
  "$SOURCE_DIR"

docker build \
  --build-arg "EMULEQT_BUILD_IMAGE=$BUILD_TAG" \
  -t "$RUNTIME_TAG" \
  "$IMAGE_DIR"

echo "built $RUNTIME_TAG from $HEAD_COMMIT"
