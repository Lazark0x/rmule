#!/usr/bin/env bash
# Build the ed2ksrv coordinator image from a clone verified at the pin of record.
#
#   tools/interop-harness/images/ed2ksrv/build.sh /path/to/ed2k-server
#   ED2KSRV_SRC=/path/to/ed2k-server tools/interop-harness/images/ed2ksrv/build.sh
#   tools/interop-harness/images/ed2ksrv/build.sh --check-only /path/to/ed2k-server
#
# The pin lives in `pin.env` beside this script and nowhere else. The clone must
# sit at that exact commit with a clean tree: a dirty checkout would build
# modified bytes under the pin's name. The verified commit rides onto the image
# as `org.rmule.ed2ksrv.commit` / `.version` labels, which the harness reads back
# before it starts the image: a mismatch is refused unless the run sets
# RMULE_BENCH_ED2KSRV_OFF_PIN=1 (ADR-0045 as amended 2026-09-16, point 1).
set -euo pipefail

IMAGE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=pin.env
source "$IMAGE_DIR/pin.env"
TAG="${ED2KSRV_TAG:-rmule/interop-ed2ksrv:local}"

CHECK_ONLY=NO
SOURCE_DIR="${ED2KSRV_SRC:-}"
for arg in "$@"; do
  case "$arg" in
    --check-only) CHECK_ONLY=YES ;;
    -*)
      echo "usage: $0 [--check-only] [SOURCE_DIR]" >&2
      exit 1
      ;;
    *) SOURCE_DIR="$arg" ;;
  esac
done
if [[ -z "$SOURCE_DIR" || ! -d "$SOURCE_DIR/.git" ]]; then
  echo "need a git clone of $ED2KSRV_REPO (argument or ED2KSRV_SRC); got '${SOURCE_DIR}'" >&2
  exit 1
fi

HEAD_COMMIT="$(git -C "$SOURCE_DIR" rev-parse HEAD)"
if [[ "$HEAD_COMMIT" != "$ED2KSRV_COMMIT" ]]; then
  echo "clone at $SOURCE_DIR is at $HEAD_COMMIT, expected $ED2KSRV_COMMIT ($ED2KSRV_VERSION)" >&2
  exit 1
fi
if [[ -n "$(git -C "$SOURCE_DIR" status --porcelain)" ]]; then
  echo "clone at $SOURCE_DIR has local changes; the pin names upstream's bytes only" >&2
  exit 1
fi
echo "ed2ksrv pin verified: $HEAD_COMMIT ($ED2KSRV_VERSION, source $SOURCE_DIR)"

if [[ "$CHECK_ONLY" == YES ]]; then
  echo "check-only: pin verified, no docker build run"
  exit 0
fi

docker build \
  --label "org.rmule.ed2ksrv.repo=$ED2KSRV_REPO" \
  --label "org.rmule.ed2ksrv.commit=$HEAD_COMMIT" \
  --label "org.rmule.ed2ksrv.version=$ED2KSRV_VERSION" \
  -t "$TAG" \
  -f "$IMAGE_DIR/Dockerfile" \
  "$SOURCE_DIR"
