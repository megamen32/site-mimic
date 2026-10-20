#!/usr/bin/env bash
# Print JA3/JA4 for a capture produced by tools/mac/capture.sh.
#
# The fingerprints come from the repository's own parser (cmd/hellofp ->
# mimic.ParseClientHello), so the numbers are the ones a server would compute
# -- not a third-party implementation's.
#
# Usage:
#   tools/mac/measure.sh <capture.jsonl> [more.jsonl ...]
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/../.." && pwd)"

[ $# -ge 1 ] || {
  echo "usage: $(basename "$0") <capture.jsonl> [more.jsonl ...]" >&2
  exit 2
}

cd "$REPO_ROOT"
exec go run ./cmd/hellofp "$@"
