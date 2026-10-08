#!/usr/bin/env bash
# Tag a release and let .github/workflows/release.yml build and publish it.
# Usage: scripts/tag-release.sh v0.1.0-rc1 [commit]   (default: origin/main)
# Idempotent: an existing identical tag is left alone; a different one is refused.
set -euo pipefail
tag=${1:?usage: tag-release.sh vX.Y.Z[-rcN] [commit]}
[[ "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$ ]] || { echo "refusing: $tag is not vX.Y.Z[-suffix]"; exit 2; }
git fetch -q origin
commit=$(git rev-parse "${2:-origin/main}")
if git rev-parse -q --verify "refs/tags/$tag" >/dev/null; then
  have=$(git rev-parse "$tag^{commit}")
  [[ "$have" == "$commit" ]] || { echo "refusing: $tag already points at $have, not $commit"; exit 2; }
  echo "tag $tag already exists locally at $commit"
else
  git tag -a "$tag" "$commit" -m "Directory Auditor $tag"
fi
echo "pushing $tag ($commit) — the release workflow builds and publishes it"
git push origin "refs/tags/$tag"
echo "watch: https://github.com/atsvetko/directory-auditor/actions/workflows/release.yml"
