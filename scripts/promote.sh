#!/usr/bin/env bash
# Moves a branch forward to a tested commit: dev -> test, test -> main.
# Only fast-forwards: the target must already be part of the commit's history,
# so nothing on the target is ever overwritten. See docs/WORKFLOW.md.
#
#   scripts/promote.sh <commit> <target-branch> [remote]
set -euo pipefail

commit="$1"
target="$2"
remote="${3:-origin}"

git fetch --quiet "$remote" "+refs/heads/$target:refs/remotes/$remote/$target"
current="$(git rev-parse "refs/remotes/$remote/$target")"
commit="$(git rev-parse "$commit^{commit}")"

if [ "$current" = "$commit" ]; then
    echo "$target is already at ${commit:0:7}"
    exit 0
fi
if ! git merge-base --is-ancestor "$current" "$commit"; then
    echo "::error::$target has commits that ${commit:0:7} does not contain; merge $target into dev first (never commit to test or main directly)." >&2
    exit 1
fi
git push --quiet "$remote" "$commit:refs/heads/$target"
echo "promoted $target: ${current:0:7} -> ${commit:0:7}"
