#!/usr/bin/env bash
# Moves a branch forward to a tested commit: dev -> test, test -> main.
# Afterwards the target holds exactly the tested content. Nothing is ever
# force-pushed, and content the target has but the commit lacks (a commit made
# directly on test or main) is never overwritten. See docs/WORKFLOW.md.
#
# - Fast-forward when the target is part of the commit's history.
# - Nothing to do when the target already has exactly this content.
# - When the target only has extra merge commits that add nothing (e.g. a
#   "dev -> test" pull request merged by hand), a merge commit with the tested
#   content is added on top of it.
#
#   scripts/promote.sh <commit> <target-branch> [remote]
set -euo pipefail

commit="$1"
target="$2"
remote="${3:-origin}"

git fetch --quiet "$remote" "+refs/heads/$target:refs/remotes/$remote/$target"
current="$(git rev-parse "refs/remotes/$remote/$target")"
commit="$(git rev-parse "$commit^{commit}")"
tree="$(git rev-parse "$commit^{tree}")"

if [ "$(git rev-parse "$current^{tree}")" = "$tree" ]; then
    echo "$target already has the content of ${commit:0:7}"
    exit 0
fi

if git merge-base --is-ancestor "$current" "$commit"; then
    git push --quiet "$remote" "$commit:refs/heads/$target"
    echo "promoted $target: ${current:0:7} -> ${commit:0:7}"
    exit 0
fi

# Would merging the target into the commit change anything? If not, the target's
# extra commits carry no content and a merge with the tested tree is safe.
merged="$(git merge-tree --write-tree "$commit" "$current" 2>/dev/null || true)"
if [ "$(printf '%s\n' "$merged" | head -n1)" != "$tree" ]; then
    echo "::error::$target has changes that ${commit:0:7} does not contain; merge $target into dev first (never commit to test or main directly)." >&2
    exit 1
fi
export GIT_AUTHOR_NAME="${GIT_AUTHOR_NAME:-github-actions[bot]}"
export GIT_AUTHOR_EMAIL="${GIT_AUTHOR_EMAIL:-41898282+github-actions[bot]@users.noreply.github.com}"
export GIT_COMMITTER_NAME="${GIT_COMMITTER_NAME:-$GIT_AUTHOR_NAME}"
export GIT_COMMITTER_EMAIL="${GIT_COMMITTER_EMAIL:-$GIT_AUTHOR_EMAIL}"
promotion="$(git commit-tree "$tree" -p "$current" -p "$commit" \
    -m "Promote ${commit:0:7} to $target")"
git push --quiet "$remote" "$promotion:refs/heads/$target"
echo "promoted $target: ${current:0:7} -> ${promotion:0:7} (merge of ${commit:0:7}, tested content)"
