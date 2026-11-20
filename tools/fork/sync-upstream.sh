#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# The release fork's daily sync (FORK.md, .github/workflows/sync-upstream.yml): merges upstream's main into the fork's main and,
# when upstream has published a stable release the fork has not, picks the commit to release it from. Pushes nothing: the
# workflow checks the result and pushes it.
#
#   tools/fork/sync-upstream.sh <fork owner/name>
#
# Run in a clone whose HEAD is the fork's main, with remotes `origin` (the fork) and `upstream`. Leaves HEAD at the merged main.
# UPSTREAM_RELEASE: upstream's latest stable release tag; unset, it is read from the GitHub API (`gh`, UPSTREAM_REPO).
#
# The release commit is upstream's release with the fork's changes and nothing newer: the merge of the release's commit into the
# fork's main, made before upstream's later commits are merged. When an earlier sync already merged that commit, it is the merge
# that brought it in. Version numbers mirror upstream's; a tag the fork has already used for something else is never reused
# (published releases are immutable), so that release is skipped and the report says so.
#
# Output, as key=value lines to $GITHUB_OUTPUT (stdout when unset): head (the merged main), changed (true when head is new),
# release_tag and release_sha (empty when there is nothing to release). sync-report.md says what happened, for the run summary or an issue.
# Exit 0: done. 2: a merge conflicts (nothing changed; resolve by hand, FORK.md). 3: a guard failed (check-guards.sh).
set -euo pipefail

fork=${1:?usage: sync-upstream.sh <fork owner/name>}
here=$(cd "$(dirname "$0")" && pwd)
report=sync-report.md
: >"$report"
out() { if [ -n "${GITHUB_OUTPUT:-}" ]; then echo "$1" >>"$GITHUB_OUTPUT"; else echo "$1"; fi; }
say() { echo "$1" | tee -a "$report"; }

# a failed merge is undone with reset --hard: never in a tree with uncommitted work
if ! git diff --quiet HEAD; then
    echo "sync.dirty: commit or stash your changes first" >&2
    exit 1
fi
start=$(git rev-parse HEAD)
echo "sync.start head=$start fork=$fork"
git fetch --no-tags upstream main

# Merges $1 into HEAD; on a conflict aborts it, reports the files and exits 2.
merge() {
    if git merge --no-edit -m "Merge upstream $2" "$1"; then
        echo "sync.merge.ok what=$2 head=$(git rev-parse HEAD)"
        return
    fi
    local files
    files=$(git diff --name-only --diff-filter=U)
    git merge --abort
    git reset -q --hard "$start"
    echo "sync.merge.conflict what=$2"
    say "Merging upstream $2 into main conflicts in:"
    while IFS= read -r f; do say "- \`$f\`"; done <<<"$files"
    say ""
    say "Nothing was pushed. Resolve it by hand: \`git fetch upstream\`, \`git merge upstream/main\` on main, fix the files, run \`tools/fork/check-guards.sh HEAD $fork\`, push. The next sync carries on from there."
    exit 2
}

# Oldest commit on HEAD's first-parent line that contains $1: the merge that brought it in.
merged_in() {
    local prev="" c
    while read -r c; do
        git merge-base --is-ancestor "$1" "$c" || break
        prev=$c
    done < <(git rev-list --first-parent HEAD)
    echo "$prev"
}

# Upstream's latest stable release, and whether the fork releases it
tag=${UPSTREAM_RELEASE-$(gh api "repos/${UPSTREAM_REPO:?}/releases/latest" --jq .tag_name)}
release_sha=""
if ! [[ "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "sync.release.not_stable tag=$tag"
    tag=""
else
    git fetch --no-tags upstream "+refs/tags/$tag:refs/upstream-tags/$tag"
    commit=$(git rev-parse "refs/upstream-tags/$tag^{commit}")
    have=$(git ls-remote origin "refs/tags/$tag" "refs/tags/$tag^{}" | awk '{print $1}' | tail -1)
    if [ -n "$have" ]; then
        git fetch --no-tags origin "+refs/tags/$tag:refs/fork-tags/$tag"
        if git merge-base --is-ancestor "$commit" "refs/fork-tags/$tag"; then
            echo "sync.release.done tag=$tag"
        else
            echo "sync.release.tag_used tag=$tag fork_tag=$have"
            say "Upstream released $tag, but the fork already used $tag for another build, and a published release's tag is never reused. The fork skips $tag; its next release mirrors upstream's next version."
        fi
        tag=""
    elif git merge-base --is-ancestor "$commit" HEAD; then
        release_sha=$(merged_in "$commit")
        echo "sync.release.already_merged tag=$tag commit=$commit at=$release_sha"
    else
        merge "$commit" "$tag"
        release_sha=$(git rev-parse HEAD)
        echo "sync.release.merged tag=$tag at=$release_sha"
    fi
fi

merge upstream/main "main ($(git rev-parse --short upstream/main))"
head=$(git rev-parse HEAD)

for c in "$head" ${release_sha:+"$release_sha"}; do
    if ! "$here/check-guards.sh" "$c" "$fork" 2>guards.err; then
        cat guards.err
        say "A guard failed on $c after the merge: $(cat guards.err)"
        say ""
        say "Upstream changed something the fork's releases rely on (tools/fork/check-guards.sh). Nothing was pushed: bring the fork's change back by hand and push, or update the guard if the change is safe."
        rm -f guards.err
        git reset -q --hard "$start"
        exit 3
    fi
done
rm -f guards.err

if [ "$head" = "$start" ]; then say "Upstream had nothing new."; else say "Merged upstream main: $(git log --oneline "$start..$head" | wc -l | tr -d ' ') new commits."; fi
[ -n "$tag" ] && say "Releasing $tag from $release_sha."
out "head=$head"
if [ "$head" = "$start" ]; then out "changed=false"; else out "changed=true"; fi
out "release_tag=$tag"
out "release_sha=$release_sha"
