#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Tests sync-upstream.sh and check-guards.sh against throwaway repositories made from this clone's history (no network): a fork
# remote whose main is <fork commit>, an upstream remote whose main is <upstream commit>, both forked at their merge base.
#
#   tools/fork/test-sync.sh [fork commit (HEAD)] [upstream commit (upstream/main)]
#
# The fork commit must hold the fork's changes (the guards pass on it) and merge cleanly with the upstream commit.
set -euo pipefail

repo=$(git rev-parse --show-toplevel)
fork_sha=$(git -C "$repo" rev-parse "${1:-HEAD}^{commit}")
up_sha=$(git -C "$repo" rev-parse "${2:-upstream/main}^{commit}")
base=$(git -C "$repo" merge-base "$fork_sha" "$up_sha")
fork=test-owner/Recompia-Releases
t=$(mktemp -d)
trap 'rm -rf "$t"' EXIT
export GIT_AUTHOR_NAME=sync-test GIT_AUTHOR_EMAIL=sync-test@example.invalid GIT_COMMITTER_NAME=sync-test GIT_COMMITTER_EMAIL=sync-test@example.invalid
export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1   # no signing, hooks or aliases from the user's config

check() {
    if [ "$1" = "$2" ]; then echo "ok: $3"; else echo "FAIL: $3: got '$1', want '$2'"; cat "$t/log" 2>/dev/null; exit 1; fi
}
has() {
    if grep -q "$1" <<<"$2"; then echo "ok: $3"; else echo "FAIL: $3: no '$1' in: $2"; exit 1; fi
}
is_ancestor() { git -C "$t/w" merge-base --is-ancestor "$1" "$2" && echo yes || echo no; }

git init -q --bare --initial-branch=main "$t/up.git"
git init -q --bare --initial-branch=main "$t/fork.git"
# the fork's releases.rs must name the fork the guards are run for
grep -q '^pub const REPO: &str = "' <<<"$(git -C "$repo" show "$fork_sha:launcher/src-tauri/src/releases.rs")" || { echo "FAIL: no REPO in releases.rs"; exit 1; }

# Resets both remotes: upstream main = $up_sha (v0.15.2 at the base), fork main = $fork_sha with REPO set to $fork (one commit on
# top), fork tags v0.15.2 = upstream's, v0.15.3 = the fork's own build. Leaves a clone of the fork in $t/w at main.
fresh() {
    rm -rf "$t/w" "$t/u"
    git -C "$repo" push -q -f "$t/up.git" "$up_sha:refs/heads/main" "$base:refs/tags/v0.15.2"
    for r in v0.15.3 v0.15.4 v0.15.5; do git -C "$t/up.git" tag -d "$r" >/dev/null 2>&1 || true; done
    git -C "$repo" push -q -f "$t/fork.git" "$fork_sha:refs/heads/main" "$base:refs/tags/v0.15.2"
    git clone -q "$t/fork.git" "$t/w"
    sed -i.bak -E "s#^pub const REPO: &str = \"[^\"]+\"#pub const REPO: \\&str = \"$fork\"#" "$t/w/launcher/src-tauri/src/releases.rs"
    rm "$t/w/launcher/src-tauri/src/releases.rs.bak"
    git -C "$t/w" commit -q -am "fork: test owner"
    git -C "$t/w" push -q -f origin main
    git -C "$t/w" push -q -f origin main:refs/tags/v0.15.3
    git -C "$t/w" remote add upstream "$t/up.git"
    start=$(git -C "$t/w" rev-parse HEAD)
    git clone -q "$t/up.git" "$t/u"
}

# Commits a change to upstream main: upcommit <message> <command run in the upstream clone>
upcommit() {
    (cd "$t/u" && eval "$2" && git commit -q -am "$1" && git push -q origin HEAD:main)
}

# Runs the sync with upstream's latest release $1; sets rc, head, release_tag, release_sha, report.
run() {
    : >"$t/out"
    rc=0
    (cd "$t/w" && GITHUB_OUTPUT="$t/out" UPSTREAM_RELEASE="$1" "$repo/tools/fork/sync-upstream.sh" "$fork") >"$t/log" 2>&1 || rc=$?
    head=$(sed -n 's/^head=//p' "$t/out"); release_tag=$(sed -n 's/^release_tag=//p' "$t/out"); release_sha=$(sed -n 's/^release_sha=//p' "$t/out")
    report=$(cat "$t/w/sync-report.md" 2>/dev/null || true)
}

echo "== upstream has no new release"
fresh
run v0.15.2
check "$rc" 0 "exit"
check "$release_tag" "" "nothing to release: the fork's v0.15.2 is upstream's"
check "$(is_ancestor "$up_sha" "$head")" yes "upstream main merged"
check "$(git -C "$t/w" rev-parse "$head^1")" "$start" "the merge is on the fork's main"

echo "== upstream released a commit before its main"
fresh
up_parent=$(git -C "$repo" rev-parse "$up_sha^1")
git -C "$t/u" push -q origin "$up_parent:refs/tags/v0.15.4"
run v0.15.4
check "$rc" 0 "exit"
check "$release_tag" v0.15.4 "the release is mirrored"
check "$(git -C "$t/w" rev-parse "$release_sha^1") $(git -C "$t/w" rev-parse "$release_sha^2")" "$start $up_parent" "released from the release commit merged into the fork, nothing newer"
check "$(is_ancestor "$release_sha" "$head") $(is_ancestor "$up_sha" "$head")" "yes yes" "main then has the rest of upstream"

echo "== an earlier sync already merged the release's commit"
fresh
run v0.15.2
first=$head
git -C "$t/w" push -q origin HEAD:main
upcommit "upstream: later work" "echo later >> README.md"
git -C "$t/u" push -q origin "$up_sha:refs/tags/v0.15.5"
run v0.15.5
check "$rc" 0 "exit"
check "$release_tag $release_sha" "v0.15.5 $first" "released from the merge that brought the commit in"

echo "== upstream's release uses a tag the fork already used"
fresh
git -C "$t/u" push -q origin "$up_sha:refs/tags/v0.15.3"
run v0.15.3
check "$rc" 0 "exit"
check "$release_tag" "" "the used tag is never released again"
has "already used v0.15.3" "$report" "the report says so"

echo "== a prerelease is not mirrored"
fresh
run v0.16.0-beta.1
check "$rc $release_tag" "0 " "prerelease skipped"

echo "== a conflict changes nothing"
fresh
upcommit "upstream: another updater repository" "sed -i.bak -E 's#^(pub )?const REPO: &str = \"[^\"]+\"#const REPO: \\&str = \"someone/else\"#' launcher/src-tauri/src/releases.rs && rm launcher/src-tauri/src/releases.rs.bak"
run v0.15.2
check "$rc" 2 "exit"
check "$(git -C "$t/w" rev-parse HEAD)" "$start" "main is where it was"
check "$(git -C "$t/w" status --porcelain --untracked-files=no)" "" "no merge left half done"
has "launcher/src-tauri/src/releases.rs" "$report" "the report names the file"

echo "== a clean merge that brings back a base release is refused"
fresh
upcommit "upstream: base package" "sed -i.bak '1a\\
# base: gh release download v0.8.2 -R Dittobyte/Recompia
' .github/workflows/release.yml && rm .github/workflows/release.yml.bak"
run v0.15.2
check "$rc" 3 "exit"
check "$(git -C "$t/w" rev-parse HEAD)" "$start" "main is where it was"
has "names upstream or a base release" "$report" "the report names the guard"

echo "== an unknown release download is refused"
fresh
upcommit "upstream: new download" "sed -i.bak '1a\\
# gh release download v1 -R someone/thing
' .github/workflows/release.yml && rm .github/workflows/release.yml.bak"
run v0.15.2
check "$rc" 3 "exit"

echo "== uncommitted work is never touched"
fresh
echo dirty >>"$t/w/README.md"
run v0.15.2
check "$rc" 1 "refused"
has dirty "$(cat "$t/w/README.md")" "the change is still there"

echo "all sync tests passed"
