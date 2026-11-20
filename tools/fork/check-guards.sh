#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# The release fork's guards (FORK.md): checks that a commit still builds releases the way the fork promises, so that a merge from
# upstream, even one without conflicts, cannot quietly undo it. Fails on the first broken guard, with what to look at.
#
#   tools/fork/check-guards.sh <commit> <fork owner/name>
#
# Guards:
# - release.yml downloads no earlier release of this project (no base package); `gh release download` only from ALLOWED_DOWNLOADS
# - release.yml fetches the Windows tools with fetch-windows-tools.ps1, and make-release.ps1 takes no base package
# - release.yml creates releases as drafts and attests them with attest-build-provenance at the commit the launcher was checked with
# - the launcher updates from the fork (releases.rs REPO) and verifies the attestation before installing (update.rs, attest.rs)
set -euo pipefail

rev=${1:?usage: check-guards.sh <commit> <fork owner/name>}
fork=${2:?usage: check-guards.sh <commit> <fork owner/name>}
# third-party projects release.yml may download release assets from (checked by SHA-256 in the workflow)
ALLOWED_DOWNLOADS=("libsdl-org/SDL" "facebook/zstd")
ATTEST_PIN="actions/attest-build-provenance@4d101475d8b20a2381f78447822ac1eab6504dd8"

fail() {
    echo "guards.fail $rev: $1" >&2
    exit 1
}
file() {
    git show "$rev:$1" 2>/dev/null || fail "$1 is missing"
}

wf=$(file .github/workflows/release.yml)
mr=$(file game-build/scripts/make-release.ps1)
rel=$(file launcher/src-tauri/src/releases.rs)
upd=$(file launcher/src-tauri/src/update.rs)
att=$(file launcher/src-tauri/src/attest.rs)
file game-build/scripts/fetch-windows-tools.ps1 >/dev/null

# no earlier release of this project as a base
if grep -niE 'dittobyte|featurejosh|BASE_RELEASE|BASE_REPO' <<<"$wf"; then
    fail "release.yml names upstream or a base release (lines above): the fork's packages are built from scratch"
fi
while IFS= read -r line; do
    repo=$(grep -oE '(-R|--repo)[ =]+[^ ]+' <<<"$line" | head -1 | sed -E 's/^(-R|--repo)[ =]+//' || true)
    ok=false
    for a in "${ALLOWED_DOWNLOADS[@]}"; do [ "$repo" = "$a" ] && ok=true; done
    if [ "$ok" != true ]; then
        echo "$line" >&2
        fail "release.yml downloads a release from '${repo:-this repository}': only ${ALLOWED_DOWNLOADS[*]} are allowed (check-guards.sh ALLOWED_DOWNLOADS)"
    fi
done < <(grep -E 'gh release download' <<<"$wf" || true)
grep -q 'fetch-windows-tools.ps1' <<<"$wf" || fail "release.yml no longer fetches the Windows tools with fetch-windows-tools.ps1"
grep -qE '[$]Base\b|-Base\b' <<<"$mr$wf" && fail "make-release.ps1 or release.yml takes a base package (-Base) again"

# drafts until complete, and attested with the action the launcher's verifier was checked against
grep -qE 'gh release create .*--draft' <<<"$wf" || fail "release.yml no longer creates the release as a draft"
grep -qF "$ATTEST_PIN" <<<"$wf" || fail "release.yml no longer attests with $ATTEST_PIN"

# the launcher: the fork's releases, verified
repo=$(grep -oE '^pub const REPO: &str = "[^"]+"' <<<"$rel" | sed -E 's/.*"([^"]+)"/\1/' || true)
lower() { tr '[:upper:]' '[:lower:]' <<<"$1"; }
[ "$(lower "$repo")" = "$(lower "$fork")" ] || fail "the launcher updates from '${repo:-?}' (releases.rs REPO), not the fork $fork"
grep -qF 'verify_origin(t, &want' <<<"$upd" || fail "update.rs no longer verifies the release before downloading it"
grep -qF 'pub fn verify_release' <<<"$att" || fail "attest.rs no longer has verify_release"

echo "guards.ok $rev"
