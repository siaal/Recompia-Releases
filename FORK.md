# The release fork

This repository is a release fork of [Dittobyte/Recompia](https://github.com/Dittobyte/Recompia). It follows upstream's code and adds no
gameplay changes. It exists so that its releases can be trusted without trusting anyone's machine or any earlier download.

## What is different from upstream

- **Built from scratch.** Every package is built by GitHub Actions from this repository. The Windows package no longer starts
  from the previous release's zip: its third-party tools (Zig, Python with the lz4 and capstone wheels, FSR 3, Streamline) are
  downloaded from their own projects by `game-build/scripts/fetch-windows-tools.ps1` and checked against pinned SHA-256s, and the
  astcdec DLLs, font and keyboard/mouse icons come from this build, as on Linux and macOS.
- **Attested.** Every archive has a build provenance attestation from `.github/workflows/release.yml`. Check one with
  `gh attestation verify <archive> -R <this repository> --signer-workflow <this repository>/.github/workflows/release.yml`.
- **Immutable.** A release is created as a draft and published only once every archive is attached. Published releases are
  immutable (repository setting): their files and tag can never be replaced. A fix ships as a new version.
- **A launcher that checks.** The launcher updates from this fork (`launcher/src-tauri/src/releases.rs`, `REPO`) and installs an
  update only when the release is immutable and its attestation verifies in the launcher itself (`attest.rs`): built by this
  repository's release workflow on a GitHub-hosted runner, from the commit the release's tag names.

`CHANGELOG.md` is upstream's, unchanged, so that merging it never conflicts; the fork's own changes are described here.

## Following upstream

`.github/workflows/sync-upstream.yml` runs every day (and from the Actions tab):

1. `tools/fork/sync-upstream.sh` merges upstream's `main` into `main`.
2. If upstream has published a stable release the fork has not, the fork releases **the same version** from upstream's release
   commit merged into the fork, with nothing newer from upstream.
3. `tools/fork/check-guards.sh` checks the merge still keeps every point above (no base release, pinned tool downloads only,
   drafts, the pinned attestation action, the launcher's repository and its check). A merge without conflicts can still undo one.
4. The launcher and recompiler checks run on the merge (branch `upstream-sync`). Only when they pass is `main` pushed and the
   release tag pushed; the tag runs `release.yml`.

When something needs a person, nothing is pushed and the run opens (or comments on) the issue **Upstream sync needs a hand**:

- **A merge conflict.** On `main`: `git fetch upstream`, `git merge upstream/main`, resolve, `tools/fork/check-guards.sh HEAD
  <this repository>`, push. The next sync carries on from there. A release whose commit was merged by hand is released from that
  merge.
- **A guard failed.** Upstream changed something the fork relies on. Bring the fork's change back by hand, or, if upstream's change
  is safe, update the guard.
- **A version the fork already used.** Published tags are never reused, so that upstream release is skipped and the fork's next
  release mirrors upstream's next version. Today this is `v0.15.3`, which the fork used for its first build.

Only stable releases are mirrored; upstream's Testing prereleases are not.

`tools/fork/test-sync.sh` tests the sync and the guards against throwaway repositories made from this clone (no network).

## Setup

1. Actions enabled, and Issues enabled (for the sync's reports).
2. Settings > General > Releases: **immutable releases** on, before any release. The launcher refuses releases without it.
3. The secret `SYNC_TOKEN`: a fine-grained personal access token for this repository only, with **Contents** and **Workflows**
   read and write. The workflow's own token can neither push upstream's workflow changes nor start `release.yml` with a tag.
4. A git remote for upstream in your clone: `git remote add upstream https://github.com/Dittobyte/Recompia`.
