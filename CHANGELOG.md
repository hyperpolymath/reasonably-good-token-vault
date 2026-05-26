<!--
SPDX-License-Identifier: MPL-2.0
SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell (hyperpolymath)
-->

# Changelog

All notable changes to `reasonably-good-token-vault` will be documented in this file.

This file is generated from conventional commits by the
[`changelog-reusable.yml`](https://github.com/hyperpolymath/standards/blob/main/.github/workflows/changelog-reusable.yml)
workflow (`hyperpolymath/standards#206`). Adopt the workflow in this repo's CI to keep this file in sync automatically — see
[`templates/cliff.toml`](https://github.com/hyperpolymath/standards/blob/main/templates/cliff.toml)
for the canonical config.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
this project aims to follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- fix(rgtv-cli): migrate to ureq 3.x API (repairs main; unblocks #87, #88) (#89)
- fix(ci): bump a2ml/k9-validate-action pins to canonical (standards#85) (#68)
- fix(ci): sync hypatia-scan.yml to canonical (kill cd-scanner build drift) (#67)
- fix(ci): drop arbitrary score-threshold gate from scorecard-enforcer
- fix(ci): split scorecard score-check into a downstream job
- fix(rgtv-cli): collapse chained str::replace into single call
- fix(rgtv-cli): pin ureq to 2.x to match existing code
- fix(ci): only run trufflehog on pull_request events
- fix(ci): change CodeQL language matrix from javascript-typescript to rust
- fix(anchor): add TOML-style agent-id and SPDX header

### Documentation

- docs: record tech-debt audit findings (2026-05-26) (#92)

### CI

- ci(deps): bump actions/checkout from 4.1.1 to 6.0.2 (#85)
- ci(deps): bump github/codeql-action from 4.35.5 to 4.36.0 (#84)
- ci(deps): bump github/codeql-action from 4.32.6 to 4.35.5 (#71)
- ci(deps): bump actions/upload-artifact from 4.6.2 to 7.0.1 (#72)
- ci(deps): bump actions/github-script from 8.0.0 to 9.0.0 (#73)

## Pre-history

Prior commits to this file's introduction are recorded in git history but not formally classified into Keep-a-Changelog sections. To backfill, run `git cliff -o CHANGELOG.md` locally using the canonical [`cliff.toml`](https://github.com/hyperpolymath/standards/blob/main/templates/cliff.toml) — this is one-shot mechanical work.

---

<!-- This file was seeded by the 2026-05-26 estate tech-debt audit follow-up (Row-2 Phase 3); see [`hyperpolymath/standards/docs/audits/2026-05-26-estate-documentation-debt.md`](https://github.com/hyperpolymath/standards/blob/main/docs/audits/2026-05-26-estate-documentation-debt.md). -->
