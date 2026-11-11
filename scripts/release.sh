#!/usr/bin/env bash
# release.sh: the release IS this script (playbook principle 6; checklist 03 is the spec).
#
#   scripts/release.sh X.Y.Z            # dry run: every check, no tag
#   scripts/release.sh X.Y.Z --tag      # same checks, then create + push the tag (LAST step)
#
# Sanctum has no version file: the tag IS the version. release.yml derives it from the
# tag and stamps it into the binary and image. So there is no bump step and no release
# commit. The CHANGELOG heading and docs are committed and pushed BEFORE this runs, and
# this script refuses to tag anything that is not exactly origin/main with green CI.
#
# Run it from a clean checkout on main. Needs: git, gh (logged in), go, bash.
set -euo pipefail

VERSION="${1:?usage: scripts/release.sh X.Y.Z [--tag]}"
MODE="${2:-}"
TAG="v${VERSION}"
REPO="herbiewalker/sanctum"

[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "ERROR: version must be X.Y.Z"; exit 1; }
[[ -z "$MODE" || "$MODE" == "--tag" ]] || { echo "ERROR: unknown option '$MODE'"; exit 2; }
cd "$(git rev-parse --show-toplevel)"

echo "== Preflight =="
[[ -z "$(git status --porcelain)" ]] || { echo "ERROR: working tree not clean"; exit 1; }
[[ "$(git rev-parse --abbrev-ref HEAD)" == "main" ]] || { echo "ERROR: not on main"; exit 1; }
git fetch --quiet --tags origin
git rev-parse -q --verify "refs/tags/${TAG}" >/dev/null && { echo "ERROR: ${TAG} already exists"; exit 1; }
HEAD_SHA="$(git rev-parse HEAD)"
[[ "$HEAD_SHA" == "$(git rev-parse origin/main)" ]] || { echo "ERROR: HEAD is not origin/main (push or pull first)"; exit 1; }
echo "ok: clean, on main, HEAD == origin/main (${HEAD_SHA:0:7}), ${TAG} unused"

echo "== Changelog =="
grep -qE "^## \[${VERSION}\] - [0-9]{4}-[0-9]{2}-[0-9]{2}" CHANGELOG.md \
  || { echo "ERROR: CHANGELOG.md has no dated '## [${VERSION}] - YYYY-MM-DD' heading"; exit 1; }
echo "ok: CHANGELOG has a dated [${VERSION}] heading"

echo "== Gates (lint, test, guards) =="
make check

echo "== Vulnerabilities =="
if command -v govulncheck >/dev/null 2>&1; then govulncheck ./...; else
  echo "WARN: govulncheck not installed; CI runs it, relying on that"; fi

echo "== CI is green on this exact commit =="
concl="$(gh run list --repo "$REPO" --branch main --commit "$HEAD_SHA" --workflow ci --limit 1 --json status,conclusion --jq '.[0] | "\(.status) \(.conclusion)"')"
[[ "$concl" == "completed success" ]] || { echo "ERROR: CI on ${HEAD_SHA:0:7} is '${concl:-none}', need 'completed success'"; exit 1; }
echo "ok: ci completed success"

if [[ "$MODE" != "--tag" ]]; then
  echo
  echo "DRY RUN OK: ${TAG} would be created at ${HEAD_SHA:0:7}. Re-run with --tag to publish."
  exit 0
fi

echo "== Tag (LAST) =="
git tag -a "${TAG}" -m "Release ${TAG}"
[[ "$(git rev-list -n1 "${TAG}")" == "$HEAD_SHA" ]] || { echo "ERROR: tag != HEAD"; git tag -d "${TAG}"; exit 1; }
echo "ok: ${TAG} -> ${HEAD_SHA:0:7}"
git push origin "${TAG}"

echo
echo "TAGGED ${TAG} at ${HEAD_SHA:0:7}. release.yml now gates, builds, scans and publishes."
echo "Watch it:  gh run watch --repo ${REPO}"
echo "Then:      pull the PUBLISHED image, smoke-test it, make the GHCR package public."
echo "Archive:   the image SBOM and provenance attestation are produced by the workflow."

# ⏣ HW ⏣ · code · tools · homelab · ⏣ HW ⏣
