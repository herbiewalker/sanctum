#!/usr/bin/env bash
# sanctum-update.sh — host-side updater for Sanctum (ADR D-19).
#
# Runs on the Unraid HOST as a User Script. The Sanctum container never
# reaches out to GitHub and never gets a docker socket (hard constraint 6):
# this script is the only thing that talks to the network, mirroring how
# sanctum-notify-dispatch.sh is the only thing that talks to Unraid (D-18).
#
# What it does:
#   1. git fetch --tags from the repo clone (read-only deploy key).
#   2. Finds the newest stable release tag (vMAJOR.MINOR.PATCH, no prerelease).
#   3. Refuses anything that is not a fast-forward from what is deployed.
#   4. --check  (default): drops a notification intent "update available".
#      --apply           : checks out the tag, validates the compose config,
#                          rebuilds, waits for the container to go healthy,
#                          and ROLLS BACK to the previous commit if it doesn't.
#
# SECURITY (D08): --apply builds the fetched tag as the host user, so it refuses
# any tag whose signature does not verify (SANCTUM_UPDATE_REQUIRE_SIGNED, default 1).
#
# SECURITY (D08): --apply builds the fetched tag as the host user, so it refuses
# any tag whose signature does not verify (SANCTUM_UPDATE_REQUIRE_SIGNED, default 1).
#
# IMPORTANT: restarting the container RE-LOCKS the vault (D-4). After an apply
# a human must unlock it. --apply therefore never runs on a schedule unless
# you opt in with SANCTUM_UPDATE_AUTO_APPLY=1, and the "updated" notification
# says plainly that the vault is locked.
#
# Install as a User Script:  Name sanctum-update   Schedule 0 4 * * *
# Manual:   sanctum-update.sh --check | --apply | --dry-run | --status
#
# Exit codes: 0 ok / nothing to do, 1 failure (rolled back if apply), 2 usage.

set -euo pipefail

REPO="${SANCTUM_REPO:-/mnt/user/appdata/sanctum/repo}"
STACK_DIR="${SANCTUM_STACK_DIR:-/boot/config/plugins/compose.manager/projects/sanctum}"
ENV_FILE="${SANCTUM_ENV_FILE:-${STACK_DIR}/.env}"
# repo = build/run from the repo's own docker-compose.yml (no drift from the
# stale copy Compose Manager keeps); stack = use Compose Manager's copy.
COMPOSE_SOURCE="${SANCTUM_UPDATE_COMPOSE_SOURCE:-repo}"
PROJECT="${SANCTUM_COMPOSE_PROJECT:-sanctum}"
CONTAINER="${SANCTUM_CONTAINER:-sanctum}"
DROP_DIR="${SANCTUM_NOTIFY_DIR:-/mnt/user/appdata/sanctum/notify}"
STATE="${SANCTUM_UPDATE_STATE:-/mnt/user/appdata/sanctum/update.state}"
LOCK="${SANCTUM_UPDATE_LOCK:-/var/lock/sanctum-update.lock}"
HEALTH_TIMEOUT="${SANCTUM_UPDATE_HEALTH_TIMEOUT:-120}"
# D08: --apply builds the fetched tag's Dockerfile on this host, so the tag must
# pass `git verify-tag` (needs the maintainer's key in this host's keyring)
# unless you explicitly opt out with SANCTUM_UPDATE_REQUIRE_SIGNED=0, which means
# accepting that whoever controls the release tags can run code here.
REQUIRE_SIGNED="${SANCTUM_UPDATE_REQUIRE_SIGNED:-1}"
AUTO_APPLY="${SANCTUM_UPDATE_AUTO_APPLY:-0}"
# Only plain release tags are ever considered: keeps odd characters out of git
# commands and notifications.
TAG_RE='^v[0-9]+\.[0-9]+\.[0-9]+$'

MODE="check"
DRY=0
case "${1:-}" in
  ""|--check)   MODE="check" ;;
  --apply)      MODE="apply" ;;
  --dry-run)    MODE="apply"; DRY=1 ;;
  --status)     MODE="status" ;;
  *) echo "usage: $0 [--check|--apply|--dry-run|--status]" >&2; exit 2 ;;
esac
# A scheduled --check run may be promoted to apply only by explicit opt-in.
if [ "${MODE}" = "check" ] && [ "${AUTO_APPLY}" = "1" ]; then MODE="apply"; fi
# Unattended apply hands host-level execution to whoever controls the release
# tags; never allow it without signature verification.
if [ "${AUTO_APPLY}" = "1" ] && [ "${REQUIRE_SIGNED}" != "1" ]; then
  echo "sanctum-update: ERROR: SANCTUM_UPDATE_AUTO_APPLY=1 requires SANCTUM_UPDATE_REQUIRE_SIGNED=1" >&2
  exit 2
fi

log() { echo "sanctum-update: $*"; }
die() { echo "sanctum-update: ERROR: $*" >&2; exit 1; }

# emit <severity> <subject> <body> — drop a notify intent for the dispatcher.
# Only version tags and fixed words go in here; never anything from the vault.
# jesc <string> — safe inside a JSON string literal: control characters dropped,
# backslash and double quote escaped.
jesc() { printf '%s' "$1" | tr -d '\000-\037' | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g'; }

emit() {
  [ "${DRY}" = "1" ] && { log "[dry-run] would notify ($1): $2 — $3"; return 0; }
  local pending="${DROP_DIR}/pending" ts f
  mkdir -p "${pending}"
  ts="$(date -u +%Y%m%dT%H%M%SZ)"
  f="${pending}/${ts}-u$$-update.json"
  printf '{"schema":1,"at":%s,"severity":"%s","kind":"update","subject":"%s","body":"%s"}\n' \
    "$(date +%s)" "$(jesc "$1")" "$(jesc "$2")" "$(jesc "$3")" > "${f}.tmp"
  mv "${f}.tmp" "${f}"
}

compose() {
  local file
  if [ "${COMPOSE_SOURCE}" = "stack" ]; then file="${STACK_DIR}/docker-compose.yml"
  else file="${REPO}/docker-compose.yml"; fi
  docker compose -p "${PROJECT}" -f "${file}" --env-file "${ENV_FILE}" "$@"
}

wait_healthy() {
  local i status
  for ((i = 0; i < HEALTH_TIMEOUT; i += 3)); do
    status="$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "${CONTAINER}" 2>/dev/null || echo missing)"
    case "${status}" in healthy) return 0 ;; esac
    sleep 3
  done
  return 1
}

# --- preflight ---------------------------------------------------------------
[ -d "${REPO}/.git" ] || die "no git checkout at ${REPO} (set SANCTUM_REPO)"
command -v git >/dev/null || die "git not found"

command -v flock >/dev/null || die "flock not found"
exec 9>"${LOCK}" || die "cannot open lock ${LOCK}"
flock -n 9 || { log "another run is in progress; exiting"; exit 0; }

cd "${REPO}"

cur_commit="$(git rev-parse HEAD)"
cur_label="$(git describe --tags --exact-match HEAD 2>/dev/null || git rev-parse --short HEAD)"

if [ "${MODE}" = "status" ]; then
  log "deployed: ${cur_label} (${cur_commit})"
  git fetch --tags --prune --quiet origin || die "git fetch failed"
  log "latest stable tag: $(git tag -l 'v[0-9]*' --sort=-v:refname | grep -E "${TAG_RE}" | head -1 || true)"
  exit 0
fi

# A dirty checkout means someone is hand-editing the deployed tree; refuse
# rather than clobber it.
[ -z "$(git status --porcelain)" ] || die "repo checkout has local changes; refusing"

git fetch --tags --prune --quiet origin || die "git fetch failed (network or deploy key?)"

latest="$(git tag -l 'v[0-9]*' --sort=-v:refname | grep -E "${TAG_RE}" | head -1 || true)"
if [ -z "${latest}" ]; then
  log "no release tags published yet; nothing to do"
  exit 0
fi

latest_commit="$(git rev-parse "${latest}^{commit}")"
if [ "${latest_commit}" = "${cur_commit}" ]; then
  log "up to date at ${cur_label}"
  exit 0
fi

# Only ever move forward. A tag that is not a descendant of what is running
# (force-moved tag, downgrade, diverged history) is refused and reported.
if ! git merge-base --is-ancestor "${cur_commit}" "${latest_commit}"; then
  emit warning "update refused" "Tag ${latest} is not a fast-forward from ${cur_label}. Investigate before deploying."
  die "${latest} is not a descendant of the deployed commit; refusing"
fi

sig_ok=0
git verify-tag "${latest}" >/dev/null 2>&1 && sig_ok=1
if [ "${MODE}" = "apply" ] && [ "${REQUIRE_SIGNED}" = "1" ] && [ "${sig_ok}" != "1" ]; then
  emit alert "update refused" "Tag ${latest} failed signature verification. Not deployed."
  die "signature verification failed for ${latest} (SANCTUM_UPDATE_REQUIRE_SIGNED=0 skips this, accepting that the tag's author can run code on this host)"
fi
sig_note=""
[ "${sig_ok}" = "1" ] || sig_note=" The tag signature could not be verified on this host."

# --- check mode --------------------------------------------------------------
if [ "${MODE}" = "check" ]; then
  if [ -f "${STATE}" ] && [ "$(cat "${STATE}")" = "${latest}" ]; then
    log "${latest} available (already notified)"
  else
    log "update available: ${cur_label} -> ${latest}"
    emit normal "update available" "Sanctum ${latest} is available (running ${cur_label}). Review the changelog, then run sanctum-update.sh --apply. The vault re-locks on restart.${sig_note}"
    echo "${latest}" > "${STATE}"
  fi
  exit 0
fi

# --- apply mode --------------------------------------------------------------
[ -f "${ENV_FILE}" ] || die "env file ${ENV_FILE} not found (set SANCTUM_ENV_FILE)"
command -v docker >/dev/null || die "docker not found"

log "plan: ${cur_label} -> ${latest}; build from ${REPO}; compose source=${COMPOSE_SOURCE}; env=${ENV_FILE}"
log "plan: on failure roll back to ${cur_commit}"
if [ "${DRY}" = "1" ]; then
  log "[dry-run] stopping here; nothing changed"
  exit 0
fi

rollback() {
  local why="$1"
  log "ROLLING BACK to ${cur_label}: ${why}"
  git checkout --quiet --detach "${cur_commit}" || true
  if compose up -d --build && wait_healthy; then
    emit alert "update failed, rolled back" "Sanctum ${latest} failed (${why}). Rolled back to ${cur_label} and healthy. The vault is LOCKED; unlock it."
  else
    emit alert "update failed, NOT recovered" "Sanctum ${latest} failed (${why}) and rollback to ${cur_label} is not healthy. Manual intervention needed."
  fi
  exit 1
}

git checkout --quiet --detach "${latest_commit}" || die "checkout of ${latest} failed"

# Catches a release that needs an env var the stack env file doesn't have,
# before we touch the running container.
compose config -q >/dev/null 2>&1 || { git checkout --quiet --detach "${cur_commit}";
  emit warning "update not applied" "Sanctum ${latest} needs compose/env changes (compose config invalid with the current env file). Read the changelog; running version unchanged."
  die "compose config invalid for ${latest}; left ${cur_label} running"; }

compose build >/dev/null 2>&1 || rollback "image build failed"
compose up -d >/dev/null 2>&1 || rollback "compose up failed"
wait_healthy || rollback "container not healthy within ${HEALTH_TIMEOUT}s"

echo "${latest}" > "${STATE}"
log "updated ${cur_label} -> ${latest}"
emit warning "updated to ${latest}" "Sanctum was updated from ${cur_label} to ${latest}. The vault is LOCKED after the restart; unlock it to resume ingest."

# ⏣ HW ⏣ · code · tools · homelab · ⏣ HW ⏣
