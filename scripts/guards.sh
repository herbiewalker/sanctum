#!/usr/bin/env bash
# ╭──────────────────────────────────────────────────────────────────╮
# │  ┌●───●───●───●───●───●───●───●───●───●───●───●───●───●───●───┐  │
# │  │                                                            │  │
# │  ●   ██╗  ██╗    ██╗    ██╗                                   ●  │
# │  │   ██║  ██║    ██║    ██║           herbiewalker            │  │
# │  │   ███████║    ██║ █╗ ██║──●──●──●──┐                       │  │
# │  │   ██╔══██║    ██║███╗██║           │                       │  │
# │  ●   ██║  ██║    ╚███╔███╔╝           ●───⏣  code · tools     ●  │
# │  │   ╚═╝  ╚═╝     ╚══╝╚══╝                    homelab         │  │
# │  │                                                            │  │
# │  └●───●───●───●───●───●───●───●───●───●───●───●───●───●───●───┘  │
# ╰──────────────────────────────────────────────────────────────────╯
# Sanctum — constraint guards.
#
# The single source of truth for CLAUDE.md's hard constraints as executable
# checks (principle 1: a rule a human has to remember is a rule that will be
# broken; principle 4: one source, generate the rest). The Makefile,
# bootstrap.ps1 and CI all call THIS script rather than reimplementing it —
# three copies of a guard is three chances for them to drift apart, and a guard
# that drifts is worse than no guard because it still shows green.
#
# Usage:  scripts/guards.sh [all|digest-pin|no-secrets|no-plaintext]
#
# Runs on Git Bash (Windows dev box) and on Ubuntu (CI). Keep it POSIX-ish and
# do not depend on GNU-only flags.

set -uo pipefail

cd "$(dirname "$0")/.." || exit 1

FAIL=0

pass() { printf '  \033[32mOK\033[0m    %s\n' "$1"; }
fail() { printf '  \033[31mFAIL\033[0m  %s\n' "$1"; FAIL=1; }
skip() { printf '  \033[33mSKIP\033[0m  %s\n' "$1"; }

# --- hard constraint 6 / N4: base images pinned by digest --------------------
# A floating base tag is an unreviewed change to what ships: the image you
# audited and the image you deploy stop being the same thing, silently.
guard_digest_pin() {
  local bad
  bad=$(grep -E '^FROM ' Dockerfile | grep -v '@sha256:')
  if [ -n "$bad" ]; then
    fail "digest-pin: unpinned base image in Dockerfile"
    printf '        %s\n' "$bad"
    return
  fi
  pass "digest-pin: every FROM pinned by @sha256:"
}

# --- hard constraints 3 + 4: nothing secret-shaped in version control --------
# Includes real .tryst files. Those are not "test data" — they are the owner's
# actual intimacy history, and one committed by accident is unrecoverable once
# pushed (lesson L18: public means the whole history, and removal is not
# rotation).
guard_no_secrets() {
  local ok=1

  if git ls-files --error-unmatch .env >/dev/null 2>&1; then
    fail "no-secrets: .env is tracked"
    ok=0
  fi

  local tracked
  tracked=$(git ls-files '*.tryst' '*.key' '*.pem' '*.pfx' '*.p12' 2>/dev/null)
  if [ -n "$tracked" ]; then
    fail "no-secrets: secret-shaped or real-backup files are tracked"
    printf '        %s\n' "$tracked"
    ok=0
  fi

  # Assignment of a long literal to a password/passphrase/secret/key name.
  # Test files are exempt: they legitimately use fixture passwords.
  local hits
  hits=$(git ls-files '*.go' '*.yml' '*.yaml' '*.ps1' 2>/dev/null \
    | grep -v '_test\.go$' \
    | xargs grep -nEI '(passphrase|password|secret|apikey|api_key)[[:space:]]*[:=][[:space:]]*"[A-Za-z0-9/+_-]{12,}"' 2>/dev/null)
  if [ -n "$hits" ]; then
    fail "no-secrets: possible hardcoded credential"
    printf '        %s\n' "$hits"
    ok=0
  fi

  [ "$ok" = "1" ] && pass "no-secrets: no tracked secrets, no hardcoded credentials"
}

# --- hard constraint 2 / N1: no plaintext user data outside tmpfs ------------
# Runs the guard test that ingests a synthetic backup carrying a sentinel
# string in data.json, then walks the vault dir asserting no file contains
# ZIP magic, no file opens with JSON, and no file contains the sentinel.
# The tmpfs staging dir is deliberately not scanned — plaintext is EXPECTED
# to exist there during an ingest (bounded by MaxBackupBytes, unlinked before
# return); the whole point of D-5 is that it never reaches the vault.
guard_no_plaintext() {
  if [ ! -d internal/ingest ]; then
    skip "no-plaintext: no ingest path before M3 — nothing to verify yet"
    return
  fi
  # Delegate to the Go test that does the actual work. -count=1 defeats the
  # test cache so a stale success does not silently vouch for a broken guard.
  if go test -run TestGuard_NoPlaintextAfterIngest -count=1 ./internal/ingest/ >/tmp/sanctum-guard.log 2>&1; then
    pass "no-plaintext: full ingest cycle wrote no plaintext to vault dir"
  else
    fail "no-plaintext: TestGuard_NoPlaintextAfterIngest failed"
    sed -n 's/^/        /p' /tmp/sanctum-guard.log | head -20
  fi
}

main() {
  local what="${1:-all}"
  echo "sanctum constraint guards (${what})"
  case "$what" in
    all)          guard_digest_pin; guard_no_secrets; guard_no_plaintext ;;
    digest-pin)   guard_digest_pin ;;
    no-secrets)   guard_no_secrets ;;
    no-plaintext) guard_no_plaintext ;;
    *) echo "unknown guard: $what" >&2; exit 2 ;;
  esac

  if [ "$FAIL" != "0" ]; then
    echo "guards FAILED — see CLAUDE.md 'Hard constraints'" >&2
    exit 1
  fi
  echo "guards passed"
}

main "$@"

# ⏣ HW ⏣ · code · tools · homelab · ⏣ HW ⏣
