#!/usr/bin/env bash
# Sanctum live smoke tests: the runtime checks the unit tests cannot cover.
#
# Run this ON THE DOCKER HOST (e.g. Unraid terminal), as root, with the image you
# intend to ship already built or pulled. It uses a THROWAWAY container (name
# `sanctum-smoke`) and a scratch directory, and never touches the real `sanctum`
# container or its vault. Everything it creates is removed on exit.
#
#   ./scripts/smoke-live.sh                 # uses image sanctum:dev
#   IMAGE=ghcr.io/herbiewalker/sanctum:stable ./scripts/smoke-live.sh
#
# Checks (AUDIT.md "human-only smokes", plus the F03 floor check):
#   1. F01  /tmp not a tmpfs            -> refuses to start (ErrTmpDirNotTmpfs); read-only also fails closed
#   2. F02  600 MB upload               -> fast 413, memory stays flat, no OOM
#   3. F05  tamper manifest KDF salt    -> "manifest.json has changed" in the log
#   4. F03  manifest KDF cost below floor -> "below production floor", no derive
#   5.      restore the manifest        -> unlock works again (the checks are reversible)
#   6. D01  kill -9 while unlocked      -> a change made just before the kill is still there after restart
#
# Exit code = number of failed checks (0 = all passed).

set -u

IMAGE="${IMAGE:-sanctum:dev}"
PORT="${PORT:-18250}"
NAME="sanctum-smoke"
DIR="${SMOKE_DIR:-/mnt/user/appdata/sanctum-smoke}"
BIG_MB="${BIG_MB:-600}"

fails=0
pass() { echo "  PASS  $*"; }
fail() { echo "  FAIL  $*"; fails=$((fails + 1)); }
say()  { echo; echo "== $* =="; }

# Never rm anything outside a directory that is plainly ours.
case "$(basename "$DIR")" in
  sanctum-smoke*) ;;
  *) echo "refusing: SMOKE_DIR must be named sanctum-smoke*"; exit 99 ;;
esac

PASSPHRASE="smoke-$(cat /proc/sys/kernel/random/uuid)"
OWNERPW="owner-$(cat /proc/sys/kernel/random/uuid)"
JAR="$DIR/cookies.txt"
BASE="http://127.0.0.1:${PORT}"

cleanup() {
  docker rm -f "$NAME" >/dev/null 2>&1
  [ -n "${SAMPLER_PID:-}" ] && kill "$SAMPLER_PID" >/dev/null 2>&1
  rm -rf "$DIR"
}
trap cleanup EXIT

# Common docker flags: same hardening as the shipped template.
run_flags() {
  echo "--user 65532:65532 --read-only --cap-drop=ALL --security-opt=no-new-privileges:true"
}
TMPFS="--tmpfs /tmp:rw,mode=1777,size=1g,noexec,nosuid,nodev"

rm -rf "$DIR"
mkdir -p "$DIR/vault" "$DIR/inbox"
chown -R 65532:65532 "$DIR/vault"
chmod 755 "$DIR/inbox"

wait_health() {
  local i
  for i in $(seq 1 40); do
    if curl -fsS -o /dev/null "$BASE/healthz" 2>/dev/null; then return 0; fi
    sleep 0.5
  done
  return 1
}

start_server() {
  docker rm -f "$NAME" >/dev/null 2>&1
  # shellcheck disable=SC2046
  docker run -d --name "$NAME" $(run_flags) --memory=2g $TMPFS \
    -p "127.0.0.1:${PORT}:8080" \
    -v "$DIR/vault:/data/vault" -v "$DIR/inbox:/data/inbox:ro" \
    "$IMAGE" >/dev/null
}

# ---------------------------------------------------------------------------
say "1. F01: a writable /tmp that is NOT a tmpfs must refuse to start"
# Writable rootfs (no --read-only) so /tmp exists and is on the overlay, which is the
# real misconfiguration: the guard must notice it is not memory-backed.
out="$(timeout 30 docker run --rm --name "${NAME}-notmpfs" --user 65532:65532 --cap-drop=ALL \
  --security-opt=no-new-privileges:true --memory=512m \
  -v "$DIR/vault:/data/vault" -v "$DIR/inbox:/data/inbox:ro" "$IMAGE" 2>&1)"
rc=$?
if [ "$rc" -ne 0 ] && echo "$out" | grep -q "not on a tmpfs"; then
  pass "exit $rc and the log says TmpDir is not on a tmpfs/ramfs mount"
else
  fail "expected a non-zero exit with 'not on a tmpfs' (exit=$rc). Output:"
  echo "$out" | tail -5
fi

say "1b. read-only rootfs with no /tmp mount must also fail closed"
# shellcheck disable=SC2046
out="$(timeout 30 docker run --rm --name "${NAME}-ro" $(run_flags) --memory=512m \
  -v "$DIR/vault:/data/vault" -v "$DIR/inbox:/data/inbox:ro" "$IMAGE" 2>&1)"
rc=$?
if [ "$rc" -ne 0 ]; then pass "exit $rc (refused to start)"; else fail "started with no usable /tmp"; fi

# ---------------------------------------------------------------------------
say "starting throwaway server on 127.0.0.1:${PORT}"
start_server
if wait_health; then pass "healthy"; else fail "never became healthy"; docker logs "$NAME" 2>&1 | tail -10; exit "$fails"; fi

# First-run unlock (creates the vault) then provision an owner and log in.
curl -fsS -o /dev/null -w '' -d "passphrase=${PASSPHRASE}" -d "passphrase_confirm=${PASSPHRASE}" "$BASE/unlock" || true
curl -sS -o /dev/null -d "label=smoke" -d "username=smoke" -d "password=${OWNERPW}" -d "password_confirm=${OWNERPW}" "$BASE/provision"
curl -sS -o /dev/null -c "$JAR" -d "username=smoke" -d "password=${OWNERPW}" "$BASE/login"
code="$(curl -sS -o /dev/null -b "$JAR" -w '%{http_code}' "$BASE/status")"
if [ "$code" = "200" ]; then pass "vault created, owner provisioned, logged in"; else fail "could not log in (status page HTTP $code)"; docker logs "$NAME" 2>&1 | tail -8; fi

# ---------------------------------------------------------------------------
say "2. F02: ${BIG_MB} MB upload must be refused with 413, fast, with flat memory"
BIG="$DIR/big.bin"
truncate -s "${BIG_MB}M" "$BIG"
SAMPLES="$DIR/mem.txt"
: > "$SAMPLES"
# D15: a refused upload returns in milliseconds, and `docker stats --no-stream`
# takes about a second, so a background sampler never got a reading and the peak
# printed as 0. Sample synchronously instead: once before the upload, and once
# right after it (the refusal is instant, so any buffering would still be resident).
mem_mib() { # one reading in MiB, empty if docker stats gave nothing
  docker stats --no-stream --format '{{.MemUsage}}' "$NAME" 2>/dev/null | cut -d/ -f1 |
    awk '{ v=$1+0; if ($1 ~ /GiB/) v*=1024; else if ($1 ~ /KiB/) v/=1024; else if ($1 ~ /MiB/) v=v; else v/=1048576; printf "%d", v }'
}
before="$(mem_mib)"; echo "${before}" >> "$SAMPLES"
res="$(curl -sS -o /dev/null -b "$JAR" -F "file=@${BIG};filename=big.tryst" --max-time 180 -w '%{http_code} %{time_total}' "$BASE/upload" 2>/dev/null)"
after="$(mem_mib)"; echo "${after}" >> "$SAMPLES"
rm -f "$BIG"
code="${res%% *}"; secs="${res##* }"
oom="$(docker inspect "$NAME" --format '{{.State.OOMKilled}}' 2>/dev/null)"
echo "  http=${code} time=${secs}s memory_before=${before:-?}MiB memory_after=${after:-?}MiB oom_killed=${oom}"
if [ "$code" = "413" ]; then pass "HTTP 413"; else fail "expected 413, got '${code}'"; fi
if [ "$oom" = "false" ]; then pass "container was not OOM-killed"; else fail "container OOM-killed"; fi
if [ -z "$before" ] || [ -z "$after" ]; then
  fail "no memory reading from docker stats; cannot confirm memory stayed flat"
elif [ "$after" -lt 300 ] && [ "$((after - before))" -lt 100 ]; then
  pass "memory flat (${before} -> ${after} MiB): the oversize body was never read"
else
  fail "memory went ${before} -> ${after} MiB across a refused ${BIG_MB} MB upload"
fi

# ---------------------------------------------------------------------------
say "lock the vault so a seal exists on disk, then stop the server"
curl -sS -o /dev/null -b "$JAR" -X POST "$BASE/lock"
docker stop "$NAME" >/dev/null
if docker logs "$NAME" 2>&1 | grep -q "shutdown complete"; then pass "graceful shutdown logged (closes OL-7 when run on the real host)"; else fail "no 'shutdown complete' in the log after docker stop"; fi

MAN="$DIR/vault/manifest.json"
cp "$MAN" "$DIR/manifest.orig"
orig="$(cat "$MAN")"

try_unlock() {
  start_server
  wait_health || { echo "  (server did not come up)"; return 1; }
  curl -sS -o /dev/null -d "passphrase=${PASSPHRASE}" "$BASE/unlock"
}

# ---------------------------------------------------------------------------
say "3. F05: tampered manifest KDF salt must report 'manifest has changed'"
oldsalt="$(echo "$orig" | grep -o '"salt": *"[^"]*"' | head -1)"
prefix="${oldsalt%\"*\"}"            # everything before the opening quote of the value
valpart="${oldsalt#"$prefix"}"     # "AbC..." (with quotes)
first="${valpart:1:1}"
if [ "$first" = "A" ]; then repl="B"; else repl="A"; fi
newval="\"${repl}${valpart:2}"      # same length, first base64 char changed
newsalt="${prefix}${newval}"
printf '%s' "${orig/"$oldsalt"/"$newsalt"}" > "$MAN"
try_unlock
logs="$(docker logs "$NAME" 2>&1)"
if echo "$logs" | grep -q "manifest.json has changed"; then
  pass "unlock refused with the out-of-band manifest error"
else
  fail "expected 'manifest.json has changed' in the log; saw:"
  echo "$logs" | grep "unlock failed" | tail -2
fi
docker stop "$NAME" >/dev/null 2>&1

# ---------------------------------------------------------------------------
say "4. F03: manifest KDF cost below the production floor must be refused"
oldt="$(echo "$orig" | grep -o '"t": *[0-9]*' | head -1)"
newt="\"t\": 1"
printf '%s' "${orig/"$oldt"/"$newt"}" > "$MAN"
try_unlock
logs="$(docker logs "$NAME" 2>&1)"
if echo "$logs" | grep -q "below production floor"; then
  pass "unlock refused: KDF below the production floor"
else
  fail "expected 'below production floor' in the log; saw:"
  echo "$logs" | grep "unlock failed" | tail -2
fi
docker stop "$NAME" >/dev/null 2>&1

# ---------------------------------------------------------------------------
say "5. restore the original manifest: unlock must work again"
cp "$DIR/manifest.orig" "$MAN"
try_unlock
code="$(curl -sS -o /dev/null -c "$JAR" -d "username=smoke" -d "password=${OWNERPW}" -w '%{http_code}' "$BASE/login")"
st="$(curl -sS -o /dev/null -b "$JAR" -w '%{http_code}' "$BASE/status")"
if [ "$st" = "200" ]; then pass "vault unlocked and owner logged in again (the tampering was reversible)"; else fail "could not unlock after restoring the manifest (status HTTP $st)"; docker logs "$NAME" 2>&1 | tail -5; fi

# ---------------------------------------------------------------------------
say "6. D01: a change made while unlocked must survive a kill (no Lock, no clean shutdown)"
MARK="killtest-$(cat /proc/sys/kernel/random/uuid | cut -c1-8)"
curl -sS -o /dev/null -b "$JAR" -d "label=${MARK}" -d "passphrase=smoke-kill-pw" "$BASE/passwords"
sleep 13   # the checkpointer runs every 10 s
docker kill "$NAME" >/dev/null
try_unlock
curl -sS -o /dev/null -c "$JAR" -d "username=smoke" -d "password=${OWNERPW}" "$BASE/login"
if curl -sS -b "$JAR" "$BASE/passwords" | grep -q "${MARK}"; then
  pass "the password entry added just before docker kill survived the restart"
else
  fail "the change made before the kill was lost (checkpoint did not reach the array)"
  docker logs "$NAME" 2>&1 | tail -5
fi

echo
if [ "$fails" -eq 0 ]; then echo "ALL SMOKE CHECKS PASSED"; else echo "${fails} CHECK(S) FAILED"; fi
exit "$fails"

# ⏣ HW ⏣ · code · tools · homelab · ⏣ HW ⏣
