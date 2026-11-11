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
# sanctum-notify-dispatch.sh — Sanctum host-side notification dispatcher.
#
# Watches ${SANCTUM_NOTIFY_DIR}/pending/ for JSON intent files written by the
# Sanctum container (ADR D-18), calls Unraid's notify helper for each, and
# moves the file to sent/ (or failed/ on error).
#
# Install as an Unraid User Script (Community Applications → User Scripts):
#   Name:     sanctum-notify-dispatch
#   Schedule: */2 * * * *   (every 2 minutes)
#   Contents: copy this file.
#
# Needs only bash, sed and cut. Unraid ships NO python3; jq is used if present.
#
# The Sanctum container never runs this script. This script never reads
# Sanctum's index or vault — it only touches the drop directory.

set -euo pipefail

DROP_DIR="${SANCTUM_NOTIFY_DIR:-/mnt/user/appdata/sanctum/notify}"
PENDING="${DROP_DIR}/pending"
SENT="${DROP_DIR}/sent"
FAILED="${DROP_DIR}/failed"
NOTIFY_BIN="${SANCTUM_NOTIFY_BIN:-/usr/local/emhttp/webGui/scripts/notify}"

# A literal backslash, built without typing one, so the sed patterns below
# survive being copied and pasted through any editor or terminal.
BS="$(printf '\134')"

mkdir -p "${SENT}" "${FAILED}"

# jget <file> <key> — read one string field from an intent file. Uses jq when
# present, else a sed fallback that relies on the fixed one-field-per-line
# layout Sanctum writes (Go's MarshalIndent).
jget() {
  if command -v jq >/dev/null 2>&1; then
    jq -r --arg k "$2" '.[$k] // empty' "$1" 2>/dev/null | tr '\n' ' ' | cut -c1-1000
  else
    sed -n "s/^[[:space:]]*\"$2\": \"\(.*\)\"[[:space:]]*,\{0,1\}\$/\1/p" "$1" | head -n 1 \
      | sed -e "s/${BS}${BS}n/ /g" \
            -e "s/${BS}${BS}t/ /g" \
            -e "s/${BS}${BS}u003c/</g" \
            -e "s/${BS}${BS}u003e/>/g" \
            -e "s/${BS}${BS}u0026/${BS}&/g" \
            -e "s/${BS}${BS}\"/\"/g" \
            -e "s/${BS}${BS}${BS}${BS}/${BS}${BS}/g" \
      | cut -c1-1000
  fi
}

if [ ! -x "${NOTIFY_BIN}" ]; then
  echo "sanctum-notify: ${NOTIFY_BIN} missing or not executable" >&2
  exit 1
fi

# Nothing to do? Exit clean so cron doesn't email about it.
shopt -s nullglob
files=( "${PENDING}"/*.json )
if [ ${#files[@]} -eq 0 ]; then
  exit 0
fi

for f in "${files[@]}"; do
  severity="$(jget "${f}" severity)"
  subject="$(jget "${f}" subject)"
  body="$(jget "${f}" body)"
  kind="$(jget "${f}" kind)"
  if [ -z "${subject}" ]; then
    echo "sanctum-notify: parse failed for ${f}" >&2
    mv "${f}" "${FAILED}/$(basename "${f}").parse_failed"
    continue
  fi
  [ -n "${kind}" ] || kind="staleness"
  # Unraid importance is normal/warning/alert; anything else becomes normal.
  case "${severity}" in normal|warning|alert) ;; *) severity="normal" ;; esac

  # Prefix with the product name unless the subject already carries it.
  case "${subject}" in Sanctum*) title="${subject}" ;; *) title="Sanctum: ${subject}" ;; esac

  if "${NOTIFY_BIN}" \
      -i "${severity}" \
      -s "${title}" \
      -d "${body}" \
      -e "sanctum/${kind}" ; then
    mv "${f}" "${SENT}/$(basename "${f}")"
  else
    mv "${f}" "${FAILED}/$(basename "${f}").notify_failed"
  fi
done

# ⏣ HW ⏣ · code · tools · homelab · ⏣ HW ⏣
