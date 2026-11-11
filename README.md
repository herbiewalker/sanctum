<div align="center">

<img src="deploy/icon.png" alt="Sanctum" width="120" height="120">

# Sanctum

**A locked-by-default vault that keeps your encrypted [Tryst](https://github.com/herbiewalker/tryst) backups safe on your own server.**

[![CI](https://github.com/herbiewalker/sanctum/actions/workflows/ci.yml/badge.svg)](https://github.com/herbiewalker/sanctum/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/herbiewalker/sanctum?sort=semver)](https://github.com/herbiewalker/sanctum/releases)
![License](https://img.shields.io/badge/license-MIT-blue)
![Platform](https://img.shields.io/badge/platform-Docker%20%2F%20Unraid-0969da)
![Key never at rest](https://img.shields.io/badge/key-never_at_rest-2ea44f)
![LAN only](https://img.shields.io/badge/network-LAN_only-2ea44f)

</div>

> [!NOTE]
> **Status: early release, one author, one home server.** Sanctum has been running on one Unraid
> host, with one person's real data. It has had eight self-run audit passes, not an independent
> review. Treat it as a careful hobby project, not audited security software. See
> [Known limitations](#known-limitations).

## What it is

[Tryst](https://github.com/herbiewalker/tryst) is a privacy-first Android app that keeps years of private records on one phone, encrypted with a key that never leaves the device,
and has no cloud backup by design. The only safety net is an exported `.tryst` file, which means the
net depends on you remembering to make one and remembering where it went. A dead phone and a stale
export is total data loss.

Sanctum is the other half. It is a small service on your own server that:

- **takes** exported backups from a watched folder or a browser upload,
- **proves** each one really opens (a real trial decrypt, not just a file copy),
- **keeps** an immutable, versioned history with configurable retention,
- **tells you** when you have not made a backup in a while (ntfy, Discord, Slack or a webhook),
- **hands back** the exact original file, byte for byte, when you need it.

It cannot see your data unless you unlock it, and it never writes the key to disk.

## Highlights

| | |
|---|---|
| **Locked by default** | Starts locked after every restart. You type the vault passphrase; it lives only in memory. |
| **Verified, not just stored** | Every backup is trial-decrypted with your saved passwords before it is kept. |
| **Tamper-evident** | Blobs are immutable and SHA-256 checked on every read; a flipped byte fails. |
| **Ciphertext on disk** | The array only ever holds the original encrypted files and a sealed, encrypted index. |
| **Byte-identical restore** | Download returns exactly what Tryst wrote, with a checksum header. |
| **Modern web UI** | Responsive on phones and desktops, light, dark or automatic theme, built-in help, upload progress bar. Plain HTML and CSS with one small optional script. |
| **Hardened container** | Distroless, non-root, read-only filesystem, all capabilities dropped, base images pinned by digest, Trivy-scanned in CI. |
| **Quiet by design** | Alerts carry only dates, counts and version numbers. Never backup contents or file names. |

## How it fits together

```
  Tryst (no network, ever)          your Unraid box
        │                    ┌──────────────────────────┐
        │  export .tryst     │  inbox/  ──► Sanctum     │
        └───────────────────►│              │           │
           Syncthing / SMB   │              ▼           │
                             │   verify · hash · store  │
   browser (LAN) ───────────►│              │           │
                             │              ▼           │
                             │   vault/ — ciphertext    │
                             └──────────────────────────┘
```

Tryst never opens a socket: backups arrive as **files**. That is why Sanctum needs zero changes to an
app whose whole identity is its empty permission list ([D-1](docs/DECISIONS.md)).

## Install

The simplest way is the published image, `ghcr.io/herbiewalker/sanctum:stable`.

**Unraid:** use the template in [`deploy/unraid-template.xml`](deploy/unraid-template.xml). It follows
the `:stable` tag, so the Docker tab's normal update check works. **Docker Compose:** use
[`docker-compose.yml`](docker-compose.yml) with [`.env.example`](.env.example). Both are walked through,
step by step, in the **[Runbook](RUNBOOK.md)**.

Then:

1. Open `http://<server>:<port>/` on your LAN and **create the vault** (choose a passphrase and save
   it in your password manager first; there is no recovery).
2. Create the owner login, then add your Tryst backup password(s) on the Passwords page.
3. Drop a `.tryst` file in the inbox folder, or upload one in the browser.
4. Paste a notification URL into `SANCTUM_NOTIFY_URL` so a stale backup reaches you.

Keep it on your LAN. Do not forward the port to the internet. After every restart or update, unlock it
again; that is the point.

**Pin a version** instead of following `:stable` by using an exact tag such as
`ghcr.io/herbiewalker/sanctum:0.1.1`. There is no `latest` tag. Releases carry a build provenance
attestation, and updates are always manual (see [D-19](docs/DECISIONS.md)).

## Configuration

All settings are environment variables with sensible defaults, and none of them is a secret except the
optional notification URL. The most useful ones:

| Variable | Default | Purpose |
|---|---|---|
| `SANCTUM_NOTIFY_URL` | none | Where alerts go: `ntfy://host/topic`, a Discord or Slack webhook, or any HTTPS URL. Treat it as a credential. |
| `SANCTUM_STALENESS_DAYS` | `30` | Alert when the newest backup is older than this. |
| `SANCTUM_LOCKED_ALERT_AFTER_HOURS` | `24` | Alert if the vault stays locked this long. `0` disables. |
| `SANCTUM_UPDATE_CHECK` | `false` | Once a day, ask GitHub whether a newer release exists, and notify. Reports only. |
| `SANCTUM_RETENTION_KEEP_MIN` / `SANCTUM_RETENTION_MAX_AGE_DAYS` | `3` / `365` | Always keep at least this many backups; prune ones older than this many days beyond that. |

The full list, with the paths and port settings, lives in [`.env.example`](.env.example) and
[SETUP.md](SETUP.md). There is deliberately **no** variable that unlocks the vault.

## Using the web UI

- **Backups** shows the count, the newest backup and whether it is on time, total size, and when it
  was last checked. Upload shows a progress bar for the transfer, then for the check.
- **Passwords** holds the Tryst passwords Sanctum tries on new backups. Each can carry an optional
  hint to jog your memory. Hints live inside the encrypted index and are never sent in alerts.
- **Theme** (footer) follows your system by default. Choose Light or Dark to override it.

## Build from source

Prerequisites: Go (the version in [`go.mod`](go.mod)) and Git for Windows or any POSIX shell. Platform
traps are listed in [SETUP.md](SETUP.md).

```powershell
git clone https://github.com/herbiewalker/sanctum.git
cd sanctum
.\bootstrap.ps1
```

Expect `BOOTSTRAP GREEN`. On Linux or in CI, `make check` runs the same gates. To try it locally:

```powershell
$env:SANCTUM_ADDR = "127.0.0.1:8080"; .\bin\sanctum.exe
```

```bash
curl http://127.0.0.1:8080/healthz
# {"status":"ok","state":"locked"}
```

`locked` is correct until you open the web UI and set the vault passphrase.

## Security model in one minute

- **The key is never at rest.** There is no passphrase in the image, the compose file, a `.env` or the
  appdata. A restart locks the vault.
- **No plaintext on the array.** Decrypted data exists only in memory or tmpfs, only for the life of a
  request. A CI guard runs a full ingest and fails if any file in the vault is readable as ZIP or JSON.
- **Sanctum can decrypt your backups** (a deliberate trade, [D-3](docs/DECISIONS.md)). It defends them
  against everyone on your LAN, a pulled disk and a stolen appdata backup. It **cannot** defend them
  against someone with root on the host while the vault is unlocked. That residual risk is stated
  plainly in the [threat model](docs/THREAT_MODEL.md#residual-risks).
- **Strict browser policy.** Pages ship a Content-Security-Policy that allows only same-origin scripts,
  styles and images, no framing, and same-site form posts.

Report a vulnerability privately, as described in [SECURITY.md](SECURITY.md).

## Documentation

| Doc | What it owns |
|-----|--------------|
| [RUNBOOK.md](RUNBOOK.md) | deploy, unlock, restore drill, upgrade, rollback, failure modes |
| [CHANGELOG.md](CHANGELOG.md) | version history |
| [SETUP.md](SETUP.md) | toolchain pins, environment, platform trap and fix list |
| [docs/REQUIREMENTS.md](docs/REQUIREMENTS.md) | scope, non-goals, functional and non-functional requirements |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | components, the locked and unlocked states, data flows |
| [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) | assets, adversaries, mitigations, accepted residual risk |
| [docs/DATA_MODEL.md](docs/DATA_MODEL.md) | index schema, vault layout, migration rules |
| [docs/DECISIONS.md](docs/DECISIONS.md) | the ADR log |
| [docs/ROADMAP.md](docs/ROADMAP.md) | milestones, what shipped, what is next |
| [docs/AUDIT.md](docs/AUDIT.md) | the self-run audit passes and their findings |
| [CRITICAL_ASSETS.md](CRITICAL_ASSETS.md) | what git deliberately does not hold |
| [CLAUDE.md](CLAUDE.md) | the hard constraints and the contract for an AI pair |

## Known limitations

Visible, chosen debt beats silent debt.

- **Tested on one host only**, with one person's data. Expect rough edges elsewhere.
- **No independent security review.** The audits in [docs/AUDIT.md](docs/AUDIT.md) were self-run with AI
  assistance, and the newest web UI changes (CSP, upload script, themes, hints) were not covered by a
  dedicated audit pass.
- **Plain HTTP, LAN only** (D-12). Session cookies drop `Secure` on non-TLS requests (D-17). Any
  non-LAN exposure would need a TLS front end and a fresh threat model.
- **Go may keep stray copies of the runtime key in memory** after it is zeroed (accepted residual risk).
- **Upload shows progress; download does not.** A large restore looks idle until the browser's own
  download bar appears.
- **An unattended reboot leaves the vault locked**, and silently not ingesting. That is the cost of
  the key never resting; the locked-too-long and stale-backup alerts are what catch it (R5).
- **Deletion is detected, not prevented.** Anyone who can write to the appdata path can delete blobs (R3).
- **Tested in Chromium only** for the web UI. It is plain HTML and CSS, so other browsers should work,
  but it has not been checked in Firefox or Safari.

## License

MIT, see [LICENSE](LICENSE). Tryst itself is GPL-3.0; Sanctum implements its backup format from
[the published spec](https://github.com/herbiewalker/tryst/blob/main/docs/EXPORT_FORMAT.md) instead of
reusing its code, so there is no GPL derivation ([D-7](docs/DECISIONS.md)).
