<div align="center">

# 🔒 Sanctum

### A locked-by-default vault that keeps encrypted Tryst backups safe on your own hardware

![License](https://img.shields.io/badge/license-MIT-blue)
![Platform](https://img.shields.io/badge/platform-docker%20%2F%20unraid-0969da)
![Locked by default](https://img.shields.io/badge/key-never_at_rest-2ea44f)
![LAN only](https://img.shields.io/badge/network-LAN_only-2ea44f)

**Status: pre-1.0, running on one home server.** Everything in the v1 scope below is built:
unlock, owner login, folder and browser ingest, trial-decrypt verification, immutable versioned
storage, retention, staleness and locked-too-long alerts (ntfy, Discord, Slack or a webhook),
byte-identical restore, and an opt-in update check. It has been deployed on **one** Unraid host and
smoke-tested there (tmpfs refusal, oversize upload, tampered manifest, KDF floor,
graceful shutdown), and a real 419 MB Tryst backup was ingested, restored byte-identical and opened
in Tryst. It has **not** been run by anyone else, there is **no published release yet**, and it has
had one author's review plus eight self-run audit passes (see [docs/AUDIT.md](docs/AUDIT.md)), not an
independent one. Treat it as a careful hobby project, not audited security software.

</div>

---

## What & why

[Tryst](https://github.com/herbiewalker/tryst) keeps years of intimacy records on a single
Android phone, encrypted under a device-bound Keystore key, with **no cloud backup by design**. The
only safety net is a manually exported `.tryst` file — which means the safety net depends on
remembering to make one, and remembering where it went. A dead phone and a stale export is total
data loss.

Sanctum is the other half: a small self-hosted service that takes those exported backups, **proves
each one actually opens**, keeps versioned history, and tells you when you have not made one in a
while.

- **In scope (v1):** ingest from a watched folder or a browser upload · verify by real trial decrypt
  · immutable versioned retention · staleness alerts · byte-identical restore.
- **Not in scope (v1):** viewing your encounter data, partner sharing, any change to the Tryst app,
  internet exposure, moving files off the phone (that is Syncthing's job).
- **Hard constraints:** the key is **never** at rest · **no plaintext ever touches the array** ·
  Tryst is **never modified** · LAN only. See [CLAUDE.md](CLAUDE.md) for all seven and the CI guard
  behind each.

> [!WARNING]
> Sanctum can decrypt your backups — that is a deliberate trade
> ([D-3](docs/DECISIONS.md)) so it can verify them and, later, show you a shared picture. It defends
> that data against everyone on your LAN, against a pulled disk, and against a stolen appdata
> backup. It **cannot** defend it against someone with root on the host while the vault is
> unlocked. That residual risk is stated plainly in
> [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md#residual-risks), not papered over.

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

Tryst never opens a socket. Backups arrive as **files**, which is why Sanctum needs zero changes to
an app whose whole identity is its empty permission list ([D-1](docs/DECISIONS.md)).

## ⚡ Quickstart

This builds and runs it from source for development. To run it for real, see
[Deploying](#deploying). Prerequisites: Go (the version in `go.mod`) and Git for Windows. Pins and
platform traps: [SETUP.md](SETUP.md).

```powershell
git clone https://github.com/herbiewalker/sanctum.git
cd sanctum
.\bootstrap.ps1
```

Expect `BOOTSTRAP GREEN`. Then run the scaffold:

```powershell
$env:SANCTUM_ADDR = "127.0.0.1:8080"; .\bin\sanctum.exe
```

```bash
curl http://127.0.0.1:8080/healthz
# {"status":"ok","state":"locked","uptime":"0s"}
```

`locked` is correct until you open the web UI and set the vault passphrase.

On Linux or CI:

```bash
make check
```

## Deploying

Follow [RUNBOOK.md](RUNBOOK.md). The image is distroless, runs as `65532:65532` with a read-only root
filesystem and all capabilities dropped, pins both base images by digest, and is scanned with Trivy
in CI. Two ways to run it:

- **Unraid template or Docker Compose**, using the image `ghcr.io/herbiewalker/sanctum:stable` once
  the first release is published (`deploy/unraid-template.xml`, `docker-compose.yml`).
- **Build from source** with `docker compose up -d --build`.

Keep it on your LAN. Do not forward the port to the internet. Sanctum starts **locked** after every
restart and a human has to unlock it.

## 🗂️ Documentation map

| Doc | What it owns |
|-----|--------------|
| [CLAUDE.md](CLAUDE.md) | the hard constraints, size class, and the contract for an AI pair |
| [SETUP.md](SETUP.md) | toolchain pins, env vars, platform trap→fix list |
| [docs/REQUIREMENTS.md](docs/REQUIREMENTS.md) | scope, non-goals, F/N requirements |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | components, the LOCKED/UNLOCKED state machine, data flows |
| [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) | assets, adversaries, mitigations, accepted residual risk |
| [docs/DATA_MODEL.md](docs/DATA_MODEL.md) | index schema, vault layout, migration rules |
| [docs/ROADMAP.md](docs/ROADMAP.md) | milestones and their exit criteria |
| [docs/DECISIONS.md](docs/DECISIONS.md) | ADR log and the open questions |
| [docs/AUDIT.md](docs/AUDIT.md) | the pre-release audit passes and their findings |
| [CHANGELOG.md](CHANGELOG.md) | version history |
| [RUNBOOK.md](RUNBOOK.md) | deploy, unlock, restore, upgrade and rollback |
| [CRITICAL_ASSETS.md](CRITICAL_ASSETS.md) | what git deliberately does not hold |

## Known limitations

Visible chosen debt beats silent debt.

- **Tested on one host only**, with one user's data. Expect rough edges on other setups.
- **No independent security review.** The audits in [docs/AUDIT.md](docs/AUDIT.md) were run by the
  author with AI assistance.
- **HTTP is plain HTTP.** LAN-only per D-12. Session cookies drop `Secure` on non-TLS requests
  (see D-17); a reverse-proxy/TLS setup would have to come with any non-LAN exposure.
- **Go may keep copies of the runtime key in memory** after it is zeroed (accepted residual risk).
- **Upload and download show no progress**, so a 400 MB transfer looks frozen for minutes.
- **An unattended reboot leaves the vault locked** and silently not ingesting. That is the deliberate
  cost of the key never resting; the staleness alert is what catches it (R5).
- **Deletion is detected, not prevented.** Anyone who can write to the appdata path can delete
  blobs (R3).

## License

MIT — see [LICENSE](LICENSE). Tryst itself is GPL-3.0; Sanctum implements its backup format from
[the published spec](https://github.com/herbiewalker/tryst/blob/main/docs/EXPORT_FORMAT.md) rather
than reusing its code, so there is no GPL derivation ([D-7](docs/DECISIONS.md)).
