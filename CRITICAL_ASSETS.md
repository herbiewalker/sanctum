# Sanctum — Critical Assets Inventory

> The stuff git **deliberately doesn't hold**. If the dev machine died today, every repo restores
> from the remote — and none of these do. This file inventories them; it **never contains the values
> themselves** (locations and metadata only).
>
> Two rules: (1) every asset has a **second copy** somewhere that isn't this machine; (2) anything
> with an expiry or a pending rotation also gets an `OPEN_LOOPS.md` entry in the DevPlaybook, so it
> is reviewed rather than remembered.

## Inventory

| Asset | Type | Lives at | Second copy | Expires / rotate | Loses what if lost |
|-------|------|----------|-------------|------------------|--------------------|
| **Sanctum vault passphrase** | passphrase | nowhere on disk — typed by a human at unlock (D-4) | password manager entry | never | **the entire vault** — index, seals, and (pending O-1) every stored backup password. Unrecoverable |
| **Sanctum owner-login passphrase** | passphrase | nowhere on disk — typed by a human at owner login (D-14) | password manager entry | never | ability to log in as that owner. The vault itself is unaffected (a different passphrase unlocks it), but no one can *use* it without this too |
| **Tryst backup password(s)** | passphrase | password manager; and sealed inside the vault (D-13, `owner_backup_password` table) | password manager | never | ability to open the stored `.tryst` blobs — the blobs survive but become useless |
| ~~Sanctum per-host SSH deploy key~~ | **no longer needed** | the repo is public, so a host clones over HTTPS with no key; the image comes from GHCR | delete any old `sanctum_<host>` deploy keys on hosts and in GitHub Settings | — | nothing |
| **Notification URL** (`SANCTUM_NOTIFY_URL`) | credential (a webhook or ntfy topic/token) | the stack env / Unraid template field on the host; never in git (D-20) | password manager entry | rotate if it leaks | alerts stop (or, if leaked, a stranger can post to your channel) |
| `.env` for the Unraid deploy | runtime config | `/mnt/user/appdata/sanctum/.env` on the box, gitignored locally | regenerate from `deploy/unraid.env.example` (Unraid) or `.env.example` (elsewhere) | on exposure | nothing secret — **paths and ports only**, by design (hard constraint 3) |
| Canonical `TRYSTBK1` backups | encrypted user data | the phone, a local backup folder, and the Sanctum vault | the vault *is* the second copy | never | years of records |

## Notes

- **The vault passphrase is a single root of failure and that is a deliberate design property**, not
  an oversight — see residual risk R4 in [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md). It makes the
  second copy load-bearing: if it exists only in one person's head, the vault is one bad week from
  being unopenable. Write it down somewhere that survives.
- **Sanctum mints no keys of its own** in v1 — no signing keystore (releases are not signed; see D-19), no API tokens, no TLS
  certificates. The one credential it holds is the notification URL above. Every row above is a passphrase or a copy of user data. That is worth preserving: it
  is why this table is short. Re-audit at each release (a checklist-03 side effect) and ask whether
  the release minted anything new.
- **Sanctum is not the system of record.** The phone is. The vault is a verified second copy — which
  is precisely why losing the passphrase is survivable in a way losing the phone plus the vault is
  not.

## Checks

- [ ] Every row has a real second copy — verified by **opening it**, not by believing the table.
- [ ] Nothing in this file is a secret value; it is safe to commit to this repo.
- [ ] Every expiring row has an `OPEN_LOOPS.md` entry. *(None expire today.)*
- [ ] Re-audit at each release: did this release mint a new key, token, or artifact that belongs here?
