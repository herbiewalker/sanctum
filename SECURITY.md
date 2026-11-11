# Security policy

Sanctum handles encrypted backups of sensitive personal data, so security reports are welcome.

**Please do not open a public issue for a vulnerability.** Use GitHub's private reporting instead:
the repository's **Security** tab → **Report a vulnerability**.

Include what you found, how to reproduce it, and the version (shown in the web UI footer once you are
logged in, or in the startup log). This is a one-person hobby project, so expect a reply within a
couple of weeks rather than days. There is no bug bounty.

What is in scope: the Sanctum service, its container image, and the scripts under `deploy/`.
What is a known, accepted limit rather than a vulnerability: see **Known limitations** in the README
and the residual risks in `docs/THREAT_MODEL.md` (for example, Sanctum cannot defend the data against
root on the host while the vault is unlocked).
