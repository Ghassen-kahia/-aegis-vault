# Security policy

AEGIS VAULT stores passwords, so security reports get priority over everything else.

## Status

The project has **not** been independently audited. Until it has, do not store real credentials
in it. The design and its known limitations are documented in:

* [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md): what is and isn't protected, and the known limitations (L-1 … L-11)
* [docs/CRYPTOGRAPHY.md](docs/CRYPTOGRAPHY.md): key hierarchy, file formats, test vectors
* [docs/SECURITY_REQUIREMENTS.md](docs/SECURITY_REQUIREMENTS.md): acceptance criteria and how each is verified
* [docs/AUDIT_SCOPE.md](docs/AUDIT_SCOPE.md): what an independent audit should cover, and how to build and test

## Reporting a vulnerability

Report privately through GitHub: open the repository's **Security** tab and choose
**Report a vulnerability**. Don't open a public issue for security problems.

Please include:

* the version or commit you tested,
* what an attacker needs (file access, code running as the user, physical access…) — see the
  attacker classes T1–T9 in the threat model,
* steps to reproduce, using synthetic credentials only.

You'll get an acknowledgement within 7 days. Fixes for confirmed issues are released before
details are published, and reporters are credited unless they ask not to be.

## In scope

* Anything that reveals vault contents, keys or the master password without the master password
  or Recovery Key
* Undetected modification of a vault or backup file
* Secrets reaching disk, logs, the clipboard after the clear timeout, or the WebView beyond what the
  threat model allows
* Bypassing auto-lock, back-off or re-authentication

## Out of scope

The limitations already documented in the threat model (for example malware running as the user
while the vault is unlocked, or OS copies of memory in the pagefile), unless you show they are
worse than described.
