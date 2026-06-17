# Helix Authentication Service Checker

A small, dependency-free toolkit for the **authorized** security assessment and
asset inventory of [Helix Authentication Service (HAS)](https://www.perforce.com/manuals/helix-auth-svc/)
deployments. Both scripts use only the Python 3.8+ standard library — no
third-party packages required.

> ⚠️ **Use only against hosts you own or are explicitly authorized to assess.**
> These tools are intended for defensive security review, configuration
> hardening, and asset inventory. Unauthorized use against systems you do not
> control may be illegal.

## Scripts

### `has_fingerprint.py`

Fingerprints a HAS deployment and identifies its service version using a range
of passive and active strategies derived from the HAS codebase. It performs
**no exploitation** — it only queries unauthenticated diagnostic surfaces and
performs a single read-only SCIM `GET` using a *public* default token to detect
a default-credential misconfiguration (the same check a vulnerability scanner
performs). No data is created, modified, or deleted.

Version-detection strategies (in order of confidence):

1. `/status` JSON — exact `app_version` + Node/V8/OpenSSL (when `STATUS_ENABLED`)
2. `/admin` static assets — Vite content-hashed bundle names (exact, via hash DB)
3. `/saml/metadata` XML — node-saml / passport-saml structure (range bracketing)
4. Security headers (CSP) — helmet + dynamic form-action (range bracketing)
5. Error / 404 page text — `error.ejs` wording + footer copyright year
6. TLS leaf certificate — detects the bundled sample cert (unhardened install)
7. `/liveness` probe — confirms a HAS-shaped service is present
8. Endpoint timeline — which feature routes are mounted bounds the release

Default / weak configuration checks include detection of the default SCIM
bearer token, default `SESSION_SECRET`, admin token endpoint exposure, and
optional diagnostic surfaces. A finding is only marked **CONFIRMED** when
actively verified.

**Usage:**

```bash
python has_fingerprint.py https://perforce-has.example.com:3000/
python has_fingerprint.py example.com:3000 --insecure --json
python has_fingerprint.py https://host:3000 --timeout 8 --user-agent "asset-scan/1.0"
```

### `scim_create_user.py`

Provisions a user account (with a password) in a HAS deployment via its SCIM
2.0 endpoint, authenticating with the configured SCIM bearer token. HAS
base64-encodes the configured `BEARER_TOKEN` before comparison, so the script
handles that encoding for you — pass the plaintext token via `--token` (or the
`BEARER_TOKEN` env var), or supply the encoded form with `--token-encoded`.

**Usage:**

```bash
python scim_create_user.py https://has.example.com:3000 \
    --token "keyboard cat" \
    --username pparker@example.com \
    --password 'iamSp!derm4n' \
    --given-name Peter --family-name Parker \
    --display-name "Peter Parker" \
    --email pparker@example.com

# token from environment, self-signed cert
BEARER_TOKEN='keyboard cat' python scim_create_user.py https://localhost:3000 \
    --username jdoe@example.com --password 'S3cret!pass' --insecure
```

## Requirements

- Python 3.8 or newer
- No third-party dependencies (standard library only)

## Disclaimer

This software is provided for legitimate security assessment and asset
inventory purposes only. The authors assume no liability for misuse. Always
obtain proper authorization before testing any system.
