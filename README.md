# Helix Authentication Service Checker

A small, dependency-free toolkit for the **authorized** security assessment and
asset inventory of [Helix Authentication Service (HAS)](https://www.perforce.com/manuals/helix-auth-svc/)
deployments. Both scripts use only the Python 3.8+ standard library — no
third-party packages required.

> **Use only against hosts you own or are explicitly authorized to assess.**

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
python has_fingerprint.py https://host:3000 --timeout 8 --user-agent "P4-HAS-SCANNER"
python has_fingerprint.py --targets-file has_targets.json --insecure
python has_fingerprint.py --targets-file has_targets.json --target-index 0 --insecure
python has_fingerprint.py --targets-file has_targets.json --workers 16 --insecure
python has_fingerprint.py --hosts-file hosts.txt --insecure
```

When the positional target is omitted, `has_fingerprint.py` reads
`has_targets.json` from the current directory. Each target record is converted
from its `ip`, `port`, and optional `scheme` fields into the concrete URL to
scan, such as `https://127.0.0.1:443`.
Target-list scans run concurrently by default; tune concurrency with
`--workers`.

For hostname-based input, use `--hosts-file` with one hostname, `host:port`, or
URL per line. Blank lines and lines beginning with `#` are ignored:

```text
host1.example.com
host2.example.com:3000
https://host3.example.com
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
    --username legitimate_user \
    --password 'password123!' \
    --given-name Cat --family-name Dog \
    --display-name "Cat Dog" \
    --email legitimate_user@example.com

python scim_create_user.py https://has.example.com:3000 \
    --token "keyboard cat" \
    --username legitimate_user \
    --password 'password123!' \
    --user-agent "P4-HAS-SCANNER"
```

## Requirements

- Python 3.8 or newer
- No third-party dependencies (standard library only)

## Disclaimer

This software is provided for legitimate security assessment and asset
inventory purposes only. The authors assume no liability for misuse. Always
obtain proper authorization before testing any system.
