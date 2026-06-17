#!/usr/bin/env python3
"""
scim_create_user.py

Provision a user account (with a password) in a Helix Authentication Service
(HAS) deployment via its SCIM 2.0 endpoint, authenticating with the configured
SCIM bearer token.

HAS authenticates SCIM requests with passport-http-bearer using a
BearerTokenStrategy that base64-encodes the configured shared secret
(BEARER_TOKEN) and compares it to the presented bearer value. The client must
therefore send `Authorization: Bearer <base64(plaintext-token)>`. This script
does that encoding for you: pass the plaintext token via --token (or the
BEARER_TOKEN env var) and it base64-encodes it before sending. Use
--token-encoded if you already have the base64 form.

The account is created with a POST to /scim/v2/Users containing a SCIM User
resource including the `password` attribute, which HAS uses to set the P4
password for the provisioned user.

Usage:
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

Requires only the Python 3.8+ standard library (no third-party packages).
"""

from __future__ import annotations

import argparse
import base64
import getpass
import json
import os
import ssl
import sys
import urllib.error
import urllib.request
from typing import Any, Dict, Optional, Tuple
from urllib.parse import urlparse, urlunparse


SCIM_USER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User"
SCIM_CONTENT_TYPE = "application/scim+json"


def normalize_base_url(target: str) -> str:
    """Accept host:port or full URL; return a clean scheme://host[:port] base."""
    if "://" not in target:
        target = "https://" + target
    parsed = urlparse(target)
    if not parsed.netloc:
        raise ValueError(f"could not parse target URL: {target!r}")
    return urlunparse((parsed.scheme, parsed.netloc, "", "", "", "")).rstrip("/")


def encode_token(plaintext: str) -> str:
    """Base64-encode the plaintext bearer token as HAS expects it."""
    return base64.b64encode(plaintext.encode("utf-8")).decode("ascii")


def build_user_payload(args: argparse.Namespace) -> Dict[str, Any]:
    """Construct the SCIM User resource to POST."""
    given = args.given_name or ""
    family = args.family_name or ""
    formatted = (f"{given} {family}").strip() or args.display_name or args.username
    payload: Dict[str, Any] = {
        "schemas": [SCIM_USER_SCHEMA],
        "userName": args.username,
        "name": {
            "formatted": formatted,
            "givenName": given,
            "familyName": family,
        },
        "displayName": args.display_name or formatted,
        "password": args.password,
        "active": True,
    }
    email = args.email or (args.username if "@" in args.username else None)
    if email:
        payload["emails"] = [{"primary": True, "type": "work", "value": email}]
    if args.external_id:
        payload["externalId"] = args.external_id
    return payload


def post_user(base_url: str, encoded_token: str, payload: Dict[str, Any],
              timeout: float, verify_tls: bool, user_agent: str
              ) -> Tuple[Optional[int], Dict[str, str], bytes]:
    """POST the SCIM User resource. Returns (status, headers, body)."""
    url = base_url + "/scim/v2/Users"
    data = json.dumps(payload).encode("utf-8")
    headers = {
        "User-Agent": user_agent,
        "Authorization": f"Bearer {encoded_token}",
        "Accept": SCIM_CONTENT_TYPE,
        "Content-Type": SCIM_CONTENT_TYPE,
    }
    ctx = ssl.create_default_context() if verify_tls else ssl._create_unverified_context()
    req = urllib.request.Request(url, headers=headers, data=data, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            rheaders = {k.lower(): v for k, v in resp.getheaders()}
            return resp.status, rheaders, resp.read()
    except urllib.error.HTTPError as exc:
        rheaders = {k.lower(): v for k, v in exc.headers.items()} if exc.headers else {}
        return exc.code, rheaders, exc.read()
    except urllib.error.URLError as exc:
        raise SystemExit(f"ERROR: request to {url} failed: {exc.reason}")


def parse_args(argv: Optional[list] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Create a HAS user account with a password via SCIM.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("target", help="HAS base URL or host:port (e.g. https://has.example.com:3000)")
    p.add_argument("--token", help="Plaintext SCIM bearer token (or set BEARER_TOKEN env var). "
                                    "Will be base64-encoded before sending.")
    p.add_argument("--token-encoded", help="Already base64-encoded bearer token (sent as-is).")
    p.add_argument("--username", required=True, help="SCIM userName for the new account.")
    p.add_argument("--password", help="Password for the new account. If omitted, you are prompted.")
    p.add_argument("--given-name", help="Given (first) name.")
    p.add_argument("--family-name", help="Family (last) name.")
    p.add_argument("--display-name", help="Display name.")
    p.add_argument("--email", help="Primary work email (defaults to userName if it is an email).")
    p.add_argument("--external-id", help="Optional SCIM externalId.")
    p.add_argument("--timeout", type=float, default=10.0, help="Per-request timeout in seconds.")
    p.add_argument("--insecure", action="store_true", help="Do not verify the TLS certificate.")
    p.add_argument("--user-agent", default="scim-create-user/1.0", help="HTTP User-Agent header.")
    p.add_argument("--json", action="store_true", help="Print the raw JSON response only.")
    return p.parse_args(argv)


def main(argv: Optional[list] = None) -> int:
    args = parse_args(argv)

    try:
        base_url = normalize_base_url(args.target)
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    # Resolve the bearer token (encoded form takes precedence if supplied).
    if args.token_encoded:
        encoded_token = args.token_encoded
    else:
        plaintext = args.token or os.environ.get("BEARER_TOKEN")
        if not plaintext:
            print("ERROR: no bearer token provided. Use --token, --token-encoded, "
                  "or set BEARER_TOKEN.", file=sys.stderr)
            return 2
        encoded_token = encode_token(plaintext)

    # Resolve the password (prompt securely if not supplied on the command line).
    if not args.password:
        args.password = getpass.getpass(f"Password for {args.username}: ")
        if not args.password:
            print("ERROR: a password is required.", file=sys.stderr)
            return 2

    payload = build_user_payload(args)
    status, headers, body = post_user(
        base_url, encoded_token, payload,
        timeout=args.timeout, verify_tls=not args.insecure, user_agent=args.user_agent,
    )

    text = body.decode("utf-8", "replace")
    try:
        parsed = json.loads(text)
        pretty = json.dumps(parsed, indent=2)
    except json.JSONDecodeError:
        parsed = None
        pretty = text

    if args.json:
        print(pretty)
    else:
        if status in (200, 201):
            location = headers.get("location", "")
            user_id = parsed.get("id") if isinstance(parsed, dict) else None
            print(f"SUCCESS: created user '{args.username}' (HTTP {status})")
            if user_id:
                print(f"  id:       {user_id}")
            if location:
                print(f"  location: {location}")
            print(f"  endpoint: {base_url}/scim/v2/Users")
        else:
            print(f"FAILED: HTTP {status} from {base_url}/scim/v2/Users", file=sys.stderr)
            detail = parsed.get("detail") if isinstance(parsed, dict) else None
            if detail:
                print(f"  detail: {detail}", file=sys.stderr)
            print(pretty, file=sys.stderr)

    return 0 if status in (200, 201) else 1


if __name__ == "__main__":
    raise SystemExit(main())
