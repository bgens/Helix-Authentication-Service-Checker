#!/usr/bin/env python3
"""
has_fingerprint.py

Fingerprint a Helix Authentication Service (HAS) deployment and identify its
service version using every passive/active strategy derivable from the HAS
codebase. Intended for asset inventory and authorized security assessment of a
service you operate.

Strategies (in order of confidence):
  1. /status JSON           -> exact app_version + Node/V8/OpenSSL (if STATUS_ENABLED)
  2. /admin static assets   -> Vite content-hashed bundle names (exact, via hash DB)
  3. /saml/metadata XML      -> node-saml/passport-saml structure (range bracketing)
  4. Security headers (CSP)  -> helmet + dynamic form-action (range bracketing)
  5. Error/404 page text     -> error.ejs wording + footer copyright year
  6. TLS leaf certificate    -> detects bundled sample cert (unhardened install)
  7. /liveness probe         -> confirms a HAS-shaped service is present
  8. Endpoint timeline       -> which feature routes are mounted bounds the
                                release from below (e.g. /scim => >=2021.2,
                                /admin => >=2022.2); legacy connect.sid cookie
                                instead of JSESSIONID implies <=2020.1

Default / weak configuration checks (HAS-669/670 and related):
  A. Default SCIM bearer token ("keyboard cat") -> read-only GET on /scim/v2/*,
     PARSED to prove real provisioned identities (shown in full; --mask-identities to redact)
  B. Default SESSION_SECRET                      -> JSESSIONID cookie detection (risk flag)
  C. Admin token endpoint exposure (/tokens)     -> presence + default ADMIN_USERNAME note
  D. Diagnostic surfaces (/status, /validate)    -> enabled optional endpoints

A finding is only marked CONFIRMED when actively verified — the default-token
check requires a parseable SCIM ListResponse (real records or a valid empty
directory), not merely an HTTP 200, so a blank 200 from a proxy is NOT reported
as confirmed.

No exploitation is performed: requests target unauthenticated diagnostic
surfaces, and the only credentialed probe is a read-only SCIM GET using a
PUBLIC default token to detect a default-credential misconfiguration (the same
check a vulnerability scanner performs). No data is created, modified, or
deleted, and no password guessing is attempted. Provisioned identities are
shown in full to demonstrate impact (pass --mask-identities to redact). Use
only against hosts you are authorized to assess.

Usage:
    python has_fingerprint.py https://perforce-has.example.com:3000/
    python has_fingerprint.py example.com:3000 --insecure --json
    python has_fingerprint.py https://host:3000 --timeout 8 --user-agent "asset-scan/1.0"

Requires only the Python 3.8+ standard library (no third-party packages).
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import socket
import ssl
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse, urlunparse


# --------------------------------------------------------------------------- #
# Fingerprint reference data
# --------------------------------------------------------------------------- #
# Map of known asset/byte hashes to HAS release. Populate this over time by
# downloading the admin SPA / static assets from known-version installs and
# recording sha256 of the referenced bundle files. Empty by default so the tool
# degrades gracefully to range-bracketing strategies.
#
#   "<sha256-hex>": "2025.2"
KNOWN_ASSET_HASHES: Dict[str, str] = {
    # "e3b0c44298fc1c149afbf4c8996fb924...": "2025.1",
}

# Substrings that strongly indicate the target is a HAS instance at all.
HAS_INDICATORS = (
    "P4 Authentication Service",
    "Authentication Service",
    "Perforce Software",
    "no_strategy",
    "Check the service logs",
)

# Default HAS view artifacts (anchors verified against the repo views/*.ejs).
ERROR_DETAIL_MARKER = "Check the service logs"
FOOTER_COPYRIGHT_RE = re.compile(r"Copyright\s+&copy;\s+(\d{4})\s+<a[^>]*>Perforce Software")
SERVICE_TITLE = "P4 Authentication Service"

# --- Default / weak configuration reference data ------------------------------
# Well-known default secrets shipped in defaults.env / example.* (HAS-669/670).
# The SCIM BearerTokenStrategy base64-encodes the configured shared secret and
# compares it to the presented bearer token, so the client sends base64(plain).
DEFAULT_BEARER_TOKENS = (
    "keyboard cat",   # defaults.env BEARER_TOKEN / example.env (uncommented)
)

# Well-known default SESSION_SECRET (defaults.env). Cannot be confirmed remotely
# without a pre-existing valid session, but its presence is a documented risk.
DEFAULT_SESSION_SECRET = "keyboard cat"

# Default admin account name (defaults.env ADMIN_USERNAME). Not a secret, but a
# predictable username paired with a weak password is a common weakness.
DEFAULT_ADMIN_USERNAME = "perforce"

# SHA-256 of the bundled sample server certificate (certs/server.crt) and its
# distinctive subject/issuer CNs. A live leaf matching these means the operator
# never replaced the shipped key pair (private key is public in the distro).
SAMPLE_CERT_SHA256 = "4e0cdc2c2237188d55edb99e09dca38763680cbd4ee46ce5ae34a0932cc6de1c"
SAMPLE_CERT_SUBJECT_CN = "authen.doc"
SAMPLE_CERT_ISSUER_CN = "FakeAuthority"
SESSION_COOKIE_NAME = "JSESSIONID"

# Pre-2020.2 builds used the Express-session default cookie name. Observing this
# instead of JSESSIONID places the instance before the Sep-2020 cookie rename.
LEGACY_SESSION_COOKIE_NAME = "connect.sid"

# --- Endpoint introduction timeline (derived from upstream commit history) ----
# Each entry bounds the version from BELOW: if the endpoint is served, the
# instance is at least the mapped release. Dates/commits are the upstream change
# where the route first appeared (see git log of helix-authentication-service).
# Probing is read-only GETs; auth-gated routes still reveal presence via status.
#
#   (path, floor_version, introduced_date, commit, note)
ENDPOINT_TIMELINE = (
    ("/oidc/.well-known/openid-configuration", "2019.1", "2019-02-06", "00006",
     "OIDC provider — earliest core feature"),
    ("/saml/metadata", "2019.1", "2019-02-07", "00017", "SAML SP/IdP support"),
    ("/requests/status", "2019.1", "2019-02-11", "00038", "login request tracking"),
    ("/scim/v2/Users", "2021.2", "2021-10-13", "00610",
     "SCIM user/group provisioning (introduces BEARER_TOKEN)"),
    ("/oauth/token", "2021.2", "2021-10-28", "00648", "OAuth token endpoint"),
    ("/status", "2021.2", "2021-11-05", "00670",
     "status page (exposes versions when STATUS_ENABLED)"),
    ("/admin/", "2022.2", "2022-06-27", "00751",
     "web admin SPA (feature-flagged ADMIN_ENABLED from commit 00756)"),
)

# Ordering of release floors so we can pick the highest satisfied bound.
RELEASE_ORDER = ("2019.1", "2020.1", "2020.2", "2021.1", "2021.2", "2022.1",
                 "2022.2", "2023.1", "2024.1", "2025.1", "2025.2")


# --------------------------------------------------------------------------- #
# Result model
# --------------------------------------------------------------------------- #
@dataclass
class Evidence:
    strategy: str
    confidence: str            # "exact" | "range" | "weak" | "none"
    detail: str
    version: Optional[str] = None
    version_range: Optional[str] = None
    raw: Optional[Any] = None


@dataclass
class Finding:
    id: str
    severity: str              # "critical" | "high" | "medium" | "low" | "info"
    title: str
    detail: str
    confirmed: bool = False    # True = actively verified, False = heuristic/cannot confirm
    remediation: str = ""
    raw: Optional[Any] = None


SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


@dataclass
class Report:
    target: str
    base_url: str
    reachable: bool = False
    is_has: bool = False
    best_version: Optional[str] = None
    best_confidence: str = "none"
    evidence: List[Evidence] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    generated_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def add(self, ev: Evidence) -> None:
        self.evidence.append(ev)

    def add_finding(self, f: Finding) -> None:
        self.findings.append(f)

    def max_confirmed_severity(self) -> str:
        worst = "info"
        for f in self.findings:
            if f.confirmed and SEVERITY_RANK.get(f.severity, 0) > SEVERITY_RANK.get(worst, 0):
                worst = f.severity
        return worst

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        return d


# --------------------------------------------------------------------------- #
# HTTP helpers
# --------------------------------------------------------------------------- #
class HttpClient:
    def __init__(self, timeout: float, verify_tls: bool, user_agent: str):
        self.timeout = timeout
        self.user_agent = user_agent
        if verify_tls:
            self.ctx = ssl.create_default_context()
        else:
            self.ctx = ssl._create_unverified_context()

    def request(self, method: str, url: str,
                headers: Optional[Dict[str, str]] = None,
                data: Optional[bytes] = None,
                ) -> Tuple[Optional[int], Dict[str, str], bytes]:
        """Return (status, headers, body). status is None on transport failure."""
        hdrs = {"User-Agent": self.user_agent}
        if headers:
            hdrs.update(headers)
        req = urllib.request.Request(url, headers=hdrs, data=data, method=method)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=self.ctx) as resp:
                rheaders = {k.lower(): v for k, v in resp.getheaders()}
                body = resp.read(2_000_000)  # cap body at ~2MB
                return resp.status, rheaders, body
        except urllib.error.HTTPError as e:
            rheaders = {k.lower(): v for k, v in (e.headers.items() if e.headers else [])}
            try:
                body = e.read(2_000_000)
            except Exception:
                body = b""
            return e.code, rheaders, body
        except (urllib.error.URLError, socket.timeout, ConnectionError, OSError):
            return None, {}, b""

    def get(self, url: str) -> Tuple[Optional[int], Dict[str, str], bytes]:
        return self.request("GET", url)


# --------------------------------------------------------------------------- #
# URL normalization
# --------------------------------------------------------------------------- #
def normalize_base(target: str) -> str:
    """Accepts host:port, scheme://host:port, etc. Returns scheme://host:port."""
    raw = target.strip()
    if "://" not in raw:
        # default to https since HAS is TLS-first; http will be retried by caller
        raw = "https://" + raw
    parsed = urlparse(raw)
    scheme = parsed.scheme or "https"
    netloc = parsed.netloc or parsed.path
    return urlunparse((scheme, netloc, "", "", "", "")).rstrip("/")


def swap_scheme(base_url: str, scheme: str) -> str:
    parsed = urlparse(base_url)
    return urlunparse((scheme, parsed.netloc, "", "", "", "")).rstrip("/")


# --------------------------------------------------------------------------- #
# Strategy 1: /status JSON (exact)
# --------------------------------------------------------------------------- #
def probe_status(client: HttpClient, base: str, report: Report) -> None:
    url = base + "/status"
    status, _headers, body = client.get(url)
    if status is None:
        return
    if status != 200 or not body:
        report.add(Evidence(
            strategy="status_endpoint",
            confidence="none",
            detail=f"/status returned HTTP {status} (likely STATUS_ENABLED=false)",
        ))
        return
    try:
        data = json.loads(body.decode("utf-8", "replace"))
    except json.JSONDecodeError:
        return
    app_version = data.get("app_version")
    versions = data.get("versions") or {}
    runtime = []
    for k in ("node", "v8", "openssl"):
        if k in versions:
            runtime.append(f"{k}={versions[k]}")
    detail = "/status exposed app_version directly"
    if runtime:
        detail += " (" + ", ".join(runtime) + ")"
    if app_version:
        report.is_has = True
        report.add(Evidence(
            strategy="status_endpoint",
            confidence="exact",
            detail=detail,
            version=str(app_version),
            raw={"versions": versions, "uptime": data.get("uptime")},
        ))


# --------------------------------------------------------------------------- #
# Strategy 2: /admin static asset hashes (exact via hash DB)
# --------------------------------------------------------------------------- #
ASSET_REF_RE = re.compile(r'(?:src|href)\s*=\s*["\']([^"\']+\.(?:js|css))["\']', re.I)


def probe_admin_assets(client: HttpClient, base: str, report: Report) -> None:
    index_status, _h, index_body = client.get(base + "/admin/")
    if index_status is None or index_status >= 400 or not index_body:
        report.add(Evidence(
            strategy="admin_assets",
            confidence="none",
            detail=f"/admin/ not served (HTTP {index_status}); ADMIN_ENABLED likely false",
        ))
        return
    html = index_body.decode("utf-8", "replace")
    refs = ASSET_REF_RE.findall(html)
    if not refs:
        report.add(Evidence(
            strategy="admin_assets",
            confidence="weak",
            detail="/admin/ served but no hashed asset references found",
        ))
        return
    report.is_has = True
    matched_version: Optional[str] = None
    hashed_assets: List[str] = []
    for ref in refs:
        asset_url = ref if ref.startswith("http") else base + ("" if ref.startswith("/") else "/admin/") + ref.lstrip("/")
        a_status, _ah, a_body = client.get(asset_url)
        if a_status == 200 and a_body:
            digest = hashlib.sha256(a_body).hexdigest()
            hashed_assets.append(f"{ref} -> {digest[:16]}…")
            if digest in KNOWN_ASSET_HASHES:
                matched_version = KNOWN_ASSET_HASHES[digest]
    if matched_version:
        report.add(Evidence(
            strategy="admin_assets",
            confidence="exact",
            detail="admin SPA asset hash matched known release",
            version=matched_version,
            raw=hashed_assets,
        ))
    else:
        report.add(Evidence(
            strategy="admin_assets",
            confidence="weak",
            detail="admin SPA present; asset hashes not in local DB (add them to KNOWN_ASSET_HASHES)",
            raw=hashed_assets,
        ))


# --------------------------------------------------------------------------- #
# Strategy 3: SAML metadata structure (range)
# --------------------------------------------------------------------------- #
def probe_saml_metadata(client: HttpClient, base: str, report: Report) -> None:
    found_any = False
    for path in ("/saml/metadata", "/saml/idp/metadata"):
        status, headers, body = client.get(base + path)
        if status == 200 and body and b"EntityDescriptor" in body:
            found_any = True
            report.is_has = True
            xml = body.decode("utf-8", "replace")
            signals = []
            if "has.example.com" in xml:
                signals.append("default SAML_SP_ENTITY_ID (unconfigured issuer)")
            if "WantAuthnRequestsSigned" in xml:
                signals.append("WantAuthnRequestsSigned present")
            # node-saml v5 emits md: prefixed elements; older emits unprefixed
            ns_style = "md:-prefixed (node-saml v5.x style)" if "md:EntityDescriptor" in xml else "unprefixed elements"
            signals.append(ns_style)
            report.add(Evidence(
                strategy="saml_metadata",
                confidence="range",
                detail=f"{path}: " + "; ".join(signals),
                version_range="2024.x–2025.x (node-saml v5 family)" if "md:EntityDescriptor" in xml else "<=2023.x range",
                raw={"content_type": headers.get("content-type")},
            ))
    if not found_any:
        report.add(Evidence(
            strategy="saml_metadata",
            confidence="none",
            detail="no SAML SP/IdP metadata served",
        ))


# --------------------------------------------------------------------------- #
# Strategy 4: Security headers / CSP (range)
# --------------------------------------------------------------------------- #
def probe_headers(client: HttpClient, base: str, report: Report) -> None:
    status, headers, _body = client.get(base + "/")
    if status is None:
        return
    csp = headers.get("content-security-policy")
    signals = []
    if csp:
        signals.append("CSP present")
        if "form-action" in csp:
            signals.append("dynamic form-action directive (HAS-generated)")
    helmet_markers = [h for h in (
        "x-dns-prefetch-control", "x-content-type-options",
        "x-download-options", "x-frame-options",
        "strict-transport-security", "x-permitted-cross-domain-policies",
    ) if h in headers]
    if helmet_markers:
        signals.append(f"helmet header set ({len(helmet_markers)} markers)")
    powered = headers.get("x-powered-by")
    if powered is None:
        signals.append("X-Powered-By suppressed (consistent with helmet/HAS)")
    if signals:
        report.add(Evidence(
            strategy="security_headers",
            confidence="range",
            detail="; ".join(signals),
            raw={"content-security-policy": csp, "server": headers.get("server")},
        ))
        if csp and "form-action" in csp:
            report.is_has = True
    else:
        report.add(Evidence(
            strategy="security_headers",
            confidence="none",
            detail="no distinctive helmet/CSP headers observed",
        ))


# --------------------------------------------------------------------------- #
# Strategy 5: Error / footer page text (weak/range)
# --------------------------------------------------------------------------- #
def probe_error_and_footer(client: HttpClient, base: str, report: Report) -> None:
    # Trigger a 404 to render error.ejs
    status, _h, body = client.get(base + "/this-path-should-not-exist-" + hashlib.md5(base.encode()).hexdigest()[:8])
    text = body.decode("utf-8", "replace") if body else ""
    found = False
    if ERROR_DETAIL_MARKER in text:
        report.is_has = True
        found = True
        report.add(Evidence(
            strategy="error_page",
            confidence="weak",
            detail=f"error.ejs marker present: '{ERROR_DETAIL_MARKER}'",
        ))
    # Home page footer copyright year hints at release year
    h_status, _hh, h_body = client.get(base + "/")
    h_text = h_body.decode("utf-8", "replace") if h_body else ""
    if SERVICE_TITLE in h_text:
        report.is_has = True
        found = True
    m = FOOTER_COPYRIGHT_RE.search(h_text)
    if m:
        year = m.group(1)
        report.add(Evidence(
            strategy="footer_copyright",
            confidence="range",
            detail=f"footer copyright year {year} (≈ release {year}.x)",
            version_range=f"{year}.x",
        ))
        found = True
    if not found:
        report.add(Evidence(
            strategy="error_page",
            confidence="none",
            detail="no HAS-specific page text observed",
        ))


# --------------------------------------------------------------------------- #
# Strategy 6: TLS leaf certificate (weak; detects bundled sample cert)
# --------------------------------------------------------------------------- #
def fetch_tls_leaf(base: str, timeout: float
                   ) -> Tuple[Optional[bytes], Optional[Dict[str, Any]]]:
    parsed = urlparse(base)
    if parsed.scheme != "https":
        return None, None
    host = parsed.hostname
    port = parsed.port or 443
    try:
        ctx = ssl._create_unverified_context()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                der = ssock.getpeercert(binary_form=True)
                cert = ssock.getpeercert()
        return der, cert
    except (OSError, ssl.SSLError):
        return None, None


def probe_tls_cert(base: str, timeout: float, report: Report) -> None:
    der, cert = fetch_tls_leaf(base, timeout)
    if not der:
        return
    fp = hashlib.sha256(der).hexdigest()
    subject = _name_to_str(cert.get("subject")) if cert else "(unverified)"
    issuer = _name_to_str(cert.get("issuer")) if cert else "(unverified)"
    detail = f"TLS leaf sha256={fp[:24]}…; subject={subject}; issuer={issuer}"

    # Exact match against the bundled sample certificate shipped in the repo.
    exact_sample = fp == SAMPLE_CERT_SHA256
    cn_sample = (SAMPLE_CERT_SUBJECT_CN in (subject or "")) and (SAMPLE_CERT_ISSUER_CN in (issuer or ""))
    looks_sample = exact_sample or cn_sample

    report.add(Evidence(
        strategy="tls_certificate",
        confidence="weak",
        detail=detail + ("  [BUNDLED SAMPLE CERT — unhardened install]" if looks_sample else ""),
        raw={"sha256": fp, "matches_sample": exact_sample, "sample_cn_match": cn_sample},
    ))

    if looks_sample:
        report.add_finding(Finding(
            id="HAS-SAMPLE-TLS-CERT",
            severity="high",
            title="Bundled sample TLS certificate in use",
            detail=(
                ("Live leaf SHA-256 exactly matches the distribution's certs/server.crt. "
                 if exact_sample else
                 f"Live leaf subject/issuer match the sample cert (CN={SAMPLE_CERT_SUBJECT_CN}, "
                 f"issuer={SAMPLE_CERT_ISSUER_CN}). ")
                + "The matching private key (certs/server.key) ships publicly in the HAS "
                  "distribution, so TLS provides no real confidentiality/authenticity."
            ),
            confirmed=exact_sample,
            remediation="Replace CERT_FILE/KEY_FILE with a certificate from a trusted CA and rotate the key.",
            raw={"sha256": fp},
        ))
        report.notes.append(
            "TLS leaf resembles the bundled sample certificate (default CERT_FILE). "
            "Such installs commonly also retain other defaults — see findings."
        )


def _name_to_str(name_seq) -> str:
    if not name_seq:
        return ""
    parts = []
    for rdn in name_seq:
        for k, v in rdn:
            if k in ("commonName", "organizationName"):
                parts.append(f"{k}={v}")
    return ", ".join(parts)


# --------------------------------------------------------------------------- #
# Strategy 7: /liveness existence probe (presence only)
# --------------------------------------------------------------------------- #
def probe_liveness(client: HttpClient, base: str, report: Report) -> None:
    status, _h, _b = client.get(base + "/liveness")
    if status in (200, 500):
        # /liveness exists in all HAS versions and returns a bare status code
        report.add(Evidence(
            strategy="liveness",
            confidence="weak",
            detail=f"/liveness present (HTTP {status}) — HAS-shaped health endpoint",
        ))
        report.is_has = True


# --------------------------------------------------------------------------- #
# Strategy 8: endpoint introduction timeline (range floor)
# --------------------------------------------------------------------------- #
def _release_index(version: str) -> int:
    try:
        return RELEASE_ORDER.index(version)
    except ValueError:
        return -1


def probe_endpoint_timeline(client: HttpClient, base: str, report: Report) -> None:
    """Bound the version from below by which feature endpoints are served.

    A route that exists only from release X onward means: if we see it, the
    instance is >= X. We take the highest such floor across all present routes.
    Any response other than a 404 from the catch-all (incl. auth-gated 401/403)
    counts as "route mounted".
    """
    present: List[Tuple[str, str, str, str]] = []  # (path, floor, date, commit)
    for path, floor, date, commit, _note in ENDPOINT_TIMELINE:
        status, _h, _b = client.get(base + path)
        if status is None or status == 404:
            continue
        present.append((path, floor, date, commit))

    if not present:
        report.add(Evidence(
            strategy="endpoint_timeline",
            confidence="none",
            detail="no version-distinguishing endpoints responded",
        ))
        return

    report.is_has = True
    best = max(present, key=lambda p: _release_index(p[1]))
    floor = best[1]
    served = ", ".join(
        f"{p[0]} (\u2265{p[1]})"
        for p in sorted(present, key=lambda p: _release_index(p[1]))
    )
    report.add(Evidence(
        strategy="endpoint_timeline",
        confidence="range",
        detail=f"served endpoints imply release floor \u2265 {floor}  [{served}]",
        version_range=f">= {floor}",
        raw={"floor": floor, "floor_since": best[2], "floor_commit": best[3],
             "present": [p[0] for p in present]},
    ))


# --------------------------------------------------------------------------- #
# Config check A: default SCIM bearer token ("keyboard cat")  [active, read-only]
# --------------------------------------------------------------------------- #
def build_repro(base: str, path: str, plain: str, encoded: str) -> Dict[str, str]:
    """Produce copy-paste reproductions devs can run to independently validate.

    The SCIM BearerTokenStrategy base64-encodes the configured shared secret and
    compares it to the presented bearer token, so the client must send the
    base64 of the plaintext default token. Both forms are documented here.
    """
    url = base + path
    curl = (
        f"curl -sk -i '{url}' "
        f"-H 'Accept: application/scim+json' "
        f"-H 'Authorization: Bearer {encoded}'"
    )
    powershell = (
        "Invoke-WebRequest -SkipCertificateCheck -Uri "
        f"'{url}' -Headers @{{ 'Authorization' = 'Bearer {encoded}'; "
        "'Accept' = 'application/scim+json' }"
    )
    http_raw = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {urlparse(base).netloc}\r\n"
        f"Authorization: Bearer {encoded}\r\n"
        "Accept: application/scim+json\r\n"
        "Connection: close\r\n\r\n"
    )
    return {
        "note": (f"Default token plaintext is '{plain}'; the service expects it base64-encoded "
                 f"as the bearer value ('{encoded}'). Expected result: HTTP 200 + SCIM "
                 "ListResponse. After remediation this must return 401."),
        "curl": curl,
        "powershell": powershell,
        "http_request": http_raw,
        "expected_before_fix": "HTTP 200 application/scim+json (auth bypass)",
        "expected_after_fix": "HTTP 401 Unauthorized",
    }


def capture_exchange(url: str, plain: str, encoded: str,
                     status: int, headers: Dict[str, str], body: bytes,
                     body_cap: int = 8000) -> Dict[str, Any]:
    """Capture the exact request/response so the finding is self-evidencing."""
    text = body.decode("utf-8", "replace")
    pretty = text
    try:
        pretty = json.dumps(json.loads(text), indent=2)
    except json.JSONDecodeError:
        pass
    truncated = len(pretty) > body_cap
    return {
        "request": {
            "method": "GET",
            "url": url,
            "headers": {
                "Authorization": f"Bearer {encoded}",
                "Accept": "application/scim+json",
            },
            "default_token_plaintext": plain,
        },
        "response": {
            "status": status,
            "headers": {k: headers.get(k) for k in (
                "content-type", "www-authenticate", "date", "content-length") if k in headers},
            "body": pretty[:body_cap] + ("\n…[truncated]" if truncated else ""),
            "body_sha256": hashlib.sha256(body).hexdigest(),
            "body_truncated": truncated,
        },
        "captured_at": datetime.now(timezone.utc).isoformat(),
    }


def _mask(value: Optional[str], reveal: bool) -> str:
    """Redact PII unless reveal=True (default shows full values for impact demo)."""
    if value is None:
        return ""
    s = str(value)
    if reveal:
        return s
    if "@" in s:  # email: keep first char of local part + domain
        local, _, domain = s.partition("@")
        head = local[:1] if local else ""
        return f"{head}***@{domain}"
    if len(s) <= 2:
        return s[:1] + "*"
    return s[:2] + "*" * max(1, len(s) - 3) + s[-1]


def _summarize_scim(body: bytes, reveal: bool) -> Optional[Dict[str, Any]]:
    """Parse a SCIM ListResponse and extract proof. Returns None if not SCIM."""
    try:
        data = json.loads(body.decode("utf-8", "replace"))
    except (json.JSONDecodeError, AttributeError):
        return None
    schemas = data.get("schemas") or []
    is_list = any("ListResponse" in s for s in schemas) or "Resources" in data
    if not is_list:
        return None
    resources = data.get("Resources") or []
    total = data.get("totalResults", len(resources))
    samples = []
    for r in resources[:100]:
        if not isinstance(r, dict):
            continue
        emails = r.get("emails") or []
        email = ""
        if emails and isinstance(emails[0], dict):
            email = emails[0].get("value", "")
        samples.append({
            "id": _mask(r.get("id"), reveal),
            "userName": _mask(r.get("userName"), reveal),
            "displayName": _mask(r.get("displayName"), reveal),
            "email": _mask(email, reveal),
            "active": r.get("active"),
        })
    return {"totalResults": total, "returned": len(resources), "samples": samples}


def check_default_bearer_token(client: HttpClient, base: str, report: Report,
                               reveal: bool = True) -> None:
    """List SCIM resources using the well-known default BEARER_TOKEN and, on
    success, parse the response to prove real identities are exposed.

    Non-destructive: only HTTP GET (no create/modify/delete). Proof requires a
    parseable SCIM ListResponse, not merely an HTTP 200, so a bare/blank 200 from
    a proxy will NOT be reported as confirmed. Identities are shown in full by
    default to demonstrate impact; pass reveal=False to redact.
    """
    tested: List[str] = []
    for plain in DEFAULT_BEARER_TOKENS:
        encoded = base64.b64encode(plain.encode("utf-8")).decode("ascii")
        for path in ("/scim/v2/Users", "/scim/v2/Groups"):
            status, rheaders, body = client.request(
                "GET", base + path,
                headers={
                    "Authorization": "Bearer " + encoded,
                    "Accept": "application/scim+json",
                },
            )
            tested.append(f"{path}<='{plain}'=>{status}")
            if status != 200 or not body:
                continue

            # Build the reproducible evidence bundle for this exact exchange.
            repro = build_repro(base, path, plain, encoded)
            evidence = capture_exchange(base + path, plain, encoded,
                                        status, rheaders, body)

            summary = _summarize_scim(body, reveal)
            if summary is None:
                # 200 but the body is not a SCIM ListResponse: do not over-claim.
                report.add_finding(Finding(
                    id="HAS-DEFAULT-BEARER",
                    severity="medium",
                    title="Default SCIM token returned HTTP 200 (unverified)",
                    detail=(f"{path} returned 200 with the default token '{plain}', but the body "
                            "was not a parseable SCIM ListResponse, so identity exposure is "
                            "not confirmed. Inspect manually."),
                    confirmed=False,
                    remediation="Replace the default BEARER_TOKEN and rotate it.",
                    raw={"endpoint": path,
                         "body_prefix": body[:200].decode("utf-8", "replace"),
                         "repro": repro, "evidence": evidence},
                ))
                return

            report.is_has = True
            total = summary["totalResults"]
            if summary["returned"] > 0:
                # Real provisioned records were read back — definitive proof.
                kind = "users" if "Users" in path else "groups"
                proof_lines = "; ".join(
                    f"{s['userName'] or s['displayName'] or s['id']}"
                    + (f" <{s['email']}>" if s['email'] else "")
                    + (f" active={s['active']}" if s['active'] is not None else "")
                    for s in summary["samples"][:10]
                )
                if summary["returned"] > 10:
                    proof_lines += f"; … (+{summary['returned'] - 10} more in --json raw)"
                report.add_finding(Finding(
                    id="HAS-DEFAULT-BEARER",
                    severity="critical",
                    title="Default SCIM bearer token exposes provisioned identities",
                    detail=(f"{path} returned HTTP 200 using the public default BEARER_TOKEN "
                            f"'{plain}' and yielded {total} {kind}. Sample"
                            f"{' (masked)' if not reveal else ''}: {proof_lines}. Anyone with "
                            "the default token can read the full provisioning directory and "
                            "create/disable users."),
                    confirmed=True,
                    remediation=("Set a unique BEARER_TOKEN_FILE / PROVISIONING token, never copy "
                                 "example.env's uncommented 'keyboard cat', and rotate it."),
                    raw={"endpoint": path, "totalResults": total,
                         "returned": summary["returned"], "samples": summary["samples"],
                         "masked": not reveal, "repro": repro, "evidence": evidence},
                ))
                return
            else:
                # Valid SCIM response but the directory is empty: auth bypass is
                # still proven (token accepted), there is just nothing to read.
                report.add_finding(Finding(
                    id="HAS-DEFAULT-BEARER",
                    severity="high",
                    title="Default SCIM bearer token accepted (directory empty)",
                    detail=(f"{path} accepted the default token '{plain}' and returned a valid "
                            f"SCIM ListResponse with totalResults={total}. Authentication is "
                            "bypassed; no identities are currently provisioned at this endpoint "
                            f"(try the other SCIM collection / provider domains). The bypass "
                            "itself is proven and repeatable via the attached repro."),
                    confirmed=True,
                    remediation=("Set a unique BEARER_TOKEN_FILE / PROVISIONING token and rotate it."),
                    raw={"endpoint": path, "totalResults": total,
                         "repro": repro, "evidence": evidence},
                ))
                return
    # All attempts rejected — record a reassuring informational finding.
    report.add_finding(Finding(
        id="HAS-DEFAULT-BEARER",
        severity="info",
        title="Default SCIM bearer token rejected",
        detail="SCIM endpoints rejected the known default token(s): " + "; ".join(tested[:4]),
        confirmed=False,
    ))


# --------------------------------------------------------------------------- #
# Config check B: default SESSION_SECRET ("keyboard cat")  [detection only]
# --------------------------------------------------------------------------- #
def check_default_session_secret(client: HttpClient, base: str, report: Report) -> None:
    """Detect the express-session cookie and flag the default-secret risk.

    NOTE: SESSION_SECRET cannot be confirmed over the network without an existing
    valid session, because express-session regenerates the session id whether the
    presented cookie signature is valid-but-unknown or invalid. We therefore only
    detect the cookie and surface the documented risk rather than claim a forge.
    """
    status, headers, _b = client.get(base + "/")
    set_cookie = headers.get("set-cookie", "") if status is not None else ""
    has_session_cookie = SESSION_COOKIE_NAME in set_cookie
    legacy_cookie = LEGACY_SESSION_COOKIE_NAME in set_cookie
    if legacy_cookie and not has_session_cookie:
        # Express-session default name was replaced by JSESSIONID in Sep-2020
        # (commit 00413). Observing it places the build before 2020.2.
        report.is_has = True
        report.add(Evidence(
            strategy="session_cookie",
            confidence="range",
            detail=f"legacy '{LEGACY_SESSION_COOKIE_NAME}' cookie — pre-2020.2 build "
                   "(cookie renamed to JSESSIONID in 2020.2)",
            version_range="<= 2020.1",
        ))
    if has_session_cookie:
        report.is_has = True
        flags = []
        low = set_cookie.lower()
        for flag in ("httponly", "secure", "samesite=none", "samesite=lax", "samesite=strict"):
            if flag in low:
                flags.append(flag)
        report.add_finding(Finding(
            id="HAS-DEFAULT-SESSION-SECRET",
            severity="medium",
            title="Session cookie present — verify SESSION_SECRET is not the default",
            detail=(f"Server issues '{SESSION_COOKIE_NAME}' (flags: {', '.join(flags) or 'none'}). "
                    "If SESSION_SECRET is the well-known default 'keyboard cat' (defaults.env), "
                    "session cookies can be forged. This cannot be confirmed remotely; verify "
                    "the deployed configuration locally."),
            confirmed=False,
            remediation=("Ensure SESSION_SECRET is a unique random value (the configure script "
                         "auto-generates one; manual/container installs must set it explicitly)."),
            raw={"set_cookie_sample": set_cookie[:200]},
        ))


# --------------------------------------------------------------------------- #
# Config check C: admin API exposure + default username  [detection only]
# --------------------------------------------------------------------------- #
def check_admin_surface(client: HttpClient, base: str, report: Report) -> None:
    """Detect whether the admin token endpoint is mounted (ADMIN_ENABLED).

    Sends an *invalid* grant (empty body) only to distinguish 404 (admin off)
    from 400/401 (admin on). Does NOT submit any credentials or guess passwords.
    """
    status, _h, _b = client.request(
        "POST", base + "/tokens",
        headers={"Content-Type": "application/json"},
        data=b"{}",
    )
    if status is None:
        return
    if status == 404:
        return  # admin disabled — nothing exposed
    # 400 (invalid grant_type) or 401 means the endpoint exists and is reachable.
    if status in (400, 401, 415, 429):
        report.is_has = True
        report.add_finding(Finding(
            id="HAS-ADMIN-EXPOSED",
            severity="medium",
            title="Admin token endpoint reachable",
            detail=(f"POST /tokens responded HTTP {status} (not 404), so ADMIN_ENABLED is on and "
                    f"the admin login API is network-reachable. The default ADMIN_USERNAME is "
                    f"'{DEFAULT_ADMIN_USERNAME}'; a weak/default admin password would grant full "
                    "configuration control (read/write of all settings and provider secrets)."),
            confirmed=True,
            remediation=("Restrict /admin and /tokens to internal networks / client-cert at the "
                         "reverse proxy, use a strong admin password, and disable ADMIN_ENABLED if unused."),
            raw={"status": status},
        ))


# --------------------------------------------------------------------------- #
# Config check D: diagnostic surfaces enabled (/validate, /status)  [detection]
# --------------------------------------------------------------------------- #
def check_exposed_surfaces(client: HttpClient, base: str, report: Report) -> None:
    enabled: List[str] = []

    # /status (STATUS_ENABLED) — already probed for version; re-flag as surface.
    s_status, _sh, s_body = client.get(base + "/status")
    if s_status == 200 and s_body and b"app_version" in s_body:
        enabled.append("/status (STATUS_ENABLED) — leaks version + Node/OpenSSL")

    # /validate/swarm (VALIDATE_ENABLED): POST with wrong content-type returns a
    # 400 "must be multipart/form-data" when mounted, vs 404 when disabled.
    v_status, _vh, v_body = client.request(
        "POST", base + "/validate/swarm",
        headers={"Content-Type": "application/json"},
        data=b"{}",
    )
    if v_status == 400 and v_body and b"multipart/form-data" in v_body:
        enabled.append("/validate (VALIDATE_ENABLED) — config-diagnostic surface")

    if enabled:
        report.is_has = True
        report.add_finding(Finding(
            id="HAS-DIAG-SURFACES",
            severity="low",
            title="Diagnostic/config surfaces enabled",
            detail="Publicly reachable optional surfaces: " + "; ".join(enabled),
            confirmed=True,
            remediation="Disable unused diagnostic endpoints or restrict them at the proxy.",
            raw={"surfaces": enabled},
        ))


# --------------------------------------------------------------------------- #
# Orchestration
# --------------------------------------------------------------------------- #
def reachable(client: HttpClient, base: str) -> bool:
    for path in ("/liveness", "/"):
        status, _h, _b = client.get(base + path)
        if status is not None:
            return True
    return False


def consolidate(report: Report) -> None:
    """Pick the highest-confidence version statement."""
    rank = {"exact": 3, "range": 2, "weak": 1, "none": 0}
    best: Optional[Evidence] = None
    for ev in report.evidence:
        if ev.version or ev.version_range:
            if best is None or rank.get(ev.confidence, 0) > rank.get(best.confidence, 0):
                best = ev
    if best:
        report.best_version = best.version or best.version_range
        report.best_confidence = best.confidence
    for ind in HAS_INDICATORS:
        for ev in report.evidence:
            if ev.detail and ind in ev.detail:
                report.is_has = True


def run(target: str, timeout: float, verify_tls: bool, user_agent: str,
        try_http_fallback: bool = True, cred_tests: bool = True,
        reveal_identities: bool = True) -> Report:
    base = normalize_base(target)
    report = Report(target=target, base_url=base)
    client = HttpClient(timeout=timeout, verify_tls=verify_tls, user_agent=user_agent)

    if not reachable(client, base):
        # retry over http if https failed and user gave bare host
        if try_http_fallback and urlparse(base).scheme == "https":
            http_base = swap_scheme(base, "http")
            if reachable(client, http_base):
                base = http_base
                report.base_url = base
                report.notes.append("HTTPS unreachable; fell back to HTTP.")
            else:
                report.notes.append("Target unreachable over HTTPS and HTTP.")
                return report
        else:
            report.notes.append("Target unreachable.")
            return report

    report.reachable = True

    # Version fingerprinting strategies (each independent / best-effort).
    probe_status(client, base, report)
    probe_admin_assets(client, base, report)
    probe_saml_metadata(client, base, report)
    probe_headers(client, base, report)
    probe_error_and_footer(client, base, report)
    probe_liveness(client, base, report)
    probe_endpoint_timeline(client, base, report)
    probe_tls_cert(base, timeout, report)
    # Default / weak configuration checks.
    if cred_tests:
        check_default_bearer_token(client, base, report, reveal=reveal_identities)
    check_default_session_secret(client, base, report)
    check_admin_surface(client, base, report)
    check_exposed_surfaces(client, base, report)

    consolidate(report)
    return report


# --------------------------------------------------------------------------- #
# Output
# --------------------------------------------------------------------------- #
def print_human(report: Report) -> None:
    line = "=" * 70
    print(line)
    print(f"HAS fingerprint report  ({report.generated_at})")
    print(f"Target      : {report.target}")
    print(f"Base URL    : {report.base_url}")
    print(f"Reachable   : {report.reachable}")
    print(f"Is HAS      : {report.is_has}")
    print(f"Best version: {report.best_version or 'unknown'}  "
          f"(confidence: {report.best_confidence})")
    print(line)
    print("Evidence:")
    if not report.evidence:
        print("  (none)")
    for ev in report.evidence:
        ver = ""
        if ev.version:
            ver = f"  => version={ev.version}"
        elif ev.version_range:
            ver = f"  => range={ev.version_range}"
        print(f"  [{ev.confidence:5}] {ev.strategy}: {ev.detail}{ver}")
    if report.findings:
        print(line)
        print("Configuration findings:")
        order = sorted(
            report.findings,
            key=lambda f: (SEVERITY_RANK.get(f.severity, 0), f.confirmed),
            reverse=True,
        )
        for f in order:
            mark = "CONFIRMED" if f.confirmed else "potential"
            print(f"  [{f.severity.upper():8}] ({mark}) {f.title}")
            print(f"            {f.detail}")
            if f.remediation:
                print(f"            fix: {f.remediation}")
            # Print the reproducible PoC + captured evidence for confirmed findings.
            if f.confirmed and isinstance(f.raw, dict):
                repro = f.raw.get("repro")
                if isinstance(repro, dict):
                    print(f"            repro (curl): {repro.get('curl')}")
                    print(f"            expected before fix: {repro.get('expected_before_fix')}")
                    print(f"            expected after fix : {repro.get('expected_after_fix')}")
                ev = f.raw.get("evidence")
                if isinstance(ev, dict):
                    resp = ev.get("response", {})
                    print(f"            evidence: HTTP {resp.get('status')} "
                          f"{resp.get('headers', {}).get('content-type', '')} "
                          f"body_sha256={resp.get('body_sha256', '')[:16]}…")
    if report.notes:
        print(line)
        print("Notes:")
        for n in report.notes:
            print(f"  - {n}")
    print(line)


def main(argv: List[str]) -> int:
    ap = argparse.ArgumentParser(
        description="Fingerprint a Helix Authentication Service (HAS) deployment "
                    "and identify its version. Authorized assessment use only."
    )
    ap.add_argument("target", help="Base URL or host:port, e.g. https://host:3000/")
    ap.add_argument("--timeout", type=float, default=10.0, help="Per-request timeout (s)")
    ap.add_argument("--insecure", action="store_true",
                    help="Do not verify TLS certificates (default verifies)")
    ap.add_argument("--no-http-fallback", action="store_true",
                    help="Do not retry over HTTP if HTTPS is unreachable")
    ap.add_argument("--no-cred-tests", action="store_true",
                    help="Skip active default-credential checks (e.g. default SCIM bearer token); "
                         "run detection-only")
    ap.add_argument("--mask-identities", action="store_true",
                    help="Redact SCIM identities (userNames/emails) in the default-token proof. "
                         "By default identities are shown in full to demonstrate impact.")
    ap.add_argument("--save-evidence", metavar="PATH",
                    help="Write the full JSON report (findings + captured request/response "
                         "evidence + repro commands) to PATH for the engagement writeup.")
    ap.add_argument("--user-agent", default="has-fingerprint/1.0 (asset-inventory)",
                    help="HTTP User-Agent string")
    ap.add_argument("--json", action="store_true", help="Emit machine-readable JSON")
    args = ap.parse_args(argv)

    report = run(
        target=args.target,
        timeout=args.timeout,
        verify_tls=not args.insecure,
        user_agent=args.user_agent,
        try_http_fallback=not args.no_http_fallback,
        cred_tests=not args.no_cred_tests,
        reveal_identities=not args.mask_identities,
    )

    if args.json:
        print(json.dumps(report.to_dict(), indent=2, default=str))
    else:
        print_human(report)

    if args.save_evidence:
        try:
            with open(args.save_evidence, "w", encoding="utf-8") as fh:
                json.dump(report.to_dict(), fh, indent=2, default=str)
            print(f"\n[+] Evidence bundle written to {args.save_evidence}")
        except OSError as e:
            print(f"\n[!] Failed to write evidence bundle: {e}", file=sys.stderr)

    # Exit codes for scripting/asset pipelines:
    #   1 = unreachable
    #   3 = reachable and at least one CONFIRMED high/critical config finding
    #   0 = identified as HAS (no confirmed high/critical finding)
    #   2 = reachable but not identified as HAS
    if not report.reachable:
        return 1
    if SEVERITY_RANK.get(report.max_confirmed_severity(), 0) >= SEVERITY_RANK["high"]:
        return 3
    return 0 if report.is_has else 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
