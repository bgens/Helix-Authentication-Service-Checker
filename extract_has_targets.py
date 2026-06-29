#!/usr/bin/env python3
"""
extract_has_targets.py

Extract IP + port (and optional hostnames / URL) for Helix Authentication
Service (HAS) instances from Shodan JSON output.

Input formats accepted (auto-detected):
  * NDJSON / JSON Lines  -> one Shodan banner object per line (the format
                            produced by `shodan download` after `shodan parse`,
                            or by the streaming API). This is the default.
  * A single JSON array  -> [ {...}, {...}, ... ]
  * A single JSON object -> { "matches": [ {...}, ... ] }  (search API result)

A record is treated as HAS when its HTTP title is the service banner
("P4 Authentication Service") or that string appears in the crawled HTML.
Use --all to skip the HAS filter and emit every record's host:port.

Each Shodan banner carries the network endpoint directly:
    ip_str   -> dotted IPv4/IPv6 string   (fallback: integer `ip`)
    port     -> TCP port
    transport-> usually "tcp"
    _shodan.module / ssl / port -> used to infer http vs https for --url

Usage:
    python extract_has_targets.py shodan.json
    python extract_has_targets.py shodan.json --format csv -o has_targets.csv
    python extract_has_targets.py shodan.json --url --dedupe
    python extract_has_targets.py shodan.json --all --format json

Requires only the Python 3.8+ standard library.
"""

from __future__ import annotations

import argparse
import csv
import ipaddress
import json
import sys
from typing import Any, Dict, Iterator, List, Optional, Tuple


# HTTP title / HTML marker that identifies a HAS instance.
HAS_TITLE = "P4 Authentication Service"


def iter_records(text: str) -> Iterator[Dict[str, Any]]:
    """Yield Shodan banner dicts from NDJSON, a JSON array, or a search result.

    Tries whole-document JSON first (array or {"matches": [...]}); if that
    fails, falls back to line-by-line NDJSON parsing, skipping blank/comment
    lines and reporting unparseable lines on stderr.
    """
    stripped = text.lstrip()
    if stripped[:1] in ("[", "{"):
        try:
            doc = json.loads(text)
        except json.JSONDecodeError:
            doc = None
        if isinstance(doc, list):
            yield from (r for r in doc if isinstance(r, dict))
            return
        if isinstance(doc, dict):
            matches = doc.get("matches")
            if isinstance(matches, list):
                yield from (r for r in matches if isinstance(r, dict))
            else:
                yield doc
            return

    # NDJSON / JSON Lines fallback.
    for lineno, line in enumerate(text.splitlines(), start=1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError as e:
            print(f"[!] skipping unparseable line {lineno}: {e}", file=sys.stderr)
            continue
        if isinstance(obj, dict):
            yield obj


def is_has(record: Dict[str, Any]) -> bool:
    """True if the Shodan banner looks like a Helix Authentication Service."""
    http = record.get("http") or {}
    title = http.get("title") or ""
    if HAS_TITLE in title:
        return True
    html = http.get("html") or ""
    return HAS_TITLE in html


def int_to_ip(value: int) -> Optional[str]:
    """Convert Shodan's integer IP form to a dotted string, if possible."""
    try:
        return str(ipaddress.ip_address(value))
    except (ValueError, TypeError):
        return None


def extract_endpoint(record: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Pull the network endpoint fields out of a Shodan banner."""
    ip = record.get("ip_str")
    if not ip:
        raw = record.get("ip")
        if isinstance(raw, int):
            ip = int_to_ip(raw)
        elif isinstance(raw, str):
            ip = raw
    port = record.get("port")
    if not ip or port is None:
        return None

    http = record.get("http") or {}
    shodan_meta = record.get("_shodan") or {}
    module = (shodan_meta.get("module") or "").lower()
    is_tls = bool(record.get("ssl")) or module.startswith("https") or port == 443
    scheme = "https" if is_tls else "http"

    hostnames = record.get("hostnames") or []
    if not isinstance(hostnames, list):
        hostnames = []

    return {
        "ip": ip,
        "port": int(port),
        "transport": record.get("transport") or "tcp",
        "scheme": scheme,
        "host": http.get("host") or "",
        "hostnames": hostnames,
        "title": http.get("title") or "",
        "timestamp": record.get("timestamp") or "",
        "org": record.get("org") or "",
        "country": (record.get("location") or {}).get("country_code") or "",
    }


def build_url(ep: Dict[str, Any]) -> str:
    """Render scheme://ip:port, omitting the port when it is the scheme default."""
    default = 443 if ep["scheme"] == "https" else 80
    host = ep["ip"]
    if ":" in host and not host.startswith("["):  # bracket IPv6 literals
        host = f"[{host}]"
    if ep["port"] == default:
        return f"{ep['scheme']}://{host}"
    return f"{ep['scheme']}://{host}:{ep['port']}"


def main(argv: List[str]) -> int:
    ap = argparse.ArgumentParser(
        description="Extract IP + port for Helix Authentication Service (HAS) "
                    "hosts from Shodan JSON output."
    )
    ap.add_argument("input", help="Path to Shodan JSON file ('-' for stdin)")
    ap.add_argument("-o", "--output", help="Write results here (default: stdout)")
    ap.add_argument("--format", choices=("plain", "csv", "json"), default="plain",
                    help="Output format (default: plain 'ip:port' lines)")
    ap.add_argument("--url", action="store_true",
                    help="Emit scheme://ip[:port] instead of bare ip:port (plain format)")
    ap.add_argument("--all", action="store_true",
                    help="Do not filter by HAS banner; emit every record's endpoint")
    ap.add_argument("--dedupe", action="store_true",
                    help="Collapse duplicate ip:port endpoints")
    args = ap.parse_args(argv)

    # Read input.
    try:
        if args.input == "-":
            text = sys.stdin.read()
        else:
            with open(args.input, "r", encoding="utf-8", errors="replace") as fh:
                text = fh.read()
    except OSError as e:
        print(f"[!] cannot read input: {e}", file=sys.stderr)
        return 1

    endpoints: List[Dict[str, Any]] = []
    seen: set[Tuple[str, int]] = set()
    total = 0
    for record in iter_records(text):
        total += 1
        if not args.all and not is_has(record):
            continue
        ep = extract_endpoint(record)
        if ep is None:
            continue
        if args.dedupe:
            key = (ep["ip"], ep["port"])
            if key in seen:
                continue
            seen.add(key)
        endpoints.append(ep)

    # Render output.
    out = sys.stdout
    close = False
    if args.output:
        try:
            out = open(args.output, "w", encoding="utf-8", newline="")
            close = True
        except OSError as e:
            print(f"[!] cannot write output: {e}", file=sys.stderr)
            return 1

    try:
        if args.format == "json":
            json.dump(endpoints, out, indent=2)
            out.write("\n")
        elif args.format == "csv":
            writer = csv.writer(out)
            writer.writerow(["ip", "port", "transport", "scheme", "url",
                             "host", "hostnames", "org", "country", "timestamp"])
            for ep in endpoints:
                writer.writerow([
                    ep["ip"], ep["port"], ep["transport"], ep["scheme"],
                    build_url(ep), ep["host"], ";".join(ep["hostnames"]),
                    ep["org"], ep["country"], ep["timestamp"],
                ])
        else:  # plain
            for ep in endpoints:
                out.write((build_url(ep) if args.url else f"{ep['ip']}:{ep['port']}") + "\n")
    finally:
        if close:
            out.close()

    scope = "records" if args.all else "HAS records"
    print(f"[+] {len(endpoints)} {scope} extracted from {total} scanned",
          file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
