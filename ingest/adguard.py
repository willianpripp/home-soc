"""Ingest AdGuard Home's DNS query log into dns_query and dns_domain.

Two ways in, one shared write path. `ingest_api` pulls from AdGuard Home's own
REST API, paginating backwards through `older_than` until it reaches entries
already stored (the max ts already in dns_query IS the cursor, so no separate
cursor table is needed). `ingest_file` reads one JSON file shaped like a single
API response, which is what the demo and any test use since there is no live
AdGuard to poll there.

Everything else, the entry mapping, the registrable-domain and entropy math,
the transaction, the prune, is shared between the two, matching the shape of
`trivy.ingest_run`: a scan_run row per pull, a natural key that makes re-ingest
a no-op, and one result dict the CLI prints a single line from.
"""
from __future__ import annotations

import base64
import json
import math
import os
import pathlib
import urllib.parse
import urllib.request
from collections import Counter
from datetime import datetime

import psycopg
import tldextract

SOURCE_ID = "adguard"
PAGE_LIMIT = 500

# A first backfill has no idea how far back AdGuard's query log actually goes.
# This caps it at 200 pages (100k entries) so a misbehaving or unexpectedly
# deep log cannot turn one ingest run into an infinite pull.
MAX_PAGES = 200

DEFAULT_RETENTION_DAYS = 35

UA = "home-soc/0.1 (+https://github.com/willianpripp/home-soc)"

# Offline only. This tool has to work with no internet (it runs against a
# household DNS resolver, not out to it), so tldextract is pinned to its
# bundled public-suffix snapshot and never allowed to fetch a fresh one.
_extract = tldextract.TLDExtract(suffix_list_urls=())


def _shannon_entropy(s: str) -> float:
    """Shannon entropy in bits per character. Empty input is 0, not NaN."""
    if not s:
        return 0.0
    length = len(s)
    counts = Counter(s)
    return -sum((n / length) * math.log2(n / length) for n in counts.values())


def _labels_excluding_suffix(qname: str, ext: tldextract.tldextract.ExtractResult) -> list[str]:
    """Labels of qname with the public suffix stripped off.

    Both a DGA registrable domain (xk9qz3vd7hw2.top: one high-entropy label,
    the domain itself) and a tunnel encoded into a long subdomain (one
    high-entropy label under an otherwise ordinary domain) need to show up the
    same way, so the max is taken over every remaining label, not just the
    registrable domain's own.
    """
    if not ext.suffix:
        # A bare IP, a single-label name (localhost), or a name under a suffix
        # tldextract's snapshot does not recognise (router.lan). There is no
        # known suffix boundary to exclude, so every label counts.
        return [p for p in qname.split(".") if p]
    parts = ext.subdomain.split(".") if ext.subdomain else []
    return [p for p in (*parts, ext.domain) if p]


def _registrable_domain(qname: str) -> tuple[str, float]:
    """Return (registrable_domain, label_entropy) for one normalised qname."""
    ext = _extract(qname)
    domain = ext.top_domain_under_public_suffix or qname
    labels = _labels_excluding_suffix(qname, ext)
    entropy = max((_shannon_entropy(label) for label in labels), default=0.0)
    return domain, entropy


def _normalize_qname(name: str) -> str:
    return name.strip().rstrip(".").lower()


def _parse_ts(raw: str | None) -> datetime | None:
    if not raw:
        return None
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None


def _map_entry(entry: dict) -> dict | None:
    """Map one AdGuard querylog entry to a dns_query row, or None to skip.

    AdGuard's `reason` is the filtering verdict: NotFiltered* (typically
    NotFilteredNotFound) means nothing matched and the query went through,
    Filtered* (FilteredBlackList, FilteredSafeBrowsing, FilteredParental,
    FilteredBlockedService, FilteredSafeSearch, ...) means a filter matched
    and the query was blocked, and Rewritten* means a DNS rewrite rule fired,
    which changes the answer but is not a block.

    Entries missing `time` or `question.name` are skipped rather than raising:
    a single malformed row from AdGuard should not fail an entire pull, but
    silently dropping it would hide data loss, so the caller counts skips.
    """
    ts = _parse_ts(entry.get("time"))
    question = entry.get("question") or {}
    qname_raw = question.get("name")
    if ts is None or not qname_raw:
        return None
    qname = _normalize_qname(qname_raw)
    if not qname:
        return None

    registrable_domain, label_entropy = _registrable_domain(qname)
    reason = entry.get("reason") or ""
    return {
        "ts": ts,
        "client": entry.get("client") or "",
        "qname": qname,
        "qtype": question.get("type") or "",
        "reason": reason or None,
        "blocked": reason.startswith("Filtered"),
        "status": entry.get("status") or None,
        "upstream": entry.get("upstream") or None,
        "cached": entry.get("cached"),
        "elapsed_ms": entry.get("elapsedMs"),
        "registrable_domain": registrable_domain,
        "label_entropy": label_entropy,
    }


def _ingest_entries(conn: psycopg.Connection, run_key: str, entries: list[dict]) -> dict:
    """Shared write path: one scan_run, one transaction, then the prune."""
    rows: list[dict] = []
    skipped = 0
    for entry in entries:
        mapped = _map_entry(entry)
        if mapped is None:
            skipped += 1
        else:
            rows.append(mapped)

    with conn.cursor() as cur:
        cur.execute(
            """insert into scan_run (source_id, run_key, started_at)
               values (%s, %s, now())
               on conflict (source_id, run_key) do nothing
               returning id""",
            (SOURCE_ID, run_key),
        )
        row = cur.fetchone()
        if row is None:
            conn.rollback()
            return {"run_key": run_key, "skipped": True, "reason": "already ingested"}
        run_id = row[0]

        inserted = duplicates = 0
        # One aggregate per registrable domain in this batch, applied to
        # dns_domain in a single upsert per domain rather than one per query
        # row: last_seen and the counters only need the batch's min/max/sums.
        domain_batch: dict[str, dict] = {}

        for r in rows:
            cur.execute(
                """insert into dns_query
                     (ts, client, qname, qtype, reason, blocked, status, upstream,
                      cached, elapsed_ms, registrable_domain, label_entropy, run_id)
                   values (%(ts)s, %(client)s, %(qname)s, %(qtype)s, %(reason)s,
                           %(blocked)s, %(status)s, %(upstream)s, %(cached)s,
                           %(elapsed_ms)s, %(registrable_domain)s, %(label_entropy)s, %(run)s)
                   on conflict (ts, client, qname, qtype) do nothing""",
                {**r, "run": run_id},
            )
            if not cur.rowcount:
                # Already stored by an earlier pull. It must not reach the
                # dns_domain aggregate either, or every overlapping re-ingest
                # would quietly inflate query_count, and a counter wrong in
                # the busy-looking direction is still a counter that lies.
                duplicates += 1
                continue
            inserted += 1

            agg = domain_batch.setdefault(
                r["registrable_domain"],
                {"first": r["ts"], "last": r["ts"], "count": 0, "blocked": 0},
            )
            agg["first"] = min(agg["first"], r["ts"])
            agg["last"] = max(agg["last"], r["ts"])
            agg["count"] += 1
            if r["blocked"]:
                agg["blocked"] += 1

        new_domains = 0
        for domain, agg in domain_batch.items():
            cur.execute(
                """insert into dns_domain (domain, first_seen, last_seen, query_count, blocked_count)
                   values (%s, %s, %s, %s, %s)
                   on conflict (domain) do update
                     -- first_seen only ever moves BACKWARD (a backfill of
                     -- older history is proof the domain was seen earlier),
                     -- never forward. Same spirit as vuln_finding: a domain
                     -- must never be made to look newer than it is.
                     set first_seen = least(dns_domain.first_seen, excluded.first_seen),
                         last_seen = greatest(dns_domain.last_seen, excluded.last_seen),
                         query_count = dns_domain.query_count + excluded.query_count,
                         blocked_count = dns_domain.blocked_count + excluded.blocked_count
                   returning (xmax = 0) as was_insert""",
                (domain, agg["first"], agg["last"], agg["count"], agg["blocked"]),
            )
            if cur.fetchone()[0]:
                new_domains += 1

    conn.commit()

    retention_days = int(os.environ.get("HOMESOC_DNS_RETENTION_DAYS") or DEFAULT_RETENTION_DAYS)
    with conn.cursor() as cur:
        cur.execute(
            "delete from dns_query where ts < now() - (%s * interval '1 day')",
            (retention_days,),
        )
        pruned = cur.rowcount
    conn.commit()

    return {
        "run_key": run_key,
        "skipped": False,
        "seen": len(entries),
        "inserted": inserted,
        "duplicates": duplicates,
        "skipped_entries": skipped,
        "new_domains": new_domains,
        "pruned": pruned,
    }


def ingest_file(conn: psycopg.Connection, path: pathlib.Path) -> dict:
    """Ingest one JSON file shaped like a single AdGuard API response.

    `{"data": [...]}`, exactly what one page of `ingest_api` sees. Used by
    demo/ and by tests, where there is no live AdGuard Home to poll.
    """
    doc = json.loads(path.read_text())
    entries = doc.get("data") or []
    return _ingest_entries(conn, path.name, entries)


def _api_get(url: str, user: str, password: str, timeout: int = 30) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    if user or password:
        token = base64.b64encode(f"{user}:{password}".encode()).decode()
        req.add_header("Authorization", f"Basic {token}")
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read())


def ingest_api(conn: psycopg.Connection) -> dict:
    """Pull AdGuard Home's query log over its REST API and ingest it.

    Paginates backwards in time through `older_than` (500 entries per page),
    stopping at the first page that comes back empty or whose entries are no
    newer than the max ts already stored in dns_query. That makes every pull
    after the first one incremental for free: nothing here has to remember
    where the last pull left off, dns_query already knows.
    """
    base_url = os.environ.get("HOMESOC_ADGUARD_URL", "").strip().rstrip("/")
    if not base_url:
        raise SystemExit(
            "HOMESOC_ADGUARD_URL is not set. Copy .env.example to .env and fill it in."
        )
    user = os.environ.get("HOMESOC_ADGUARD_USER", "")
    password = os.environ.get("HOMESOC_ADGUARD_PASSWORD", "")

    with conn.cursor() as cur:
        cur.execute("select max(ts) from dns_query")
        watermark = cur.fetchone()[0]

    entries: list[dict] = []
    older_than = None
    hit_cap = True
    for _ in range(MAX_PAGES):
        params = {"limit": PAGE_LIMIT}
        if older_than:
            params["older_than"] = older_than
        url = f"{base_url}/control/querylog?{urllib.parse.urlencode(params)}"
        doc = _api_get(url, user, password)
        page = doc.get("data") or []
        if not page:
            hit_cap = False
            break

        reached_watermark = False
        for entry in page:
            ts = _parse_ts(entry.get("time"))
            if watermark is not None and ts is not None and ts <= watermark:
                reached_watermark = True
                continue
            entries.append(entry)

        older_than = page[-1].get("time")
        if reached_watermark or not older_than:
            hit_cap = False
            break
    if hit_cap:
        print(f"warning: ingest-dns hit the {MAX_PAGES}-page hard cap; more history may remain unpulled")

    if not entries:
        return {"run_key": "no-op", "skipped": True, "reason": "nothing new since last pull"}

    newest = max((e["time"] for e in entries if e.get("time")), default=None)
    if newest is None:
        return {"run_key": "no-op", "skipped": True, "reason": "no entry carried a timestamp"}
    return _ingest_entries(conn, newest, entries)
