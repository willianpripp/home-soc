"""Enrichment: what the rest of the world already knows about these CVEs and
domains.

Severity alone cannot rank 453 findings. Two free public feeds do most of the
work of turning that list into a short one:

  CISA KEV     small, and the strongest signal there is. Presence means the CVE
               is being exploited in the wild right now, which outranks any
               severity label a scanner attaches.
  FIRST EPSS   a probability of exploitation in the next 30 days, for nearly
               every CVE. Most score below 0.001; a handful score above 0.1.
               That distribution is exactly what makes a long backlog tractable.

A third feed plays the same role on the DNS side:

  abuse.ch     URLhaus's hostfile: domains a public community already knows
  URLhaus      are serving malware. The shape-based DNS rules (entropy,
               newly-seen, blocked-spike) all infer suspicion; this one states
               it outright, the same relationship KEV has to a CVE's own
               severity score.

All three are fetched over plain HTTPS with no credentials. None is required
for the tool to work: without them the priority view still ranks by
fixability and exposure, and the DNS rules still fire on shape alone, just
less sharply.
"""
from __future__ import annotations

import csv
import gzip
import io
import json
import urllib.request

import psycopg

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
URLHAUS_HOSTFILE_URL = "https://urlhaus.abuse.ch/downloads/hostfile/"

UA = "home-soc/0.1 (+https://github.com/willianpripp/home-soc)"


def _get(url: str, timeout: int = 120) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


def fetch_kev(conn: psycopg.Connection) -> int:
    doc = json.loads(_get(KEV_URL))
    rows = doc.get("vulnerabilities") or []
    with conn.cursor() as cur:
        for v in rows:
            cur.execute(
                """insert into kev (cve, vendor_project, product, date_added, due_date,
                                    known_ransomware, fetched_at)
                   values (%s, %s, %s, %s, %s, %s, now())
                   on conflict (cve) do update
                     set due_date = excluded.due_date,
                         known_ransomware = excluded.known_ransomware,
                         fetched_at = now()""",
                (
                    v.get("cveID"),
                    v.get("vendorProject"),
                    v.get("product"),
                    v.get("dateAdded") or None,
                    v.get("dueDate") or None,
                    (v.get("knownRansomwareCampaignUse") or "").lower() == "known",
                ),
            )
    conn.commit()
    return len(rows)


def fetch_epss(conn: psycopg.Connection, only_known: bool = True) -> int:
    """Load EPSS scores.

    `only_known` restricts the load to CVEs already present in vuln_finding.
    The full feed is roughly 300k rows and this database only ever asks about a
    few hundred of them; storing the rest would be a daily import that nothing
    reads. Pass False if that ever stops being true.
    """
    raw = gzip.decompress(_get(EPSS_URL))
    text = io.StringIO(raw.decode("utf-8"))

    # The first line is a comment carrying the model version and score date.
    first = text.readline()
    model_date = None
    if first.startswith("#"):
        for part in first.strip("#\n ").split(","):
            if "score_date" in part:
                model_date = part.split(":", 1)[1].strip()[:10]
    else:
        text.seek(0)

    wanted: set[str] | None = None
    if only_known:
        with conn.cursor() as cur:
            cur.execute("select distinct cve from vuln_finding")
            wanted = {r[0] for r in cur.fetchall()}
        if not wanted:
            return 0

    loaded = 0
    with conn.cursor() as cur:
        for row in csv.DictReader(text):
            cve = row.get("cve")
            if not cve or (wanted is not None and cve not in wanted):
                continue
            cur.execute(
                """insert into epss_score (cve, score, percentile, model_date, fetched_at)
                   values (%s, %s, %s, %s, now())
                   on conflict (cve) do update
                     set score = excluded.score,
                         percentile = excluded.percentile,
                         model_date = excluded.model_date,
                         fetched_at = now()""",
                (cve, row.get("epss"), row.get("percentile"), model_date),
            )
            loaded += 1
    conn.commit()
    return loaded


def fetch_urlhaus(conn: psycopg.Connection) -> int:
    """Load abuse.ch's URLhaus hostfile into known_bad_domain.

    The hostfile is plain text, one entry per line, "127.0.0.1<tab>domain"
    (the format DNS sinkholes and ad blockers consume directly); lines
    starting with # are header comments. Parsing is defensive on purpose:
    a blank line, a comment, or a line with fewer than two fields is skipped
    rather than raising, because a feed that lightly changes shape should not
    take enrichment down with it.

    The feed is a current-state snapshot, not an event stream: it says what
    abuse.ch considers bad right now, not "this domain went bad on this
    date". So the load strategy matches that shape instead of upserting like
    KEV and EPSS do: everything already stored from this source is deleted
    and the file's current contents are inserted, in one transaction. Without
    that, a domain abuse.ch de-listed months ago would sit here forever,
    and a hit against it would look exactly as current as one against a
    domain still on the list today.
    """
    text = _get(URLHAUS_HOSTFILE_URL).decode("utf-8", errors="replace")

    domains: set[str] = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        fields = line.split()
        if len(fields) < 2:
            continue
        domain = fields[1].strip().rstrip(".").lower()
        if domain:
            domains.add(domain)

    with conn.cursor() as cur:
        cur.execute("delete from known_bad_domain where source = 'urlhaus'")
        for domain in domains:
            cur.execute(
                """insert into known_bad_domain (domain, source, fetched_at)
                   values (%s, 'urlhaus', now())
                   on conflict (domain, source) do update set fetched_at = excluded.fetched_at""",
                (domain,),
            )
    conn.commit()
    return len(domains)
