"""Small insert helpers shared by the per-rule tests.

Each per-rule test crafts rows directly in dns_query / dns_domain rather than
going through ingest/adguard.py: the rule tests are about what the rule's SQL
does with given data, not about the ingester, and inserting directly keeps
the fixed timestamps the interval math depends on fully in the test's hands.
"""
from __future__ import annotations

from datetime import datetime

import psycopg


def insert_domain(
    conn: psycopg.Connection,
    domain: str,
    first_seen: datetime,
    last_seen: datetime | None = None,
    query_count: int = 1,
    blocked_count: int = 0,
) -> None:
    with conn.cursor() as cur:
        cur.execute(
            """insert into dns_domain (domain, first_seen, last_seen, query_count, blocked_count)
               values (%s, %s, %s, %s, %s)""",
            (domain, first_seen, last_seen or first_seen, query_count, blocked_count),
        )
    conn.commit()


def insert_query(
    conn: psycopg.Connection,
    ts: datetime,
    client: str,
    qname: str,
    registrable_domain: str,
    label_entropy: float = 0.0,
    qtype: str = "A",
    blocked: bool = False,
    status: str | None = None,
    client_name: str | None = None,
) -> None:
    """`status` defaults to the value AdGuard would actually report for
    `blocked` (NXDOMAIN for a block, NOERROR otherwise), same as before this
    parameter existed. It only needs overriding for a rule like
    dns_nxdomain_burst, which cares about a genuine resolution failure
    (blocked=False, status='NXDOMAIN') as distinct from an AdGuard block that
    also happens to answer NXDOMAIN.

    `client_name` defaults to None, same as a client AdGuard has not been
    given a name for.
    """
    with conn.cursor() as cur:
        cur.execute(
            """insert into dns_query
                 (ts, client, client_name, qname, qtype, reason, blocked, status,
                  registrable_domain, label_entropy)
               values (%(ts)s, %(client)s, %(client_name)s, %(qname)s, %(qtype)s,
                       %(reason)s, %(blocked)s, %(status)s, %(registrable_domain)s,
                       %(label_entropy)s)""",
            {
                "ts": ts,
                "client": client,
                "client_name": client_name,
                "qname": qname,
                "qtype": qtype,
                "reason": "FilteredBlackList" if blocked else "NotFilteredNotFound",
                "blocked": blocked,
                "status": status if status is not None else ("NXDOMAIN" if blocked else "NOERROR"),
                "registrable_domain": registrable_domain,
                "label_entropy": label_entropy,
            },
        )
    conn.commit()


def insert_known_bad(
    conn: psycopg.Connection,
    domain: str,
    source: str = "urlhaus",
) -> None:
    """fetched_at is left to its table default (now()); no test so far needs
    to control it, since dns_known_bad_domain does not read that column."""
    with conn.cursor() as cur:
        cur.execute(
            "insert into known_bad_domain (domain, source) values (%s, %s)",
            (domain, source),
        )
    conn.commit()
