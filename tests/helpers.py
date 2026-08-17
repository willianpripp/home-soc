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
) -> None:
    with conn.cursor() as cur:
        cur.execute(
            """insert into dns_query
                 (ts, client, qname, qtype, reason, blocked, status,
                  registrable_domain, label_entropy)
               values (%(ts)s, %(client)s, %(qname)s, %(qtype)s, %(reason)s, %(blocked)s,
                       %(status)s, %(registrable_domain)s, %(label_entropy)s)""",
            {
                "ts": ts,
                "client": client,
                "qname": qname,
                "qtype": qtype,
                "reason": "FilteredBlackList" if blocked else "NotFilteredNotFound",
                "blocked": blocked,
                "status": "NXDOMAIN" if blocked else "NOERROR",
                "registrable_domain": registrable_domain,
                "label_entropy": label_entropy,
            },
        )
    conn.commit()
