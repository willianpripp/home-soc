"""dns_known_bad_domain: fires for a domain matched against known_bad_domain,
either by registrable_domain or by the exact qname (subdomain-specific
listings)."""
from __future__ import annotations

import pathlib
from datetime import datetime, timezone

import rules
from helpers import insert_known_bad, insert_query

RULES_DIR = pathlib.Path(__file__).resolve().parent.parent / "rules"


def _entities(conn):
    with conn.cursor() as cur:
        cur.execute("select entity from rule_hit where rule_id = 'dns_known_bad_domain'")
        return {r[0] for r in cur.fetchall()}


def test_fires_for_a_registrable_domain_match(conn):
    now = datetime.now(timezone.utc)
    insert_known_bad(conn, "evil-malware.example")
    insert_query(conn, now, "192.168.1.10", "www.evil-malware.example",
                 "evil-malware.example")
    insert_query(conn, now, "192.168.1.11", "evil-malware.example",
                 "evil-malware.example", blocked=True)

    rules.run(conn, RULES_DIR)
    assert "evil-malware.example" in _entities(conn)


def test_fires_for_a_subdomain_specific_listing_matched_on_the_full_qname(conn):
    now = datetime.now(timezone.utc)
    # The listing IS a subdomain, not the registrable domain: matching only
    # registrable_domain would miss this entirely, only the exact-qname join
    # catches it.
    insert_known_bad(conn, "bad-host.cdn-provider.example")
    insert_query(conn, now, "192.168.1.12", "bad-host.cdn-provider.example",
                 "cdn-provider.example")

    rules.run(conn, RULES_DIR)
    assert "bad-host.cdn-provider.example" in _entities(conn)


def test_unblocked_query_is_called_out_in_the_summary(conn):
    now = datetime.now(timezone.utc)
    insert_known_bad(conn, "leaked-creds.example")
    insert_query(conn, now, "192.168.1.13", "leaked-creds.example",
                 "leaked-creds.example", blocked=False)

    rules.run(conn, RULES_DIR)
    with conn.cursor() as cur:
        cur.execute(
            "select summary from rule_hit where rule_id = 'dns_known_bad_domain' "
            "and entity = 'leaked-creds.example'"
        )
        (summary,) = cur.fetchone()
    assert "1 NOT blocked" in summary


def test_does_not_fire_for_a_domain_that_is_not_listed(conn):
    now = datetime.now(timezone.utc)
    insert_query(conn, now, "192.168.1.14", "perfectly-fine.example",
                 "perfectly-fine.example")

    rules.run(conn, RULES_DIR)
    assert "perfectly-fine.example" not in _entities(conn)
