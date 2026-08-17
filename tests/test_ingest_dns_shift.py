"""ingest_file's --shift-to-now: demo/querylog.json rebased so the two
24-hour-window rules have something to fire on.

demo/querylog.json is frozen at 2026-08-15. Left alone, its entries age past
the 24h window used by dns_newly_seen_domain and dns_blocked_spike within a
day of being written, and every day after that makes the gap worse. Shifting
the whole file by (now - newest entry) keeps its internal spread (a few
hours) intact while landing the newest entry at now.
"""
from __future__ import annotations

import pathlib
import sys
from datetime import datetime, timedelta, timezone

import rules

INGEST_DIR = pathlib.Path(__file__).resolve().parent.parent / "ingest"
if str(INGEST_DIR) not in sys.path:
    sys.path.insert(0, str(INGEST_DIR))

import adguard

RULES_DIR = pathlib.Path(__file__).resolve().parent.parent / "rules"
DEMO_FILE = pathlib.Path(__file__).resolve().parent.parent / "demo" / "querylog.json"


def test_shift_to_now_rebases_max_ts_near_now(conn):
    result = adguard.ingest_file(conn, DEMO_FILE, shift_to_now=True)
    assert result["skipped"] is False

    with conn.cursor() as cur:
        cur.execute("select max(ts) from dns_query")
        (max_ts,) = cur.fetchone()

    now = datetime.now(timezone.utc)
    assert abs((now - max_ts).total_seconds()) < 180  # within a couple of minutes


def test_shift_to_now_makes_dns_newly_seen_domain_fire(conn):
    adguard.ingest_file(conn, DEMO_FILE, shift_to_now=True)

    rules.run(conn, RULES_DIR)
    with conn.cursor() as cur:
        cur.execute("select count(*) from rule_hit where rule_id = 'dns_newly_seen_domain'")
        (hits,) = cur.fetchone()
    assert hits > 0


def test_shift_to_now_keeps_run_key_as_the_file_name_for_idempotent_reruns(conn):
    first = adguard.ingest_file(conn, DEMO_FILE, shift_to_now=True)
    assert first["run_key"] == DEMO_FILE.name

    second = adguard.ingest_file(conn, DEMO_FILE, shift_to_now=True)
    assert second["skipped"] is True
    assert second["run_key"] == DEMO_FILE.name


def test_without_shift_max_ts_stays_in_the_past(conn):
    result = adguard.ingest_file(conn, DEMO_FILE, shift_to_now=False)
    assert result["skipped"] is False

    with conn.cursor() as cur:
        cur.execute("select max(ts) from dns_query")
        (max_ts,) = cur.fetchone()

    now = datetime.now(timezone.utc)
    assert now - max_ts > timedelta(days=1)
