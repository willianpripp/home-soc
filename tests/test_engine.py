"""Rule engine semantics, independent of any real rule's SQL.

Each test builds its own tiny rules/ directory in tmp_path so the engine's
persistence contract (first_seen set once, hit_count incrementing, status
left alone on a re-hit, a broken rule failing loudly without stopping the
others, a disabled rule skipped) is proven without depending on what any real
rule in the repo happens to select.
"""
from __future__ import annotations

import pathlib

import rules

# Always returns exactly one fixed row, so re-running it is a deterministic
# re-hit of the same entity every time, with no data setup required.
PROBE_SQL = """-- description: engine test probe, always returns one fixed row
select 'probe-entity'::text as entity, 'probe summary'::text as summary;
"""

# Selects from a table that does not exist, so it fails every time it runs.
BROKEN_SQL = """-- description: engine test probe, deliberately broken SQL
select entity, summary from a_table_that_does_not_exist;
"""


def _write_rule(rules_dir: pathlib.Path, name: str, sql: str) -> None:
    (rules_dir / f"{name}.sql").write_text(sql)


def test_first_run_inserts_hit_count_one(tmp_path, conn):
    _write_rule(tmp_path, "probe", PROBE_SQL)

    result = rules.run(conn, tmp_path)
    probe = next(r for r in result["rules"] if r["rule_id"] == "probe")
    assert probe == {"rule_id": "probe", "hits": 1, "new": 1, "re_reported": 0}

    with conn.cursor() as cur:
        cur.execute("select hit_count, first_seen, last_seen from rule_hit where rule_id = 'probe'")
        hit_count, first_seen, last_seen = cur.fetchone()
    assert hit_count == 1
    assert first_seen == last_seen


def test_second_run_re_reports_without_moving_first_seen(tmp_path, conn):
    _write_rule(tmp_path, "probe", PROBE_SQL)
    rules.run(conn, tmp_path)
    with conn.cursor() as cur:
        cur.execute("select first_seen from rule_hit where rule_id = 'probe'")
        (first_seen_1,) = cur.fetchone()

    result = rules.run(conn, tmp_path)
    probe = next(r for r in result["rules"] if r["rule_id"] == "probe")
    assert probe == {"rule_id": "probe", "hits": 1, "new": 0, "re_reported": 1}

    with conn.cursor() as cur:
        cur.execute("select hit_count, first_seen, last_seen from rule_hit where rule_id = 'probe'")
        hit_count, first_seen_2, last_seen_2 = cur.fetchone()
    assert hit_count == 2
    assert first_seen_2 == first_seen_1
    assert last_seen_2 >= first_seen_1


def test_accepted_status_survives_a_re_hit(tmp_path, conn):
    _write_rule(tmp_path, "probe", PROBE_SQL)
    rules.run(conn, tmp_path)
    with conn.cursor() as cur:
        cur.execute(
            "update rule_hit set status = 'accepted', status_changed_at = now() "
            "where rule_id = 'probe'"
        )
    conn.commit()

    rules.run(conn, tmp_path)
    with conn.cursor() as cur:
        cur.execute("select status from rule_hit where rule_id = 'probe'")
        (status,) = cur.fetchone()
    assert status == "accepted"


def test_broken_rule_fails_without_killing_the_others(tmp_path, conn):
    _write_rule(tmp_path, "probe", PROBE_SQL)
    _write_rule(tmp_path, "broken", BROKEN_SQL)

    result = rules.run(conn, tmp_path)
    assert result["any_failed"] is True

    probe = next(r for r in result["rules"] if r["rule_id"] == "probe")
    broken = next(r for r in result["rules"] if r["rule_id"] == "broken")
    assert probe["hits"] == 1
    assert "failed" in broken


def test_disabled_rule_is_skipped(tmp_path, conn):
    _write_rule(tmp_path, "probe", PROBE_SQL)
    rules.run(conn, tmp_path)
    with conn.cursor() as cur:
        cur.execute("update rule set enabled = false where id = 'probe'")
    conn.commit()

    result = rules.run(conn, tmp_path)
    probe = next(r for r in result["rules"] if r["rule_id"] == "probe")
    assert probe == {"rule_id": "probe", "skipped": "disabled"}

    with conn.cursor() as cur:
        cur.execute("select hit_count from rule_hit where rule_id = 'probe'")
        (hit_count,) = cur.fetchone()
    assert hit_count == 1  # untouched: the disabled run never ran the query
