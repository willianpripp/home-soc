"""The rule engine: a thin registry that runs rules/*.sql and persists hits.

Deliberately not clever. Each rule is one .sql file whose header line the
engine parses into a description, and whose body must select exactly two
columns, entity and summary. The engine's only job is to keep rule and
rule_hit up to date with the same persistence semantics vuln_finding already
uses: first_seen is set once and never moved, a re-hit updates last_seen and
bumps hit_count, and status is owned by a human and never touched by a
re-hit. See rules/README.md for the file contract and schema/003_rules.sql
for why the engine never resolves a hit on its own.
"""
from __future__ import annotations

import pathlib

import psycopg

DEFAULT_RULES_DIR = pathlib.Path(__file__).resolve().parent.parent / "rules"

DESCRIPTION_PREFIX = "-- description:"


def discover(path: pathlib.Path) -> list[tuple[str, str, str]]:
    """Return (rule_id, description, sql) for every rules/*.sql file.

    The rule id is the filename stem. The description is parsed out of the
    file's own first line rather than duplicated in Python, so a rule's
    description lives in exactly one place: the file a reviewer actually
    reads. A file whose first line does not carry that header is a mistake
    worth stopping on, not silently skipping.
    """
    rules: list[tuple[str, str, str]] = []
    for rule_path in sorted(path.glob("*.sql")):
        text = rule_path.read_text()
        first_line = text.splitlines()[0] if text else ""
        if not first_line.strip().startswith(DESCRIPTION_PREFIX):
            raise SystemExit(
                f"{rule_path.name}: first line must start with "
                f"'{DESCRIPTION_PREFIX} ', got: {first_line!r}"
            )
        description = first_line.strip()[len(DESCRIPTION_PREFIX):].strip()
        rules.append((rule_path.stem, description, text))
    return rules


def run(conn: psycopg.Connection, rules_dir: pathlib.Path = DEFAULT_RULES_DIR) -> dict:
    """Run every discovered rule and upsert its hits. Never raises for a rule
    whose SQL fails; that failure is recorded and the run continues, so one
    broken rule cannot take the rest of the engine down with it.
    """
    results: list[dict] = []
    any_failed = False

    for rule_id, description, sql in discover(rules_dir):
        with conn.cursor() as cur:
            cur.execute(
                """insert into rule (id, description) values (%s, %s)
                   on conflict (id) do update set description = excluded.description
                   returning enabled""",
                (rule_id, description),
            )
            (enabled,) = cur.fetchone()
        conn.commit()

        if not enabled:
            results.append({"rule_id": rule_id, "skipped": "disabled"})
            continue

        try:
            with conn.cursor() as cur:
                cur.execute(sql)
                columns = [c.name for c in cur.description or []]
                if columns != ["entity", "summary"]:
                    raise psycopg.errors.SyntaxError(
                        f"expected columns (entity, summary), got {columns}"
                    )
                rows = cur.fetchall()

                new = re_reported = 0
                for entity, summary in rows:
                    cur.execute(
                        """insert into rule_hit (rule_id, entity, summary)
                           values (%s, %s, %s)
                           on conflict (rule_id, entity) do update
                             set last_seen = now(),
                                 hit_count = rule_hit.hit_count + 1,
                                 summary = excluded.summary
                           returning (xmax = 0) as was_insert""",
                        (rule_id, entity, summary),
                    )
                    (was_insert,) = cur.fetchone()
                    if was_insert:
                        new += 1
                    else:
                        re_reported += 1
            conn.commit()
        except psycopg.Error as exc:
            conn.rollback()
            results.append({"rule_id": rule_id, "failed": str(exc).strip()})
            any_failed = True
            continue

        results.append(
            {
                "rule_id": rule_id,
                "hits": new + re_reported,
                "new": new,
                "re_reported": re_reported,
            }
        )

    return {"rules": results, "any_failed": any_failed}
