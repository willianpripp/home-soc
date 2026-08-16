"""Ingest a Trivy run directory into vuln_finding.

Input is one directory per run, one JSON file per image, written by the
`container_scan` Ansible role in the homelab repo. Until 2026-08-16 that role
computed counts from this JSON and threw it away; this module is the reason it
now survives.

The important behaviour is not the insert, it is what happens on the SECOND
run: a finding that is still there gets its `last_seen` moved and nothing else,
and a finding that has stopped being reported gets `resolved_at` set. That is
what turns a weekly snapshot into a backlog you can age.
"""
from __future__ import annotations

import json
import pathlib
from datetime import datetime, timezone

import psycopg

SOURCE_ID = "trivy"


def _rows_from_file(path: pathlib.Path) -> tuple[str, list[dict]]:
    """Return (image name, findings) for one Trivy JSON report."""
    doc = json.loads(path.read_text())
    image = doc.get("ArtifactName") or path.stem
    out: list[dict] = []
    for result in doc.get("Results") or []:
        target = result.get("Target")
        pkg_class = result.get("Class")
        for v in result.get("Vulnerabilities") or []:
            # Trivy omits FixedVersion entirely when there is no fix, and uses
            # an empty string in some feeds. Normalise both to None so the
            # "is it actionable" test is one condition everywhere else.
            fixed = (v.get("FixedVersion") or "").strip() or None
            out.append(
                {
                    "image": image,
                    "pkg_name": v.get("PkgName") or "",
                    "installed_version": v.get("InstalledVersion") or "",
                    "cve": v.get("VulnerabilityID") or "",
                    "severity": v.get("Severity") or "UNKNOWN",
                    "fixed_version": fixed,
                    "title": (v.get("Title") or "")[:500] or None,
                    "purl": ((v.get("PkgIdentifier") or {}).get("PURL")) or None,
                    "target": target,
                    "pkg_class": pkg_class,
                }
            )
    return image, out


def ingest_run(conn: psycopg.Connection, run_dir: pathlib.Path) -> dict:
    """Ingest one run directory. Idempotent: re-running is a no-op."""
    if not run_dir.is_dir():
        raise SystemExit(f"not a directory: {run_dir}")

    run_key = run_dir.name
    # The directory name is the scan timestamp (YYYYmmdd-HHMMSS), which is the
    # only record of when the scan actually ran. File mtimes would drift if the
    # tree were ever copied, and this has to survive a restore.
    try:
        started = datetime.strptime(run_key, "%Y%m%d-%H%M%S").replace(tzinfo=timezone.utc)
    except ValueError:
        raise SystemExit(f"run directory name is not a YYYYmmdd-HHMMSS stamp: {run_key}")

    files = sorted(run_dir.glob("*.json"))
    if not files:
        raise SystemExit(f"no JSON in {run_dir}; refusing to record an empty run")

    with conn.cursor() as cur:
        cur.execute(
            """insert into scan_run (source_id, run_key, started_at, images_total)
               values (%s, %s, %s, %s)
               on conflict (source_id, run_key) do nothing
               returning id""",
            (SOURCE_ID, run_key, started, len(files)),
        )
        row = cur.fetchone()
        if row is None:
            conn.rollback()
            return {"run_key": run_key, "skipped": True, "reason": "already ingested"}
        run_id = row[0]

        images: list[str] = []
        inserted = updated = 0

        for path in files:
            image, rows = _rows_from_file(path)
            images.append(image)
            for r in rows:
                cur.execute(
                    """insert into vuln_finding
                         (image, pkg_name, installed_version, cve, severity,
                          fixed_version, title, purl, target, pkg_class,
                          first_run_id, last_run_id)
                       values (%(image)s, %(pkg_name)s, %(installed_version)s, %(cve)s,
                               %(severity)s, %(fixed_version)s, %(title)s, %(purl)s,
                               %(target)s, %(pkg_class)s, %(run)s, %(run)s)
                       on conflict (image, pkg_name, installed_version, cve) do update
                         set last_seen   = now(),
                             last_run_id = excluded.last_run_id,
                             severity    = excluded.severity,
                             fixed_version = excluded.fixed_version,
                             -- A finding that comes back was never really gone.
                             -- Clearing resolved_at keeps its original
                             -- first_seen, so an old problem that reappears
                             -- does not masquerade as a new one.
                             resolved_at = null
                       returning (xmax = 0) as was_insert""",
                    {**r, "run": run_id},
                )
                if cur.fetchone()[0]:
                    inserted += 1
                else:
                    updated += 1

        # Anything for a scanned image that this run did NOT report is fixed or
        # gone. Scoped to the images actually in this run: an image that was not
        # scanned tonight must not have its findings silently marked resolved,
        # which would read as progress when it is really a coverage gap.
        # Every row this run touched has last_run_id = run_id, so "not reported
        # tonight" is simply "last_run_id is not this run". No key list to ship
        # to the server and no composite-type comparison, which was the first
        # attempt and is fragile in Postgres.
        cur.execute(
            """update vuln_finding
                  set resolved_at = now()
                where resolved_at is null
                  and image = any(%s)
                  and last_run_id is distinct from %s""",
            (images, run_id),
        )
        resolved = cur.rowcount

    conn.commit()
    with conn.cursor() as cur:
        cur.execute("update scan_run set images_scanned = %s where id = %s", (len(files), run_id))
    conn.commit()

    return {
        "run_key": run_key,
        "skipped": False,
        "images": len(files),
        "inserted": inserted,
        "updated": updated,
        "resolved": resolved,
    }
