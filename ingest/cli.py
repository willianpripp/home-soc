"""home-soc command line.

One entry point, invoked by systemd right after the weekly scan and by hand the
rest of the time. Deliberately not a daemon: there is nothing here that needs to
be resident, and a cron-shaped tool is one less thing that can be quietly dead.
"""
from __future__ import annotations

import argparse
import pathlib
import sys

import yaml

import adguard
import db
import enrich
import rules
import trivy


def cmd_migrate(args, conn):
    applied = db.migrate(conn)
    print("\n".join(f"applied {a}" for a in applied) if applied else "schema up to date")


def cmd_ingest_trivy(args, conn):
    db.migrate(conn)
    root = pathlib.Path(args.path)
    # A directory of runs, or a single run. Being able to point at the whole
    # tree is what makes backfilling the history a one-liner.
    runs = sorted(p for p in root.iterdir() if p.is_dir()) if args.all else [root]
    for run in runs:
        result = trivy.ingest_run(conn, run)
        if result.get("skipped"):
            print(f"{result['run_key']}: skipped ({result['reason']})")
        else:
            print(
                f"{result['run_key']}: {result['images']} images, "
                f"{result['inserted']} new, {result['updated']} still open, "
                f"{result['resolved']} resolved"
            )


def cmd_ingest_dns(args, conn):
    db.migrate(conn)
    if args.from_file:
        result = adguard.ingest_file(conn, pathlib.Path(args.from_file))
    else:
        result = adguard.ingest_api(conn)
    if result.get("skipped"):
        print(f"{result['run_key']}: skipped ({result['reason']})")
    else:
        print(
            f"{result['run_key']}: {result['seen']} seen, {result['inserted']} inserted, "
            f"{result['duplicates']} duplicate, {result['skipped_entries']} skipped, "
            f"{result['new_domains']} new domains, {result['pruned']} pruned"
        )


def cmd_exposure(args, conn):
    """Load the hand-written exposure map.

    Nothing can infer this. With zero inbound ports, whether an image is
    reachable over the tailnet, only internally, or exists purely at build time
    is the difference between a finding that matters and one that does not, and
    only a human knows which is which.
    """
    db.migrate(conn)
    doc = yaml.safe_load(pathlib.Path(args.path).read_text()) or {}
    entries = doc.get("images") or {}
    with conn.cursor() as cur:
        for image, spec in entries.items():
            cur.execute(
                """insert into image_exposure (image, exposure, note, updated_at)
                   values (%s, %s, %s, now())
                   on conflict (image) do update
                     set exposure = excluded.exposure,
                         note = excluded.note,
                         updated_at = now()""",
                (image, spec.get("exposure", "unknown"), spec.get("note")),
            )
    conn.commit()
    print(f"exposure: {len(entries)} images")

    # Anything scanned but unmapped defaults to 'unknown', which the priority
    # view scores between internal and build-only. Say so out loud rather than
    # letting a new stack silently inherit a middling rank.
    with conn.cursor() as cur:
        cur.execute(
            """select distinct f.image from vuln_finding f
                left join image_exposure e on e.image = f.image
               where e.image is null order by 1"""
        )
        missing = [r[0] for r in cur.fetchall()]
    if missing:
        print("  UNMAPPED (defaulting to 'unknown'): " + ", ".join(missing))


def cmd_enrich(args, conn):
    db.migrate(conn)
    n = enrich.fetch_kev(conn)
    print(f"kev: {n} entries")
    n = enrich.fetch_epss(conn, only_known=not args.full)
    print(f"epss: {n} scores")


def cmd_rules(args, conn):
    db.migrate(conn)
    rules_dir = pathlib.Path(args.dir) if args.dir else rules.DEFAULT_RULES_DIR
    result = rules.run(conn, rules_dir)
    for r in result["rules"]:
        if "failed" in r:
            print(f"{r['rule_id']}: FAILED - {r['failed']}")
        elif "skipped" in r:
            print(f"{r['rule_id']}: skipped ({r['skipped']})")
        else:
            print(f"{r['rule_id']}: {r['hits']} hits ({r['new']} new)")

    total_hits = sum(r.get("hits", 0) for r in result["rules"])
    total_new = sum(r.get("new", 0) for r in result["rules"])
    failed = sum(1 for r in result["rules"] if "failed" in r)
    print(f"\n{len(result['rules'])} rules, {total_hits} hits ({total_new} new), {failed} failed")
    if result["any_failed"]:
        # A broken rule has to fail the timer unit loudly, not vanish into a
        # clean-looking exit code.
        raise SystemExit(1)


def cmd_report(args, conn):
    with conn.cursor() as cur:
        cur.execute(
            """select count(*) filter (where fixable),
                      count(*) filter (where not fixable),
                      count(*) filter (where in_kev),
                      count(*) filter (where epss >= 0.1)
                 from vuln_priority"""
        )
        fixable, unfixable, kev, hot = cur.fetchone()
        print(
            f"open: {fixable} fixable, {unfixable} with no fix available"
            f"  |  in CISA KEV: {kev}  |  EPSS >= 0.1: {hot}\n"
        )

        cur.execute(
            """select image, exposure, cve, severity, pkg_name,
                      installed_version, fixed_version, in_kev, epss, priority
                 from vuln_priority order by priority desc, cve limit %s""",
            (args.limit,),
        )
        rows = cur.fetchall()
        if not rows:
            print("nothing open. Either the estate is clean or nothing has been ingested.")
        else:
            print(f"{'PRI':>4}  {'IMAGE':<34} {'EXPOSURE':<11} {'CVE':<18} {'SEV':<8} PACKAGE")
            for image, exp, cve, sev, pkg, inst, fix, in_kev, epss, pri in rows:
                flags = []
                if in_kev:
                    flags.append("KEV")
                if epss is not None and epss >= 0.1:
                    flags.append(f"EPSS {epss:.2f}")
                tail = ("  [" + ", ".join(flags) + "]") if flags else ""
                arrow = f"{inst} -> {fix}" if fix else f"{inst} (no fix)"
                print(f"{pri:>4}  {image[:34]:<34} {exp:<11} {cve:<18} {sev:<8} {pkg} {arrow}{tail}")

            cur.execute(
                """select image, count(*) from vuln_priority
                    where fixable group by image order by 2 desc limit 5"""
            )
            print("\nworst images by fixable count:")
            for image, n in cur.fetchall():
                print(f"  {n:>4}  {image}")

        # Only printed when there is something to say: an empty rule engine
        # section would just be noise in a report that is otherwise a
        # backlog of things worth looking at.
        cur.execute(
            """select rule_id, entity, summary, first_seen, hit_count
                 from rule_hit
                where status = 'open'
                order by first_seen desc
                limit 15"""
        )
        hit_rows = cur.fetchall()
        if hit_rows:
            cur.execute("select count(*) from rule_hit where status = 'open'")
            (open_count,) = cur.fetchone()
            print("\nopen rule hits:")
            for rule_id, entity, summary, first_seen, hit_count in hit_rows:
                print(f"  {first_seen.date()}  {rule_id:<26} {entity:<28} {summary} (x{hit_count})")
            print(f"\n{open_count} open rule hit{'s' if open_count != 1 else ''}")


def main() -> int:
    p = argparse.ArgumentParser(prog="home-soc")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("migrate", help="apply schema migrations").set_defaults(fn=cmd_migrate)

    q = sub.add_parser("ingest-trivy", help="ingest a Trivy run directory")
    q.add_argument("path")
    q.add_argument("--all", action="store_true",
                   help="treat PATH as a directory OF run directories and ingest every one")
    q.set_defaults(fn=cmd_ingest_trivy)

    q = sub.add_parser("ingest-dns", help="ingest AdGuard Home's DNS query log")
    q.add_argument("--from-file",
                    help="ingest a local JSON file shaped like one AdGuard API response, "
                         "instead of pulling from AdGuard")
    q.set_defaults(fn=cmd_ingest_dns)

    q = sub.add_parser("exposure", help="load the hand-written image exposure map")
    q.add_argument("path", nargs="?", default="exposure.yaml")
    q.set_defaults(fn=cmd_exposure)

    q = sub.add_parser("enrich", help="fetch CISA KEV and FIRST EPSS")
    q.add_argument("--full", action="store_true",
                   help="load every EPSS score, not just CVEs already present")
    q.set_defaults(fn=cmd_enrich)

    q = sub.add_parser("rules", help="run the rule engine over rules/*.sql")
    q.add_argument("--dir", help="rules directory (default: ../rules relative to ingest/)")
    q.set_defaults(fn=cmd_rules)

    q = sub.add_parser("report", help="the prioritised backlog")
    q.add_argument("--limit", type=int, default=25)
    q.set_defaults(fn=cmd_report)

    args = p.parse_args()
    with db.connect() as conn:
        args.fn(args, conn)
    return 0


if __name__ == "__main__":
    sys.exit(main())
