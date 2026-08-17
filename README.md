# home-soc

A small detection platform for a home network. It takes the telemetry a
household already produces, gives it a schema, ranks it against what the rest of
the world knows, and turns it into a backlog somebody can actually work.

It exists because of a specific moment. A weekly container scan reported **453
fixable HIGH and CRITICAL findings**, and the only way to read them was:

```sh
ssh lab 'sudo cat /srv/scan/latest.txt'
```

A number you cannot act on is just anxiety. Ten minutes after the first ingest,
the same data said something useful instead:

```
open: 421 fixable, 298 with no fix available  |  in CISA KEV: 0  |  EPSS >= 0.1: 1
```

Nothing in this estate is being actively exploited, one thing has a meaningful
probability, and the rest is maintenance. That is a completely different
Saturday.

## What it does today

- **Ingests Trivy scan output** into Postgres, one row per finding, with a
  natural key so a finding is a thing that persists rather than a line in
  tonight's report. `first_seen` is set once and never moved, so "this has been
  open three weeks" is answerable.
- **Enriches from two free public feeds**: CISA KEV (is it being exploited in
  the wild) and FIRST EPSS (probability of exploitation in the next 30 days).
- **Ingests the household's DNS query log** from AdGuard Home, one row per
  query, with a registrable domain and a Shannon entropy score computed at
  ingest so DGA-shaped domains and tunnelled subdomains stand out without a
  rule reading raw qnames one at a time. Raw rows are pruned after a
  retention window; a "domain ever seen" registry is not.
- **Ranks by what actually matters here**, not by severity alone.
- **Tracks state**: a finding that stops being reported is resolved, not
  deleted, and one that comes back keeps its original `first_seen` instead of
  masquerading as new.

## How it works: why severity alone does not rank anything

This network has **zero inbound ports**. Everything is reached over a private
overlay network. In that world a CRITICAL in an image that only exists at build
time is not the same problem as a HIGH in the one process answering on the
network, and sorting by CVSS puts them side by side.

So the priority score asks four questions in order:

| Question | Weight | Why it is first |
|---|---|---|
| Is there a fix? | 1000 | Nothing without a fixed version can be worked this week. Unfixable findings are counted, never hidden, and always sort last. |
| Is it being exploited? | 500 | CISA KEV presence outranks any severity label a scanner attaches. |
| Is exploitation likely? | 250 | EPSS ≥ 0.1 puts a CVE in the small minority worth caring about. |
| Can it be reached? | 0–120 | Hand-written in [`exposure.yaml`](exposure.yaml), because nothing can infer it. |
| Severity | 0–40 | Last, as a tie-break rather than the headline. |

## Quick start

```sh
cp .env.example .env          # only HOMESOC_DB_PASSWORD needs a value
docker compose up -d db
docker compose run --rm ingest migrate
docker compose run --rm ingest exposure
docker compose run --rm ingest ingest-trivy /scan/json --all
docker compose run --rm ingest enrich
docker compose run --rm ingest report
```

`demo/` carries an invented scan run so the whole pipeline can be exercised
without a real scanner:

```sh
HOMESOC_SCAN_DIR=./demo docker compose run --rm ingest ingest-trivy /scan/json --all
docker compose run --rm ingest ingest-dns --from-file demo/querylog.json
```

## Layout

```
home-soc/
├── schema/
│   ├── 001_init.sql       # the whole data model, and the reasoning for it
│   └── 002_dns.sql        # dns_query and dns_domain, for the AdGuard ingester
├── ingest/
│   ├── cli.py             # one entry point, invoked by a timer and by hand
│   ├── trivy.py           # Trivy JSON to findings, including the resolve pass
│   ├── enrich.py          # CISA KEV and FIRST EPSS
│   ├── adguard.py         # AdGuard Home query log to dns_query and dns_domain
│   ├── db.py              # connection and numbered SQL migrations
│   └── Dockerfile         # built from the repo root, so it can see schema/
├── demo/                  # an invented run, so a stranger can see it work
│   └── querylog.json      # an invented AdGuard API response
├── exposure.yaml          # which images are reachable, and how. Hand-written
├── docker-compose.yml     # postgres, plus a CLI container that never stays up
└── README.md
```

There is no daemon. Nothing here needs to be resident, and a cron-shaped tool
is one less thing that can be quietly dead while looking alive.

## Running it for real

This is not a demo that was built and abandoned. It runs on the small home
server it monitors, in Docker, against that machine's own weekly scan output.

- **The database is loopback-bound.** Nothing here publishes a port to the
  network. The host has no inbound ports open at all, which is also why
  `exposure.yaml` exists: with nothing internet-facing, "how reachable is this
  image" is the question severity cannot answer.
- **Ingest is invoked by a systemd timer** immediately after the weekly scan
  finishes, so the backlog is current without anything sitting resident.
- **The scan tree is mounted read-only.** This container has no business
  writing to the directory it reads, and that directory is an inventory of
  every unpatched hole on the host.
- **Findings and the raw scan output never leave the machine.** What you see in
  this repository is the code and an invented demo run, never real findings.
- **The AdGuard pull is also timer-invoked**, credentials live in `.env` (the
  API user and password AdGuard Home was given), never in this repository.
  Query rows are pruned after `HOMESOC_DNS_RETENTION_DAYS` (35 by default),
  while `dns_domain`, the "have I ever seen this domain" registry, is kept.

## Design notes

**No ORM.** The queries are the interesting part of this repository, and hiding
them behind a mapper would make the detection logic harder to read, which is the
opposite of the point. Migrations are numbered SQL files applied in order.

**Suppression is owned in exactly one place.** The scanner's own ignore
mechanism is deliberately unused: a finding suppressed at the scanner never
reaches the database at all, and the count would then be wrong in the
safe-looking direction, which is the worst way for a security number to be wrong.
Suppression lives in `vuln_finding.status`.

**Typed tables over a shared envelope.** `source` and `scan_run` are the
envelope; facts live in typed tables rather than generic JSONB, because rules
have to be readable SQL and a rule full of `payload->>'field'` is not. Adding a
source later is a new ingester and a new table, never a migration of what is
already there.

## Status

Early. Trivy ingest, enrichment, the prioritised report and DNS ingest work
against real data (phases 1 and 2). Not built yet: the rule engine with
per-rule tests, and the triage UI. Those are phases 3 and 4.

## How this was built

I built this with [Claude Code](https://claude.com/claude-code), using several
of Anthropic's models, and I would rather say that plainly than leave anyone to
guess. Most of the code here was written by a model. The decisions were not:
what to rank, what to refuse to build, and why an unfixable CRITICAL sorts below
a fixable HIGH. It runs against my own household's real telemetry, which is
where every design decision in it came from.

## License

MIT, see [LICENSE](LICENSE).
