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
- **Enriches from three free public feeds**: CISA KEV (is it being exploited
  in the wild) and FIRST EPSS (probability of exploitation in the next 30
  days) for CVEs, and abuse.ch URLhaus (domains a public community already
  knows are serving malware) for the DNS side.
- **Ingests the household's DNS query log** from AdGuard Home, one row per
  query, with a registrable domain and a Shannon entropy score computed at
  ingest so DGA-shaped domains and tunnelled subdomains stand out without a
  rule reading raw qnames one at a time. Raw rows are pruned after a
  retention window; a "domain ever seen" registry is not. The device name
  AdGuard already knows for a client (from DHCP or its own client config)
  is captured at the same ingest step; it lives only in the database, never
  in this repository.
- **Ranks by what actually matters here**, not by severity alone.
- **Tracks state**: a finding that stops being reported is resolved, not
  deleted, and one that comes back keeps its original `first_seen` instead of
  masquerading as new.
- **Runs a rule engine over the typed tables.** Rules are plain SQL files in
  `rules/`, each one readable top to bottom. A hit persists the same way a
  finding does: `first_seen` set once, a re-hit moves `last_seen` and nothing
  else, and closing a hit out (accepted, false positive, resolved) is a
  human decision the engine never makes on its own.

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

## Rules

A rule is one `.sql` file in `rules/`. The file's first line, `-- description:
<one line>`, is parsed into `rule.description`; the query below it must select
exactly two columns, `entity` and `summary`. Everything else in the file is
prose explaining why the rule exists and why its thresholds are what they are,
because a rule nobody can read top to bottom is a rule nobody trusts. See
[`rules/README.md`](rules/README.md) for the full contract.

| Rule | What it watches | Why the threshold |
|---|---|---|
| `dns_newly_seen_domain` | A registrable domain queried for the first time in the last 24 hours | With zero inbound ports, both initial access and C2 start with a lookup nobody made before |
| `dns_dga_entropy` | DNS names with Shannon entropy >= 3.5 bits/char and at least 12 characters | English-like labels sit under 3 bits/char; base32 or random labels sit above. The length floor stops short labels from maxing out entropy on a tiny alphabet |
| `dns_blocked_spike` | A client whose blocked-query count in the last 24h is at least 3x its prior-week daily average, and at least 20 in absolute terms | Fires on change, not on volume; the floor stops a 0-to-3 jump from tripping it |
| `dns_known_bad_domain` | A query (by registrable domain or exact qname) for a domain on an abuse.ch blocklist | Someone else already knows this is bad; an unblocked hit is the urgent case, AdGuard's own filtering missed what a public list already caught |
| `dns_nxdomain_burst` | A client with at least 30 unblocked NXDOMAIN answers in the last 24h, at least 3x its prior-week daily average | A DGA burns through mostly-nonexistent generated names before any of them resolves; the burst of failures is the earliest signal there is |
| `dns_tunnel_volume` | A registrable domain queried with at least 50 distinct qnames in the last 24h, averaging at least 3.0 bits/char entropy | Tunnelling's tell is cardinality times randomness; the entropy term keeps big legitimate CDNs (many distinct but word-shaped subdomains) below the line |

The engine (`ingest/rules.py`) never closes a hit on its own. A hit that stops
firing simply stops moving `last_seen`; deciding it is fixed, accepted, or a
false positive is a human call, the same principle `vuln_finding.status`
already applies to scan findings.

CI refuses a rule without a matching `tests/test_rule_<stem>.py`, in both
directions: an untested rule fails the build, and so does a test left behind
for a rule that no longer exists.

## Quick start

```sh
cp .env.example .env          # only HOMESOC_DB_PASSWORD needs a value
docker compose up -d db
docker compose run --rm ingest migrate
docker compose run --rm ingest exposure
docker compose run --rm ingest ingest-trivy /scan/json --all
docker compose run --rm ingest enrich
docker compose run --rm ingest rules
docker compose run --rm ingest report
```

`demo/` carries an invented scan run so the whole pipeline can be exercised
without a real scanner:

```sh
HOMESOC_SCAN_DIR=./demo docker compose run --rm ingest ingest-trivy /scan/json --all
docker compose run --rm ingest ingest-dns --from-file demo/querylog.json --shift-to-now
```

`demo/querylog.json` is a static file, its timestamps froze the day it was
written, so `--shift-to-now` rebases them (preserving every gap between
entries) to end at the moment you run it, which is what gives the two
24-hour-window rules something to fire on.

`pytest` runs the whole suite, including one test file per rule, against a
scratch database created and dropped per test (see `tests/conftest.py`).

## Layout

```
home-soc/
├── schema/
│   ├── 001_init.sql       # the whole data model, and the reasoning for it
│   ├── 002_dns.sql        # dns_query and dns_domain, for the AdGuard ingester
│   ├── 003_rules.sql      # rule and rule_hit, for the rule engine
│   └── 004_known_bad.sql  # known_bad_domain, for the abuse.ch enrichment
├── rules/
│   ├── README.md          # the rule file contract
│   ├── dns_newly_seen_domain.sql
│   ├── dns_dga_entropy.sql
│   ├── dns_blocked_spike.sql
│   ├── dns_known_bad_domain.sql
│   ├── dns_nxdomain_burst.sql
│   └── dns_tunnel_volume.sql
├── ingest/
│   ├── cli.py             # one entry point, invoked by a timer and by hand
│   ├── trivy.py           # Trivy JSON to findings, including the resolve pass
│   ├── enrich.py          # CISA KEV and FIRST EPSS
│   ├── adguard.py         # AdGuard Home query log to dns_query and dns_domain
│   ├── rules.py           # discovers rules/*.sql and upserts what they find
│   ├── db.py              # connection and numbered SQL migrations
│   └── Dockerfile         # built from the repo root, so it can see schema/
├── tests/                 # pytest: engine semantics, one file per rule
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
- **The AdGuard pull is also timer-invoked**, hourly, credentials live in
  `.env` (the API user and password AdGuard Home was given), never in this
  repository. The pull runs through the `ingest-dns` compose service, which
  joins the host network because AdGuard's API is deliberately loopback-bound
  on the machine it protects. Query rows are pruned after
  `HOMESOC_DNS_RETENTION_DAYS` (35 by default), while `dns_domain`, the "have
  I ever seen this domain" registry, is kept.

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

Early. Trivy ingest, enrichment, the prioritised report, DNS ingest and the
rule engine work against real data. Phase 3 is complete: six rules, a test
file per rule, and a CI gate that refuses a rule without one. Not built yet:
the triage UI, phase 4.

## How this was built

I built this with [Claude Code](https://claude.com/claude-code), using several
of Anthropic's models, and I would rather say that plainly than leave anyone to
guess. Most of the code here was written by a model. The decisions were not:
what to rank, what to refuse to build, and why an unfixable CRITICAL sorts below
a fixable HIGH. It runs against my own household's real telemetry, which is
where every design decision in it came from.

## License

MIT, see [LICENSE](LICENSE).
