-- home-soc, DNS ingest (phase 2).
--
-- Same envelope as 001: `source` and `scan_run` already exist, this file only
-- adds a source row and the typed tables for AdGuard Home's query log.
--
-- Two tables, two different lifetimes, on purpose.
--
-- 1. `dns_query` is the raw firehose: one row per query AdGuard logged, kept
--    only for a retention window (HOMESOC_DNS_RETENTION_DAYS, default 35).
--    A home network's query log grows without bound and most of it is never
--    read twice, so keeping it forever would be storage spent on nothing.
--
-- 2. `dns_domain` is the registry that survives the prune: it answers "have I
--    ever seen this registrable domain before" long after the raw rows that
--    first proved it are gone. Without it, a domain that stops being queried
--    for 40 days and then reappears would look newly seen, the same failure
--    mode `vuln_finding.first_seen` exists to avoid for vulnerabilities.
--    `first_seen` here follows that exact same principle: set once, never
--    moved.

insert into source (id, description) values
    ('adguard', 'AdGuard Home query log, pulled from its REST API by the DNS ingester')
on conflict (id) do nothing;

-- --------------------------------------------------------------------------
-- Raw query log, pruned after HOMESOC_DNS_RETENTION_DAYS
-- --------------------------------------------------------------------------

create table if not exists dns_query (
    id                  bigserial primary key,
    ts                  timestamptz not null,
    client              text not null,
    qname               text not null,
    qtype               text not null,

    -- AdGuard's own filtering verdict, verbatim (NotFilteredNotFound,
    -- FilteredBlackList, FilteredSafeBrowsing, Rewritten, ...). Kept as text
    -- rather than folded away, because `blocked` alone loses which list or
    -- rule fired.
    reason              text,
    blocked             boolean not null,

    -- The DNS rcode as AdGuard reports it (NOERROR, NXDOMAIN, ...). Nullable:
    -- not every entry carries one.
    status              text,
    upstream            text,
    cached              boolean,
    elapsed_ms          numeric,

    -- Computed at ingest time, not left for a query to derive on the fly:
    -- both are cheap to get wrong (a naive "last two labels" split breaks on
    -- multi-label public suffixes) and expensive to get wrong silently in a
    -- detection rule.
    registrable_domain  text not null,
    label_entropy       numeric not null,

    run_id              bigint references scan_run(id),

    -- The natural key. Same property as the Trivy ingester's
    -- (image, pkg_name, installed_version, cve): re-ingesting a page the
    -- pull already saw is a no-op rather than a duplicate row, which is what
    -- makes incremental pulls (and replaying a failed pull) safe.
    unique (ts, client, qname, qtype)
);

create index if not exists dns_query_ts_idx on dns_query (ts);
create index if not exists dns_query_registrable_domain_idx on dns_query (registrable_domain);
create index if not exists dns_query_blocked_ts_idx on dns_query (blocked, ts);

-- --------------------------------------------------------------------------
-- Domain registry, never pruned
-- --------------------------------------------------------------------------

create table if not exists dns_domain (
    domain          text primary key,

    -- Set once at the first query ever seen for this domain and never moved
    -- again, same principle as vuln_finding.first_seen: without it, "newly
    -- seen domain" stops being answerable the moment the raw row that first
    -- proved it ages out of dns_query.
    first_seen      timestamptz not null,
    last_seen       timestamptz not null,

    query_count     bigint not null default 0,
    blocked_count   bigint not null default 0
);

insert into schema_version (version) values (2) on conflict do nothing;
