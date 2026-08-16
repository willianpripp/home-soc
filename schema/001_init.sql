-- home-soc, initial schema.
--
-- Two ideas run through this file and both are deliberate.
--
-- 1. TYPED TABLES OVER A SHARED ENVELOPE. `source` and `scan_run` are the
--    envelope: every fact that arrives knows which source produced it and in
--    which run. The facts themselves live in typed tables (`vuln_finding`
--    today, DNS tomorrow) rather than a generic JSONB soup, because rules have
--    to be readable SQL and a rule full of `payload->>'field'` is not.
--    Adding a source later is a new ingester and a new table, never a
--    migration of what already exists. That matters because a firewall is
--    planned and its logs will arrive one day.
--
-- 2. A FINDING IS A THING THAT PERSISTS, not a row in tonight's report.
--    `first_seen` is set once and never moved, so "this has been open for
--    three weeks" is answerable. A scan that re-reports the same finding
--    updates `last_seen` and nothing else. Without that, every scan looks like
--    a fresh set of problems and nothing can be aged, trended or triaged.

create table if not exists schema_version (
    version     integer primary key,
    applied_at  timestamptz not null default now()
);

-- --------------------------------------------------------------------------
-- Envelope
-- --------------------------------------------------------------------------

create table if not exists source (
    id          text primary key,
    description text not null,
    added_at    timestamptz not null default now()
);

insert into source (id, description) values
    ('trivy', 'Weekly Trivy scan of every running container image, from the homelab container_scan role')
on conflict (id) do nothing;

-- One row per ingested run. `run_key` is the source's own idea of a run (for
-- Trivy, the /srv/scan/json/<stamp> directory name) and is unique, so
-- re-ingesting the same directory is a no-op rather than a duplicate. Ingest
-- has to be safely repeatable: it will be re-run by hand, after a failure, and
-- during a restore rehearsal.
create table if not exists scan_run (
    id              bigserial primary key,
    source_id       text not null references source(id),
    run_key         text not null,
    started_at      timestamptz not null,
    ingested_at     timestamptz not null default now(),
    images_total    integer,
    images_scanned  integer,
    images_skipped  integer,
    unique (source_id, run_key)
);

-- --------------------------------------------------------------------------
-- Context that only a human can supply
-- --------------------------------------------------------------------------

-- With zero inbound ports (ADR-0002), a flat CVSS or severity sort is close to
-- meaningless here: a CRITICAL in an image nothing can reach is not the same
-- problem as a HIGH in the one thing answering on the tailnet. Nothing can
-- infer this, so it is hand-written in exposure.yaml and loaded from there.
create table if not exists image_exposure (
    image     text primary key,
    exposure  text not null check (exposure in ('tailnet', 'internal', 'build-only', 'unknown')),
    note      text,
    updated_at timestamptz not null default now()
);

-- --------------------------------------------------------------------------
-- Findings
-- --------------------------------------------------------------------------

create table if not exists vuln_finding (
    id                bigserial primary key,
    image             text not null,
    pkg_name          text not null,
    installed_version text not null,
    cve               text not null,

    severity          text not null,
    fixed_version     text,
    title             text,
    purl              text,
    target            text,
    pkg_class         text,

    first_seen        timestamptz not null default now(),
    last_seen         timestamptz not null default now(),
    first_run_id      bigint references scan_run(id),
    last_run_id       bigint references scan_run(id),

    -- Suppression is owned HERE and nowhere else. The scanner's own ignore
    -- mechanism was deliberately not used: a finding suppressed in Trivy never
    -- reaches this table at all, and the count would then be wrong in the
    -- safe-looking direction, which is the worst way for a security number to
    -- be wrong.
    status            text not null default 'open'
                      check (status in ('open', 'accepted', 'false_positive', 'fixed')),
    status_note       text,
    status_changed_at timestamptz,

    -- Set when a scan stops reporting it. Not deleted: "this went away" is
    -- itself a fact worth keeping, and a finding that reappears should show
    -- its original first_seen rather than looking new.
    resolved_at       timestamptz,

    -- The natural key. Installed version is part of it on purpose: the same
    -- CVE against a rebuilt package is a different finding, and collapsing
    -- them would hide the fact that a fix landed and a new one appeared.
    unique (image, pkg_name, installed_version, cve)
);

create index if not exists vuln_finding_open_idx
    on vuln_finding (status, severity) where resolved_at is null;
create index if not exists vuln_finding_image_idx on vuln_finding (image);
create index if not exists vuln_finding_cve_idx on vuln_finding (cve);

-- --------------------------------------------------------------------------
-- Enrichment: what the rest of the world knows about these CVEs
-- --------------------------------------------------------------------------

-- CISA Known Exploited Vulnerabilities. Small, high signal: presence here
-- means someone is actually using it, which outranks any severity label.
create table if not exists kev (
    cve             text primary key,
    vendor_project  text,
    product         text,
    date_added      date,
    due_date        date,
    known_ransomware boolean,
    fetched_at      timestamptz not null default now()
);

-- FIRST.org EPSS: probability of exploitation in the next 30 days. This is the
-- one that makes a 432-item backlog tractable, because most CVEs score under
-- 0.001 and a handful score above 0.1.
create table if not exists epss_score (
    cve         text primary key,
    score       numeric(8,6) not null,
    percentile  numeric(8,6),
    model_date  date,
    fetched_at  timestamptz not null default now()
);

-- --------------------------------------------------------------------------
-- The prioritised view. This is the thing that replaces `sudo cat`.
-- --------------------------------------------------------------------------
--
-- Ordering, worst first:
--   1. Is it actionable at all? Nothing without a fixed version can be worked
--      this week, so unfixable findings sort last regardless of severity.
--      They are still counted, never hidden.
--   2. Is it being exploited? KEV presence, then EPSS above 0.1.
--   3. Can it be reached? exposure weights tailnet over internal over
--      build-only, because ADR-0002 means severity alone does not rank here.
--   4. Severity, last, as a tie-break rather than the headline.
create or replace view vuln_priority as
select
    f.id,
    f.image,
    coalesce(e.exposure, 'unknown')                        as exposure,
    f.cve,
    f.severity,
    f.pkg_name,
    f.installed_version,
    f.fixed_version,
    (f.fixed_version is not null and f.fixed_version <> '') as fixable,
    (k.cve is not null)                                     as in_kev,
    s.score                                                 as epss,
    f.first_seen,
    f.last_seen,
    f.status,
    f.title,
    (
        (case when f.fixed_version is not null and f.fixed_version <> '' then 1000 else 0 end)
      + (case when k.cve is not null then 500 else 0 end)
      + (case when coalesce(s.score, 0) >= 0.1 then 250 else 0 end)
      + (case coalesce(e.exposure, 'unknown')
             when 'tailnet'    then 120
             when 'internal'   then 60
             when 'unknown'    then 30
             when 'build-only' then 0
         end)
      + (case f.severity when 'CRITICAL' then 40 when 'HIGH' then 20 else 0 end)
    ) as priority
from vuln_finding f
left join image_exposure e on e.image = f.image
left join kev k            on k.cve   = f.cve
left join epss_score s     on s.cve   = f.cve
where f.resolved_at is null
  and f.status = 'open';

insert into schema_version (version) values (1) on conflict do nothing;
