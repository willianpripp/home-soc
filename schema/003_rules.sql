-- home-soc, rule engine (phase 3).
--
-- Everything the earlier schemas already got right is reused rather than
-- reinvented: a rule hit is a thing that persists, `first_seen` is set once
-- and never moved, and closing a hit is owned by a human, never inferred.
-- That is exactly the reasoning `vuln_finding.status` and `dns_domain`
-- already carry; this file just applies it to detections instead of scans.
--
-- Two tables.
--
-- 1. `rule` is the registry of what the engine knows how to run. One row per
--    file in rules/, keyed by the filename stem. `description` is parsed out
--    of the rule file's own header at run time and kept here mostly so a
--    human looking at the database (not the repo) can still tell what a rule
--    is for. `enabled` lives in the database, not the filesystem, on purpose:
--    turning a noisy rule off is a one-row UPDATE that survives a redeploy,
--    rather than deleting or renaming a file that the next `git pull` would
--    silently bring back.
--
-- 2. `rule_hit` is one row per (rule, entity) the engine has ever reported.
--    The engine never resolves a hit on its own. A hit that stops firing
--    simply stops moving `last_seen`; it still sits there with whatever
--    `status` a human last gave it. Deciding "this is fixed" or "this is
--    fine" is exactly the kind of judgement `vuln_finding.status` already
--    refuses to automate, and a detection rule has even less business making
--    that call than a scanner does.

create table if not exists rule (
    id          text primary key,
    description text not null,
    enabled     boolean not null default true,
    added_at    timestamptz not null default now()
);

create table if not exists rule_hit (
    id                bigserial primary key,
    rule_id           text not null references rule(id),

    -- What the hit is about: a domain, a client address, an image. The
    -- meaning is entirely up to the rule, which is why this is untyped text
    -- rather than a foreign key into any one table.
    entity            text not null,

    -- One human line of context, produced by the rule's own SQL. Free text
    -- rather than structured columns, for the same reason rules read typed
    -- tables directly: the summary a rule author can write in one line is
    -- worth more here than a schema nobody will extend correctly.
    summary           text,

    -- Set once at the first run that reports this (rule_id, entity) and never
    -- moved again, same principle as vuln_finding.first_seen and
    -- dns_domain.first_seen: without it, "this has been firing for a week"
    -- stops being answerable the moment a re-run touches the row.
    first_seen        timestamptz not null default now(),
    last_seen         timestamptz not null default now(),

    -- How many engine runs have re-reported this hit, including the one that
    -- created it. A hit sitting at hit_count 1 for weeks is a one-off; a hit
    -- climbing every run is a standing condition.
    hit_count         integer not null default 1,

    -- Human-owned, exactly like vuln_finding.status. The engine writes 'open'
    -- once at insert and never touches this column again on a re-hit.
    status            text not null default 'open'
                      check (status in ('open', 'accepted', 'false_positive', 'resolved')),
    status_note       text,
    status_changed_at timestamptz,

    unique (rule_id, entity)
);

create index if not exists rule_hit_open_idx on rule_hit (rule_id, status) where status = 'open';

insert into schema_version (version) values (3) on conflict do nothing;
