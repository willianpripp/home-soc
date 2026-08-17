-- home-soc, known-bad domain enrichment (phase 3, continued).
--
-- One table. `known_bad_domain` is the "someone already knows this is bad"
-- signal, sitting next to the shape-based DNS rules (entropy, newly-seen,
-- blocked-spike) the same way `kev` sits next to EPSS for CVEs: those rules
-- infer suspicion from shape, this table states it outright because a public
-- blocklist already did the work. dns_known_bad_domain (rules/) is the rule
-- that reads it.
--
-- (domain, source) is the primary key, not domain alone, because more than
-- one feed can list the same domain and losing that overlap would throw away
-- a genuine corroboration signal (two independent lists agreeing is stronger
-- than one).

create table if not exists known_bad_domain (
    domain      text not null,
    source      text not null,
    fetched_at  timestamptz not null default now(),
    primary key (domain, source)
);

create index if not exists known_bad_domain_domain_idx on known_bad_domain (domain);

insert into schema_version (version) values (4) on conflict do nothing;
