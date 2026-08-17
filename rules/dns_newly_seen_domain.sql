-- description: registrable domain seen for the first time in the last 24 hours
--
-- On a network with zero inbound ports (ADR-0002), nothing gets in
-- unsolicited. Both initial access and command-and-control start the same
-- way instead: something on the client resolves a name nobody here has ever
-- looked up before, a phishing link, a dropped payload's C2, a new piece of
-- ad tech riding along in an app update. dns_domain.first_seen already marks
-- that moment and survives the dns_query prune, so this rule is a thin read
-- of a fact the ingester already computed rather than new detection logic.
--
-- A newly-seen domain is not a verdict, most of them are exactly what they
-- look like: a new app, a new vendor, a CDN edge nobody hit before. That is
-- why this fires wide (every domain, every day) rather than trying to guess
-- which new domains are suspicious; the DGA and tunnel shapes below narrow
-- that question with actual signal instead of recency alone.

select
    d.domain as entity,
    format(
        'first seen %s, %s quer%s from %s client%s, %s blocked',
        to_char(d.first_seen, 'YYYY-MM-DD HH24:MI'),
        d.query_count,
        case when d.query_count = 1 then 'y' else 'ies' end,
        c.client_count,
        case when c.client_count = 1 then '' else 's' end,
        d.blocked_count
    ) as summary
from dns_domain d
cross join lateral (
    select count(distinct q.client) as client_count
    from dns_query q
    where q.registrable_domain = d.domain
) c
where d.first_seen >= now() - interval '24 hours';
