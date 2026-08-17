-- description: query for a domain on an abuse.ch blocklist
--
-- known_bad_domain is the "someone already knows this is bad" signal, sitting
-- next to the shape-based DNS rules the same way CISA KEV sits next to
-- severity for CVEs: dns_dga_entropy and dns_tunnel_volume infer suspicion
-- from shape, this one states it outright because a public blocklist
-- (currently URLhaus, see ingest/enrich.py) already did the work.
--
-- Matched two ways on purpose: dns_query.registrable_domain (a listing for
-- the whole domain) and the full qname (some blocklist entries are
-- themselves a subdomain, a specific compromised path host rather than the
-- registrable domain). Matching only the registrable domain would miss a
-- subdomain-specific listing entirely; matching only qname would miss every
-- other subdomain of a domain that is bad end to end. Counts are taken as
-- count(distinct dns_query.id) rather than count(*) because a domain listed
-- under more than one source would otherwise be double-counted per matching
-- query row, which is exactly the kind of inflated-looking count that erodes
-- trust in every other number this rule reports.
--
-- Whether AdGuard already blocked the query matters more than the raw count.
-- A query AdGuard's own blocklist already caught was stopped at the resolver
-- and never reached anything; a query that went through UNBLOCKED to a
-- domain a public list already flags is the urgent case, because this
-- household's own filtering missed something a stranger on the internet
-- already knew to catch, and something on the network may have gotten a real
-- answer back from it.

select
    kb.domain as entity,
    format(
        'listed by %s: %s quer%s from %s client%s, %s blocked / %s NOT blocked',
        string_agg(distinct kb.source, ', '),
        count(distinct q.id),
        case when count(distinct q.id) = 1 then 'y' else 'ies' end,
        count(distinct q.client),
        case when count(distinct q.client) = 1 then '' else 's' end,
        count(distinct q.id) filter (where q.blocked),
        count(distinct q.id) filter (where not q.blocked)
    ) as summary
from known_bad_domain kb
join dns_query q
  on q.registrable_domain = kb.domain
  or q.qname = kb.domain
group by kb.domain;
