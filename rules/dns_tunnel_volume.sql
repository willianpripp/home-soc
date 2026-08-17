-- description: one domain answering an unusual number of distinct names
--
-- DNS tunnelling moves data by encoding it into a stream of unique
-- subdomains, one query per chunk of whatever is being smuggled in or out.
-- Volume alone does not distinguish that from a busy but ordinary domain (a
-- CDN edge, a telemetry endpoint), so the tell here is cardinality times
-- randomness: many distinct names AND those names look random, neither one
-- on its own.
--
-- Why 50 distinct names: a household's ordinary domains reuse the same
-- handful of subdomains over and over (www, api, cdn, static); a tunnel
-- invents a new label on every single query, so distinct qnames in a day
-- climbs fast for a tunnel and stays flat for almost everything else.
--
-- Why entropy >= 3.0: this is what keeps a big legitimate domain that can
-- also produce dozens of distinct subdomains below the line, region codes,
-- build hashes, sharded telemetry IDs are distinct but still word-shaped or
-- drawn from a small, structured alphabet, so their average entropy sits
-- well under a tunnel's. A tunnel's labels are closer to random bytes, and
-- averaging entropy across every distinct name in the window catches that
-- even when no single label is a DGA-grade outlier on its own.

select
    registrable_domain as entity,
    format(
        '%s distinct name%s in 24h, avg entropy %s bits/char, %s client%s',
        count(distinct qname),
        case when count(distinct qname) = 1 then '' else 's' end,
        round(avg(label_entropy), 2),
        count(distinct client),
        case when count(distinct client) = 1 then '' else 's' end
    ) as summary
from dns_query
where ts >= now() - interval '24 hours'
group by registrable_domain
having count(distinct qname) >= 50
   and avg(label_entropy) >= 3.0;
