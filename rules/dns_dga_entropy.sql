-- description: high-entropy DNS name, DGA or tunnel shaped
--
-- Why 3.5 bits per character: English-like labels (and most vendor CDN
-- naming) sit comfortably under 3 bits/char, because real words repeat
-- letters and follow a language's own frequency distribution. A label
-- generated from base32, base36 or plain random bytes has none of that
-- structure and lands north of 3.5. The threshold is a tripwire, not a
-- verdict: it flags "shaped like a DGA or an encoded tunnel label", and a
-- human still decides what it actually is.
--
-- Why length has a floor: entropy on a short string is noisy. A four or five
-- character label can max out its entropy score just by using distinct
-- characters ("zx7q"), with no room for the character-frequency structure
-- entropy is actually trying to measure. Requiring at least 12 characters
-- keeps the floor from firing on ordinary short hostnames.
--
-- Blocked queries are kept in, not filtered out. A high-entropy lookup that
-- AdGuard's blocklist happened to catch is still a compromised client trying
-- to reach something; dropping blocked rows here would hide the exact query
-- that proves the attempt.

select
    registrable_domain as entity,
    format(
        -- format() only understands %s/%I/%L, not printf-style width or
        -- precision specifiers, so the rounding happens before the call
        -- rather than inside the format string.
        'max entropy %s bits/char, e.g. %s, %s quer%s from %s client%s',
        round(max(label_entropy), 2),
        min(qname),
        count(*),
        case when count(*) = 1 then 'y' else 'ies' end,
        count(distinct client),
        case when count(distinct client) = 1 then '' else 's' end
    ) as summary
from dns_query
where label_entropy >= 3.5
  and length(qname) >= 12
group by registrable_domain;
