-- description: client with a burst of NXDOMAIN answers
--
-- DGA malware resolves many algorithmically generated names, and most of
-- them do not exist: the C2 domain live this week is one name out of
-- hundreds the algorithm can produce, and the client burns through the whole
-- list looking for it. That burst of resolution failures is itself the
-- signal, and it typically shows up before any of those names actually
-- resolves, which is exactly the lead time worth having; by the time one of
-- them answers, the client already made its first C2 contact.
--
-- Only queries AdGuard did NOT block are counted. AdGuard answers a blocked
-- query with NXDOMAIN too (see dns_query.status vs dns_query.blocked), and
-- that is a different fact entirely: it says the household's own blocklist
-- caught something, not that a client is grinding through a DGA's candidate
-- list. Counting both together would make an ordinary ad-blocking day look
-- identical to an actual burst of genuinely unresolvable names.
--
-- Mirrors dns_blocked_spike's exact shape: fire on change relative to the
-- client's own baseline, not on an absolute count that punishes whichever
-- device already generates the most everyday NXDOMAIN traffic (a phone
-- probing for a captive portal, a laggy app retrying a typo'd hostname).
-- Why the floor of 30: without it, a client with a near-zero baseline would
-- trip the rule on a jump to single digits, which is noise, not a burst. The
-- floor and the multiplier have to both hold.
--
-- The entity stays the client address, never the name: an IP is the stable
-- key a hit tracks across runs, while a name is data AdGuard may not always
-- have. The name only rides along in the summary, because a human triages
-- "the living-room TV", not an IP.

with last_day as (
    select client, max(client_name) as client_name, count(*) as nxdomain_count
    from dns_query
    where status = 'NXDOMAIN'
      and not blocked
      and ts >= now() - interval '24 hours'
    group by client
),
prior_week as (
    -- The 7 days before the last-day window, not including it: last_day and
    -- prior_week must never overlap, or a burst would be comparing itself
    -- against a baseline that already contains the burst.
    select client, count(*) / 7.0 as avg_daily_nxdomain
    from dns_query
    where status = 'NXDOMAIN'
      and not blocked
      and ts >= now() - interval '8 days'
      and ts < now() - interval '24 hours'
    group by client
)
select
    d.client as entity,
    format(
        -- format() only understands %s/%I/%L, not printf-style width or
        -- precision specifiers, so the rounding happens before the call
        -- rather than inside the format string.
        '%s NXDOMAIN answers in the last 24h vs a %s/day average over the prior week',
        d.nxdomain_count,
        round(coalesce(w.avg_daily_nxdomain, 0)::numeric, 1)
    ) || coalesce(', device ' || d.client_name, '') as summary
from last_day d
left join prior_week w on w.client = d.client
where d.nxdomain_count >= 30
  and d.nxdomain_count >= 3 * coalesce(w.avg_daily_nxdomain, 0);
