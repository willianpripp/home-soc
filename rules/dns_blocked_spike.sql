-- description: client with an unusual spike in blocked queries
--
-- A blocked-query spike has two ordinary explanations and both are worth a
-- look: a newly installed app dragging along a pile of trackers, or
-- something on the client hammering denylisted infrastructure it should
-- never be talking to. Either way, "this client is suddenly generating a lot
-- more blocked traffic than usual" is the useful question, not "this client
-- has a lot of blocked traffic", because a household's noisiest phone is
-- noisy every day and would drown out everything else if raw volume were
-- the trigger.
--
-- Why 3x: it fires on change relative to the client's own baseline, not on
-- an absolute count that punishes whichever device already blocks the most.
-- Why the floor of 20: without it, a client with a near-zero baseline (say,
-- one blocked query a day) would trip the rule on a jump to three, which is
-- noise, not a spike. The floor and the multiplier have to both hold.
--
-- The entity stays the client address, never the name: an IP is the stable
-- key a hit tracks across runs, while a name is data AdGuard may not always
-- have. The name only rides along in the summary, because a human triages
-- "the living-room TV", not an IP.

with last_day as (
    select client, max(client_name) as client_name, count(*) as blocked_count
    from dns_query
    where blocked
      and ts >= now() - interval '24 hours'
    group by client
),
prior_week as (
    -- The 7 days before the last-day window, not including it: last_day and
    -- prior_week must never overlap, or a spike would be comparing itself
    -- against a baseline that already contains the spike.
    select client, count(*) / 7.0 as avg_daily_blocked
    from dns_query
    where blocked
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
        '%s blocked queries in the last 24h vs a %s/day average over the prior week',
        d.blocked_count,
        round(coalesce(w.avg_daily_blocked, 0)::numeric, 1)
    ) || coalesce(', device ' || d.client_name, '') as summary
from last_day d
left join prior_week w on w.client = d.client
where d.blocked_count >= 20
  and d.blocked_count >= 3 * coalesce(w.avg_daily_blocked, 0);
