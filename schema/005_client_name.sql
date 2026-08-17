-- home-soc, DNS client name (phase 3, continued).
--
-- AdGuard Home already knows a name for many of its clients (from DHCP leases
-- or its own client config), and its querylog API hands that name back as
-- `client_info.name` on every entry. Storing it turns per-device attribution
-- from an IP-guessing game into reading a column.
--
-- Nullable, for two reasons: not every client AdGuard sees has been given a
-- name, and every row ingested before this column existed has no way to
-- backfill one.
--
-- Deliberately data, not schema: this column lives only in the database this
-- repository never carries. The rules that read it stay generic (a name that
-- rides along in a summary), so the public repo never has to know, or leak,
-- what any of this household's devices are actually called.

alter table dns_query add column if not exists client_name text;

insert into schema_version (version) values (5) on conflict do nothing;
