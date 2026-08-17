# Rules

A rule is one `.sql` file in this directory. The engine (`ingest/rules.py`)
discovers every file here, runs its query, and upserts whatever comes back
into `rule_hit`.

## The contract

- **Header.** The first line of the file must be `-- description: <one line>`.
  The engine parses that single line into `rule.description`. Everything
  else in the header is prose for humans: why the rule exists and why its
  thresholds are what they are, not for the engine.
- **Shape.** The query must select exactly two columns, `entity` (text) and
  `summary` (text). `entity` is whatever the hit is about, a domain, a
  client, an image. `summary` is one human line of context.
- **Readable SQL, no exceptions.** Rules read the typed tables directly
  (`dns_query`, `dns_domain`, `vuln_finding`, ...), never a JSONB envelope.
  A rule nobody can read top to bottom is a rule nobody trusts, and a rule
  nobody trusts gets its alerts ignored.
- **The rule id is the filename stem.** `dns_newly_seen_domain.sql` becomes
  rule id `dns_newly_seen_domain`.

## Disabling a rule

Turning a rule off is a database update, not a file deletion:

```sql
update rule set enabled = false where id = 'dns_blocked_spike';
```

That survives a redeploy; deleting or renaming the file would not, since the
next `git pull` would silently bring it back.
