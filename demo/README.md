# Demo data

An invented scan run so the whole pipeline can be exercised with no scanner and
no real infrastructure. Three fake images, real-shaped CVE identifiers, and one
finding with no fix available so the "counted but never hidden" path is visible.

```sh
HOMESOC_SCAN_DIR=./demo docker compose run --rm ingest ingest-trivy /scan/json --all
docker compose run --rm ingest report
```

`demo-builder:latest` is mapped as `build-only` in `exposure.yaml`, so its
CRITICAL correctly sorts below a fixable HIGH in something reachable. That
inversion is the whole argument of the ranking, and it is the thing to look at
first.
