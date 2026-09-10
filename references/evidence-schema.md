# Evidence schema

Each JSONL record has `domain`, `brand`, `candidate_reasons`, `risk_score`, `risk_factors`, `collected_at`, and `sources`. A source is an object with `kind`, `collected_at`, `status`, `data`, and optional `error`.

Allowed `kind` values include `generator`, `dns`, `http`, `rdap`, `certificate_transparency`, `passive_dns`, `threat_intelligence`, and `manual_review`. A failed or unavailable source must be represented as unavailable; do not silently substitute one source for another.

Snapshot comparison uses DNS addresses, HTTP status/location/title, and each evidence source's normalized data. It reports a delta rather than overwriting prior evidence.
