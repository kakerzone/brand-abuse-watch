# Collector and intelligence adapter contract

An adapter must declare its source name, collection time, query scope, rate limit, authentication mechanism, retention constraint, and fields returned. It writes an evidence object using `references/evidence-schema.md` and marks unavailable, partial, or failed collection explicitly.

Supported adapter categories: certificate transparency, RDAP/WHOIS, DNS/MX/NS, passive DNS, IP/ASN, registrar, HTTPS/content, screenshot/fingerprint, search-index, and threat intelligence. A provider is optional; the report must expose which categories were not collected.

Adapters must not store credentials in profiles or findings. They must support bounded queries, retries with backoff, source attribution, and a dry-run mode. Use fixtures rather than live providers in regression tests.
