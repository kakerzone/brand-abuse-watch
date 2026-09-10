# Data parsing

Use a separate raw file for each provider run. The bundled parser normalizes common DNS, CT, RDAP, HTTP, passive-DNS, and threat-intelligence JSON exports into the evidence schema; it does not query providers.

Required inputs are source identity, collection time (or a reliable provider timestamp), and a domain. CT names containing newline-separated SAN entries are expanded one domain per record. RDAP `ldhName`, HTTP URL/host/domain, and common passive-DNS record names are accepted. Unknown fields are preserved under `raw` so no material evidence is discarded.

Normalize first, validate the resulting count and domains, then merge by canonical lower-case FQDN. Keep raw export hash and parsing errors. Never merge evidence that lacks a valid domain or silently map a subdomain to a parent domain.
