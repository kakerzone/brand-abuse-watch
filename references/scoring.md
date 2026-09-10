# Triage scoring

Maintain separate, explainable values instead of treating a single score as a verdict.

- `brand_similarity`: lexical edit distance, token/alias match, Unicode confusables, visual logo/favion similarity, and content references to protected assets.
- `abuse_likelihood`: phishing or financial-abuse vocabulary, credential/payment forms, MX capability, suspicious redirects, new registration, malicious reputation, and campaign infrastructure links.
- `evidence_completeness`: percentage of the profile's configured collection categories that were collected; missing data is not a negative signal. The built-in DNS plus bounded HTTP collectors cover only 2 of the 8 documented categories (25%), even when both run successfully.

The current local score is only a conservative discovery-priority score: exact brand/alias match (30), high-risk business keyword (25), phishing-oriented keyword (15), typo/character-confusion (15), network resolution (10), and allowlist override (0). A provider adapter may add evidence-backed signals, but it must retain the raw fields and source timestamp.

`scripts/rescore_findings.py` recomputes the operational priority score from the evidence: protected-brand page mentions increase similarity; credential/payment forms and threat-intelligence signals increase abuse likelihood; visual matches increase similarity; configured official IPs reduce abuse likelihood; and collection coverage is calculated from the eight configured evidence categories. It must be rerun after a merge, not used to overwrite raw evidence.

Suggested queues: high at 70 or above, medium at 40–69, low below 40. A human reviewer must validate source evidence, ownership, and content before abuse reporting or blocking.
