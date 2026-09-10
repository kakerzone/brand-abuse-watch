---
name: brand-abuse-watch
description: Discover, assess, and continuously track suspected brand impersonation, lookalike domains, and unauthorized brand use using evidence-first, human-reviewed workflows.
---

# Brand Abuse Watch

Use this portable skill for defensive brand-protection reviews: typo-squatting, phishing-domain discovery, suspicious brand-combination domains, and ongoing tracking of confirmed candidates. It does not authorize takedowns, blocking, external reporting, outreach, or a maliciousness verdict.

## Inputs

Accept an official website or domains, brand name and aliases, visual reference when available, legitimate-domain and partner allowlists, risk terms, and existing findings. Treat every supplied domain as a candidate rather than proof of abuse.

## Workflow

1. Create and review a brand profile with `scripts/init_brand_profile.py` and `scripts/validate_profiles.py`. Use [references/brand-profile.md](references/brand-profile.md) for profile scope and allowlists.
2. Generate candidates with `scripts/discover_profiles.py`, with `scripts/collect_dnstwist.py` available for deeper permutations. Candidate generation is discovery only.
3. With explicit authorization for network access, collect bounded public evidence with `scripts/brand_monitor.py enrich`, `scripts/collect_public_intel.py`, or `scripts/capture_web.py`. Follow [references/evidence-schema.md](references/evidence-schema.md) and [references/web-capture.md](references/web-capture.md).
4. Rescore and correlate with `scripts/rescore_findings.py` and `scripts/correlate_findings.py`; use [references/scoring.md](references/scoring.md) and [references/correlation.md](references/correlation.md) for interpretation.
5. Track snapshots, create evidence packages, and deliver notifications only when warranted. See [references/case-management.md](references/case-management.md), [references/takedown-evidence.md](references/takedown-evidence.md), and [references/lark-alerts.md](references/lark-alerts.md).

## Decision rules

- Keep brand similarity, abuse likelihood, and evidence completeness separate; combined scores only prioritize review.
- Show missing, failed, or unavailable evidence explicitly.
- Treat shared infrastructure as a correlation signal, not proof of common ownership or a campaign.
- Honor documented allowlists, legitimate partners, and recorded false positives.

## Safety boundaries

Use unauthenticated, bounded collection by default. Do not log in, submit forms, upload files, execute page JavaScript, bypass access controls, or use credentials. Do not automatically report, block, contact, complain about, or request takedown of a domain. Escalate evidence-supported candidates for human legal and security review.

## Outputs

Produce a review record with the protected brand, candidate URL/domain, evidence and timestamps, risk-signal explanation, evidence gaps, priority, recommended next step, and direct public-evidence links where available. State that results require human review unless an authorized reviewer has recorded a decision.
