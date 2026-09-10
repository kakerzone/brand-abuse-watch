# Brand profile

Profiles are organization-owned configuration, not hard-coded logic. One file equals one protected brand; include a stable `brand_id`, legal brand name, protected domains, normalized aliases, local-language and transliteration variants, approved business vocabulary, risky business and phishing vocabulary, target TLDs/countries, official IP/ASN/certificate identifiers when known, and allowlisted partners.

Maintain separate `risk_keywords` groups by purpose: gambling/financial abuse, credential phishing, payment impersonation, customer-support impersonation, and region/language terms. Adding a word increases recall and false positives; record its owner, rationale, and review date.

For candidate generation, cover brand-word and word-brand forms, concatenated and hyphenated forms, dot/subdomain forms, and selected TLDs. Never treat a keyword match by itself as proof of abuse.
