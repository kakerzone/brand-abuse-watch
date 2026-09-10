# Lark alert delivery

Use an incoming webhook stored in the runtime environment (`LARK_WEBHOOK_URL`) or macOS Keychain service `brand-impersonation-monitor:lark-webhook-url`; if webhook signing is enabled, use `LARK_WEBHOOK_SECRET` or Keychain service `brand-impersonation-monitor:lark-webhook-secret`. Never place either value in a profile, finding, report, state file, or command transcript.

Generate and review the preview file before delivery. The card must read as an operational incident brief: initial conclusion, direct suspected-site link, plain-language reason for concern, verified evidence, external-promotion leads, scan coverage, and next step. Use `--context` for verified human-readable narrative, coverage, and attributed external links, keyed by `brand_id:domain`; never invent a link or present an unverified claim as evidence. Include official-site buttons when `--profiles` is supplied. Limit the card to six unique buttons and eight evidence summaries so it remains readable.

For an English card, invoke `notify_lark.py` with `--language en` and include a verified `translations.en` block for the finding in the context file. Send Chinese and English cards as separate, independently deduplicated deliveries when both are requested.

When a cases state file is supplied, send only high-priority findings in `new` or `triaged` status by default; confirmed, false-positive, ignored, takedown-pending, and resolved cases are excluded. The configured `run_pipeline.py` workflow sends those deduplicated cards by default; use `--lark-preview-only` or `--no-lark` when the owner requests a dry run or suppression. Preserve the deduplication state after successful delivery, and phrase the card as a review-required security alert rather than a final accusation.
