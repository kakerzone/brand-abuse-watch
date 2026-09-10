# Web capture evidence

Analyze only locally captured, unauthenticated HTML or screenshots. Capture must not execute page JavaScript, submit forms, authenticate, upload, download, or follow redirects automatically. Preserve capture time, URL/domain, headers, and original file hash outside the normalized result.

`scripts/capture_web.py` is the bounded capture option: HTTPS only, certificate validation via Python defaults, proxy disabled, no redirects, no JavaScript, no authentication, 256 KiB body limit, explicit `--network`, and a risk-score/record-count limit. Review capture output before parsing or sharing it.

Useful indicators are protected-brand mentions, title, credential/password forms, payment/withdrawal forms, form destination, content hash, text SimHash, favicon hash, and screenshot pHash. A single indicator is insufficient to call a site fraudulent; compare it with official assets and retain the raw capture for review.

The bundled visual helper generates offline average-hash and difference-hash fingerprints for screenshots, favicons, and logos. A low Hamming distance is a triage signal, not a finding by itself. OCR, logo classification, and screenshot capture are separate optional adapters and must identify their model/source in evidence.
