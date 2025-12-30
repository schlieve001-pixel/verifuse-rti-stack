# Copilot instructions for VeriFuse RTI Verifier

This project is a small, self-contained offline RTI verifier. Keep changes minimal and focused — follow the patterns already present in the `core/` module and mirror behaviour in the web UI when appropriate.

## Big Picture

Verification logic lives in `core/verify.py` (Python) and is mirrored in `web/app.js` (client-side JS). The CLI wrapper is `cli/rti_cli.py`. Tests that demonstrate expected bundle shapes and decisions live in `tests/test_verify.py`.

## Key Files

- [core/verify.py](core/verify.py) – Main verification logic (bundle schema validation, digest/hash checks, media file verification)
- [core/canonical.py](core/canonical.py) – JSON canonicalization for consistent hashing
- [core/crypto.py](core/crypto.py) – SHA-256 utilities for hashing
- [cli/rti_cli.py](cli/rti_cli.py) – CLI entry point
- [web/app.js](web/app.js) – Browser JS verifier (mirrors Python logic)
- [tests/test_verify.py](tests/test_verify.py) – Unit tests with `_build_bundle` pattern
- [README.md](README.md) – Usage documentation

## Data Model & Invariants

**Bundle Structure (Required Top-Level Keys):**
- `record`, `rti0`, `rti1`, `rti2`, `rti3`, `rti4` (enforced by `_validate_presence`)

**Canonicalization (CRITICAL):**
- Use `core.canonical.canonicalize()` (Python) or `canonicalize()`/`sortObject()` (JS)
- JSON with sorted keys, compact separators `(",", ":")`, UTF-8 encoding
- Any change must be mirrored in both Python and JS

**Layer Digests & Record Hash:**
- Stored in `record.digests` as: `digest_rti0`, `digest_rti1`, `digest_rti2`, `digest_rti3`, `digest_rti4`, `record_hash`
- Each digest: SHA-256 hex of canonicalized layer
- `record_hash`: SHA-256 hex of concatenated bytes: `canonicalize(record_without_record_hash) + canonicalize(rti0..rti4)`
- See `_record_hash_inputs` and `_verify_record_hash` for exact concatenation order

**Hashing:**
- All hashes: SHA-256 hex (no binary output)
- Media files: streamed reads with `core.crypto.sha256_file()`; JS uses `crypto.subtle.digest()`

## Decision Rules

Issues have `severity` (`"critical"` → layer fails, else `"warning"` → suspect). Decision logic:
- `"invalid"` if any critical issue
- `"suspect"` if any warning issues but no critical
- `"valid"` if no issues

See `_result()` in `core/verify.py` and `buildResult()` in `web/app.js`.

## Developer Workflows

**Run Tests:**
```bash
python -m unittest discover -s tests -v
```

**Run CLI:**
```bash
PYTHONPATH=. python cli/rti_cli.py \
  --bundle /path/to/bundle.json \
  --media-root /path/to/media \
  --out verification.json
```

**Run Web UI:**
Open `web/index.html` in a browser (or serve locally for service worker caching).

**Run in Docker:**
```bash
docker build -t rti-verifier .
docker run --rm rti-verifier python -m unittest discover -s tests -v
```

## Conventions & Editing Patterns

**Canonicalization Invariant:**
- Any change to the canonical JSON format (key order, separators, encoding) must be applied in **both** `core/canonical.py` and the JS `canonicalize()` in `web/app.js`, or tests will fail due to hash mismatches.

**Adding New Verification Issues:**
1. Define an `Issue` in `core/verify.py` with `code` (enum-like string), `severity` (`"critical"`/`"warning"`), `layer` (e.g., `"rti0"`, `"media"`), `details`, and optional `related_ids`.
2. Add a corresponding check function (e.g., `_verify_something()`) that returns a list of `Issue` objects.
3. Call the function from `verify_bundle()`.
4. Write a test in `tests/test_verify.py` using the `_build_bundle()` pattern, mutate the bundle, and assert the expected decision.
5. Mirror the check in `web/app.js`'s `verifyBundle()` if it affects correctness on the browser side.

**Example: Adding a custom issue code**
```python
# In _verify_something(bundle):
if condition:
    issues.append(
        Issue(
            code="MY_ERROR_CODE",
            severity="critical",
            layer="rti0",
            details="explanation with context",
            related_ids=["id-123"]
        )
    )
```

**Testing Digest Construction:**
- Tests construct bundles with all hashes pre-computed via `_digest(obj)` and `_build_bundle()`.
- If you change how digests are computed, re-run tests to catch mismatches.

## Integration Points & Assumptions

- **Python**: 3.11+ (no breaking language features in later versions).
- **Media Root**: `expected_path` in `record.media_index` is relative to the `--media-root` CLI argument.
- **Service Worker**: `web/sw.js` caches HTML, CSS, JS for offline PWA support.
- **No External Dependencies**: The core verifier uses only Python stdlib and Web Crypto API (browser-native).

## What NOT to Change

- JSON key names (`record_hash`, `digest_rti0`, `policy_id`, etc.) without coordinating across Python, JS, and tests.
- Canonicalization algorithm without syncing both implementations.
- Layer concatenation order in `record_hash` without re-running tests.

## Debugging & Development

- **Python Imports**: Ensure `PYTHONPATH=.` when running CLI outside Docker.
- **Browser Console**: Open DevTools to see JS errors or `verifyBundle()` output.
- **Test Bundle**: Use `_build_bundle()` in `tests/test_verify.py` as the canonical reference for valid bundle structure.

---

For questions or to clarify any section (e.g., examples of adding a new issue type, or more detail on digest computation), ask.
