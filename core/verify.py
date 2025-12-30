from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from core.canonical import canonicalize
from core.crypto import sha256_file, sha256_hex
from core.policy import Policy, load_policy


@dataclass
class Issue:
    code: str
    severity: str
    layer: str
    details: str
    related_ids: Optional[List[str]] = None

    def to_dict(self) -> Dict[str, Any]:
        data = {
            "code": self.code,
            "severity": self.severity,
            "layer": self.layer,
            "details": self.details,
        }
        if self.related_ids:
            data["related_ids"] = self.related_ids
        return data


def _load_json(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _record_hash_inputs(bundle: Dict[str, Any]) -> List[bytes]:
    record = _canonical_record_for_hash(bundle["record"])
    return [
        canonicalize(record),
        canonicalize(bundle["rti0"]),
        canonicalize(bundle["rti1"]),
        canonicalize(bundle["rti2"]),
        canonicalize(bundle["rti3"]),
        canonicalize(bundle["rti4"]),
    ]


def _canonical_record_for_hash(record: Dict[str, Any]) -> Dict[str, Any]:
    record_copy = json.loads(json.dumps(record))
    digests = record_copy.get("digests", {})
    if "record_hash" in digests:
        digests = dict(digests)
        digests.pop("record_hash", None)
        record_copy["digests"] = digests
    return record_copy


def _validate_presence(bundle: Dict[str, Any]) -> List[Issue]:
    issues: List[Issue] = []
    for key in ("record", "rti0", "rti1", "rti2", "rti3", "rti4"):
        if key not in bundle:
            issues.append(
                Issue(
                    code="SCHEMA_ERROR",
                    severity="critical",
                    layer="schema",
                    details=f"missing top-level key: {key}",
                )
            )
    return issues


def _verify_digests(bundle: Dict[str, Any]) -> List[Issue]:
    issues: List[Issue] = []
    record = bundle["record"]
    digests = record.get("digests", {})
    layers = {
        "rti0": "digest_rti0",
        "rti1": "digest_rti1",
        "rti2": "digest_rti2",
        "rti3": "digest_rti3",
        "rti4": "digest_rti4",
    }
    for layer, digest_key in layers.items():
        expected = digests.get(digest_key)
        if not expected:
            issues.append(
                Issue(
                    code="SCHEMA_ERROR",
                    severity="critical",
                    layer=layer,
                    details=f"missing {digest_key} in record.digests",
                )
            )
            continue
        computed = sha256_hex(canonicalize(bundle[layer]))
        if computed != expected:
            issues.append(
                Issue(
                    code=f"DIGEST_MISMATCH_{layer.upper()}",
                    severity="critical",
                    layer=layer,
                    details=f"expected {expected} but computed {computed}",
                )
            )
    return issues


def _verify_record_hash(bundle: Dict[str, Any]) -> List[Issue]:
    issues: List[Issue] = []
    record = bundle["record"]
    digests = record.get("digests", {})
    expected = digests.get("record_hash")
    if not expected:
        issues.append(
            Issue(
                code="SCHEMA_ERROR",
                severity="critical",
                layer="record",
                details="missing record_hash in record.digests",
            )
        )
        return issues
    payload = b"".join(_record_hash_inputs(bundle))
    computed = sha256_hex(payload)
    if computed != expected:
        issues.append(
            Issue(
                code="RECORD_HASH_MISMATCH",
                severity="critical",
                layer="record",
                details=f"expected {expected} but computed {computed}",
            )
        )
    return issues


def _verify_media(bundle: Dict[str, Any], media_root: Path) -> List[Issue]:
    issues: List[Issue] = []
    record = bundle["record"]
    media_index = record.get("media_index", [])
    rti1_files = {item["file_id"]: item for item in bundle["rti1"].get("files", [])}
    rti2_required = {
        item["file_id"]: item.get("required", True)
        for item in bundle["rti2"].get("set", {}).get("files", [])
        if "file_id" in item
    }
    for entry in media_index:
        file_id = entry.get("file_id", "unknown")
        expected_path = entry.get("expected_path")
        if not expected_path:
            issues.append(
                Issue(
                    code="SCHEMA_ERROR",
                    severity="critical",
                    layer="media",
                    details=f"missing expected_path for {file_id}",
                    related_ids=[file_id],
                )
            )
            continue
        path = (media_root / expected_path).resolve()
        if not path.exists():
            required = rti2_required.get(file_id, True)
            issues.append(
                Issue(
                    code="MISSING_CRITICAL_MEDIA"
                    if required
                    else "MISSING_OPTIONAL_MEDIA",
                    severity="critical" if required else "warning",
                    layer="media",
                    details=f"missing file {expected_path}",
                    related_ids=[file_id],
                )
            )
            continue
        computed = sha256_file(path)
        expected_hash = entry.get("hash_value")
        if expected_hash and computed != expected_hash:
            issues.append(
                Issue(
                    code="MEDIA_HASH_MISMATCH",
                    severity="critical",
                    layer="media",
                    details=f"hash mismatch for {expected_path}",
                    related_ids=[file_id],
                )
            )
        rti1_entry = rti1_files.get(file_id)
        if rti1_entry and rti1_entry.get("hash_value") not in (None, computed):
            issues.append(
                Issue(
                    code="MEDIA_HASH_MISMATCH",
                    severity="critical",
                    layer="media",
                    details=f"hash mismatch vs rti1 for {expected_path}",
                    related_ids=[file_id],
                )
            )
    return issues


def verify_bundle(
    bundle_path: Path,
    media_root: Path,
    certificate_path: Optional[Path] = None,
    policy_path: Optional[Path] = None,
) -> Dict[str, Any]:
    bundle = _load_json(bundle_path)
    issues: List[Issue] = []
    policy = load_policy(policy_path) if policy_path else None

    issues.extend(_validate_presence(bundle))
    if issues:
        return _result(bundle, issues)

    issues.extend(_verify_digests(bundle))
    issues.extend(_verify_record_hash(bundle))
    issues.extend(_verify_media(bundle, media_root))
    issues.extend(_verify_cross_links(bundle))
    issues.extend(_verify_policy_ids(bundle))
    if policy:
        issues.extend(_verify_policy_coverage(bundle, policy))
    issues.extend(_verify_transcript_refs(bundle))
    issues.extend(_verify_anchor_phrase(bundle))
    issues.extend(_verify_rti4_checks(bundle, media_root, policy))
    if certificate_path:
        issues.extend(_verify_certificate(bundle, certificate_path))
    issues.extend(_verify_time_window(bundle, policy))
    issues.extend(_verify_transcript(bundle))
    return _result(bundle, issues)


def _verify_certificate(
    bundle: Dict[str, Any], certificate_path: Path
) -> List[Issue]:
    issues: List[Issue] = []
    certificate = _load_json(certificate_path).get("rti6", {}).get("certificate", {})
    record_hash = (
        certificate.get("integrity", {}).get("record_hash")
        or certificate.get("record_hash")
    )
    expected = bundle.get("record", {}).get("digests", {}).get("record_hash")
    if record_hash and expected and record_hash != expected:
        issues.append(
            Issue(
                code="CERTIFICATE_MISMATCH",
                severity="warning",
                layer="certificate",
                details="certificate record_hash does not match bundle",
            )
        )
    return issues


def _verify_cross_links(bundle: Dict[str, Any]) -> List[Issue]:
    issues: List[Issue] = []
    record = bundle["record"]
    rti0 = bundle["rti0"]
    rti2 = bundle["rti2"].get("set", {})
    rti3 = bundle["rti3"].get("actor", {})

    if record.get("rti0_id") != rti0.get("rti0_id"):
        issues.append(
            Issue(
                code="XREF_MISMATCH",
                severity="critical",
                layer="record",
                details="record.rti0_id does not match rti0.rti0_id",
            )
        )
    if record.get("set_id") and record.get("set_id") != rti2.get("set_id"):
        issues.append(
            Issue(
                code="XREF_MISMATCH",
                severity="critical",
                layer="record",
                details="record.set_id does not match rti2.set_id",
            )
        )
    if rti3 and rti3.get("rti0_id") and rti3.get("rti0_id") != rti0.get("rti0_id"):
        issues.append(
            Issue(
                code="XREF_MISMATCH",
                severity="critical",
                layer="rti3",
                details="rti3.actor.rti0_id does not match rti0.rti0_id",
            )
        )
    rti1_ids = {item["file_id"] for item in bundle["rti1"].get("files", [])}
    record_ids = {
        item.get("file_id") for item in bundle["record"].get("media_index", [])
    }
    for item in rti2.get("files", []):
        file_id = item.get("file_id")
        if file_id and file_id not in rti1_ids:
            issues.append(
                Issue(
                    code="XREF_MISMATCH",
                    severity="critical",
                    layer="rti2",
                    details=f"rti2 references missing file_id {file_id}",
                    related_ids=[file_id],
                )
            )
    for file_id in record_ids:
        if file_id and file_id not in rti1_ids:
            issues.append(
                Issue(
                    code="XREF_MISMATCH",
                    severity="critical",
                    layer="record",
                    details=f"record.media_index references missing file_id {file_id}",
                    related_ids=[file_id],
                )
            )
    return issues


def _verify_policy_ids(bundle: Dict[str, Any]) -> List[Issue]:
    issues: List[Issue] = []
    policy_ids = {
        bundle["record"].get("policy", {}).get("policy_id"),
        bundle["rti0"].get("policy_id"),
        bundle["rti2"].get("set", {}).get("policy_id"),
        bundle["rti4"].get("checks", {}).get("policy", {}).get("policy_id"),
    }
    policy_ids.discard(None)
    if len(policy_ids) > 1:
        issues.append(
            Issue(
                code="POLICY_COVERAGE_INVALID",
                severity="critical",
                layer="policy",
                details=f"policy_id mismatch across layers: {sorted(policy_ids)}",
            )
        )
    return issues


def _verify_transcript_refs(bundle: Dict[str, Any]) -> List[Issue]:
    issues: List[Issue] = []
    transcript = bundle["rti4"].get("transcript", [])
    rti1_ids = {item["file_id"] for item in bundle["rti1"].get("files", [])}
    actor_id = bundle["rti3"].get("actor", {}).get("actor_id")
    for entry in transcript:
        file_ref = entry.get("file_ref")
        actor_ref = entry.get("actor_ref")
        if file_ref and file_ref not in rti1_ids:
            issues.append(
                Issue(
                    code="TRANSCRIPT_REF_ERROR",
                    severity="critical",
                    layer="rti4",
                    details=f"transcript references missing file_id {file_ref}",
                    related_ids=[file_ref],
                )
            )
        if actor_ref and actor_id and actor_ref != actor_id:
            issues.append(
                Issue(
                    code="TRANSCRIPT_REF_ERROR",
                    severity="critical",
                    layer="rti4",
                    details="transcript actor_ref does not match rti3.actor_id",
                )
            )
    return issues


def _verify_anchor_phrase(bundle: Dict[str, Any]) -> List[Issue]:
    issues: List[Issue] = []
    narrative = bundle["rti3"].get("narrative", {})
    anchor = narrative.get("anchor_phrase")
    anchor_hash = narrative.get("anchor_phrase_hash")
    if not anchor or not anchor_hash:
        return issues
    session_token = bundle["rti0"].get("session_token", "")
    time_utc = bundle["rti0"].get("time_utc", "")
    salt = sha256_hex(f"{session_token}{time_utc}".encode("utf-8"))
    normalized = anchor.strip().lower()
    computed = sha256_hex(f"{salt}{normalized}".encode("utf-8"))
    if computed != anchor_hash:
        issues.append(
            Issue(
                code="ANCHOR_PHRASE_HASH_MISMATCH",
                severity="critical",
                layer="rti3",
                details="anchor_phrase_hash mismatch",
            )
        )
    return issues


def _verify_rti4_checks(
    bundle: Dict[str, Any], media_root: Path, policy: Optional[Policy]
) -> List[Issue]:
    issues: List[Issue] = []
    checks = bundle["rti4"].get("checks", {})
    time_checks = checks.get("time", {})
    files_checks = checks.get("files", {})
    policy_checks = checks.get("policy", {})

    time_issues = _verify_time_window(bundle, policy)
    if time_issues and time_checks.get("time_window_ok", True):
        issues.append(
            Issue(
                code="RTI4_CHECKS_TAMPERED",
                severity="critical",
                layer="rti4",
                details="rti4 time_window_ok does not match recomputed value",
            )
        )

    files_present = not any(
        issue.code == "MISSING_CRITICAL_MEDIA"
        for issue in _verify_media(bundle, media_root)
    )
    if "files_present" in files_checks and files_checks["files_present"] != files_present:
        issues.append(
            Issue(
                code="RTI4_CHECKS_TAMPERED",
                severity="critical",
                layer="rti4",
                details="rti4 files_present does not match recomputed value",
            )
        )

    rti2_coverage = bundle["rti2"].get("set", {}).get("coverage", {})
    coverage_status = rti2_coverage.get("status")
    if coverage_status and policy_checks.get("coverage_status") != coverage_status:
        issues.append(
            Issue(
                code="POLICY_COVERAGE_INVALID",
                severity="critical",
                layer="policy",
                details="rti4 policy coverage_status does not match rti2 coverage",
            )
        )
    return issues


def _verify_policy_coverage(bundle: Dict[str, Any], policy: Policy) -> List[Issue]:
    issues: List[Issue] = []
    roles = [item.get("role") for item in bundle["rti2"].get("set", {}).get("files", [])]
    missing = sorted(role for role in policy.required if role not in roles)
    coverage_status = "complete" if not missing else "partial"
    recorded = bundle["rti2"].get("set", {}).get("coverage", {}).get("status")
    if recorded and recorded != coverage_status:
        issues.append(
            Issue(
                code="POLICY_COVERAGE_INVALID",
                severity="critical",
                layer="policy",
                details="rti2 coverage.status does not match policy requirements",
            )
        )
    return issues


def _parse_utc(value: str) -> Optional[datetime]:
    if not value:
        return None
    if value.endswith("Z"):
        value = value.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _verify_time_window(bundle: Dict[str, Any], policy: Optional[Policy]) -> List[Issue]:
    issues: List[Issue] = []
    rti0_time = _parse_utc(bundle["rti0"].get("time_utc"))
    if not rti0_time:
        issues.append(
            Issue(
                code="SCHEMA_ERROR",
                severity="critical",
                layer="rti0",
                details="invalid or missing rti0.time_utc",
            )
        )
        return issues
    captures = []
    for item in bundle["rti1"].get("files", []):
        capture_time = _parse_utc(item.get("capture_time_utc", ""))
        if capture_time:
            captures.append(capture_time)
    if not captures:
        return issues
    max_skew = None
    if policy and policy.time_window_seconds is not None:
        max_skew = policy.time_window_seconds
    if max_skew is None:
        max_skew = bundle["rti4"].get("checks", {}).get("time", {}).get(
            "max_skew_seconds"
        )
    if max_skew is None:
        return issues
    earliest = min(captures)
    latest = max(captures)
    if abs((earliest - rti0_time).total_seconds()) > max_skew or abs(
        (latest - rti0_time).total_seconds()
    ) > max_skew:
        issues.append(
            Issue(
                code="TIME_WINDOW_INVALID",
                severity="critical",
                layer="rti4",
                details="capture times outside RTI-0 time window",
            )
        )
    return issues


def _verify_transcript(bundle: Dict[str, Any]) -> List[Issue]:
    issues: List[Issue] = []
    transcript = bundle["rti4"].get("transcript", [])
    if not transcript:
        issues.append(
            Issue(
                code="TRANSCRIPT_ORDER_ERROR",
                severity="critical",
                layer="rti4",
                details="missing transcript entries",
            )
        )
        return issues
    timestamps = [_parse_utc(item.get("ts_utc", "")) for item in transcript]
    if any(ts is None for ts in timestamps):
        issues.append(
            Issue(
                code="TRANSCRIPT_ORDER_ERROR",
                severity="critical",
                layer="rti4",
                details="invalid transcript timestamps",
            )
        )
        return issues
    ordered = sorted(zip(timestamps, transcript), key=lambda item: item[0])
    if [item[1] for item in ordered] != transcript:
        issues.append(
            Issue(
                code="TRANSCRIPT_ORDER_ERROR",
                severity="critical",
                layer="rti4",
                details="transcript is not ordered by ts_utc",
            )
        )
    kinds = [item.get("kind") for item in transcript]
    if kinds.count("start_ritual") != 1:
        issues.append(
            Issue(
                code="TRANSCRIPT_ORDER_ERROR",
                severity="critical",
                layer="rti4",
                details="transcript must contain exactly one start_ritual",
            )
        )
    terminals = [i for i, kind in enumerate(kinds) if kind in ("finalize_record", "abort_ritual")]
    if len(terminals) != 1:
        issues.append(
            Issue(
                code="TRANSCRIPT_TERMINAL_ERROR",
                severity="critical",
                layer="rti4",
                details="transcript must contain exactly one terminal event",
            )
        )
    else:
        terminal_index = terminals[0]
        if terminal_index != len(kinds) - 1:
            issues.append(
                Issue(
                    code="TRANSCRIPT_TERMINAL_ERROR",
                    severity="critical",
                    layer="rti4",
                    details="terminal event must be last in transcript",
                )
            )
    return issues


def _decision(issues: List[Issue]) -> Tuple[str, Dict[str, str]]:
    decision = "valid"
    layer_results = {
        "rti0": "ok",
        "rti1": "ok",
        "rti2": "ok",
        "rti3": "ok",
        "rti4": "ok",
        "record": "ok",
        "media": "ok",
        "certificate": "not_provided",
    }
    for issue in issues:
        if issue.layer in layer_results:
            layer_results[issue.layer] = (
                "invalid" if issue.severity == "critical" else "suspect"
            )
        if issue.severity == "critical":
            decision = "invalid"
    if decision != "invalid" and issues:
        decision = "suspect"
        for issue in issues:
            if issue.layer in layer_results and layer_results[issue.layer] == "ok":
                layer_results[issue.layer] = "suspect"
    return decision, layer_results


def _result(bundle: Dict[str, Any], issues: List[Issue]) -> Dict[str, Any]:
    record_id = bundle.get("record", {}).get("record_id", "unknown")
    decision, layer_results = _decision(issues)
    return {
        "record_id": record_id,
        "decision": decision,
        "layer_results": layer_results,
        "issues": [issue.to_dict() for issue in issues],
    }
