import json
import tempfile
import unittest
from pathlib import Path

from core.canonical import canonicalize
from core.crypto import sha256_hex
from core.verify import verify_bundle


def _digest(obj):
    return sha256_hex(canonicalize(obj))


def _build_bundle(media_root: Path):
    media_root.mkdir(parents=True, exist_ok=True)
    files = []
    media_index = []
    for idx, name in enumerate(
        ["IMG_0001.JPG", "IMG_0002.JPG", "DOC_ID_0001.JPG", "WITNESS_AUDIO_0001.WAV"],
        start=1,
    ):
        path = media_root / name
        path.write_bytes(f"file-{idx}".encode("utf-8"))
        hash_value = sha256_hex(path.read_bytes())
        file_id = f"file-00{idx}"
        files.append(
            {
                "file_id": file_id,
                "capture_time_utc": "2025-12-28T14:33:02Z",
                "hash_algo": "sha256",
                "hash_value": hash_value,
            }
        )
        media_index.append(
            {
                "file_id": file_id,
                "file_name": name,
                "media_type": "application/octet-stream",
                "expected_path": f"media/{name}",
                "hash_algo": "sha256",
                "hash_value": hash_value,
            }
        )

    session_token = "FOX-72-DELTA"
    rti0 = {
        "rti0_id": "rti0-abc",
        "time_utc": "2025-12-28T14:32:00Z",
        "policy_id": "AUTO-COLLISION-v1",
        "session_token": session_token,
    }
    rti1 = {"files": files}
    rti2 = {
        "set": {
            "set_id": "set-001",
            "rti0_id": "rti0-abc",
            "policy_id": "AUTO-COLLISION-v1",
            "files": [
                {"file_id": "file-001", "role": "overview", "required": True},
                {"file_id": "file-002", "role": "detail_damage", "required": True},
                {"file_id": "file-003", "role": "id_document", "required": True},
                {"file_id": "file-004", "role": "witness_audio", "required": False},
            ],
        }
    }
    anchor_phrase = "front driver side damage only"
    salt = sha256_hex(f"{session_token}{rti0['time_utc']}".encode("utf-8"))
    anchor_hash = sha256_hex(f"{salt}{anchor_phrase}".encode("utf-8"))
    rti3 = {
        "actor": {"actor_id": "act-001", "rti0_id": "rti0-abc"},
        "narrative": {
            "anchor_phrase": anchor_phrase,
            "anchor_phrase_hash": anchor_hash,
        },
    }
    rti4 = {
        "checks": {
            "time": {"max_skew_seconds": 300, "time_window_ok": True},
            "files": {"files_present": True},
            "policy": {"policy_id": "AUTO-COLLISION-v1", "coverage_status": "complete"},
        },
        "transcript": [
            {
                "step_id": "st-0001",
                "ts_utc": "2025-12-28T14:32:17Z",
                "kind": "start_ritual",
                "actor_ref": "act-001",
                "result": "ok",
            },
            {
                "step_id": "st-0002",
                "ts_utc": "2025-12-28T14:33:02Z",
                "kind": "capture_file",
                "file_ref": "file-001",
                "result": "ok",
            },
            {
                "step_id": "st-0003",
                "ts_utc": "2025-12-28T14:36:10Z",
                "kind": "finalize_record",
                "result": "ok",
            },
        ],
    }
    record = {
        "record_id": "rec-1234",
        "set_id": "set-001",
        "rti0_id": "rti0-abc",
        "policy": {"policy_id": "AUTO-COLLISION-v1"},
        "media_index": media_index,
    }
    digests = {
        "hash_algo": "sha256",
        "digest_rti0": _digest(rti0),
        "digest_rti1": _digest(rti1),
        "digest_rti2": _digest(rti2),
        "digest_rti3": _digest(rti3),
        "digest_rti4": _digest(rti4),
    }
    record["digests"] = digests
    record_for_hash = dict(record)
    record_for_hash["digests"] = dict(digests)
    record_for_hash["digests"].pop("record_hash", None)
    record["digests"]["record_hash"] = sha256_hex(
        b"".join(
            [
                canonicalize(record_for_hash),
                canonicalize(rti0),
                canonicalize(rti1),
                canonicalize(rti2),
                canonicalize(rti3),
                canonicalize(rti4),
            ]
        )
    )
    return {
        "record": record,
        "rti0": rti0,
        "rti1": rti1,
        "rti2": rti2,
        "rti3": rti3,
        "rti4": rti4,
    }


class VerifyBundleTests(unittest.TestCase):
    def test_valid_bundle(self):
        with tempfile.TemporaryDirectory() as tmp:
            media_root = Path(tmp) / "media"
            bundle = _build_bundle(media_root)
            bundle_path = Path(tmp) / "bundle.json"
            bundle_path.write_text(json.dumps(bundle), encoding="utf-8")

            result = verify_bundle(bundle_path, Path(tmp))
            self.assertEqual(result["decision"], "valid")
            self.assertEqual(result["issues"], [])

    def test_missing_optional_media_marks_suspect(self):
        with tempfile.TemporaryDirectory() as tmp:
            media_root = Path(tmp) / "media"
            bundle = _build_bundle(media_root)
            (media_root / "WITNESS_AUDIO_0001.WAV").unlink()
            bundle_path = Path(tmp) / "bundle.json"
            bundle_path.write_text(json.dumps(bundle), encoding="utf-8")

            result = verify_bundle(bundle_path, Path(tmp))
            self.assertEqual(result["decision"], "suspect")
            self.assertTrue(result["issues"])

    def test_certificate_mismatch_is_suspect(self):
        with tempfile.TemporaryDirectory() as tmp:
            media_root = Path(tmp) / "media"
            bundle = _build_bundle(media_root)
            bundle_path = Path(tmp) / "bundle.json"
            bundle_path.write_text(json.dumps(bundle), encoding="utf-8")
            certificate = {
                "rti6": {
                    "certificate": {
                        "integrity": {"record_hash": "deadbeef"},
                        "record_id": "rec-1234",
                    }
                }
            }
            cert_path = Path(tmp) / "rti6.json"
            cert_path.write_text(json.dumps(certificate), encoding="utf-8")

            result = verify_bundle(bundle_path, Path(tmp), cert_path)
            self.assertEqual(result["decision"], "suspect")
            self.assertTrue(result["issues"])

    def test_anchor_phrase_mismatch_invalid(self):
        with tempfile.TemporaryDirectory() as tmp:
            media_root = Path(tmp) / "media"
            bundle = _build_bundle(media_root)
            bundle["rti3"]["narrative"]["anchor_phrase_hash"] = "deadbeef"
            bundle_path = Path(tmp) / "bundle.json"
            bundle_path.write_text(json.dumps(bundle), encoding="utf-8")

            result = verify_bundle(bundle_path, Path(tmp))
            self.assertEqual(result["decision"], "invalid")
            self.assertTrue(result["issues"])

    def test_rti4_checks_tampered_invalid(self):
        with tempfile.TemporaryDirectory() as tmp:
            media_root = Path(tmp) / "media"
            bundle = _build_bundle(media_root)
            bundle["rti4"]["checks"]["time"]["time_window_ok"] = False
            bundle_path = Path(tmp) / "bundle.json"
            bundle_path.write_text(json.dumps(bundle), encoding="utf-8")

            result = verify_bundle(bundle_path, Path(tmp))
            self.assertEqual(result["decision"], "invalid")
            self.assertTrue(result["issues"])


if __name__ == "__main__":
    unittest.main()
