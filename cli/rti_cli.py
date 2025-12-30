import argparse
import json
from pathlib import Path

from core.verify import verify_bundle


def main() -> None:
    parser = argparse.ArgumentParser(description="VeriFuse RTI verifier CLI")
    parser.add_argument("--bundle", required=True, help="Path to bundle.json")
    parser.add_argument("--media-root", required=True, help="Path to media root")
    parser.add_argument("--certificate", help="Optional path to RTI-6 certificate JSON")
    parser.add_argument("--policy", help="Optional path to policy JSON")
    parser.add_argument(
        "--out",
        default="verification.json",
        help="Output path for verification report",
    )
    args = parser.parse_args()

    bundle_path = Path(args.bundle)
    media_root = Path(args.media_root)
    certificate_path = Path(args.certificate) if args.certificate else None
    policy_path = Path(args.policy) if args.policy else None
    result = verify_bundle(bundle_path, media_root, certificate_path, policy_path)

    out_path = Path(args.out)
    out_path.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(f"✓ Wrote {out_path} – decision: {result['decision']}")


if __name__ == "__main__":
    main()
