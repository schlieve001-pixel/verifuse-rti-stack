# VeriFuse RTI Verifier (Starter)

Minimal offline verifier for RTI bundles.

## Requirements

- Python 3.11+

## Usage

```bash
python cli/rti_cli.py --bundle /path/to/bundle.json --media-root /path/to/media --out verification.json
python cli/rti_cli.py --bundle /path/to/bundle.json --media-root /path/to/media --policy /path/to/policy.json --out verification.json
```

## Offline Web Verifier (Phone-friendly)

Open `web/index.html` in a local browser (or host it on your laptop and open it on your phone).
Select `bundle.json`, the files from `media/`, and optionally `rti6.json` or a policy JSON to verify offline.

To install on a phone:
- Serve the `web/` folder locally (for service worker support).
- Open the URL on your phone and use “Add to Home Screen.”

Quick host command:

```bash
python tools/serve_web.py
```

## Android App (Capture Wizard Scaffold)

The Android app scaffold lives under `android/` and provides the capture wizard shell
that will be wired to CameraX, audio, GNSS, and sensor capture.

From the `android/` directory:

```bash
./gradlew :app:assembleDebug
```

## Testing

```bash
python -m unittest
python -m unittest discover -s tests
```
