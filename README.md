# VeriFuse RTI Verifier (Starter)

Minimal offline verifier for RTI bundles.

## Requirements

- Python 3.11+

## Usage

```bash
python cli/rti_cli.py --bundle /path/to/bundle.json --media-root /path/to/media --out verification.json
```

## Offline Web Verifier (Phone-friendly)

Open `web/index.html` in a local browser (or host it on your laptop and open it on your phone).
Select `bundle.json`, the files from `media/`, and optionally `rti6.json` to verify offline.

To install on a phone:
- Serve the `web/` folder locally (for service worker support).
- Open the URL on your phone and use “Add to Home Screen.”

## Testing

```bash
python -m unittest
python -m unittest discover -s tests
```
