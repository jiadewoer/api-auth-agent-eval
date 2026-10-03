"""Human-readable P01/P04 paired HTTP reproductions with the real TestClient."""

import argparse
import json
from pathlib import Path
from tempfile import TemporaryDirectory

from fastapi.testclient import TestClient

from app.main import create_app


def reproduce() -> dict:
    output = {}
    with TemporaryDirectory() as tmp:
        for pair, path, legal in (
            ("P01", "/tickets/201", "B"),
            ("P04", "/admin/export", "M"),
        ):
            output[pair] = {}
            for variant in ("vuln", "fixed"):
                db = Path(tmp) / f"{pair}_{variant}.sqlite"
                with TestClient(create_app(f"{pair}_{variant}", db)) as client:
                    legal_response = client.get(path, headers={"Authorization":
                                                f"Bearer lab-token-{legal.lower()}"})
                    denied_or_leaked = client.get(path, headers={"Authorization":
                                                "Bearer lab-token-a"})
                output[pair][variant] = {
                    "legal_status": legal_response.status_code,
                    "A_status": denied_or_leaked.status_code,
                    "A_body": denied_or_leaked.json(),
                    "marker_observed": ("b-private-201" in denied_or_leaked.text),
                }
                expected = 200 if variant == "vuln" else 403
                assert legal_response.status_code == 200
                assert denied_or_leaked.status_code == expected
                assert output[pair][variant]["marker_observed"] == (variant == "vuln")
    return output


def main() -> None:
    parser = argparse.ArgumentParser(description="Reproduce synthetic P01/P04 vulnerabilities")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    output = reproduce()
    target = Path(args.output)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(output, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({"saved": str(target), "pairs": list(output)}, ensure_ascii=False))


if __name__ == "__main__":
    main()
