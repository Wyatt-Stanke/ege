import json
import os
import re
import shutil
import sys
from json import JSONDecodeError
from pathlib import Path


def main() -> None:
    session_id = sys.argv[1]
    harness_path = Path(f"captures/{session_id}/harness.json")
    try:
        harness = json.loads(harness_path.read_text(encoding="utf-8"))
    except FileNotFoundError as error:
        raise SystemExit(f"Missing harness metadata: {harness_path}") from error
    except JSONDecodeError as error:
        raise SystemExit(f"Invalid harness metadata JSON: {harness_path}: {error}") from error

    browser = harness["browser"].lower()
    version = harness["browser_version"]
    system = harness["platform"]["system"].lower()
    machine = harness["platform"]["machine"].lower()

    slug = re.sub(r"[^a-z0-9._-]", "_", f"{browser}-{version}-{system}-{machine}")
    target_dir = Path("fingerprints") / browser / version / system / machine
    target_dir.mkdir(parents=True, exist_ok=True)
    dest_base = target_dir / slug

    src = Path(f"fingerprints/{session_id}.json")
    if src.exists():
        shutil.move(src, f"{dest_base}.json")

    variation_src = Path(f"fingerprints/{session_id}.variation.json")
    if variation_src.exists():
        shutil.move(variation_src, f"{dest_base}.variation.json")

    with open(os.environ["GITHUB_ENV"], "a", encoding="utf-8") as github_env:
        github_env.write(f"FP_DIR={target_dir}\n")
        github_env.write(f"FP_SLUG={slug}\n")

    print(f"Fingerprint: {dest_base}", flush=True)


if __name__ == "__main__":
    main()
