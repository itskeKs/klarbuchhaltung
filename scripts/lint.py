"""Validate Python and Bash source syntax without executing project code."""

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASH_WRAPPERS = {"bb", "bb-mcp", "bb-web"}


def main() -> int:
    output = subprocess.check_output(
        ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard",
         "--", "*.py", "*.sh", ".githooks/*", *sorted(BASH_WRAPPERS)],
        cwd=ROOT,
    )
    names = sorted({os.fsdecode(name) for name in output.split(b"\0") if name})
    failed = False
    checked = 0
    for name in names:
        path = ROOT / name
        if not path.is_file():
            continue
        checked += 1
        if path.suffix == ".py":
            try:
                compile(path.read_bytes(), name, "exec")
            except (SyntaxError, ValueError) as error:
                print(f"{name}: {error}", file=sys.stderr)
                failed = True
        else:
            result = subprocess.run(["bash", "-n", name], cwd=ROOT, check=False)
            failed |= result.returncode != 0
    if not failed:
        print(f"lint: OK ({checked} Python and Bash files)")
    return int(failed)


if __name__ == "__main__":
    sys.exit(main())
