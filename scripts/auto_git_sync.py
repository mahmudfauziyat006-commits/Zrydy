import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEBOUNCE_SECONDS = 5


def run(*args):
    return subprocess.run(
        list(args),
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=120,
    )


def status():
    return run("git", "status", "--porcelain")


def sync():
    result = status()
    if result.returncode != 0:
        print(result.stderr.strip(), flush=True)
        return
    if not result.stdout.strip():
        return

    staged = run("git", "add", "-A")
    if staged.returncode != 0:
        print(staged.stderr.strip(), flush=True)
        return

    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    committed = run("git", "commit", "-m", f"chore: auto-sync {timestamp}")
    if committed.returncode == 0:
        print(committed.stdout.strip(), flush=True)
    elif "nothing to commit" not in committed.stdout.lower():
        print(committed.stderr.strip(), flush=True)


def main():
    print(f"Zrydy auto Git sync watching {ROOT}", flush=True)
    last_change = None
    while True:
        result = status()
        changed = bool(result.returncode == 0 and result.stdout.strip())
        now = time.monotonic()
        if changed:
            if last_change is None:
                last_change = now
            elif now - last_change >= DEBOUNCE_SECONDS:
                sync()
                last_change = None
        else:
            last_change = None
        time.sleep(1)


if __name__ == "__main__":
    main()
