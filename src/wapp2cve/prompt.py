"""Interactive prompts.

Asking the user is not a fallback. Of the 463 technologies that carry a CPE,
251 have no version pattern at all, so for those the version can never be
detected automatically no matter how hard we try.

When stdin is not a TTY nothing is ever asked: the tool quietly degrades to
"no version" so it still works in a pipeline or a cron job.
"""

from __future__ import annotations

import sys

from .cpe import is_queryable_version, normalize_version

SKIP_ALL = {"q", "quit", "skip", "skip all"}


class SkipAll(Exception):
    """The user asked to skip every remaining version question."""


def is_interactive() -> bool:
    return sys.stdin.isatty() and sys.stdout.isatty()


def ask_version(name: str) -> str | None:
    print(f"\n[!] Could not detect a version for: {name}")
    print("    You can check it in your browser's developer tools or with a")
    print("    technology detection extension.")
    print("    Example: 1.18.0   (the version number only, not the product name)")
    print("    Press Enter to skip this one, or q to skip all remaining.")
    while True:
        try:
            raw = input(f"\n    {name} version > ").strip()
        except EOFError:
            return None
        if not raw:
            return None
        if raw.lower() in SKIP_ALL:
            raise SkipAll
        version = normalize_version(raw)
        if is_queryable_version(version):
            return version
        print(f"    '{raw}' does not look like a version. Digits and dots only: 1.18.0")


def ask_versions(names: list[str], versions: dict[str, str]) -> dict[str, str]:
    """Ask for each missing version in turn, filling in ``versions`` as we go."""
    if not names or not is_interactive():
        return versions
    for name in names:
        if name in versions:
            continue
        try:
            answer = ask_version(name)
        except SkipAll:
            print("    Skipped the remaining version questions.")
            break
        except KeyboardInterrupt:
            print("\n    Version questions interrupted.")
            break
        if answer:
            versions[name] = answer
    return versions


def ask_api_key() -> str:
    print("\nNo NVD API key found.")
    print("  Without a key NVD allows 5 requests per 30 seconds (slow mode).")
    print("  With one the limit is 50 per 30 seconds, so a scan takes seconds.")
    print("  Keys are free: https://nvd.nist.gov/developers/request-an-api-key")
    print("  Press Enter to continue without one.")
    try:
        return input("\n  NVD API key > ").strip()
    except (EOFError, KeyboardInterrupt):
        return ""
