"""Command line interface and flow control."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from . import collector, fingerprints, prompt, report
from .cache import Cache
from .cpe import is_queryable_version, resolve_cpe, virtual_match_string
from .matcher import match, query_plan
from .nvd import NvdClient, NvdError

CONFIG_DIR = Path.home() / ".wapp2cve"
CONFIG_FILE = CONFIG_DIR / "config"
CACHE_FILE = CONFIG_DIR / "cache.db"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="wapp2cve",
        description="Detect the technologies behind a URL and pull their CVEs from NVD.",
    )
    parser.add_argument("url", nargs="?", help="address to scan")
    parser.add_argument(
        "--login",
        action="store_true",
        help="open a visible browser, wait for you to log in, then scan that page",
    )
    parser.add_argument("--all", action="store_true", help="do not truncate long CVE lists")
    parser.add_argument(
        "--api-key",
        metavar="KEY",
        help="save an NVD API key, replacing any stored one (empty string clears it)",
    )
    parser.add_argument("--no-cache", action="store_true", help="bypass the NVD cache")
    parser.add_argument("--timeout", type=int, default=30000, help="page load timeout in ms")
    parser.add_argument(
        "--update-fingerprints", action="store_true", help="refresh the fingerprint dataset"
    )
    parser.add_argument("--save-evidence", metavar="FILE", help="write the evidence bundle to disk")
    parser.add_argument(
        "--from-evidence", metavar="FILE", help="replay a saved evidence bundle, no browser"
    )
    return parser


def read_config() -> dict[str, str]:
    if not CONFIG_FILE.is_file():
        return {}
    config: dict[str, str] = {}
    for line in CONFIG_FILE.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        config[key.strip()] = value.strip()
    return config


def write_config(config: dict[str, str]) -> None:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    CONFIG_FILE.write_text(
        "".join(f"{key}={value}\n" for key, value in config.items()), encoding="utf-8"
    )


def get_api_key() -> str:
    """Environment variable first, then the config file, then ask."""
    env_key = os.environ.get("NVD_API_KEY", "").strip()
    if env_key:
        return env_key
    config = read_config()
    if "api_key" in config:
        return config["api_key"]
    if not prompt.is_interactive():
        # Not a terminal: don't ask, and don't persist an empty key either, so
        # the next interactive run still gets the chance to set one.
        print("[!] No NVD API key, running in slow mode (5 requests / 30s).", file=sys.stderr)
        return ""
    key = prompt.ask_api_key()
    save_api_key(key)
    if not key:
        print("  Continuing in slow mode (5 requests / 30s).")
    return key


def save_api_key(key: str) -> None:
    """Store the key and say where it went, so a wrong one can be found again."""
    config = read_config()
    config["api_key"] = key.strip()
    write_config(config)
    print(f"  Key saved to {CONFIG_FILE} (--api-key replaces it)")


def classify(detections, versions: dict[str, str]) -> tuple[list, list]:
    """Split detections into what can be queried and what has to be explained.

    Returns ``(queryable, results)`` where queryable items are
    ``(detection, base_cpe, version)`` triples.
    """
    queryable: list[tuple] = []
    other: list[report.TechResult] = []
    for det in detections:
        if det.implied:
            # An implied technology was never actually seen, so we neither ask
            # for its version nor look up CVEs for it.
            other.append(
                report.TechResult(
                    name=det.name,
                    status=report.IMPLIED,
                    note=f"implied by {det.implied_by}",
                    confidence=det.confidence,
                )
            )
            continue
        base = resolve_cpe(det.tech)
        if base is None:
            other.append(
                report.TechResult(name=det.name, status=report.NO_CPE, confidence=det.confidence)
            )
            continue
        version = versions.get(det.name) or det.version
        if is_queryable_version(version):
            queryable.append((det, base, version))
        elif version:
            other.append(
                report.TechResult(
                    name=det.name,
                    status=report.DIRTY_VERSION,
                    version=version,
                    confidence=det.confidence,
                )
            )
        else:
            other.append(
                report.TechResult(
                    name=det.name, status=report.NO_VERSION, confidence=det.confidence
                )
            )
    return queryable, other


def needs_version(detections, versions: dict[str, str]) -> list[str]:
    names = []
    for det in detections:
        if det.implied or resolve_cpe(det.tech) is None:
            continue
        if not is_queryable_version(versions.get(det.name) or det.version):
            names.append(det.name)
    return names


def run(args: argparse.Namespace) -> int:
    if args.api_key is not None:
        save_api_key(args.api_key)
        if not args.url and not args.from_evidence:
            return 0

    if args.update_fingerprints:
        commit = fingerprints.update()
        print(f"Fingerprint dataset updated (commit {commit[:10]}).")
        return 0

    if not args.url and not args.from_evidence:
        build_parser().print_usage()
        print("wapp2cve: pass a URL or use --from-evidence", file=sys.stderr)
        return 2

    technologies = fingerprints.load()

    if args.from_evidence:
        evidence = collector.load(Path(args.from_evidence))
        url = evidence.get("final_url") or evidence.get("url") or args.from_evidence
    else:
        url = args.url
        js_paths, dom_rules = query_plan(technologies)
        print(f"[*] Loading {url}")
        evidence = collector.collect(
            url, js_paths, dom_rules, login=args.login, timeout=args.timeout
        )
        url = evidence.get("final_url") or url

    if args.save_evidence:
        collector.save(evidence, Path(args.save_evidence))
        print(f"[*] Evidence bundle written to {args.save_evidence}")

    if evidence.get("blocked"):
        print(
            f"\n[!] The site served bot protection ({evidence['blocked']}).\n"
            "    These results are not trustworthy. Try again with --login and\n"
            "    clear the challenge yourself.\n",
            file=sys.stderr,
        )

    detections = match(evidence, technologies)
    if not detections:
        print("No technologies detected.")
        return 0

    versions: dict[str, str] = {}
    prompt.ask_versions(needs_version(detections, versions), versions)

    queryable, results = classify(detections, versions)

    if queryable:
        client = NvdClient(get_api_key())
        with Cache(CACHE_FILE, enabled=not args.no_cache) as cache:
            for det, base, version in queryable:
                key = virtual_match_string(base, version)
                cves = cache.get(key)
                if cves is None:
                    print(f"[*] Querying NVD for {det.name} {version}")
                    try:
                        cves = client.cves_for(key)
                    except NvdError as exc:
                        results.append(
                            report.TechResult(
                                name=det.name,
                                status=report.ERROR,
                                version=version,
                                note=str(exc),
                            )
                        )
                        continue
                    cache.put(key, cves)
                results.append(
                    report.TechResult(
                        name=det.name,
                        status=report.QUERIED,
                        version=version,
                        cves=cves,
                        confidence=det.confidence,
                    )
                )

    print()
    print(report.render(url, results, show_all=args.all))
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return run(args)
    except KeyboardInterrupt:
        print("\nAborted.", file=sys.stderr)
        return 130
    except (RuntimeError, FileNotFoundError, OSError) as exc:
        print(f"wapp2cve: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
