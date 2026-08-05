"""Plain text report.

No `rich` dependency: the output looks the same in every terminal and stays
greppable. Grouped by technology, CVSS descending within each group.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field

DEFAULT_LIMIT = 10

QUERIED = "queried"
NO_VERSION = "no_version"
NO_CPE = "no_cpe"
IMPLIED = "implied"
DIRTY_VERSION = "dirty_version"
ERROR = "error"


@dataclass
class TechResult:
    name: str
    status: str
    version: str | None = None
    cves: list[dict] = field(default_factory=list)
    note: str = ""
    confidence: int = 100


def render(url: str, results: list[TechResult], show_all: bool = False) -> str:
    lines: list[str] = [f"wapp2cve {url}", ""]

    queried = [r for r in results if r.status == QUERIED]
    lines.append(
        f"Detected: {len(results)} technologies | "
        f"Queried: {len(queried)} | "
        f"Vulnerabilities: {sum(len(r.cves) for r in queried)}"
    )

    for result in sorted(queried, key=lambda r: (-_top_score(r), r.name.lower())):
        lines.append("")
        lines.append(f"[{result.name} {result.version}]" if result.version else f"[{result.name}]")
        if not result.cves:
            lines.append("  no CVEs found")
            continue
        shown = result.cves if show_all else result.cves[:DEFAULT_LIMIT]
        for cve in shown:
            score = f"{cve['score']:.1f}" if cve.get("score") is not None else " -- "
            lines.append(f"  {cve['id']:<18}{score:>5}  {_short(cve.get('summary', ''))}")
        hidden = len(result.cves) - len(shown)
        if hidden > 0:
            lines.append(f"  +{hidden} more, use --all to see them")

    lines.append("")
    lines.extend(_footer(results))
    return "\n".join(lines)


def _footer(results: list[TechResult]) -> list[str]:
    """Everything that was detected but not queried, and why."""
    lines: list[str] = []
    grouped: dict[str, list[TechResult]] = {}
    for result in results:
        if result.status != QUERIED:
            grouped.setdefault(result.status, []).append(result)

    def names(status: str) -> str:
        return ", ".join(sorted(r.name for r in grouped.get(status, [])))

    if grouped.get(NO_VERSION):
        lines.append(f"[NO VERSION]  {names(NO_VERSION)}")
    if grouped.get(DIRTY_VERSION):
        detail = ", ".join(
            f"{r.name} ({r.version})" for r in sorted(grouped[DIRTY_VERSION], key=lambda r: r.name)
        )
        lines.append(f"[BAD VERSION] {detail}")
    if grouped.get(IMPLIED):
        lines.append(f"[IMPLIED]     {names(IMPLIED)}")
    if grouped.get(NO_CPE):
        lines.append(f"[NO CPE]      {len(grouped[NO_CPE])} technologies")
        lines.append(f"              {names(NO_CPE)}")
    for result in grouped.get(ERROR, []):
        lines.append(f"[ERROR]       {result.name}: {result.note}")
    return lines


def _top_score(result: TechResult) -> float:
    return max((c.get("score") or 0 for c in result.cves), default=-1)


def _short(summary: str, width: int = 70) -> str:
    summary = " ".join(summary.split())
    return summary if len(summary) <= width else summary[: width - 1] + "..."


def render_json(url: str, results: list[TechResult]) -> str:
    out = {
        "url": url,
        "results": [
            {
                "name": r.name,
                "status": r.status,
                "version": r.version,
                "cves": r.cves,
                "note": r.note,
                "confidence": r.confidence,
            }
            for r in results
        ]
    }
    return json.dumps(out, indent=2, ensure_ascii=False)

