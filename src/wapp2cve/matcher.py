"""Evidence bundle -> technologies and versions.

Nothing here touches the network or a browser. The input is the plain dict the
collector produces, which means the matcher can be exercised against recorded
fixtures without Playwright installed.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .fingerprints import DomRule, Pattern, Technology

# `\1?yes:no` is the conditional version form used by Magento, Shopware, CodeIgniter.
_CONDITIONAL = re.compile(r"\\(\d+)\?([^:]*):(.*)$")
_GROUP_REF = re.compile(r"\\(\d+)")


@dataclass
class Detection:
    name: str
    tech: Technology
    versions: set[str] = field(default_factory=set)
    confidence: int = 0
    implied_by: str | None = None
    evidence: list[str] = field(default_factory=list)

    @property
    def implied(self) -> bool:
        return self.implied_by is not None

    @property
    def version(self) -> str | None:
        """The most informative version seen: most components, then longest."""
        if not self.versions:
            return None
        return max(self.versions, key=lambda v: (v.count("."), len(v), v))


def resolve_version(expr: str, match: re.Match) -> str:
    r"""Apply a version expression to a regex match.

    The dataset only ever uses five shapes: capture groups (``\1``, ``\1.\2``),
    literals (``6.5``), affixed literals (``pro \1``), and the conditional
    ``\1?yes:no``.
    """

    def group(index: int) -> str:
        try:
            return match.group(index) or ""
        except (IndexError, re.error):
            return ""

    conditional = _CONDITIONAL.search(expr)
    if conditional:
        index, yes, no = conditional.groups()
        expr = expr[: conditional.start()] + (yes if group(int(index)) else no)
    return _GROUP_REF.sub(lambda m: group(int(m.group(1))), expr).strip()


def _apply(
    detections: dict[str, Detection],
    tech: Technology,
    pattern: Pattern,
    value: str,
    where: str,
) -> None:
    if value is None:
        return
    match = pattern.match(value)
    if match is None:
        return
    detection = detections.setdefault(tech.name, Detection(name=tech.name, tech=tech))
    detection.confidence = min(100, detection.confidence + pattern.confidence)
    detection.evidence.append(where)
    if pattern.version:
        version = resolve_version(pattern.version, match)
        if version:
            detection.versions.add(version)


def _key_matches(key: str, candidate: str) -> bool:
    """Header/cookie/meta keys are usually literal, but some are regexes."""
    if key.lower() == candidate.lower():
        return True
    try:
        return re.fullmatch(key, candidate, re.I) is not None
    except re.error:
        return False


def _match_map(
    detections: dict[str, Detection],
    tech: Technology,
    patterns: dict[str, list[Pattern]],
    evidence_map: dict[str, list[str]],
    where: str,
) -> None:
    for key, key_patterns in patterns.items():
        for candidate, values in evidence_map.items():
            if not _key_matches(key, candidate):
                continue
            for value in values:
                for pattern in key_patterns:
                    _apply(detections, tech, pattern, value, f"{where}:{candidate}")


def _match_list(
    detections: dict[str, Detection],
    tech: Technology,
    patterns: list[Pattern],
    values: list[str],
    where: str,
) -> None:
    for value in values:
        for pattern in patterns:
            _apply(detections, tech, pattern, value, where)


def _match_dom(
    detections: dict[str, Detection],
    tech: Technology,
    rules: list[DomRule],
    dom: dict[str, list[dict]],
) -> None:
    for rule in rules:
        for node in dom.get(rule.selector) or []:
            if rule.exists is not None:
                _apply(detections, tech, rule.exists, "", f"dom:{rule.selector}")
            if rule.text is not None:
                _apply(
                    detections, tech, rule.text, node.get("text") or "", f"dom:{rule.selector}"
                )
            for attr, pattern in rule.attributes.items():
                value = (node.get("attributes") or {}).get(attr)
                if value is not None:
                    _apply(detections, tech, pattern, value, f"dom:{rule.selector}[{attr}]")
            for prop, pattern in rule.properties.items():
                value = (node.get("properties") or {}).get(prop)
                if value is not None:
                    _apply(detections, tech, pattern, value, f"dom:{rule.selector}.{prop}")


def _detect(evidence: dict, technologies: dict[str, Technology]) -> dict[str, Detection]:
    detections: dict[str, Detection] = {}
    headers = evidence.get("headers") or {}
    cookies = {k: [v] for k, v in (evidence.get("cookies") or {}).items()}
    meta = evidence.get("meta") or {}
    js_values = evidence.get("js") or {}
    dom = evidence.get("dom") or {}
    url = [evidence.get("final_url") or evidence.get("url") or ""]
    html = [evidence.get("html") or ""]
    text = [evidence.get("text") or ""]
    script_src = evidence.get("scriptSrc") or []
    scripts = evidence.get("scripts") or []
    xhr = evidence.get("xhr") or []

    for tech in technologies.values():
        _match_map(detections, tech, tech.headers, headers, "header")
        _match_map(detections, tech, tech.cookies, cookies, "cookie")
        _match_map(detections, tech, tech.meta, meta, "meta")
        for path, patterns in tech.js.items():
            if path not in js_values:
                continue
            for pattern in patterns:
                _apply(detections, tech, pattern, js_values[path], f"js:{path}")
        _match_list(detections, tech, tech.url, url, "url")
        _match_list(detections, tech, tech.html, html, "html")
        _match_list(detections, tech, tech.text, text, "text")
        _match_list(detections, tech, tech.scriptSrc, script_src, "scriptSrc")
        _match_list(detections, tech, tech.scripts, scripts, "scripts")
        _match_list(detections, tech, tech.xhr, xhr, "xhr")
        _match_dom(detections, tech, tech.dom, dom)
    return detections


def _resolve_requires(detections: dict[str, Detection]) -> None:
    """Drop detections whose prerequisites are missing.

    Removal cascades: if A requires B and B goes, A goes with it.
    """
    while True:
        present = set(detections)
        categories = {cat for det in detections.values() for cat in det.tech.cats}
        doomed = [
            name
            for name, det in detections.items()
            if (det.tech.requires and not set(det.tech.requires) <= present)
            or (det.tech.requiresCategory and not set(det.tech.requiresCategory) & categories)
        ]
        if not doomed:
            return
        for name in doomed:
            del detections[name]


def _resolve_excludes(detections: dict[str, Detection]) -> None:
    for det in list(detections.values()):
        for excluded in det.tech.excludes:
            detections.pop(excluded, None)


def _resolve_implies(
    detections: dict[str, Detection], technologies: dict[str, Technology]
) -> None:
    queue = list(detections.values())
    while queue:
        det = queue.pop(0)
        for implied_name in det.tech.implies:
            if implied_name in detections:
                continue
            implied_tech = technologies.get(implied_name)
            if implied_tech is None:
                continue
            new = Detection(
                name=implied_name,
                tech=implied_tech,
                confidence=det.confidence,
                implied_by=det.name,
                evidence=[f"implies:{det.name}"],
            )
            detections[implied_name] = new
            queue.append(new)


def match(evidence: dict, technologies: dict[str, Technology]) -> list[Detection]:
    detections = _detect(evidence, technologies)
    _resolve_requires(detections)
    _resolve_excludes(detections)
    _resolve_implies(detections, technologies)
    return sorted(detections.values(), key=lambda d: d.name.lower())


def query_plan(technologies: dict[str, Technology]) -> tuple[list[str], list[DomRule]]:
    """Collect every JS path and DOM selector the fingerprints care about.

    The collector has no idea what a fingerprint is; this is how it learns what
    to ask the page.
    """
    js_paths = sorted({path for tech in technologies.values() for path in tech.js})
    rules: dict[str, DomRule] = {}
    for tech in technologies.values():
        for rule in tech.dom:
            existing = rules.get(rule.selector)
            if existing is None:
                rules[rule.selector] = DomRule(
                    selector=rule.selector,
                    attributes=dict(rule.attributes),
                    properties=dict(rule.properties),
                    text=rule.text,
                )
            else:
                existing.attributes.update(rule.attributes)
                existing.properties.update(rule.properties)
                existing.text = existing.text or rule.text
    return js_paths, list(rules.values())
