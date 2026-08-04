"""Loading, parsing and updating the fingerprint dataset.

Every pattern in the raw JSON is a single string of the form
``regex\\;version:EXPR\\;confidence:N``. This module turns those into
:class:`Pattern` objects once, at load time.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parents[2] / "data"
UPSTREAM = "https://github.com/enthec/webappanalyzer.git"

# The dataset escapes its field separator as "\\;" in JSON, which decodes to "\;".
_SEP = "\\;"

_JS_NAMED_GROUP = re.compile(r"\(\?<([A-Za-z_]\w*)>")


@dataclass(frozen=True)
class Pattern:
    regex: re.Pattern | None
    version: str = ""
    confidence: int = 100
    source: str = ""

    def match(self, value: str) -> re.Match | None:
        if self.regex is None:
            return None
        return self.regex.search(value)


@dataclass
class DomRule:
    """A CSS selector plus whatever should be read off the matching node."""

    selector: str
    exists: Pattern | None = None
    attributes: dict[str, Pattern] = field(default_factory=dict)
    properties: dict[str, Pattern] = field(default_factory=dict)
    text: Pattern | None = None


@dataclass
class Technology:
    name: str
    cats: list[int] = field(default_factory=list)
    cpe: str | None = None
    website: str = ""
    description: str = ""
    headers: dict[str, list[Pattern]] = field(default_factory=dict)
    cookies: dict[str, list[Pattern]] = field(default_factory=dict)
    meta: dict[str, list[Pattern]] = field(default_factory=dict)
    js: dict[str, list[Pattern]] = field(default_factory=dict)
    html: list[Pattern] = field(default_factory=list)
    text: list[Pattern] = field(default_factory=list)
    scriptSrc: list[Pattern] = field(default_factory=list)
    scripts: list[Pattern] = field(default_factory=list)
    url: list[Pattern] = field(default_factory=list)
    xhr: list[Pattern] = field(default_factory=list)
    dom: list[DomRule] = field(default_factory=list)
    implies: list[str] = field(default_factory=list)
    requires: list[str] = field(default_factory=list)
    requiresCategory: list[int] = field(default_factory=list)
    excludes: list[str] = field(default_factory=list)


def _compile(raw: str, source: str = "") -> Pattern:
    parts = raw.split(_SEP)
    version = ""
    confidence = 100
    for extra in parts[1:]:
        if extra.startswith("version:"):
            version = extra[len("version:") :]
        elif extra.startswith("confidence:"):
            try:
                confidence = int(extra[len("confidence:") :])
            except ValueError:
                pass
    try:
        # An empty body is deliberate: it means "does this field exist at all".
        regex = re.compile(_JS_NAMED_GROUP.sub(r"(?P<\1>", parts[0]), re.I)
    except re.error:
        # A handful of patterns use JS-only syntax such as variable-length
        # lookbehind. Dropping the pattern beats dropping the technology.
        regex = None
    return Pattern(regex=regex, version=version, confidence=confidence, source=source)


def _compile_list(value, source: str = "") -> list[Pattern]:
    if isinstance(value, str):
        value = [value]
    return [_compile(v, source) for v in value or []]


def _compile_map(value: dict, source: str = "") -> dict[str, list[Pattern]]:
    return {key: _compile_list(raw, f"{source}[{key}]") for key, raw in (value or {}).items()}


def _compile_dom(value) -> list[DomRule]:
    if isinstance(value, str):
        value = [value]
    if isinstance(value, list):
        # List form: the selector matching at all is the whole signal.
        return [DomRule(selector=s, exists=_compile("", "dom")) for s in value]

    rules: list[DomRule] = []
    for selector, spec in (value or {}).items():
        if not isinstance(spec, dict):
            rules.append(DomRule(selector=selector, exists=_compile("", "dom")))
            continue
        rule = DomRule(selector=selector)
        if "exists" in spec:
            rule.exists = _compile(spec["exists"] or "", "dom")
        if "text" in spec:
            rule.text = _compile(spec["text"] or "", "dom")
        for attr, raw in (spec.get("attributes") or {}).items():
            rule.attributes[attr] = _compile(raw or "", f"dom[{attr}]")
        for prop, raw in (spec.get("properties") or {}).items():
            rule.properties[prop] = _compile(raw or "", f"dom[{prop}]")
        rules.append(rule)
    return rules


def _build(name: str, raw: dict) -> Technology:
    tech = Technology(
        name=name,
        cats=list(raw.get("cats") or []),
        cpe=raw.get("cpe"),
        website=raw.get("website", ""),
        description=raw.get("description", ""),
        implies=[i.split(_SEP)[0] for i in raw.get("implies") or []],
        requires=[r.split(_SEP)[0] for r in raw.get("requires") or []],
        requiresCategory=list(raw.get("requiresCategory") or []),
        excludes=[e.split(_SEP)[0] for e in raw.get("excludes") or []],
    )
    for key in ("headers", "cookies", "meta", "js"):
        setattr(tech, key, _compile_map(raw.get(key) or {}, key))
    for key in ("html", "text", "scriptSrc", "scripts", "url", "xhr"):
        setattr(tech, key, _compile_list(raw.get(key) or [], key))
    tech.dom = _compile_dom(raw.get("dom"))
    return tech


def load(data_dir: Path | None = None) -> dict[str, Technology]:
    directory = (data_dir or DATA_DIR) / "technologies"
    if not directory.is_dir():
        raise FileNotFoundError(
            f"No fingerprint data at {directory}\n"
            "Run `wapp2cve --update-fingerprints` to fetch it."
        )
    techs: dict[str, Technology] = {}
    for path in sorted(directory.glob("*.json")):
        with path.open(encoding="utf-8") as handle:
            for name, raw in json.load(handle).items():
                techs[name] = _build(name, raw)
    return techs


def load_categories(data_dir: Path | None = None) -> dict[int, str]:
    path = (data_dir or DATA_DIR) / "categories.json"
    if not path.is_file():
        return {}
    with path.open(encoding="utf-8") as handle:
        return {int(k): v.get("name", k) for k, v in json.load(handle).items()}


def update(data_dir: Path | None = None) -> str:
    """Refresh the vendored dataset from upstream. Returns the commit hash."""
    target = data_dir or DATA_DIR
    with tempfile.TemporaryDirectory() as tmp:
        clone = Path(tmp) / "webappanalyzer"
        subprocess.run(
            ["git", "clone", "--depth", "1", UPSTREAM, str(clone)],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        commit = subprocess.run(
            ["git", "-C", str(clone), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        src = clone / "src" / "technologies"
        if not src.is_dir():
            raise RuntimeError("Upstream layout changed: src/technologies is missing")
        dest = target / "technologies"
        shutil.rmtree(dest, ignore_errors=True)
        shutil.copytree(src, dest)
        shutil.copy(clone / "src" / "categories.json", target / "categories.json")
        (target / "SOURCE.txt").write_text(
            f"{UPSTREAM.removesuffix('.git')} (GPL-3.0)\ncommit: {commit}\n",
            encoding="utf-8",
        )
    return commit
