"""Technology -> CPE resolution.

Everything that decides what gets sent to NVD lives behind ``resolve_cpe``.
There is no fuzzy name matching: a technology without a ``cpe`` field in the
dataset is never queried, it is reported as unqueried instead. In a CVE tool a
wrong CVE does more damage than a missing one.
"""

from __future__ import annotations

import re

from .fingerprints import Technology

# Hand-verified name -> CPE mappings, overriding the dataset. Adding a line here
# means "I looked this product up myself and confirmed the match".
OVERRIDES: dict[str, str] = {}

# The version DSL can produce values like "1 (Enterprise)", "2+", "pro 3.1" or
# "GA4". Those are meaningless to NVD, so anything that fails this pattern is
# treated as "detected but not queryable".
_CLEAN_VERSION = re.compile(r"^\d+(\.\d+)*$")


def is_queryable_version(version: str | None) -> bool:
    return bool(version) and _CLEAN_VERSION.match(version) is not None


def normalize_version(raw: str) -> str:
    """``v1.18.0``, `` 1.18 ``, ``1.18.0-1ubuntu`` all become ``1.18.0`` / ``1.18``."""
    value = (raw or "").strip().lstrip("vV").strip()
    match = re.match(r"\d+(\.\d+)*", value)
    return match.group(0) if match else value


def _split(cpe: str) -> list[str]:
    """Split a CPE 2.3 string without tripping over escaped colons."""
    parts: list[str] = []
    current: list[str] = []
    escaped = False
    for char in cpe:
        if escaped:
            current.append(char)
            escaped = False
        elif char == "\\":
            current.append(char)
            escaped = True
        elif char == ":":
            parts.append("".join(current))
            current = []
        else:
            current.append(char)
    parts.append("".join(current))
    return parts


def resolve_cpe(tech: Technology) -> str | None:
    """Return the ``cpe:2.3:part:vendor:product`` prefix, or None if unknown."""
    raw = OVERRIDES.get(tech.name) or tech.cpe
    if not raw:
        return None
    parts = _split(raw)
    if len(parts) < 5 or parts[0].lower() != "cpe" or parts[1] != "2.3":
        # CPE 2.2 (`cpe:/a:...`) or a malformed record. We do not guess.
        return None
    part, vendor, product = parts[2], parts[3], parts[4]
    if not vendor or not product or "*" in (vendor, product):
        return None
    return f"cpe:2.3:{part}:{vendor}:{product}"


def virtual_match_string(base_cpe: str, version: str | None = None) -> str:
    """Build the ``virtualMatchString`` for an NVD query.

    Given a version, NVD evaluates the range fields (``versionEndExcluding`` and
    friends) itself, which is why there is no version comparison code anywhere
    in this project.
    """
    return f"{base_cpe}:{version}" if version else base_cpe
