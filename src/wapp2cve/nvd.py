"""NVD API 2.0 client."""

from __future__ import annotations

import time

import requests

API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
RESULTS_PER_PAGE = 2000

# NVD allows 5 requests per 30s without a key, 50 per 30s with one.
INTERVAL_WITH_KEY = 30 / 50
INTERVAL_WITHOUT_KEY = 30 / 5

_RETRY_STATUS = {403, 429, 500, 502, 503, 504}


class NvdError(RuntimeError):
    pass


class NvdClient:
    def __init__(self, api_key: str | None = None, timeout: int = 30, retries: int = 3):
        self.api_key = api_key or None
        self.timeout = timeout
        self.retries = retries
        self.interval = INTERVAL_WITH_KEY if self.api_key else INTERVAL_WITHOUT_KEY
        self._last_request = 0.0
        self._session = requests.Session()
        self._session.headers["User-Agent"] = "wapp2cve"
        if self.api_key:
            self._session.headers["apiKey"] = self.api_key

    def _throttle(self) -> None:
        wait = self.interval - (time.monotonic() - self._last_request)
        if wait > 0:
            time.sleep(wait)
        self._last_request = time.monotonic()

    def _get(self, params: dict) -> dict:
        last_error = ""
        for attempt in range(self.retries):
            self._throttle()
            try:
                response = self._session.get(API_URL, params=params, timeout=self.timeout)
            except requests.RequestException as exc:
                last_error = str(exc)
            else:
                if response.status_code == 200:
                    try:
                        return response.json()
                    except ValueError as exc:
                        last_error = f"invalid JSON: {exc}"
                elif response.status_code in _RETRY_STATUS:
                    last_error = f"HTTP {response.status_code}"
                else:
                    raise NvdError(
                        f"NVD HTTP {response.status_code}: {response.text[:200]}"
                        + self._key_hint(response.status_code)
                    )
            time.sleep(2**attempt)
        raise NvdError(f"could not reach NVD ({last_error}){self._key_hint(403)}")

    def _key_hint(self, status: int) -> str:
        """NVD answers 403/404 for a bad key, which reads like a network fault."""
        if status in (401, 403, 404) and self.api_key:
            return "\n    If this keeps happening the API key may be wrong: wapp2cve --api-key NEW"
        return ""

    def cves_for(self, virtual_match_string: str) -> list[dict]:
        collected: list[dict] = []
        start_index = 0
        while True:
            payload = self._get(
                {
                    "virtualMatchString": virtual_match_string,
                    "resultsPerPage": RESULTS_PER_PAGE,
                    "startIndex": start_index,
                }
            )
            for item in payload.get("vulnerabilities") or []:
                parsed = parse_cve(item.get("cve") or {})
                if parsed:
                    collected.append(parsed)
            total = payload.get("totalResults", 0)
            start_index += payload.get("resultsPerPage", 0) or RESULTS_PER_PAGE
            if start_index >= total:
                break
        collected.sort(key=lambda c: (-(c["score"] or 0), c["id"]))
        return collected


def parse_cve(cve: dict) -> dict | None:
    cve_id = cve.get("id")
    if not cve_id:
        return None
    score, severity, vector = _best_metric(cve.get("metrics") or {})
    return {
        "id": cve_id,
        "score": score,
        "severity": severity,
        "vector": vector,
        "summary": _description(cve),
        "published": (cve.get("published") or "")[:10],
    }


def _best_metric(metrics: dict) -> tuple[float | None, str, str]:
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key) or []
        if not entries:
            continue
        data = entries[0].get("cvssData") or {}
        score = data.get("baseScore")
        severity = data.get("baseSeverity") or entries[0].get("baseSeverity") or ""
        return (float(score) if score is not None else None, severity, data.get("vectorString", ""))
    return (None, "", "")


def _description(cve: dict) -> str:
    descriptions = cve.get("descriptions") or []
    english = [e for e in descriptions if e.get("lang") == "en"]
    chosen = (english or descriptions or [{}])[0]
    return " ".join((chosen.get("value") or "").split())
