"""Load a page with Playwright and produce an evidence bundle.

The bundle is plain JSON-serialisable data. Keeping it separate from the
matcher means a page can be captured once and replayed offline forever.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path

from .fingerprints import DomRule

_JS_PROBE = """(paths) => {
  const out = {};
  for (const path of paths) {
    try {
      let value = window;
      for (const part of path.split('.')) {
        if (value === null || value === undefined) { value = undefined; break; }
        value = value[part];
      }
      if (value === undefined) continue;
      const type = typeof value;
      if (type === 'string' || type === 'number' || type === 'boolean') {
        out[path] = String(value);
      } else {
        out[path] = '';  // presence only; the value itself is never matched
      }
    } catch (e) { /* exploding getter, skip */ }
  }
  return out;
}"""

_DOM_PROBE = """(rules) => {
  const out = {};
  for (const rule of rules) {
    let nodes;
    try { nodes = document.querySelectorAll(rule.selector); }
    catch (e) { continue; }
    if (!nodes.length) continue;
    const collected = [];
    for (const node of Array.from(nodes).slice(0, 5)) {
      const info = { attributes: {}, properties: {} };
      for (const name of rule.attributes) {
        const value = node.getAttribute(name);
        if (value !== null) info.attributes[name] = value;
      }
      for (const name of rule.properties) {
        try {
          const value = node[name];
          if (value !== undefined) info.properties[name] = String(value);
        } catch (e) { /* skip */ }
      }
      if (rule.text) info.text = (node.textContent || '').slice(0, 2000);
      collected.push(info);
    }
    out[rule.selector] = collected;
  }
  return out;
}"""

_PAGE_PROBE = """() => {
  const meta = {};
  for (const node of document.querySelectorAll('meta[name], meta[property]')) {
    const key = (node.getAttribute('name') || node.getAttribute('property') || '').toLowerCase();
    const content = node.getAttribute('content');
    if (!key || content === null) continue;
    (meta[key] = meta[key] || []).push(content);
  }
  const scriptSrc = [];
  const scripts = [];
  for (const node of document.querySelectorAll('script')) {
    if (node.src) scriptSrc.push(node.src);
    else if (node.textContent) scripts.push(node.textContent.slice(0, 100000));
  }
  return {
    meta,
    scriptSrc,
    scripts,
    text: (document.body ? document.body.innerText : '').slice(0, 500000),
  };
}"""

_BLOCK_TITLES = re.compile(r"just a moment|attention required|checking your browser", re.I)
_BLOCK_BODY = re.compile(r"cf-chl|cf_chl_opt|_cf_chl|__cf_bm|challenge-platform", re.I)


def detect_block(evidence: dict) -> str | None:
    """Return a human-readable reason if the page looks like a bot challenge.

    Reporting a challenge page as "no technologies found" is the worst possible
    outcome: the user walks away thinking the site is clean.
    """
    status = evidence.get("status")
    html = evidence.get("html") or ""
    if status in (403, 429, 503):
        return f"HTTP {status}"
    title = re.search(r"<title[^>]*>(.*?)</title>", html, re.I | re.S)
    if title and _BLOCK_TITLES.search(title.group(1)):
        return f"challenge page: {title.group(1).strip()[:60]}"
    if _BLOCK_BODY.search(html) and len(html) < 20000:
        return "Cloudflare challenge signature"
    return None


def _dom_payload(rules: list[DomRule]) -> list[dict]:
    return [
        {
            "selector": rule.selector,
            "attributes": sorted(rule.attributes),
            "properties": sorted(rule.properties),
            "text": rule.text is not None,
        }
        for rule in rules
    ]


def collect(
    url: str,
    js_paths: list[str],
    dom_rules: list[DomRule],
    *,
    login: bool = False,
    timeout: int = 30000,
) -> dict:
    try:
        from playwright.sync_api import Error as PlaywrightError
        from playwright.sync_api import sync_playwright
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError(
            "Playwright is not installed.\n"
            "  pip install -r requirements.txt\n"
            "  python -m playwright install chromium"
        ) from exc

    evidence: dict = {"url": url, "xhr": []}

    with sync_playwright() as playwright:
        browser = _launch(playwright, headless=not login)
        context = browser.new_context(ignore_https_errors=True)
        page = context.new_page()
        page.on(
            "request",
            lambda request: (
                evidence["xhr"].append(request.url)
                if request.resource_type in ("xhr", "fetch")
                else None
            ),
        )

        try:
            response = page.goto(url, wait_until="domcontentloaded", timeout=timeout)
        except PlaywrightError as exc:
            browser.close()
            raise RuntimeError(f"could not load {url}: {_reason(exc)}") from None
        _settle(page, timeout)

        if login:
            print(
                "\n[*] Browser is open. Log in, navigate to the page you want scanned,\n"
                "    then come back here and press Enter."
            )
            input()
            _settle(page, 5000)

        evidence["status"] = response.status if response else None
        evidence["final_url"] = page.url
        evidence["headers"] = _headers(response)
        evidence["html"] = page.content()
        evidence["cookies"] = {c["name"]: c.get("value", "") for c in context.cookies()}
        evidence.update(page.evaluate(_PAGE_PROBE))
        evidence["js"] = page.evaluate(_JS_PROBE, js_paths)
        evidence["dom"] = page.evaluate(_DOM_PROBE, _dom_payload(dom_rules))

        context.close()
        browser.close()

    evidence["blocked"] = detect_block(evidence)
    return evidence


_NAVIGATION_ERRORS = {
    "ERR_CONNECTION_TIMED_OUT": "the host did not respond",
    "ERR_CONNECTION_REFUSED": "connection refused",
    "ERR_NAME_NOT_RESOLVED": "DNS lookup failed",
    "ERR_CONNECTION_RESET": "the connection was reset",
    "ERR_CERT_AUTHORITY_INVALID": "invalid TLS certificate",
    "ERR_ABORTED": "the navigation was aborted",
    "Timeout": "timed out, try raising --timeout",
}


def _reason(exc: Exception) -> str:
    """Turn Playwright's multi-line call log into one useful sentence."""
    message = str(exc)
    for needle, explanation in _NAVIGATION_ERRORS.items():
        if needle in message:
            return explanation
    return message.splitlines()[0].removeprefix("Page.goto: ")


def _settle(page, timeout: int) -> None:
    try:
        page.wait_for_load_state("networkidle", timeout=min(timeout, 10000))
    except Exception:
        # Pages that poll forever never reach networkidle. Take what we have.
        pass


def _launch_args() -> list[str]:
    args = ["--disable-blink-features=AutomationControlled"]
    if getattr(os, "geteuid", lambda: 1)() == 0:
        # Chromium will not start as root without this, which is the default
        # situation on Kali and inside most containers.
        args.append("--no-sandbox")
    return args


def _launch(playwright, *, headless: bool):
    """Prefer the real Chrome install; its fingerprint draws far less suspicion."""
    args = _launch_args()
    try:
        return playwright.chromium.launch(channel="chrome", headless=headless, args=args)
    except Exception:
        # No system Chrome (the normal case on Kali) - fall back to the bundled build.
        return playwright.chromium.launch(headless=headless, args=args)


def _headers(response) -> dict[str, list[str]]:
    if response is None:
        return {}
    headers: dict[str, list[str]] = {}
    try:
        for entry in response.headers_array():
            headers.setdefault(entry["name"].lower(), []).append(entry["value"])
    except Exception:
        for name, value in (response.headers or {}).items():
            headers.setdefault(name.lower(), []).append(value)
    return headers


def save(evidence: dict, path: Path) -> None:
    path.write_text(json.dumps(evidence, ensure_ascii=False, indent=2), encoding="utf-8")


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))
