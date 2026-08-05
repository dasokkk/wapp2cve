# wapp2cve

Give it a URL. It opens the page in a real browser, works out which technologies are running
and at which versions, asks you about the ones it cannot pin down, then pulls the matching CVEs
from NVD and prints them.

```
$ wapp2cve https://example.com

Detected: 6 technologies | Queried: 4 | Vulnerabilities: 53

[Nginx 1.18.0]
  CVE-2021-23017      7.7  A security issue in nginx resolver was identified...
  CVE-2023-44487      7.5  The HTTP/2 protocol allows a denial of service...

[jQuery 3.4.1]
  CVE-2020-11022      6.9  In jQuery starting with 1.12.0 and before 3.5.0...

[IMPLIED]     MySQL
[NO CPE]      1 technologies
```

## Install

```bash
git clone <this-repo>
cd wapp2cve
pip install -e .
python -m playwright install chromium
```

If Chrome is installed on the machine wapp2cve drives that instead of Playwright's bundled
Chromium; its fingerprint draws far less attention from bot protection.

### Kali and other Debian-based systems

Three things differ:

```bash
python3 -m venv .venv && source .venv/bin/activate   # pip refuses to touch system Python
pip install -e .
playwright install chromium
playwright install-deps chromium                     # needs sudo, pulls libnss3/libgbm/etc.
```

- Recent Debian derivatives mark the system Python as externally managed, so `pip install`
  outside a venv fails with `externally-managed-environment`.
- `install-deps` is the step people skip; without it Chromium dies on launch complaining about
  missing shared libraries.
- Running as root is handled: `--no-sandbox` is added automatically, because Chromium refuses
  to start as root otherwise.

`--login` needs a graphical session. On a headless box the default headless scan works fine,
but there is no window to log in through.

## Usage

```bash
wapp2cve https://site.com
wapp2cve https://site.com --login          # visible browser, log in, press Enter
wapp2cve https://site.com --all            # don't truncate long CVE lists
wapp2cve https://site.com --json           # output results as JSON
wapp2cve https://site.com --no-cache       # skip the NVD cache
wapp2cve --update-fingerprints             # refresh the fingerprint dataset
```

| Flag | What it does |
|---|---|
| `--login` | Opens a visible browser, waits while you log in, and scans whatever page you land on. The interesting software usually lives behind the login, not on the marketing homepage. |
| `--all` | Long CVE lists are cut at 10 entries by default; this prints all of them. |
| `--json` | Outputs the final results in JSON format instead of plain text, useful for automation and pipelines. |
| `--no-cache` | Ignores the SQLite cache and refetches everything from NVD. |
| `--timeout` | Page load timeout in milliseconds (default 30000). |
| `--api-key KEY` | Saves an NVD API key, replacing any stored one. An empty string clears it. |
| `--save-evidence FILE` | Writes the collected evidence bundle to disk. |
| `--from-evidence FILE` | Replays a saved bundle without opening a browser at all. |

## NVD API key

Without a key NVD allows 5 requests per 30 seconds; with one, 50. Keys are free:
<https://nvd.nist.gov/developers/request-an-api-key>

On first run wapp2cve asks for a key and stores it in `~/.wapp2cve/config`, printing the full
path so you can find it later. You can leave it empty and run in slow mode.

The key is only ever asked for once. To replace one that was mistyped, or to clear it and be
asked again:

```bash
wapp2cve --api-key YOUR-KEY     # save or replace
wapp2cve --api-key ""           # clear
```

The `NVD_API_KEY` environment variable takes precedence over the file, which is the better
option if you use `sudo` (it resets `HOME`, so a key saved as your own user is invisible to
`sudo wapp2cve` and vice versa).

## How it works

```
Playwright  ->  evidence bundle  ->  matcher  ->  CPE  ->  NVD  ->  report
```

**Collection and matching are separate.** Playwright loads the page once and produces an
evidence bundle: headers, cookies, HTML, meta tags, script sources, JS globals, DOM nodes. The
matcher is plain Python: it never sees a browser, it only reads that bundle. Save one with
`--save-evidence` and you can replay it with `--from-evidence` as often as you like, which is
also how the test suite runs without Playwright installed.

**Name matching goes through CPE.** Detecting `Nginx 1.18.0` turns into a query for
`cpe:2.3:a:f5:nginx:1.18.0`, and NVD evaluates the version ranges (`versionEndExcluding` and
friends) on its side. There is no version comparison code in this project.

**Only technologies with a CPE are queried.** 463 of the 7542 technologies in the dataset carry
one; for the rest nothing is guessed. In a CVE tool a wrong CVE does more damage than a missing
one, so there is no fuzzy name matching anywhere. What could not be queried is listed under
`[NO CPE]` at the bottom of the report rather than silently dropped.

**Missing versions get asked about.** 251 of those 463 technologies have no version pattern at
all, so for them detection can never produce a version. If stdin is not a TTY nothing is asked
and the tool degrades to "no version", which keeps it usable from a pipeline or cron.

**Implied technologies are not queried.** "If you see WordPress there is also PHP" style
inferences show up under `[IMPLIED]`, but wapp2cve will not ask you for the version of something
it never actually observed, and it will not look up CVEs for it.

**Bot protection is detected.** Reporting a challenge page as "no technologies found" is the
worst possible outcome. On HTTP 403, a `Just a moment...` title, or a Cloudflare challenge
signature, wapp2cve says the results are untrustworthy and points you at `--login`.

## Limitations

- The `dns`, `css`, `probe`, `robots` and `certIssuer` fingerprint fields are not collected.
  They are used by 89, 22, 3, 1 and 6 technologies respectively.
- A handful of patterns use JS-only regex syntax (variable-length lookbehind) and cannot be
  compiled in Python, so they are dropped. A test keeps that below 2%.
- CVEs with no CVSS score render as `--` and sort last.

## Tests

```bash
python -m unittest discover -s tests
```

## License and data

This project is **GPL-3.0** (see `LICENSE`).

The fingerprint dataset under `data/technologies/` comes from
[enthec/webappanalyzer](https://github.com/enthec/webappanalyzer) and is **GPL-3.0** licensed.
The vendored commit is recorded in `data/SOURCE.txt`; `--update-fingerprints` refreshes it.

Keeping the data in the repo means the tool works offline and the same scan does not quietly
produce different results than it did yesterday.
