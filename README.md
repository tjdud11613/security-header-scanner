# 🛡️ Security Header Scanner

A lightweight command-line tool that checks any website for missing or
misconfigured **HTTP security headers** — the kind of quick win that's
often overlooked but makes a real difference in hardening a web app
against clickjacking, MIME-sniffing, protocol downgrade attacks, and
information disclosure.

## Why this matters

Modern browsers support a set of response headers that act as an extra
layer of defense on top of your application code. Missing them doesn't
always mean you're "hacked," but it does mean you're leaving free
security on the table. This tool gives you a fast, scriptable way to
check your own (or your client's) site before an audit does.

## Features

- ✅ Checks for 6 key security headers:
  - `Strict-Transport-Security` (HSTS)
  - `Content-Security-Policy` (CSP)
  - `X-Frame-Options`
  - `X-Content-Type-Options`
  - `Referrer-Policy`
  - `Permissions-Policy`
- ⚠️ Flags information-leaking headers (`Server`, `X-Powered-By`, etc.)
- 📊 Gives a simple pass/fail score and severity rating per header
- 🧾 Human-readable report **or** `--json` output for CI pipelines
- 🧪 Unit-tested with mocked HTTP responses (no live network needed to test)

## Installation

```bash
git clone https://github.com/<your-username>/security-header-scanner.git
cd security-header-scanner
pip install -r requirements.txt
```

## Usage

```bash
python scanner.py https://example.com
```

Example output:

```
Security Header Scan: https://example.com
Score: 3/6

✅ Strict-Transport-Security      [PASS] (info)
❌ Content-Security-Policy        [FAIL] (high)
    -> Missing. Define a strict CSP, e.g. "default-src 'self'" and tighten per-resource as needed.
✅ X-Frame-Options                [PASS] (info)
❌ X-Content-Type-Options         [FAIL] (medium)
    -> Missing. Add 'X-Content-Type-Options: nosniff'.
✅ Referrer-Policy                [PASS] (info)
❌ Permissions-Policy             [FAIL] (low)
    -> Missing. Add 'Permissions-Policy' limiting camera, microphone, geolocation, etc.

⚠️  Information-leaking headers detected:
   - Server: Apache/2.4.41 (Ubuntu)
```

Or get machine-readable JSON for CI/CD:

```bash
python scanner.py https://example.com --json
```

## Running tests

```bash
python -m unittest test_scanner.py -v
```

## Roadmap / ideas for contributions

- [ ] Add CSP policy parsing (flag `unsafe-inline`, wildcard sources, etc.)
- [ ] Support scanning a list of URLs from a file
- [ ] Add a GitHub Action so this can run automatically on every deploy
- [ ] HTML report output

## Disclaimer

This tool only inspects **publicly visible response headers** of a URL
you provide — it does not perform any intrusive testing, exploitation,
or scanning beyond a normal HTTP GET request. Always make sure you have
permission to scan a target if it isn't your own site.

## License

MIT — see [LICENSE](LICENSE).
