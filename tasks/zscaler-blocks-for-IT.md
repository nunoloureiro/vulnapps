# Zscaler blocks on vulnapps.net — note for IT / #ask-infosec

## What is blocked
Zscaler's **IPS (inbound response inspection)** blocks API responses from our own security-benchmark
site, **vulnapps.net**, with HTTP 403 and the Zscaler block page:

> We found a security threat. Website blocked. Questions? Ask in #ask-infosec on Slack.
> **IPS block inbound response: phishing content** (code D29)
> You tried to visit: https://vulnapps.net/api/scans/1456

The request is allowed out; it is the **response body** that is classified and dropped.

## Where and when (UTC)
| When | URL | Result |
|---|---|---|
| 2026-11-12 22:20 | `GET https://vulnapps.net/api/scans/1456` | 403 Zscaler IPS block ("phishing content"); repeated on every retry |
| 2026-11-13 ~09:10 | `GET https://vulnapps.net/api/scans/1490` | 403 Zscaler block |
| 2026-11-13 ~09:20 | `GET https://vulnapps.net/api/scans/1490` | allowed (200) — the block is intermittent |
| 2026-11-13 ~10:00 | `GET https://vulnapps.net/api/scans/1490` | 403 Zscaler block again |

- Affects both the command-line tools (Python import script) and the **browser**: the scan page at
  `https://vulnapps.net/scans/<id>` loads the same `/api/scans/<id>` JSON, so the page fails to load.
- **Not affected:** small requests and responses on the same host (POST/PUT updates, `GET /api/scans?…`
  lists, `GET /api/apps/<id>/vulns`, labels). Only the full scan responses, which carry the scanners'
  findings text, are blocked.
- Earlier, unrelated: Python HTTPS needs the macOS trust store because Zscaler re-signs TLS
  (solved locally with `truststore`; no action needed).

## Why it happens
vulnapps.net is our internal **benchmark of security scanners** (team app). Each scan stores the
scanner's findings against a deliberately vulnerable test app (TaintedPort, taintedport.com), and the
findings contain **proof-of-concept attack text by design**, for example:
- XSS payloads that read a session token (`<img src=x onerror=…localStorage.getItem('token')…>`),
  stored XSS and open-redirect/`javascript:` URLs — the most likely trigger for a "phishing content" rule;
- PHP web-shell snippets used to prove remote code execution (`$_GET[...]` passed to a command);
- forged JWTs, SQL-injection payloads, fake/test payment-card numbers, cloud-metadata URLs.
None of it is live phishing; it is evidence text inside JSON returned to authenticated users of our own app.

## Most likely trigger (analysed 2026-11-13 with Zscaler off; not confirmed — please check the event log)
We compared the two blocked responses with six scan responses Zscaler allowed (same app, same kind of
content). Generic attack text is **not** the difference: allowed scans carry as much XSS, `<script>`,
`onerror=`, `javascript:` and token-exfiltration code as the blocked ones (scan 1582, allowed, has more).

What only the blocked responses contain is a **look-alike of the real site's domain**:
- `GET /api/scans/1490` → finding "Permissive CORS Policy Reflects Arbitrary Origins…": `Origin: https://api.taintedport.com.evil.com`
  (plus `https://data-thief.evil.com`, `https://data-stealer.evil.org`, `attacker.evil.com`)
- `GET /api/scans/1456` (same report as today's 1457) → finding "F-54: CORS reflects any Origin…": `https://taintedport.com.evil.example`

Both come from the scanners' CORS test: they check whether the API trusts a look-alike origin, a standard
penetration-test step. `<brand-domain>.<other-domain>` is the classic phishing-URL shape, which matches the block
reason "IPS block inbound response: **phishing content**". The intermittent result on 1490 also fits a URL/reputation
classifier rather than a fixed byte signature. The Zscaler event for the URLs/times above should name the rule or
threat; that would confirm or rule this out.

## What we need
An exception for **`vulnapps.net`** (the site and its `/api/*` paths, served via Cloudflare) from Zscaler
**IPS / inbound response content inspection** — or an SSL-inspection bypass for that domain — so scan
results and scan pages load for the people who run the benchmark.
If a domain-wide exception isn't acceptable, the narrowest useful scope is: `https://vulnapps.net/api/scans/*`
(GET) and `https://vulnapps.net/scans/*`.

Related host that may need the same treatment later: `taintedport.com` / `api.taintedport.com`
(the deliberately vulnerable test target; scanners and reviewers browse it).
