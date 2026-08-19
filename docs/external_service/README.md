# External Service Risk Watch

External Service Risk Watch monitors external services, APIs, and SDKs used by
the system. It is intentionally separate from the existing CVE Watch.

The existing CVE Watch monitors vulnerabilities in internally used packages and
writes `docs/alerts.json`. This watcher monitors Slack, Google Calendar,
Microsoft Graph/Outlook Calendar, Microsoft Graph/Teams, and Zoom API surfaces,
and writes only under `docs/external_service/`.

## Scope

The watcher keeps API/security-relevant changes:

- `VULNERABILITY`
- `SECURITY_ADVISORY`
- `SECURITY_GUIDANCE`
- `AUTH_CHANGE`
- `BREAKING_CHANGE`
- `DEPRECATION`

Ordinary feature announcements are dropped unless the text also indicates
security, authentication, breaking-change, or deprecation impact.

## Sources

The implementation uses only free public sources and GitHub Actions hosted
runners:

- NVD API 2.0, using the existing `NVD_API_KEY` secret when present
- OSV API querybatch for `google/apiclient 2.12.6` and `microsoft/microsoft-graph 1.81.0`
- Slack Developer Docs changelog RSS/Atom
- Google Calendar API release notes XML feed
- Microsoft Graph changelog HTML pages and MSRC CVRF metadata endpoint
- Zoom Developer Forum changelog RSS
- Zoom Security Bulletins HTML page

NVD is queried by both publication time and last-modified time. This allows a
previously suppressed CVE to be re-evaluated if vendor data later expands the
affected scope from, for example, a desktop client to an API surface.

Microsoft Graph has public changelog pages and Microsoft has announced
filterable RSS support, but this implementation avoids an unverified RSS direct
URL. It monitors the confirmed official changelog pages with an HTML adapter
instead.

NVD alone is not sufficient for external APIs because important provider
notices often never become CVEs. OAuth behavior changes, security guidance,
breaking API changes, and deprecations can still affect implementation safety
and availability, so vendor feeds are monitored independently.

## Relevance

Relevance is rule-based and does not use any LLM API.

- `RELEVANT`: the event clearly matches a monitored service, endpoint, product, or SDK.
- `REVIEW`: the event is a CVE/vendor hit but the affected API surface cannot be proven by rules.
- `NOT_RELEVANT`: the affected product is clearly outside current usage, such as Zoom Workplace for Windows when only Zoom REST API is used.
- `INFORMATIONAL`: a breaking change or deprecation matches monitored API terms but is not an immediate vulnerability.

Each record includes a reason, confidence, and matched targets so later triage
can explain why an event was included or suppressed.

## JSON Files

`alerts.json` contains human-reviewable records with relevance `RELEVANT`,
`REVIEW`, or `INFORMATIONAL`.

`history.json` contains the retained history, including `NOT_RELEVANT` records,
to support deduplication, auditability, and future re-evaluation if vendor
information changes.

`state.json` records source adapter health. Adapter statuses distinguish
`SUCCESS`, `SUCCESS_NO_RESULTS`, `FETCH_ERROR`, `PARSE_ERROR`, and
`SCHEMA_CHANGED`. Fetch or parser failures fail the workflow instead of being
treated as an empty result.

## Configuration

Targets are configured in `config/external_services.yml`. The file is written
as JSON-compatible YAML so the watcher can run with the Python standard library
only. Add a service entry with `key`, `products`, `endpoints`, `keywords`,
`exclude_keywords`, optional `sdk`, and source URLs.

## Automation

`.github/workflows/external-service-watch.yml` runs daily at `21:17 UTC` and can
also be started manually with `workflow_dispatch`.

The workflow commits only these files when they change:

- `docs/external_service/alerts.json`
- `docs/external_service/history.json`
- `docs/external_service/state.json`

## Running Locally

```bash
python scripts/external_service/run.py
```

Run tests without network access:

```bash
python -m unittest discover -s tests
```

## Free Operation

This watcher has a hard non-functional requirement of additional cost `¥0`.
It uses public GitHub repositories, standard GitHub Actions hosted runners,
public provider feeds/pages, NVD, OSV, JVN-compatible parsing helpers, and
Python standard-library code only.
