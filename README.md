# KQL Assist

A single-file HTML query builder for **Microsoft Defender Advanced Hunting** (and Sentinel Logs). Click through dropdowns, chips, and checkboxes — get a paste-ready Kusto query.

No install, no build step, no dependencies, no network calls. Open the HTML file in a browser and go.

![status](https://img.shields.io/badge/status-stable-brightgreen)
![deps](https://img.shields.io/badge/dependencies-none-blue)
![license](https://img.shields.io/badge/license-MIT-lightgrey)

---

## Why

Threat hunts stall on two things: remembering which table holds the field you need, and pulling back fifty columns you don't. KQL Assist front-loads the schema so you spend your time on the hunt hypothesis, not on `project` statements.

Every table ships with a curated set of ~10–20 relevant columns pre-checked by default, so queries come back scoped and cheap instead of dumping the full row.

## Features

- **12 Advanced Hunting tables**, grouped by domain (Endpoint / Identity / Email / Cloud / Alerts)
- **Time scoping** — 1h / 24h / 7d / 30d chips, custom `ago(N unit)`, or an exact `between(datetime .. datetime)` window for incident timelines
- **Schema-aware filters** — text fields get an operator dropdown (`contains`, `==`, `!=`, `has`, `startswith`, `endswith`, `in`), enum fields (ActionType, LogonType, Severity, DeliveryAction…) render as dropdowns of valid values
- **IP handling** — CIDR input auto-generates `ipv4_is_in_subnet()`, single addresses use `==`
- **Column projection** — defaults pre-selected per table, with select-all / clear / reset
- **Summarize mode** — flip to `summarize count() by <field>` for aggregation hunts
- **Live syntax-highlighted output** with one-click copy
- Empty filters are skipped; string values are quote-escaped

## Tables covered

| Domain | Tables |
|---|---|
| Endpoint | `DeviceLogonEvents`, `DeviceProcessEvents`, `DeviceNetworkEvents`, `DeviceFileEvents`, `DeviceRegistryEvents`, `DeviceImageLoadEvents`, `DeviceEvents` |
| Identity | `IdentityLogonEvents`, `AADSignInEventsBeta` |
| Email | `EmailEvents` |
| Cloud | `CloudAppEvents` |
| Alerts | `AlertInfo` |

## Usage

```bash
git clone https://github.com/<you>/kql-assist.git
cd kql-assist
open kql-assist.html          # or just double-click it
```

1. Pick a table — filters and columns reconfigure to that schema
2. Set your time window
3. Fill in whatever you're hunting for (hostname, account, IP, command line, hash…)
4. Trim columns
5. Copy → paste into **Defender → Hunting → Advanced hunting**, or Sentinel **Logs**

## Example output

```kql
DeviceLogonEvents
| where Timestamp > ago(24h)
| where ActionType == "LogonFailed"
| where LogonType == "RemoteInteractive"
| where ipv4_is_in_subnet(RemoteIP, "10.20.0.0/16")
| project Timestamp, DeviceName, ActionType, AccountDomain, AccountName, LogonType, RemoteIP, RemoteDeviceName, FailureReason
| sort by Timestamp desc
| take 100
```

## Detection notes

The generated queries are hunt scaffolding, not finished detections. A few things worth doing before promoting anything to a custom detection rule:

- **Baseline first.** Run the query in summarize mode against a wide window to see what normal looks like before you alert on it.
- **Watch `contains`.** It's forgiving for exploration but expensive and noisy at scale — tighten to `has`, `==`, or `startswith` once you know the exact string.
- **Custom detection rules require `Timestamp`, a device/account identifier, and `ReportId`** in the projection. Several tables include `ReportId` as an unchecked column for exactly this reason — tick it before you convert a hunt into a rule.
- **`take` is not deterministic.** Fine for eyeballing results, wrong for anything you need to be complete. Drop it or swap to `top ... by` when the result set matters.

## Notes and caveats

- Timestamps are **UTC**, matching the portal.
- `AADSignInEventsBeta` is the beta table name; some tenants expose the GA `AADSignInEvents` instead. If your query errors, rename the table in the output.
- Table schemas change. If Microsoft adds or renames a field, edit the `SOURCES` object at the top of the `<script>` block — each entry is a plain object of `filters` and `columns`, so adding a table is a copy-paste job.
- Queries are constructed client-side only. Nothing is sent anywhere.

## Roadmap

- SPL mode for Splunk (separate schema model, likely a top-level toggle)
- `join` support for `AlertEvidence` / `EmailAttachmentInfo` pivots
- Saveable query presets

## License

MIT
