# KQL Assist

A single-file HTML query builder for **Microsoft Defender Advanced Hunting** and **Microsoft Sentinel**, including **AWS and Google Cloud logs routed to Sentinel**. Click through dropdowns, chips, and checkboxes — get a paste-ready Kusto query.

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
- **Multi-cloud (Sentinel)**: `AzureActivity`, `GCPAuditLogs`, `AWSCloudTrail`, `SecurityAlert`, and `TriCloudActivity` (all three clouds in one shape)
- **Starter hunts across all 3 clouds**: one click for permission changes, logging switched off, new VMs (crypto-mining watch), keys/secrets created, or everything that failed
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
| Multi-cloud (Sentinel) | `TriCloudActivity`, `AzureActivity`, `GCPAuditLogs`, `AWSCloudTrail`, `SecurityAlert` |

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

## Multi-cloud hunting in Sentinel (Azure + AWS + Google Cloud)

When AWS CloudTrail (S3 connector) and Google Cloud audit logs (Pub/Sub connector) are routed into a Sentinel
workspace, each cloud still names things differently. The **Multi-cloud (Sentinel)** tables cover each one, with
details that are easy to get wrong:

- These tables use `TimeGenerated`, not `Timestamp`. KQL Assist switches automatically.
- Google stores `RequestMetadata` and `Status` as JSON text, so `RequestMetadata.callerIp` comes back empty.
  KQL Assist reads them with `parse_json(tostring(...))`.
- IP ranges use `ipv4_is_in_range()`, which works in both Defender and Sentinel (`ipv4_is_in_subnet()` is
  Defender-only).
- Azure logs every action twice (`Start`, then the outcome).

**`TriCloudActivity`** gives all three clouds the same columns (Cloud, Actor, Action, Target, Result, Failed,
SourceIp), so one query hunts across all of them. It's a workspace function: create it once in
**Sentinel > Logs**. Paste the query below, then **Save > Save as function**, name it `TriCloudActivity`.
A cloud whose table doesn't exist yet is skipped (`isfuzzy=true`), so it works with one, two or three clouds.

```kql
union isfuzzy=true
  (AzureActivity
    | where ActivityStatusValue !~ "Start"   // Azure logs each action twice (Start, then the outcome)
    | project TimeGenerated, Cloud = "Azure", Actor = Caller, Action = OperationNameValue, Target = _ResourceId,
              Failed = ActivityStatusValue in~ ("Failure", "Failed"), Result = ActivityStatusValue, SourceIp = CallerIpAddress),
  (GCPAuditLogs
    | extend code = toint(parse_json(tostring(Status)).code)   // GCP stores these nested fields as JSON text
    | project TimeGenerated, Cloud = "GCP", Actor = PrincipalEmail, Action = MethodName, Target = GCPResourceName,
              Failed = isnotnull(code) and code != 0, Result = iff(isnull(code) or code == 0, "Success", StatusMessage),
              SourceIp = tostring(parse_json(tostring(RequestMetadata)).callerIp)),
  (AWSCloudTrail
    | project TimeGenerated, Cloud = "AWS", Actor = UserIdentityArn, Action = strcat(EventSource, ":", EventName),
              Target = tostring(RequestParameters), Failed = isnotempty(ErrorCode),
              Result = iff(isempty(ErrorCode), "Success", ErrorCode), SourceIp = SourceIpAddress)
```

Then pick **Starter hunt (all 3 clouds)** in KQL Assist, copy, and paste into Sentinel > Logs.
