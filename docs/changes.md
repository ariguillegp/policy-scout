# Organization control changes

`policy-scout aws changes` answers "who changed these controls, and when?" from
CloudTrail. `aws administrators` reports who *can* change organization
controls; this command reports who *did*. It lists recent AWS Organizations
events that change guardrails or who administers them, with the caller, time,
source IP, affected policy or target, and request ID of each.

```bash
# Every control change in the last 90 days, newest first
policy-scout aws changes

# The last week, as a human-readable summary
policy-scout aws changes --since 168h --output-format text

# Who created, updated, attached, detached, or deleted one SCP?
policy-scout aws changes --policy-id p-e5f6g7h8

# What changed for one OU within a fixed window?
policy-scout aws changes --target-id ou-cww9-x2atbcle \
  --start-time 2026-10-01T00:00:00Z --end-time 2026-10-15T00:00:00Z
```

JSON is the default output format. Like other AWS commands, it accepts
`--profile`, `--timeout`, and `--max-retries`, and writes nothing to stdout
unless every AWS call succeeds. It only reads event history; it never changes
CloudTrail or Organizations.

## Events

| Event | Reported policy or target |
| --- | --- |
| `CreatePolicy`, `UpdatePolicy` | `policy` with `id`, `name`, and `type` from the response |
| `DeletePolicy` | `policy.id` |
| `AttachPolicy`, `DetachPolicy` | `policy.id` and `target` |
| `EnablePolicyType`, `DisablePolicyType` | `policy.type` and the root as `target` |
| `MoveAccount` | the account as `target`, plus `source_parent_id` and `destination_parent_id` |
| `RegisterDelegatedAdministrator`, `DeregisterDelegatedAdministrator` | the account as `target`, plus `service_principal` |
| `PutResourcePolicy`, `DeleteResourcePolicy` | `resource_policy_id` when AWS returns it |
| `EnableAWSServiceAccess`, `DisableAWSServiceAccess` | `service_principal` |

Failed attempts are recorded by CloudTrail too, and are reported with
`error_code` and `error_message`. A denied `DetachPolicy` is still evidence that
someone tried to weaken a guardrail. Events from other services that share a
name, such as IAM `CreatePolicy`, are excluded.

`--policy-id` keeps events whose `policy.id` matches. `--target-id` takes an
account, OU, or root ID and keeps events whose `target`, `source_parent_id`,
or `destination_parent_id` matches. An account moved into an OU therefore
appears when you filter by that OU. When both are given, an event must match
both.

## Data source and its limits

AWS Organizations is a global service and records its CloudTrail events only in
US East (N. Virginia), so the command queries `us-east-1` regardless of
`AWS_REGION`. Use `--region us-gov-west-1` for AWS GovCloud (US).

Policy Scout uses [`LookupEvents`](https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_LookupEvents.html),
the CloudTrail event history API, because it is available in every account
without any setup. It has these limits:

- **90 days.** Event history covers only the last 90 days. The window defaults
  to exactly that. An earlier `--start-time` or a longer `--since` is rejected
  as an invalid invocation (exit `2`) rather than silently returning fewer
  events.
- **One account.** Event history belongs to the account whose credentials you
  use. CloudTrail records an Organizations call in the account that made it, so
  changes made from a delegated administrator account appear in that account's
  history, not the management account's. Run the command in each account listed
  by `aws administrators` to see all of them. `account_id` in the result names
  the account that was searched.
- **Two requests per second.** LookupEvents is limited to two requests per
  second per account and Region, and each request accepts only one lookup
  attribute and returns at most 50 events. Policy Scout looks up each of the 14
  event names separately and spaces requests 500 ms apart, so a run takes at
  least 7 seconds. The SDK retries throttling errors; raise `--max-retries` if
  other tools share the limit. `--policy-id` and `--target-id` filter the
  results and do not reduce the number of requests.
- **Delivery delay.** CloudTrail usually delivers events within about
  5 minutes, so a change made moments ago may not appear yet.

For history older than 90 days, or for every account at once, query an
[organization trail](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/creating-trail-organization.html)
in S3 (for example with Amazon Athena), or a CloudTrail Lake organization
event data store. Both need setup before the events happen, and their storage
costs money. CloudTrail Lake is no longer open to new customers as of
May 31, 2026. Policy Scout does not read these sources.

## Example

`policy-scout aws changes --since 168h --output-format text`:

```text
Organization control changes in CloudTrail event history for account 111111111111 (us-east-1)
Window: 2026-10-25T20:07:01Z to 2026-11-01T20:07:01Z
2026-10-30T18:22:41Z AttachPolicy
    Caller: AssumedRole arn:aws:sts::111111111111:assumed-role/OrgAdmin/alice
    Source IP: 203.0.113.10
    Policy: [p-e5f6g7h8]
    Target: OU [ou-cww9-x2atbcle]
    Request ID: 5b9e2f1a-8c3d-4f6e-a7b2-1d0c9e8f7a61
2026-10-28T14:05:09Z UpdatePolicy
    Caller: AssumedRole arn:aws:sts::111111111111:assumed-role/OrgAdmin/alice
    Source IP: 203.0.113.10
    Policy: DenyRegions [p-e5f6g7h8] (SERVICE_CONTROL_POLICY)
    Request ID: a41f7d2c-3e5b-4a9c-8d1e-6f2b0c7e9a33
2026-10-27T09:47:12Z DetachPolicy (failed: AccessDenied)
    Caller: IAMUser arn:aws:iam::111111111111:user/bob
    Source IP: 198.51.100.24
    Policy: [p-e5f6g7h8]
    Target: OU [ou-cww9-x2atbcle]
    Request ID: c7d2e9f4-1b6a-4c3e-9f8d-2a5b7c0e1d44
2026-10-25T16:31:58Z MoveAccount
    Caller: AssumedRole arn:aws:sts::111111111111:assumed-role/OrgAdmin/alice
    Source IP: 203.0.113.10
    Target: Account [339712974046]
    Moved: ou-cww9-sandbox1 -> ou-cww9-x2atbcle
    Request ID: e8a3b1c5-7d2f-4e9a-b6c0-4f1d8e2a7b55
Event history only: LookupEvents covers the last 90 days for this account and Region; changes made from delegated administrator accounts are recorded in those accounts.
```

`AttachPolicy` and `DetachPolicy` records carry only the policy ID; use
`policy-scout aws attachments --policy-id` to look up its name. The first event
in JSON:

```json
{
  "schema_version": "1",
  "source": "cloudtrail:LookupEvents",
  "account_id": "111111111111",
  "region": "us-east-1",
  "start_time": "2026-10-25T20:07:01Z",
  "end_time": "2026-11-01T20:07:01Z",
  "event_names": ["CreatePolicy", "UpdatePolicy", "...", "DisableAWSServiceAccess"],
  "events": [
    {
      "event_id": "7f3a1c2e-0d4b-4e7a-9c11-2b6f8e4d1a01",
      "event_time": "2026-10-30T18:22:41Z",
      "event_name": "AttachPolicy",
      "request_id": "5b9e2f1a-8c3d-4f6e-a7b2-1d0c9e8f7a61",
      "source_ip": "203.0.113.10",
      "caller": {
        "type": "AssumedRole",
        "arn": "arn:aws:sts::111111111111:assumed-role/OrgAdmin/alice",
        "account_id": "111111111111",
        "principal_id": "AROA4EXAMPLE:alice",
        "session_issuer_arn": "arn:aws:iam::111111111111:role/OrgAdmin"
      },
      "policy": { "id": "p-e5f6g7h8" },
      "target": { "type": "organizational_unit", "id": "ou-cww9-x2atbcle" }
    }
  ]
}
```

## JSON contract

The changes schema v1 contract is:

- `source` is always `"cloudtrail:LookupEvents"`. `account_id` is the account
  whose event history was searched, and `region` is the Region queried.
- `start_time` and `end_time` are the window actually queried, in RFC 3339 UTC.
  `policy_id` and `target_id` are present only when that filter was used.
- `event_names` lists every event name that was looked up, in lookup order.
- `events` is always an array, sorted newest first and then by `event_id`.
  It is `[]` when nothing matched. Events repeated across pages are reported
  once.
- Each event always has `event_id`, `event_time`, `event_name`, and `caller`.
  `request_id`, `source_ip`, and every `caller` field are present when
  CloudTrail recorded them. For AWS service callers, `caller.invoked_by` names
  the service. `policy`, `resource_policy_id`, `target`, the parent IDs,
  `service_principal`, `error_code`, and `error_message` are present only when
  they apply, as listed in [Events](#events). `target.type` is `root`,
  `organizational_unit`, or `account`.
- Policy content, account email addresses, access key IDs, and user agents are
  never emitted.

Print the Draft 2020-12 schema locally with `policy-scout schema changes`. Its
canonical identifier is `https://policy-scout.dev/schemas/changes/v1`, and
`policy-scout version --output-format json` reports it as
`changes_schema_version`. Within schema v1, consumers must tolerate additive
object fields, including new event names in `event_names`.

Text output contains the same events but, like other text output, is meant for
people and is not a stable automation interface.

## Required permissions

- `cloudtrail:LookupEvents`. The command calls it in `us-east-1` (or
  `--region`).
- `sts:GetCallerIdentity`, which every identity is allowed, to report
  `account_id`.

It needs no Organizations permissions. A denied LookupEvents request exits `4`
with `"code": "aws_access_denied"` and `"operation": "LookupEvents"`.
