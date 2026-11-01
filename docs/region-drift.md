# Region drift

`policy-scout aws region-drift` compares the Regions each account has enabled
with the Regions its service control policies allow. It answers "which enabled
Regions does no guardrail cover?" for every account in the organization.

```bash
policy-scout aws region-drift
policy-scout aws region-drift --output-format text
policy-scout aws region-drift --fail-on-blind-spots --timeout 5m --max-retries 3
```

JSON is the default output format. Like other AWS commands, the command accepts
`--profile`, `--timeout`, and `--max-retries`. It writes nothing to stdout
unless every AWS call succeeds.

> [!IMPORTANT]
> This is a configuration report. Policy Scout does not evaluate effective
> permissions. It does not evaluate carve-outs, IAM policies, or other
> policies, and it does not consider Regions that are restricted in ways other
> than `aws:RequestedRegion` conditions in SCP `Deny` statements.

## Inputs

- **Enabled Regions** come from the AWS Account Management `ListRegions` API,
  called with each member account's ID. `ENABLED`, `ENABLED_BY_DEFAULT`,
  `ENABLING`, and `DISABLING` count as enabled, so a Region in transition
  cannot hide a blind spot. Only `DISABLED` counts as disabled.
- **Region restrictions** come from each account's applicable SCPs, attached
  directly or inherited from the root and OUs. Policy Scout reads
  `aws:RequestedRegion` conditions in their `Deny` statements with the same
  static extraction as [`aws exemptions`](exemptions.md).

A `Deny` statement is an interpretable Region restriction when it has exactly
one `aws:RequestedRegion` condition that uses a string operator, and it applies
to every action and every resource:

| `kind` | Operators (each also with `IfExists`) | Meaning |
| --- | --- | --- |
| `allow_list` | `StringNotEquals`, `StringNotEqualsIgnoreCase`, `StringNotLike` | Denies every Region except the listed ones. |
| `deny_list` | `StringEquals`, `StringEqualsIgnoreCase`, `StringLike` | Denies only the listed Regions. |

`Like` operators match `*` and `?` wildcards, so `eu-*` matches `eu-west-1`.
`Action: "*"` with a `NotAction` carve-out for global services, and
`NotResource`, still count as covering every action and resource. The
statement's other carve-outs, such as an exempt administrator role, are listed
in `carve_outs` in the [exemptions format](exemptions.md#json-contract) but are
not evaluated. When several restrictions apply, a Region is allowed only if
every allow list includes it and no deny list names it.

## Results per account

Each enabled Region is in exactly one of the first three lists:

| Field | Regions |
| --- | --- |
| `enabled_allowed_regions` | Enabled, and allowed by every allow list. Always `[]` when no allow list applies. |
| `blind_spot_regions` | Enabled, and no Region restriction denies them. With an allow list there are none. With only deny lists, every enabled Region they do not name is a blind spot. With no restriction, every enabled Region is a blind spot. |
| `enabled_denied_regions` | Enabled, but a Region restriction denies them. |
| `allowed_disabled_regions` | Informational: an allow list permits them, but the account has not enabled them. |

`no_region_restriction` is `true` when no interpretable Region restriction
applies to the account. `enabled_regions` lists each enabled Region with its
`opt_status` from `ListRegions`. `restrictions` lists each interpretable
restriction with its policy, attachment, `statement_index`, and `sid`. One SCP
appears once for each place it is attached.

### Not interpreted

Region conditions that cannot be cleanly interpreted as Region restrictions are
listed in `uninterpretable_restrictions` with the policy, statement, operator,
values, and a `reason`. They never allow or deny a Region in the report. This
covers:

- `ForAnyValue:` and `ForAllValues:` qualifiers, and non-string operators.
- Policy variables in the values, such as `${aws:PrincipalTag/home-region}`.
- More than one `aws:RequestedRegion` condition in one statement.
- A `Deny` limited to some actions, such as `ec2:*`, or to some resources.
  Such a statement restricts a service in a Region, not the Region.

An account with only uninterpretable restrictions has
`"no_region_restriction": true`, and all of its enabled Regions are blind
spots. Review these items by hand.

## Excluded accounts

`excluded_accounts` lists accounts that are not compared, with a `reason`.
`ListRegions` is not called for them:

| `reason` | Meaning |
| --- | --- |
| `management_account` | SCPs never restrict the management account, even when attached to it. |
| `inactive_account` | The account's AWS `state` is not `ACTIVE`, for example `SUSPENDED` or `PENDING_CLOSURE`. |

## Example

Workloads OU has an approved-Regions SCP that follows the AWS-documented
pattern: it denies everything outside `us-east-1` and `eu-west-1`, except
global services and an `OrgAdmin` role. `eu-analytics` also has a direct
`eu-*` allow list. `shared-services` denies only `ap-east-1`. `sandbox` has
only Region conditions that cannot be interpreted.

```text
$ policy-scout aws region-drift --output-format text
Accounts: 6 (3 restricted, 1 unrestricted, 2 with blind spots, 1 with uninterpretable restrictions, 2 excluded)

Account payments-prod [222222222222] in Root [r-root] > OU Workloads [ou-root-workload] > OU Nested [ou-root-nested01]
  SCP DenyOutsideApprovedRegions [p-regions01] statement 0 (DenyOutsideApproved), inherited from OU Workloads [ou-root-workload]: allows only us-east-1, eu-west-1 [StringNotEquals]
      carve-out: exempt actions (NotAction): iam:*, organizations:*, route53:*, cloudfront:*, sts:*, support:*
      carve-out: principal exempt when aws:PrincipalArn matches arn:aws:iam::*:role/OrgAdmin [ArnNotLike]
  Enabled and allowed: us-east-1
  Blind spots (enabled, not denied): none
  Enabled but denied: ap-east-1, us-west-2
  Allowed but disabled: eu-west-1

Account eu-analytics [333333333333] in Root [r-root] > OU Workloads [ou-root-workload]
  SCP DenyOutsideApprovedRegions [p-regions01] statement 0 (DenyOutsideApproved), inherited from OU Workloads [ou-root-workload]: allows only us-east-1, eu-west-1 [StringNotEquals]
      carve-out: exempt actions (NotAction): iam:*, organizations:*, route53:*, cloudfront:*, sts:*, support:*
      carve-out: principal exempt when aws:PrincipalArn matches arn:aws:iam::*:role/OrgAdmin [ArnNotLike]
  SCP EUOnly [p-euonly01] statement 0, direct: allows only eu-* [StringNotLike]
  Enabled and allowed: eu-west-1
  Blind spots (enabled, not denied): none
  Enabled but denied: eu-central-1, us-east-1
  Allowed but disabled: none

Account shared-services [444444444444] in Root [r-root]
  SCP DenyHongKong [p-denyhk01] statement 1 (DenyHongKong), direct: denies ap-east-1 [StringEquals]
  Enabled and allowed: none
  Blind spots (enabled, not denied): us-east-1
  Enabled but denied: ap-east-1
  Allowed but disabled: none

Account sandbox [555555555555] in Root [r-root]
  Region restrictions: none
  SCP UnclearRegions [p-unclear1] statement 0 (SetOperator), direct: not interpretable: ForAnyValue:StringNotEquals aws:RequestedRegion us-east-1: set operator qualifiers ForAnyValue and ForAllValues are not interpreted
  SCP UnclearRegions [p-unclear1] statement 1 (OnlyEC2), direct: not interpretable: StringNotEquals aws:RequestedRegion us-east-1: Deny applies only to actions ec2:*, not to every action
  SCP UnclearRegions [p-unclear1] statement 2 (Variable), direct: not interpretable: StringNotEquals aws:RequestedRegion ${aws:PrincipalTag/home-region}: policy variables in aws:RequestedRegion values are not interpreted
  Enabled and allowed: none
  Blind spots (enabled, not denied): ap-east-1, us-east-1
  Enabled but denied: none
  Allowed but disabled: none

Excluded accounts:
- Account management [111111111111] in Root [r-root] — management account; SCPs do not apply
- Account legacy [777777777777] in Root [r-root] — account state SUSPENDED
```

`payments-prod` reports `ap-east-1` as enabled but denied, because its opt-in
status is `DISABLING`. Text output is for people and is not a stable automation
interface.

## JSON contract

The document is two-space indented and newline-terminated:

- `schema_version` is always `"1"`.
- `summary` counts `accounts` (compared plus excluded), `restricted` and
  `unrestricted` accounts, accounts `with_blind_spots`, accounts
  `with_uninterpretable_restrictions`, and `excluded` accounts.
- `accounts` and `excluded_accounts` are always arrays, ordered by account ID.
  `path` is root-to-account. The account's Region lists are always present and
  sorted. A restriction's `regions` are verbatim, in document order.
- `restrictions` and `uninterpretable_restrictions` are in root-to-account
  attachment order, then statement order.

Abbreviated account entry:

```json
{
  "account": { "id": "222222222222", "name": "payments-prod", "state": "ACTIVE" },
  "path": [
    { "type": "root", "id": "r-root", "name": "Root" },
    { "type": "organizational_unit", "id": "ou-root-workload", "name": "Workloads" },
    { "type": "organizational_unit", "id": "ou-root-nested01", "name": "Nested" },
    { "type": "account", "id": "222222222222", "name": "payments-prod" }
  ],
  "no_region_restriction": false,
  "enabled_regions": [
    { "region": "ap-east-1", "opt_status": "DISABLING" },
    { "region": "us-east-1", "opt_status": "ENABLED_BY_DEFAULT" },
    { "region": "us-west-2", "opt_status": "ENABLED_BY_DEFAULT" }
  ],
  "enabled_allowed_regions": ["us-east-1"],
  "blind_spot_regions": [],
  "enabled_denied_regions": ["ap-east-1", "us-west-2"],
  "allowed_disabled_regions": ["eu-west-1"],
  "restrictions": [
    {
      "policy_id": "p-regions01",
      "policy_name": "DenyOutsideApprovedRegions",
      "attached_to": { "type": "organizational_unit", "id": "ou-root-workload", "name": "Workloads" },
      "inherited": true,
      "statement_index": 0,
      "sid": "DenyOutsideApproved",
      "kind": "allow_list",
      "operator": "StringNotEquals",
      "regions": ["us-east-1", "eu-west-1"],
      "carve_outs": [
        { "source": "not_action", "values": ["iam:*", "organizations:*", "route53:*", "cloudfront:*", "sts:*", "support:*"], "exempt_when": "matches_values", "interpretable": true },
        { "source": "condition", "category": "principal", "operator": "ArnNotLike", "key": "aws:PrincipalArn", "values": ["arn:aws:iam::*:role/OrgAdmin"], "exempt_when": "matches_values", "exempt_if_key_absent": false, "interpretable": true }
      ]
    }
  ],
  "uninterpretable_restrictions": []
}
```

An `uninterpretable_restrictions` item has the same source fields as a
restriction, plus `operator`, `key`, and `values` when known, and a `reason`.

Print the Draft 2020-12 schema locally with `policy-scout schema region-drift`.
Its canonical identifier is `https://policy-scout.dev/schemas/region-drift/v1`,
and `policy-scout version --output-format json` reports it as
`region_drift_schema_version`. Within schema v1, consumers must tolerate
additive object fields. A later release may interpret conditions that are
currently reported as uninterpretable.

## Exit status

The command exits `0` whenever the report is complete, including when it finds
blind spots. With `--fail-on-blind-spots`, it still writes the complete report
to stdout and then exits `6` when `summary.with_blind_spots` is greater than
zero. As with `aws lint --fail-on` and `aws coverage --fail-on-gaps`, exit
status `6` is not a failure and stderr is empty. See
[automation](automation.md#region-drift-gates-in-ci).

## Required permissions

- `account:ListRegions`, called with an `AccountId` for each active member
  account. AWS permits this only from the management account or a delegated
  administrator for Account Management, and only when trusted access for
  Account Management is enabled in the organization.
- The [`aws --account-id all` permissions](../README.md#required-aws-permissions),
  because the command traverses the entire organization.
- `organizations:DescribePolicy`, once per unique applicable SCP.

If `ListRegions` is denied, the command fails with `aws_access_denied`, exit
status `4`, `"operation": "ListRegions"`, and a remediation naming
`account:ListRegions`.
