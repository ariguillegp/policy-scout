# SCP deny exemptions

`policy-scout aws exemptions` lists the carve-outs written into the `Deny`
statements of service control policies: the principals, Regions, tags,
accounts, actions, resources, and other request contexts that a guardrail
explicitly does not deny. Each exemption names its source policy and statement.

```bash
# What is exempt from one SCP?
policy-scout aws exemptions --policy-id p-e5f6g7h8

# Which exemptions apply to an account, from every SCP attached directly or inherited?
policy-scout aws exemptions --account-id 339712974046

# The same for an OU, as a concise human-readable summary
policy-scout aws exemptions --ou-id ou-cww9-x2atbcle --output-format text
```

Use exactly one of `--policy-id`, `--account-id`, or `--ou-id`. The value `all`
is not accepted. JSON is the default output format. Like other AWS commands,
the command accepts `--profile`, `--timeout`, and `--max-retries`. It writes
nothing to stdout unless every AWS call and the extraction succeed.

> [!IMPORTANT]
> This is static extraction from policy text. Policy Scout does not evaluate
> effective permissions. A request exempted from one statement can still be
> denied by another statement, another SCP, or an IAM, resource, session, or
> permissions-boundary policy. Conditions that cannot be interpreted cleanly
> are reported as `"interpretable": false` with a reason, not guessed at.

## What counts as an exemption

A `Deny` statement applies only when the action, the resource, and every
condition all match. Any one of the following therefore avoids that statement,
and each is reported as its own exemption:

| Source | Example | Exempt when |
| --- | --- | --- |
| `not_action` | `"NotAction": ["iam:*", "sts:*"]` | The action matches a listed value. |
| `not_resource` | `"NotResource": "arn:aws:s3:::org-audit-logs/*"` | The resource matches a listed value. |
| `condition` with a negated operator | `ArnNotLike aws:PrincipalArn arn:aws:iam::*:role/BreakGlass` | The key matches a listed value (`matches_values`). |
| `condition` with a matching operator | `StringEquals aws:ResourceTag/protected true` | The key does not match any listed value (`does_not_match_values`). |
| `condition` with `Null` | `Null aws:RequestTag/CostCenter true` | The key is present (`key_present`), or absent for `false` (`key_absent`). |

Negated operators are `StringNotEquals`, `StringNotEqualsIgnoreCase`,
`StringNotLike`, `ArnNotEquals`, `ArnNotLike`, and `NotIpAddress`. Matching
operators are `StringEquals`, `StringEqualsIgnoreCase`, `StringLike`,
`ArnEquals`, `ArnLike`, `Bool`, and `IpAddress`. Each also accepts the
`IfExists` suffix.

`exempt_if_key_absent` records what happens when the request has no value for
the key. AWS treats a missing key as a non-match: a matching operator is then
false, so the request is exempt, while a negated operator is true, so the deny
still applies. An `IfExists` operator is true for a missing key, so it never
exempts that request. This is why `Bool aws:MultiFactorAuthPresent false`
reports `"exempt_if_key_absent": true`.

Values are reported verbatim, in document order, including wildcards and
policy variables such as `${aws:PrincipalAccount}`. JSON booleans and numbers
become their literal text, for example `"false"` or `"3600"`.

Statements with `"Effect": "Allow"` are omitted because they are not
guardrails. A `Deny` statement without any carve-out is still listed, with
`"exemptions": []`, so a consumer can tell an unconditional deny from a policy
that has no deny statements (`"deny_statements": []`).

### Not interpreted

The following are reported with `"interpretable": false` and a `reason`, and
never have `exempt_when` or `exempt_if_key_absent`:

- `ForAnyValue:` and `ForAllValues:` set-operator qualifiers.
- Multivalued keys without a qualifier: `aws:TagKeys`, `aws:CalledVia`, and
  `aws:PrincipalServiceNamesList`.
- `Numeric*`, `Date*`, and `Binary*` operators, and unrecognized operators.
- `Null` with anything other than one `"true"` or `"false"` value.
- Values that are objects, `null`, or empty arrays, and malformed `Condition`,
  `NotAction`, or `NotResource` elements.
- `Principal` or `NotPrincipal` elements, which SCPs do not support.
- Statements that are not objects or whose `Effect` is not exactly `Allow` or
  `Deny`. These are listed as deny statements because they cannot be ruled out.

## Categories

Condition exemptions have a `category` derived from the condition key
(case-insensitively), so consumers can filter by the kind of context exempted:

| Category | Condition keys |
| --- | --- |
| `principal` | `aws:PrincipalArn`, `aws:userid`, `aws:username`, `aws:PrincipalType`, `aws:PrincipalIsAWSService`, `aws:PrincipalServiceName` |
| `principal_account` | `aws:PrincipalAccount` |
| `principal_organization` | `aws:PrincipalOrgID`, `aws:PrincipalOrgPaths` |
| `principal_tag` | `aws:PrincipalTag/*` |
| `region` | `aws:RequestedRegion` |
| `resource_owner` | `aws:ResourceAccount`, `aws:ResourceOrgID`, `aws:ResourceOrgPaths` |
| `resource_tag` | `aws:ResourceTag/*` and service keys such as `ec2:ResourceTag/*` |
| `request_tag` | `aws:RequestTag/*` and service keys such as `ec2:RequestTag/*` |
| `network` | `aws:SourceIp`, `aws:SourceVpc`, `aws:SourceVpce`, `aws:VpcSourceIp` |
| `service_call` | `aws:ViaAWSService`, `aws:CalledVia`, `aws:CalledViaFirst`, `aws:CalledViaLast` |
| `other` | Every other key, such as `aws:MultiFactorAuthPresent` |

## Example

This SCP, attached to the root and the `Production` OU, follows the
AWS-documented pattern for denying requests outside approved Regions. It
carves out global services and two administrative roles:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyAllOutsideApprovedRegions",
      "Effect": "Deny",
      "NotAction": ["iam:*", "organizations:*", "route53:*", "cloudfront:*", "support:*", "sts:*"],
      "Resource": "*",
      "Condition": {
        "StringNotEquals": {"aws:RequestedRegion": ["us-east-1", "us-west-2"]},
        "ArnNotLike": {
          "aws:PrincipalArn": [
            "arn:aws:iam::*:role/BreakGlass",
            "arn:aws:iam::*:role/OrganizationAccountAccessRole"
          ]
        }
      }
    }
  ]
}
```

`policy-scout aws exemptions --account-id 333333333333 --output-format text`:

```text
Target: Account workload [333333333333]
Path: Root [r-cww9] > OU Production [ou-cww9-x2atbcle] > Account workload [333333333333]
SCP DenyOutsideApprovedRegions [p-e5f6g7h8] — inherited from Root [r-cww9], inherited from OU Production [ou-cww9-x2atbcle]
  Deny statement 0 (DenyAllOutsideApprovedRegions):
    - exempt actions (NotAction): iam:*, organizations:*, route53:*, cloudfront:*, support:*, sts:*
    - principal exempt when aws:PrincipalArn matches arn:aws:iam::*:role/BreakGlass, arn:aws:iam::*:role/OrganizationAccountAccessRole [ArnNotLike]
    - region exempt when aws:RequestedRegion matches us-east-1, us-west-2 [StringNotEquals]
```

The same request with the default JSON output:

```json
{
  "schema_version": "1",
  "selection": {"type": "account", "target_id": "333333333333"},
  "target": {
    "type": "account",
    "id": "333333333333",
    "name": "workload",
    "management_account": false,
    "scp_applicable": true
  },
  "path": [
    {"type": "root", "id": "r-cww9", "name": "Root"},
    {"type": "organizational_unit", "id": "ou-cww9-x2atbcle", "name": "Production"},
    {"type": "account", "id": "333333333333", "name": "workload"}
  ],
  "policies": [
    {
      "policy_id": "p-e5f6g7h8",
      "policy_name": "DenyOutsideApprovedRegions",
      "provenance": [
        {"attached_to": {"type": "root", "id": "r-cww9", "name": "Root"}, "inherited": true},
        {"attached_to": {"type": "organizational_unit", "id": "ou-cww9-x2atbcle", "name": "Production"}, "inherited": true}
      ],
      "deny_statements": [
        {
          "index": 0,
          "sid": "DenyAllOutsideApprovedRegions",
          "exemptions": [
            {
              "source": "not_action",
              "values": ["iam:*", "organizations:*", "route53:*", "cloudfront:*", "support:*", "sts:*"],
              "exempt_when": "matches_values",
              "interpretable": true
            },
            {
              "source": "condition",
              "category": "principal",
              "operator": "ArnNotLike",
              "key": "aws:PrincipalArn",
              "values": ["arn:aws:iam::*:role/BreakGlass", "arn:aws:iam::*:role/OrganizationAccountAccessRole"],
              "exempt_when": "matches_values",
              "exempt_if_key_absent": false,
              "interpretable": true
            },
            {
              "source": "condition",
              "category": "region",
              "operator": "StringNotEquals",
              "key": "aws:RequestedRegion",
              "values": ["us-east-1", "us-west-2"],
              "exempt_when": "matches_values",
              "exempt_if_key_absent": false,
              "interpretable": true
            }
          ]
        }
      ]
    }
  ]
}
```

A condition Policy Scout does not interpret looks like this:

```json
{
  "source": "condition",
  "category": "other",
  "operator": "ForAnyValue:StringNotLike",
  "key": "aws:TagKeys",
  "values": ["team"],
  "interpretable": false,
  "reason": "set operator qualifiers ForAnyValue and ForAllValues are not interpreted"
}
```

## JSON contract

The exemptions schema v1 contract is:

- `schema_version` is always `"1"`.
- `selection` is `{"type": "policy", "policy_id": ...}`, or `{"type":
  "account" | "organizational_unit", "target_id": ...}`.
- `target` and `path` are present only for account and OU selections. They
  have the same shape as in the [policies query](output.md#policies-applying-to-one-target).
- `policies` is always an array. A policy selection has exactly one item. A
  target selection has one item per applicable SCP, in the same order as the
  policies query: policy name, then policy ID. It is `[]` when no SCP applies.
  A selected management account has `"scp_applicable": false` and
  `"policies": []`, and no policy document is retrieved.
- `provenance` is present on each policy only for target selections. It lists
  every attachment location that makes the policy apply to the target, from the
  root down to the target.
- `deny_statements` lists every `Deny` statement, in document order. `index` is
  the zero-based position in the document's `Statement` array. `sid` is present
  when the statement has one.
- Within a statement, `statement` items for `Principal` or `NotPrincipal` come
  first, then `not_action` and `not_resource` exemptions, then condition
  exemptions sorted by operator and then key.

| Exemption field | Interpretable condition | Interpretable `not_action` / `not_resource` | Not interpretable |
| --- | --- | --- | --- |
| `source` | `condition` | `not_action` or `not_resource` | any source, including `statement` |
| `category` | required | omitted | present for conditions with a key |
| `operator`, `key` | required | omitted | present when known |
| `values` | required | required | present when they are strings, booleans, or numbers |
| `exempt_when` | required | `matches_values` | omitted |
| `exempt_if_key_absent` | required | omitted | omitted |
| `interpretable` | `true` | `true` | `false` |
| `reason` | omitted | omitted | required |

Print the Draft 2020-12 schema locally with `policy-scout schema exemptions`.
Its canonical identifier is `https://policy-scout.dev/schemas/exemptions/v1`,
and `policy-scout version --output-format json` reports it as
`exemptions_schema_version`. Within schema v1, consumers must tolerate additive
object fields. In particular, a later release may interpret conditions that are
currently reported as `"interpretable": false`.

Text output contains the same exemptions but, like other text output, is meant
for people and is not a stable automation interface.

## Required permissions

- `--policy-id`: `organizations:ListRoots` and `organizations:DescribePolicy`.
  It does not list attachments.
- `--account-id` or `--ou-id`: the [`aws policies` permissions](../README.md#required-aws-permissions)
  for the target and its ancestors, plus `organizations:DescribePolicy` for
  each unique applicable SCP. `DescribePolicy` is called once per policy, even
  when that policy is attached at several levels.
