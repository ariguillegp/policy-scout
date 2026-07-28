# Output formats and organization JSON contract

Policy Scout supports human-readable text and structured JSON. JSON is the
default and the stable interface for automation. Text is intended for people
scanning a terminal, so its wording and layout may improve between releases.

Both formats preserve the same hierarchy, policy identities, attachment
sources, and deterministic entity and attachment ordering.

## Text output

Text output identifies whether it contains the full organization or the path to
one selected account or OU. `direct` means the SCP is attached to the containing
entity; inherited lines name the source root or OU.

```text
Organization path to Account aws-child1 [339712974046]
Root [r-cww9]
`-- OU Prod [ou-cww9-36h7ub42]
    |-- SCP FullAWSAccess [p-FullAWSAccess] — inherited from Root [r-cww9]
    `-- OU Finance [ou-cww9-x2atbcle]
        |-- SCP DenyRegions [p-e5f6g7h8] — direct
        |-- SCP FullAWSAccess [p-FullAWSAccess] — inherited from Root [r-cww9]
        `-- Account aws-child1 [339712974046]
            |-- SCP DenyAccessS3 [p-a1b2c3d4] — direct
            |-- SCP DenyRegions [p-e5f6g7h8] — inherited from OU Finance [ou-cww9-x2atbcle]
            `-- SCP FullAWSAccess [p-FullAWSAccess] — inherited from Root [r-cww9]
```

Portable ASCII connectors distinguish continuing siblings (`|--`) from final
children (`` `-- ``). An applicable entity without attachments has an explicit
`SCPs: none` line. A management account has a warning instead, because SCPs do
not affect that account's users or roles.

## JSON document

Organization JSON is an unwrapped tree rooted at the AWS organization root. The
root's required `selection` object identifies the request that produced it:

- Entire organization: `{"selection":{"type":"all"}}`
- Account: `{"selection":{"type":"account","target_id":"339712974046"}}`
- OU: `{"selection":{"type":"organizational_unit","target_id":"ou-cww9-x2atbcle"}}`

`selection.type` is exactly `all`, `account`, or `organizational_unit`.
`selection.target_id` is required for account and OU selections and omitted for
`all`.

```json
{
  "schema_version": "1",
  "selection": {
    "type": "account",
    "target_id": "339712974046"
  },
  "type": "root",
  "id": "r-cww9",
  "name": "Root",
  "children": [
    {
      "type": "organizational_unit",
      "id": "ou-cww9-x2atbcle",
      "name": "Finance",
      "scps": ["DenyRegions"],
      "scp_attachments": [
        {
          "policy_id": "p-e5f6g7h8",
          "policy_name": "DenyRegions",
          "attached_to": {
            "type": "organizational_unit",
            "id": "ou-cww9-x2atbcle",
            "name": "Finance"
          },
          "inherited": false
        }
      ],
      "children": [
        {
          "type": "account",
          "id": "339712974046",
          "name": "aws-child1",
          "management_account": false,
          "scps": ["DenyRegions"],
          "scp_attachments": [
            {
              "policy_id": "p-e5f6g7h8",
              "policy_name": "DenyRegions",
              "attached_to": {
                "type": "organizational_unit",
                "id": "ou-cww9-x2atbcle",
                "name": "Finance"
              },
              "inherited": true
            }
          ]
        }
      ]
    }
  ]
}
```

The default output is schema v1. With `--include-policy-documents`, the same
hierarchy and attachment records are emitted as schema v2 and the root also has
a required `policies` catalog. Calls without the flag remain byte-compatible
with schema v1.

## Field presence

| Field | Root | Organizational unit | Member account | Management account |
| --- | --- | --- | --- | --- |
| `schema_version` | required (`"1"` by default; `"2"` with policy documents) | omitted | omitted | omitted |
| `selection` | required | omitted | omitted | omitted |
| `policies` | required array in schema v2; omitted in v1 | omitted | omitted | omitted |
| `type` | required (`root`) | required (`organizational_unit`) | required (`account`) | required (`account`) |
| `id` | required | required | required | required |
| `name` | present when AWS returns it | required | required | required |
| `management_account` | omitted | omitted | required (`false`) | required (`true`) |
| `scps` | omitted | required array | required array | omitted |
| `scp_attachments` | omitted | required array | required array | omitted |
| `children` | required array | required array | omitted | omitted |

Applicable arrays are present as `[]` when empty. `children` contains only the
selected account or OU path unless `selection.type` is `all`. Selecting an OU
does not expand its descendants, so an empty `children` array on the selected OU
does not prove that the OU has no children.

## SCP fields

`scps` is the legacy compatibility field. It contains sorted, de-duplicated
names from SCP summaries attached directly or inherited from an ancestor. It is
name-only and does not represent evaluated effective permissions.

`scp_attachments` is the authoritative attachment provenance. Each item has:

- `policy_id` and `policy_name`, identifying the policy summary.
- `attached_to`, identifying the root, OU, or account where it is attached.
- `inherited`, which is `false` only when attached directly to the reported entity.

Each OU or account has one item per unique policy-ID and attachment-target pair.
This preserves distinct attachment locations for one policy while removing
duplicate API entries. Items are ordered by policy name, policy ID, and then
attachment position from root to reported entity.

For the entire organization, children are deterministic: accounts come before
OUs under each parent, and each category is sorted by AWS entity ID.

## Schema v2 policy catalog

`--include-policy-documents` is available with JSON output and adds a top-level
`policies` array. It contains each unique policy referenced by applicable
attachments exactly once, sorted by policy ID. An inspection with no applicable
policies emits `"policies": []`.

```json
{
  "schema_version": "2",
  "selection": {"type": "account", "target_id": "339712974046"},
  "type": "root",
  "id": "r-cww9",
  "policies": [
    {
      "id": "p-e5f6g7h8",
      "name": "DenyRegions",
      "description": "Deny access outside approved regions",
      "arn": "arn:aws:organizations::123456789012:policy/o-example/service_control_policy/p-e5f6g7h8",
      "aws_managed": false,
      "content": {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}]
      }
    }
  ],
  "children": []
}
```

Each catalog item preserves the ID, name, description, ARN, and AWS-managed
status returned by `DescribePolicy`. `description` and `arn` are omitted when
AWS omits them. `content` is parsed and emitted as a JSON object, never as an
escaped JSON string. Malformed or missing policy details fail the entire
inspection; Policy Scout does not emit partial output.

The catalog reports documents and attachment provenance only. It does not
evaluate SCP semantics or effective IAM permissions.

## Empty and management-account nodes

```json
[
  {
    "type": "organizational_unit",
    "id": "ou-cww9-empty123",
    "name": "Empty OU",
    "scps": [],
    "scp_attachments": [],
    "children": []
  },
  {
    "type": "account",
    "id": "222222222222",
    "name": "Empty member",
    "management_account": false,
    "scps": [],
    "scp_attachments": []
  },
  {
    "type": "account",
    "id": "111111111111",
    "name": "Management",
    "management_account": true
  }
]
```

For the management account, the SCP fields are omitted rather than empty. Their
absence means “not applicable,” because SCPs do not restrict users or roles in
that account.

## Version compatibility

Discover the binary and organization schema versions without AWS credentials:

```bash
policy-scout version --output-format json
```

```json
{
  "version": "1.13.0",
  "organization_schema_version": "1",
  "organization_schema_versions": ["1", "2"]
}
```

Release binaries report their release version; direct builds and `go install`
binaries report `dev`. `organization_schema_version` identifies the default
schema emitted without opt-in features. `organization_schema_versions` lists
every supported organization contract. The root-level `schema_version` is
`"1"` by default and `"2"` when policy documents are included.

Within one schema version, consumers must tolerate additive object fields and
should use `type` rather than assume every node has identical fields. Removing
or renaming fields, changing their types or meanings, or restructuring the
document requires a new schema version.

Organization JSON remains two-space indented and newline-terminated. Consumers
should parse JSON rather than use whitespace as a delimiter.

Policy Scout does not currently publish a formal JSON Schema. The field-presence
table above is the producer contract for the hierarchy shared by schemas v1 and
v2; the policy-catalog section defines the v2 addition.

## AWS entity search JSON contract

`policy-scout aws search --name <name>` returns a separate, versioned search
document. Matching is exact and case-sensitive. The optional `--type account`
or `--type organizational_unit` flag limits the entity type searched. Without
it, both types are searched. Every duplicate-name match is returned; Policy
Scout never resolves a name to one ID automatically.

```json
{
  "schema_version": "1",
  "query": {
    "name": "production"
  },
  "matches": [
    {
      "type": "account",
      "id": "222222222222",
      "name": "production",
      "path": [
        {
          "type": "root",
          "id": "r-cww9",
          "name": "Root"
        },
        {
          "type": "organizational_unit",
          "id": "ou-cww9-36h7ub42",
          "name": "Production"
        },
        {
          "type": "account",
          "id": "222222222222",
          "name": "production"
        }
      ]
    }
  ]
}
```

The search schema v1 contract is:

- `schema_version` is always the string `"1"`.
- `query.name` is the exact requested name. `query.type` is present only when a
  type filter was supplied.
- `matches` is always an array, including `[]` when no entity matches.
- Each match has `type`, `id`, `name`, and `path`. `type` is `account` or
  `organizational_unit`.
- `path` is an ordered array from the organization root through every ancestor
  to the matched entity. Each path entity has `type`, `id`, and its AWS name
  when AWS supplies one; root names can be absent.
- Matches are deterministic: accounts precede organizational units, and each
  type is sorted by ID. Child API pagination and response order do not affect
  the document.

Search JSON is two-space indented and newline-terminated. Within schema v1,
consumers must tolerate additive object fields. The search schema version is
independent of the organization inspection schema version reported by
`policy-scout version`.

Text search output is available with `--output-format text`. It contains the
same matches and paths but, like other text output, is intended for people and
is not a stable automation interface.
