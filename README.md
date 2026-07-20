# policy-scout

Explore AWS Organizations service control policy (SCP) attachments from a terminal. Policy Scout shows where an account sits in the organization and names from SCP summaries directly attached to that account or to a root/OU in its ancestor path, without requiring several AWS CLI calls or manual console navigation.

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Prerequisites](#prerequisites)
- [Usage](#usage)
- [Automation and agent usage](#automation-and-agent-usage)
- [Output](#output)
- [AWS auth status JSON compatibility](#aws-auth-status-json-compatibility)
- [Version and JSON compatibility](#version-and-json-compatibility)
- [Tooling](#tooling)
- [License](#license)
- [Feedback](#feedback)

## Features

- Display one account's path from the organization root, or the complete tree with `--account-id all`.
- Display names and attachment provenance from SCP summaries for every returned OU and member account, including inherited attachments from ancestors.
- Identify the management account, whose users and roles are not affected by SCPs.
- Produce structured JSON output (default) or a human-readable text-based tree.

Policy Scout lists SCP summary names; it does not retrieve policy documents or evaluate SCP Allow/Deny semantics, IAM policies, resource policies, permission boundaries, session policies, or effective identity permissions.

## Installation

### GitHub release binaries

Download the archive for your operating system and architecture from the [latest GitHub release](https://github.com/ariguillegp/policy-scout/releases/latest), extract it, and place the `policy-scout` executable somewhere on your `PATH`. Release assets are available for Linux, macOS, and Windows. You can verify an archive against the checksums file included with each release.

To install a particular release, select its version from the [releases page](https://github.com/ariguillegp/policy-scout/releases). These prebuilt binaries report the release version through `policy-scout version`.

### Go install

With Go 1.24 or later, install the latest release directly from its Go module:

```bash
go install github.com/ariguillegp/policy-scout@latest
```

Pin the command to a particular GitHub tag for a reproducible installation:

```bash
go install github.com/ariguillegp/policy-scout@v1.8.0
```

Ensure that Go's binary installation directory, usually `$(go env GOPATH)/bin`, is on your `PATH`. Binaries produced by `go install` currently report their version as `dev`; use a GitHub release binary when the embedded release version is important. `go get` manages dependencies in a Go module and is not the command for installing this executable.

### Build from source

Clone a particular release tag and build it with Go 1.24 or later:

```bash
git clone --branch v1.8.0 --depth 1 https://github.com/ariguillegp/policy-scout.git
cd policy-scout
go build -o policy-scout .
```

Like `go install`, a binary built directly from source reports its version as `dev`.

## Prerequisites

Policy Scout uses the [AWS SDK default configuration and credential chain](https://docs.aws.amazon.com/sdkref/latest/guide/standardized-credentials.html). Configure credentials before running it. Pass `--profile <name>` to select an AWS shared-config profile explicitly; this selection takes precedence over `AWS_PROFILE`. When `--profile` is omitted, the SDK's normal profile selection and default credential chain are unchanged.

For an AWS IAM Identity Center (SSO) profile, authenticate separately before running Policy Scout:

```bash
aws sso login --profile=my-profile
policy-scout aws --profile my-profile --account-id 339712974046
```

If the SDK reports a missing or expired SSO session, both `policy-scout aws` and `policy-scout aws auth status` include the selected profile in a copyable `aws sso login` remediation. Detection is best-effort: configuration, permissions, role assignment, network, and cache-file access failures are reported without a login suggestion. Policy Scout never runs AWS CLI login itself, opens a browser or device flow, prompts for credentials, changes environment variables, or stores credentials.

The selected AWS identity must be able to inspect the organization. Depending on the requested scope, Policy Scout calls:

- `organizations:ListRoots`
- `organizations:DescribeOrganization`
- `organizations:DescribeAccount`
- `organizations:DescribeOrganizationalUnit`
- `organizations:ListParents`
- `organizations:ListPoliciesForTarget`
- `organizations:ListChildren` when using `--account-id all`

## Usage

Check which AWS identity the default credential chain resolves and whether it
can access AWS Organizations:

```bash
policy-scout aws auth status
policy-scout aws auth status --output-format text
policy-scout aws auth status --timeout 30s --max-retries 3
```

The status command calls AWS STS `GetCallerIdentity` and Organizations
`DescribeOrganization`. It reports the credential source and expiration when
available, but never displays secret credential values. A successful identity
check with denied Organizations access is reported in the output and returns a
nonzero exit status. For ordinary Organizations API failures, the status document's
`organizations.error` is a stable AWS error code (or a Policy Scout error code
when AWS provides none), and `organizations.message` is a curated diagnostic;
raw AWS SDK error messages are not included. The classified diagnostic remains
on stderr, and the existing access-denied and transient exit codes still apply.

The AWS execution controls described below also apply to `aws auth status`.
Its timeout covers configuration and credential retrieval plus both the STS
and Organizations calls, and its retry limit applies to each API request.

Inspect one account (JSON is the default):

```bash
policy-scout aws --account-id 339712974046
```

Select a named AWS shared-config profile explicitly:

```bash
policy-scout aws --profile security-audit --account-id 339712974046
```

Inspect the entire organization and save structured output:

```bash
policy-scout aws --account-id all --output-format json > organization.json
```

Request a terminal-friendly tree:

```bash
policy-scout aws --account-id 339712974046 --output-format text
policy-scout aws --account-id all --output-format text
```

Bound AWS work for a CI job or coding agent:

```bash
policy-scout aws --account-id all --output-format json --timeout 30s --max-retries 3
```

- `--timeout <duration>` sets one overall deadline for AWS configuration and credential loading plus all STS and Organizations API work performed by the selected command. Durations use Go syntax such as `500ms`, `30s`, or `2m`. The value must be greater than zero.
- `--max-retries <count>` limits each AWS API request to that many retries after its initial attempt. `0` disables retries; accepted values are `0` through `10`. Retryability and backoff remain managed by the AWS SDK.
- When either flag is omitted, Policy Scout does not override that setting. In particular, omitting `--max-retries` preserves the AWS SDK default or settings from the AWS environment and shared configuration files.

Run `policy-scout aws --help` for complete, copyable command examples and input requirements.

Discover the installed binary version:

```bash
policy-scout version
policy-scout version --output-format json
```

## Automation and agent usage

Policy Scout is non-interactive and is designed to be safe to invoke from scripts and coding agents such as Amp, Claude Code, and Codex:

1. Run `policy-scout aws --help` to discover the supported operation and flags.
2. Ensure AWS credentials are already available through the default credential chain.
3. Use `--output-format json` explicitly in automation, even though JSON is the default.
4. Set `--timeout` and, when needed, `--max-retries` so a degraded AWS endpoint cannot leave the caller waiting indefinitely.
5. Check the exit status before parsing organization traversal output. Exit status `0` means stdout contains one JSON document; a nonzero status means the operation failed and stderr contains a diagnostic. `aws auth status` is an exception: after authenticating the identity, it also writes its status document to stdout for ordinary Organizations failures, while returning a nonzero exit and writing the classified diagnostic to stderr. Cancellation, timeout, and retry exhaustion remain stderr-only.
6. Add `--error-format json` to receive one machine-readable JSON error on stderr. This flag is independent of `--output-format` and may appear before or after the subcommand.

The CLI does not use confirmation prompts, interactive input, a pager, browser/device authentication, or colored output. Command results are written to stdout and classified diagnostics are written to stderr, so redirection and JSON processors work predictably. If an SSO login remediation is returned, an operator must run it separately in an interactive terminal; agents should report the command rather than execute it:

```bash
if policy-scout aws --account-id all --output-format json > organization.json; then
  jq '.. | objects | select(.type? == "account")' organization.json
fi
```

For example, an agent can capture successful data and structured errors separately:

```bash
policy-scout --error-format json aws --account-id all \
  > organization.json 2> policy-scout-error.json
```

JSON errors have this stable shape. `operation` and `request_id` are omitted when unavailable. Messages and remediation are curated and never include credentials or raw credential-provider errors.

```json
{
  "code": "aws_access_denied",
  "message": "AWS denied the Organizations request.",
  "operation": "ListRoots",
  "retryable": false,
  "request_id": "example-request-id",
  "remediation": "Grant the selected identity the required AWS Organizations read permissions, then retry."
}
```

Exit statuses and stable error codes are:

| Exit | Error code | Meaning |
| ---: | --- | --- |
| `0` | — | Success. |
| `1` | `unexpected` | An unexpected local or AWS response failure. |
| `2` | `invalid_invocation` | Invalid command, flag, argument, or input value. |
| `3` | `aws_credentials` | Missing, invalid, or expired AWS credentials. |
| `4` | `aws_access_denied` | AWS authorization denied the operation. |
| `5` | `aws_transient` | Retryable network, throttling, or AWS service failure. |

Human-readable stderr remains the default. Retry transient failures with backoff; correct the invocation or credentials/permissions before retrying other classified failures.

## Output

JSON output is a tree rooted at the AWS organization root. Nodes use these fields:

- `schema_version`: the organization JSON compatibility version; present on the root node.
- `type`: `root`, `organizational_unit`, or `account`.
- `id`: the AWS entity ID.
- `name`: the entity name, when applicable.
- `management_account`: `true` for the management account.
- `scps`: sorted, de-duplicated names from SCP summaries directly attached to an OU/member account or inherited from a root/OU in its ancestor path. This compatibility field is intentionally name-only and does not represent evaluated effective permissions; use `scp_attachments` when IDs or attachment locations matter.
- `scp_attachments`: direct and inherited SCP attachment provenance localized on every OU and member account. Each item contains:
  - `policy_id` and `policy_name`: the stable policy identity and its display name.
  - `attached_to`: the `type` and `id` of the `root`, `organizational_unit`, or `account` where the policy is attached, plus its `name` when that name is already returned while building the tree.
  - `inherited`: `false` only when the policy is attached directly to the reported OU or account; otherwise `true`.
- `children`: nested organization nodes.

For full-organization output (`--account-id all`), both JSON and text order children deterministically: accounts come before organizational units under each parent, and each category is sorted by AWS entity ID. This order is independent of AWS response pagination and ordering.

On each OU or account, `scp_attachments` contains one item per unique policy-ID/attachment-target pair along that entity's path. This preserves distinct attachment locations for one policy while removing duplicate API entries, and distinguishes different policy IDs that share a name. Its ordering is deterministic by policy name, policy ID, and then attachment position from root to the reported entity. The `scps` array is sorted and de-duplicated by name, so duplicate names must be disambiguated through `scp_attachments`.

Fields that do not apply or contain no values may be omitted. SCP fields are omitted for the management account because SCPs do not affect its users or roles. Policy Scout lists policy summaries attached to each hierarchy target; it does not retrieve or evaluate policy documents. The successful JSON document is not wrapped in a status envelope.

```json
{
  "schema_version": "1",
  "type": "root",
  "id": "r-cww9",
  "children": [
    {
      "type": "organizational_unit",
      "id": "ou-cww9-x2atbcle",
      "name": "Finance",
      "scps": ["DenyRegions", "FullAWSAccess"],
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
        },
        {
          "policy_id": "p-FullAWSAccess",
          "policy_name": "FullAWSAccess",
          "attached_to": {
            "type": "root",
            "id": "r-cww9",
            "name": "Root"
          },
          "inherited": true
        }
      ],
      "children": [
        {
          "type": "account",
          "id": "339712974046",
          "name": "aws-child1",
          "scps": ["DenyAccessS3", "DenyRegions", "FullAWSAccess"],
          "scp_attachments": [
            {
              "policy_id": "p-a1b2c3d4",
              "policy_name": "DenyAccessS3",
              "attached_to": {
                "type": "account",
                "id": "339712974046",
                "name": "aws-child1"
              },
              "inherited": false
            },
            {
              "policy_id": "p-e5f6g7h8",
              "policy_name": "DenyRegions",
              "attached_to": {
                "type": "organizational_unit",
                "id": "ou-cww9-x2atbcle",
                "name": "Finance"
              },
              "inherited": true
            },
            {
              "policy_id": "p-FullAWSAccess",
              "policy_name": "FullAWSAccess",
              "attached_to": {
                "type": "root",
                "id": "r-cww9",
                "name": "Root"
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

Text output renders the same hierarchy as a tree:

```text
|-- Root: [r-cww9]
    |-- OU: Prod [ou-cww9-36h7ub42] (SCP summary names from OU/ancestor attachments: FullAWSAccess)
        |-- SCP: FullAWSAccess [p-FullAWSAccess] (Attached to: root Root [r-cww9]; Inherited: true)
        |-- OU: Finance [ou-cww9-x2atbcle] (SCP summary names from OU/ancestor attachments: DenyRegions, FullAWSAccess)
            |-- SCP: DenyRegions [p-e5f6g7h8] (Attached to: organizational_unit Finance [ou-cww9-x2atbcle]; Inherited: false)
            |-- SCP: FullAWSAccess [p-FullAWSAccess] (Attached to: root Root [r-cww9]; Inherited: true)
            |-- Account: aws-child1 [339712974046] (SCP summary names from account/ancestor attachments: DenyAccessS3, DenyRegions, FullAWSAccess)
                |-- SCP: DenyAccessS3 [p-a1b2c3d4] (Attached to: account aws-child1 [339712974046]; Inherited: false)
                |-- SCP: DenyRegions [p-e5f6g7h8] (Attached to: organizational_unit Finance [ou-cww9-x2atbcle]; Inherited: true)
                |-- SCP: FullAWSAccess [p-FullAWSAccess] (Attached to: root Root [r-cww9]; Inherited: true)
```

## AWS auth status JSON compatibility

`policy-scout aws auth status` resolves the AWS SDK default credential chain, calls AWS STS `GetCallerIdentity`, and calls AWS Organizations `DescribeOrganization`. With `--output-format json` (the default), a completed status is an unwrapped JSON object on stdout: it is not wrapped in a status envelope and does not carry a `schema_version` field. Ordinary Organizations failures after authentication preserve that document and also write a diagnostic to stderr; failures before authentication, cancellation, timeout, and retry exhaustion do not write a status document.

Supported flags are `--output-format json|text`, `--profile <name>` (overrides `AWS_PROFILE`), `--timeout`, `--max-retries`, and the root-level `--error-format human|json`. No secret credential values are displayed; the `credentials` object exposes only metadata.

### Fields

| Field | Type | Presence | Meaning |
| --- | --- | --- | --- |
| `ok` | boolean | always | `true` only when the identity was resolved and AWS Organizations is accessible. |
| `authenticated` | boolean | always | `true` when STS `GetCallerIdentity` returned a complete identity. |
| `identity` | object | always | Resolved caller identity. |
| `identity.account_id` | string | always | AWS account ID from STS. |
| `identity.arn` | string | always | ARN from STS. |
| `identity.user_id` | string | always | Unique user/role ID from STS. |
| `credentials` | object | always | Credential metadata; never contains secret values. |
| `credentials.source` | string | always | AWS SDK-reported credential source label (for example, `EnvConfigCredentials` or `SharedConfigCredentials: <path>`). |
| `credentials.can_expire` | boolean | always | `true` when the resolved credentials can expire. |
| `credentials.expires_at` | string | optional | Present only when `credentials.can_expire` is `true`. UTC RFC 3339 timestamp, for example `2026-07-18T16:42:00Z`. |
| `organizations` | object | always | Organizations access result. |
| `organizations.accessible` | boolean | always | `true` when `DescribeOrganization` succeeded. |
| `organizations.organization_id` | string | optional | Present when `accessible` is `true` and AWS returned a non-empty organization ID. |
| `organizations.management_account_id` | string | optional | Present when `accessible` is `true` and AWS returned a non-empty management account ID. |
| `organizations.error` | string | optional | Present when `DescribeOrganization` fails after authentication. Contains the AWS API error code, or a Policy Scout error code when AWS provides none. |
| `organizations.message` | string | optional | Present with `organizations.error`. Contains a stable, curated diagnostic rather than the raw AWS SDK error message. |

`ok` is `true` only when both `authenticated` and `organizations.accessible` are `true`.

### Successful example

Exit status `0`; stdout contains the JSON document and stderr is empty.

```json
{
  "ok": true,
  "authenticated": true,
  "identity": {
    "account_id": "123456789012",
    "arn": "arn:aws:sts::123456789012:assumed-role/AuditRole/test",
    "user_id": "AROATEST:test"
  },
  "credentials": {
    "source": "SharedConfigCredentials: /home/test/.aws/credentials",
    "can_expire": true,
    "expires_at": "2026-07-18T16:42:00Z"
  },
  "organizations": {
    "accessible": true,
    "organization_id": "o-exampleorgid",
    "management_account_id": "123456789012"
  }
}
```

### Organizations-inaccessible example

The identity was resolved, but `DescribeOrganization` failed. stdout still contains a complete JSON document, and the command exits nonzero. stdout and stderr carry separate payloads: parse stdout for the status and stderr for the diagnostic.

stdout (exit status `1`):

```json
{
  "ok": false,
  "authenticated": true,
  "identity": {
    "account_id": "123456789012",
    "arn": "arn:aws:iam::123456789012:user/test",
    "user_id": "AIDATEST"
  },
  "credentials": {
    "source": "EnvConfigCredentials",
    "can_expire": false
  },
  "organizations": {
    "accessible": false,
    "error": "AccessDeniedException",
    "message": "AWS denied the Organizations request."
  }
}
```

stderr with `--error-format json` (exit status `4`, code `aws_access_denied`):

```json
{"code":"aws_access_denied","message":"AWS denied the Organizations request.","operation":"DescribeOrganization","retryable":false,"remediation":"Grant the selected identity the required AWS Organizations read permissions, then retry."}
```

The Organizations API error code and curated message are preserved on stdout without the raw AWS SDK error string. The original typed AWS error is classified independently on stderr. Stderr JSON is compact (single-line) because the error encoder does not indent it; only the stdout auth-status document is indented. With the default human error format, stderr is:

```text
Error [aws_access_denied]: AWS denied the Organizations request.
Operation: DescribeOrganization
Remediation: Grant the selected identity the required AWS Organizations read permissions, then retry.
```

### Exit and stdout semantics

| stdout JSON | `authenticated` | `ok` | Exit | Code | Meaning |
| --- | --- | --- | ---: | --- | --- |
| yes | `true` | `true` | `0` | — | Identity resolved and Organizations accessible. |
| yes | `true` | `false` | `1` | `unexpected` | Identity resolved; Organizations returned an unclassified error or malformed response. |
| yes | `true` | `false` | `3` | `aws_credentials` | Identity resolved; Organizations rejected expired or invalid credentials. |
| yes | `true` | `false` | `4` | `aws_access_denied` | Identity resolved; Organizations denied access. |
| yes | `true` | `false` | `5` | `aws_transient` | Identity resolved; Organizations returned a retryable service or throttling failure. |
| no | — | — | `1` | `unexpected` | STS returned an incomplete identity, or an unclassified or canceled STS failure occurred. |
| no | — | — | `2` | `invalid_invocation` | Invalid flags or arguments. |
| no | — | — | `3` | `aws_credentials` | Non-transient AWS configuration or credential retrieval failure, or a credential-classified STS error (for example, `ExpiredToken`). |
| no | — | — | `4` | `aws_access_denied` | Authorization-classified STS error (for example, STS `AccessDenied`). |
| no | — | — | `5` | `aws_transient` | Transient configuration/retrieval or STS failure, timeout, or exhausted retry limit. |

A JSON document appears on stdout only when STS `GetCallerIdentity` returned a complete identity and the Organizations check completed without cancellation, timeout, or retry exhaustion; `authenticated` is then `true`. When stdout is empty, stderr contains the diagnostic and the exit status classifies the failure. A transient inner failure during configuration or credential retrieval is classified as `aws_transient` (exit `5`), not `aws_credentials`. Automation should check the exit status before parsing stdout; when the exit status is nonzero and stdout is non-empty, treat stdout as the auth-status document and stderr as the independent diagnostic.

### Compatibility and versioning

The auth status document has no `schema_version` field, and the organization `schema_version` does not cover it. Within a binary version, consumers must tolerate additive object fields. Removing or renaming fields, changing their types or meanings, or restructuring the document is a breaking change and requires a binary version bump and a documentation update here. Discover the installed binary version with `policy-scout version --output-format json`; its `version` field is the versioning anchor for auth status compatibility.

## Version and JSON compatibility

`policy-scout version --output-format json` provides machine-readable binary and schema discovery without AWS credentials:

```json
{
  "version": "1.2.3",
  "organization_schema_version": "1"
}
```

Release binaries report their release version; binaries built directly with `go build` report `dev`. The organization output's root-level `schema_version` matches `organization_schema_version` above.

Within one schema version, consumers must tolerate additive object fields and should use the `type` field rather than assume every node has identical fields. Removing or renaming fields, changing their types or meanings, or restructuring the document is a breaking change and requires a new `schema_version`. The successful organization document remains an unwrapped root node.

## Tooling

- [Mise](https://mise.jdx.dev/) pins the development tools used locally and in CI. Run `mise install` after cloning the repository, then use the Make targets for local workflows.
- [Cobra CLI](https://cobra.dev/)
- [GolangCI-Lint](https://golangci-lint.run/)
- [Goreleaser](https://goreleaser.com/)
- [go-semantic-release](https://github.com/go-semantic-release/semantic-release)
- [GitHub Workflows](https://docs.github.com/en/actions/using-workflows)
- [Pre-Commit](https://pre-commit.com/)
- [EditorConfig](https://editorconfig.org/)

## License

Policy Scout is released under the Apache 2.0 license. See [LICENSE](./LICENSE).

## Feedback

Feel free to [open an issue](https://github.com/ariguillegp/policy-scout/issues/new) to report a bug or submit a feature request. PRs are also welcome!
