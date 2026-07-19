# policy-scout

Explore AWS Organizations service control policies (SCPs) from a terminal. Policy Scout shows where an account sits in the organization and which SCPs it inherits, without requiring several AWS CLI calls or manual console navigation.

## Table of Contents

- [Features](#features)
- [Prerequisites](#prerequisites)
- [Usage](#usage)
- [Automation and agent usage](#automation-and-agent-usage)
- [Output](#output)
- [Tooling](#tooling)
- [License](#license)
- [Feedback](#feedback)

## Features

- Display one account's path from the organization root, or the complete tree with `--account-id all`.
- Display directly attached and inherited SCPs for every returned member account.
- Identify the management account, where SCPs are not enforced.
- Produce structured `json` (default) or a human-readable `text` tree.

## Prerequisites

Policy Scout uses the [AWS SDK default configuration and credential chain](https://docs.aws.amazon.com/sdkref/latest/guide/standardized-credentials.html). Configure credentials before running it. Pass `--profile <name>` to select an AWS shared-config profile explicitly; this selection takes precedence over `AWS_PROFILE`. When `--profile` is omitted, the SDK's normal profile selection and default credential chain are unchanged. Policy Scout itself never prompts, but an external credential provider may require you to authenticate before a non-interactive run.

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
```

The status command calls AWS STS `GetCallerIdentity` and Organizations
`DescribeOrganization`. It reports the credential source and expiration when
available, but never displays secret credential values. A successful identity
check with denied Organizations access is reported in the output and returns a
nonzero exit status.

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

Run `policy-scout aws --help` for complete, copyable command examples and input requirements.

## Automation and agent usage

Policy Scout is non-interactive and is designed to be safe to invoke from scripts and coding agents such as Amp, Claude Code, and Codex:

1. Run `policy-scout aws --help` to discover the supported operation and flags.
2. Ensure AWS credentials are already available through the default credential chain.
3. Use `--output-format json` explicitly in automation, even though JSON is the default.
4. Check the exit status before parsing stdout. Exit status `0` means stdout contains one JSON document; a nonzero status means the operation failed and stderr contains a diagnostic.
5. Add `--error-format json` to receive one machine-readable JSON error on stderr. This flag is independent of `--output-format` and may appear before or after the subcommand.

The CLI does not use confirmation prompts, interactive input, a pager, or colored output. Successful data is written to stdout and errors are written to stderr, so redirection and JSON processors work predictably:

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

- `type`: `root`, `organizational_unit`, or `account`.
- `id`: the AWS entity ID.
- `name`: the entity name, when applicable.
- `management_account`: `true` for the management account.
- `scps`: sorted, de-duplicated effective SCP names for a member account.
- `children`: nested organization nodes.

Fields that do not apply or contain no values may be omitted. The successful JSON document is not wrapped in a status envelope.

```json
{
  "type": "root",
  "id": "r-cww9",
  "children": [
    {
      "type": "organizational_unit",
      "id": "ou-cww9-x2atbcle",
      "name": "Finance",
      "children": [
        {
          "type": "account",
          "id": "339712974046",
          "name": "aws-child1",
          "scps": ["DenyAccessS3", "FullAWSAccess"]
        }
      ]
    }
  ]
}
```

Text output renders the same hierarchy as a tree:

```text
|-- Root: [r-cww9]
    |-- OU: Prod [ou-cww9-36h7ub42]
        |-- OU: Finance [ou-cww9-x2atbcle]
            |-- Account: aws-child1 [339712974046] (SCPs: DenyAccessS3, FullAWSAccess)
```

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
