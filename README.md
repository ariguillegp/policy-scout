# Policy Scout

[![Latest release](https://img.shields.io/github/v/release/ariguillegp/policy-scout?label=release)](https://github.com/ariguillegp/policy-scout/releases/latest)
[![Build](https://github.com/ariguillegp/policy-scout/actions/workflows/.github-release.yml/badge.svg)](https://github.com/ariguillegp/policy-scout/actions/workflows/.github-release.yml)
[![License](https://img.shields.io/github/license/ariguillegp/policy-scout)](./LICENSE)

Policy Scout is a command-line tool for exploring AWS Organizations service
control policy (SCP) attachments. It shows an account or organizational unit's
path from the organization root and identifies which SCPs are attached directly
or inherited from ancestors.

```text
Organization path to Account aws-child1 [339712974046]
Root [r-cww9]
`-- OU Finance [ou-cww9-x2atbcle]
    |-- SCP DenyRegions [p-e5f6g7h8] — direct
    `-- Account aws-child1 [339712974046]
        |-- SCP DenyAccessS3 [p-a1b2c3d4] — direct
        `-- SCP DenyRegions [p-e5f6g7h8] — inherited from OU Finance [ou-cww9-x2atbcle]
```

> [!IMPORTANT]
> Policy Scout lists names from SCP summaries and can optionally retrieve SCP
> documents. Apart from `aws coverage`, which matches SCP Deny statements against
> one IAM action, it does not evaluate SCP Allow/Deny semantics. It never
> evaluates IAM policies, resource policies, permission boundaries, session
> policies, or effective permissions. `aws lint` inspects SCP statements only
> for specific elements, such as an `Allow` statement that uses `NotAction`.

## Features

- Inspect one account, one organizational unit, or the complete organization.
- See each target's path from the organization root.
- Distinguish direct SCP attachments from attachments inherited through ancestors.
- Identify the management account, whose users and roles are not affected by SCPs.
- Find coverage gaps: accounts that do not receive a given SCP, or that no SCP
  Deny covers for a given IAM action, with conditional Denies reported separately.
- Produce a terminal-friendly tree, stable JSON for automation, or a standalone
  HTML report with collapsible accounts, OUs, and SCPs.
- Optionally include each unique applicable SCP document in JSON or HTML.
- Lint SCP hygiene across the organization: unattached SCPs, targets and
  documents near AWS limits, redundant inherited attachments, `Allow` with
  `NotAction` or `NotResource`, and more, with an opt-in CI exit status.
- Answer "who can change these controls?": the management account, the
  Organizations resource-based delegation policy, delegated administrators and
  their services, and services with trusted access enabled.
- Answer "who did change these controls, and when?" from CloudTrail: SCP
  edits, attachments, account moves, delegation, and trusted access changes
  in the last 90 days, with caller, source IP, and request ID.
- List the principals, Regions, tags, actions, and other contexts exempted from
  SCP deny statements, for one SCP or for every SCP applying to an account or OU.
- Print version-matched JSON Schemas locally without AWS credentials or network access.

## Installation

### GitHub release binary

Download the archive for your operating system and architecture from the
[latest release](https://github.com/ariguillegp/policy-scout/releases/latest),
verify it with the included checksums file, and place `policy-scout` on your
`PATH`. Release assets are available for Linux, macOS, and Windows.

### Go install

With Go 1.24 or later:

```bash
go install github.com/ariguillegp/policy-scout@latest
```

Pin a release for a reproducible installation:

```bash
go install github.com/ariguillegp/policy-scout@v1.13.0
```

Ensure Go's binary installation directory, usually `$(go env GOPATH)/bin`, is
on your `PATH`. Binaries produced by `go install` report their version as `dev`;
use a release binary when the embedded release version matters.

### Build from source

```bash
git clone --branch v1.13.0 --depth 1 https://github.com/ariguillegp/policy-scout.git
cd policy-scout
go build -o policy-scout .
```

A binary built directly from source reports its version as `dev`.

## Quick start

Policy Scout uses the [AWS SDK default credential chain](https://docs.aws.amazon.com/sdkref/latest/guide/standardized-credentials.html).
Configure AWS credentials before running it.

1. Check the resolved identity and AWS Organizations access:

   ```bash
   policy-scout aws auth status --output-format text
   ```

2. Find every account or OU named `production` without parsing a full
   organization inspection:

   ```bash
   policy-scout aws search --name production
   ```

3. Inspect a returned account ID and display its path and SCP attachments:

   ```bash
   policy-scout aws --account-id 339712974046 --output-format text
   ```

4. Inspect an organizational unit instead:

   ```bash
   policy-scout aws --ou-id ou-cww9-x2atbcle --output-format text
   ```

JSON is the default output format. Use it explicitly in scripts:

```bash
policy-scout aws --account-id all --output-format json > organization.json
```

Create a browser-friendly report where each account, OU, and SCP can be
expanded to show its attributes:

```bash
policy-scout aws --account-id all --output-format html > organization.html
```

Add `--include-policy-documents` to show SCP metadata and documents inside the
expanded SCP details.

Retrieve the unique applicable SCP documents when they are needed:

```bash
policy-scout aws --account-id all --include-policy-documents --output-format json
```

This opt-in output uses organization schema v2. Without the flag, Policy Scout
does not call `DescribePolicy` and continues to emit schema v1 exactly as before.

Publish either organization schema from the same installed binary:

```bash
policy-scout schema organization > organization.schema.json
policy-scout schema organization-v2 > organization-v2.schema.json
```

For an AWS IAM Identity Center (SSO) profile, authenticate first and pass the
profile explicitly:

```bash
aws sso login --profile=my-profile
policy-scout aws --profile my-profile --account-id 339712974046 --output-format text
```

Policy Scout never starts an AWS login flow, opens a browser, prompts for
credentials, changes environment variables, or stores credentials.

## Common commands

```bash
# Find exact-name matches; duplicate names are all returned with distinct paths
policy-scout aws search --name production
policy-scout aws search --name production --type account
policy-scout aws search --name production --type organizational_unit

# Inspect an account, an OU, or the entire organization
policy-scout aws --account-id 339712974046
policy-scout aws --ou-id ou-cww9-x2atbcle
policy-scout aws --account-id all

# Return only the policies applying to one exact target
policy-scout aws policies --account-id 339712974046
policy-scout aws policies --ou-id ou-cww9-x2atbcle

# Find direct and inherited reach for one exact SCP ID
policy-scout aws attachments --policy-id p-a1b2c3d4

# Report SCP hygiene findings; exit 6 when any finding is medium or high
policy-scout aws lint --output-format text
policy-scout aws lint --fail-on medium
# Show who can change organization controls (configuration only)
policy-scout aws administrators
policy-scout aws administrators --output-format text

# Show who changed organization controls in the last 90 days (CloudTrail event history)
policy-scout aws changes --since 168h --output-format text
policy-scout aws changes --policy-id p-e5f6g7h8
policy-scout aws changes --target-id ou-cww9-x2atbcle --start-time 2026-10-01T00:00:00Z

# List carve-outs (break-glass roles, allowed Regions, NotAction, ...) in SCP denies
policy-scout aws exemptions --policy-id p-e5f6g7h8
policy-scout aws exemptions --account-id 339712974046 --output-format text

# Find accounts that are missing a guardrail SCP, directly or through inheritance
policy-scout aws coverage --policy-id p-a1b2c3d4

# Find accounts where no SCP Deny covers an action; fail CI (exit 6) on gaps
policy-scout aws coverage --action cloudtrail:StopLogging
policy-scout aws coverage --action cloudtrail:StopLogging --fail-on-gaps --output-format text

# Bound AWS work in CI or another automated environment
policy-scout aws --account-id all --timeout 30s --max-retries 3

# Include parsed SCP documents in JSON schema v2 (also available in HTML reports)
policy-scout aws --account-id all --include-policy-documents --output-format json

# Print version-matched JSON Schemas without AWS credentials
policy-scout schema organization
policy-scout schema organization-v2
policy-scout schema auth-status
policy-scout schema error
policy-scout schema search
policy-scout schema policies
policy-scout schema attachments
policy-scout schema lint
policy-scout schema administrators
policy-scout schema exemptions
policy-scout schema coverage
policy-scout schema changes

# Discover the binary and published JSON Schema versions
policy-scout version
policy-scout version --output-format json
```

`--timeout` sets one overall deadline for AWS configuration, credential loading,
and API calls. `--max-retries` limits retries after each request's initial
attempt; accepted values are `0` through `10`. When omitted, Policy Scout keeps
the AWS SDK or shared-configuration defaults.

Name search is exact and case-sensitive. It succeeds with an explicit empty
`matches` array when nothing matches, and never chooses among duplicate names.
Run `policy-scout aws search --help` for its complete contract and examples.

Published schemas use JSON Schema Draft 2020-12 and are embedded in release
binaries, so schema discovery performs no network access. Validate output with
the schema emitted by the same binary version. Formal schemas cover both
organization versions, auth-status, structured errors, entity search, both
focused queries, the SCP lint report, the administrators report, deny
exemptions, coverage reports, and control changes. Each document carries its own
`schema_version`; consumers must tolerate additive object fields within a
schema version.

## Required AWS permissions

The selected identity needs the following permissions, depending on the scope
requested:

- `organizations:ListRoots`
- `organizations:ListAccountsForParent` and
  `organizations:ListOrganizationalUnitsForParent` for the fastest name search,
  entire-organization inspection, `aws coverage`, and attached root/OU scopes
  queried by `aws attachments`
- Existing policies can instead grant `organizations:ListChildren`,
  `organizations:DescribeAccount`, and
  `organizations:DescribeOrganizationalUnit`; Policy Scout automatically falls
  back to these APIs when either optimized parent-list request is denied
- `organizations:DescribeAccount` for focused account inspection
- `organizations:DescribeOrganizationalUnit` for focused account/OU paths
- `organizations:DescribeOrganization` for an account, the entire organization,
  `aws attachments`, or `aws coverage`
- `organizations:ListParents`
- `organizations:ListPoliciesForTarget`
- `organizations:DescribePolicy` with `--include-policy-documents` or for `aws
  lint`, `aws exemptions`, and `aws coverage`
- `organizations:ListTargetsForPolicy` for `aws attachments`
- `organizations:ListPolicies` for `aws lint`
- `organizations:DescribeOrganization`, `organizations:DescribeResourcePolicy`,
  `organizations:ListDelegatedAdministrators`,
  `organizations:ListDelegatedServicesForAccount`, and
  `organizations:ListAWSServiceAccessForOrganization` for `aws administrators`

`aws search` always needs `ListRoots` plus OU traversal permission:
`ListOrganizationalUnitsForParent`, or `ListChildren` with
`DescribeOrganizationalUnit` for fallback. Searches that include accounts also
need `ListAccountsForParent`, or `DescribeAccount` for fallback. It does not
list policy attachments or retrieve policy documents.

`aws policies` inspects only the selected target and its ancestors. `aws
attachments` uses `ListTargetsForPolicy` for direct locations, then traverses
only directly attached roots and OU subtrees to determine inherited reach. It
therefore also needs either both optimized parent-list permissions or the
legacy fallback permissions for descendants encountered in those scopes. A
policy attached only to accounts does not require descendant traversal. AWS
permits `ListTargetsForPolicy` only from the management account or an
Organizations delegated administrator.

`aws lint` traverses the entire organization, so it needs `ListRoots`,
`DescribeOrganization`, the parent-list permissions (or the legacy fallback
permissions), and `ListPoliciesForTarget`, plus `ListPolicies` and
`DescribePolicy` to read every SCP document. It does not call `ListParents` or
`ListTargetsForPolicy`.
`aws administrators` does not traverse the hierarchy or list policy
attachments. It makes one `ListDelegatedServicesForAccount` request series per
delegated administrator. AWS permits all of its requests only from the
management account or a delegated administrator. It reports Organizations
configuration; it does not evaluate IAM policies, interpret the delegation
policy's statements, or determine which identities inside an account hold the
corresponding permissions.

`aws changes` needs only `cloudtrail:LookupEvents` in `us-east-1`, where
Organizations records its events, plus `sts:GetCallerIdentity`. LookupEvents
covers only the last 90 days, only the account whose credentials are used, and
allows two requests per second, so a run takes at least 7 seconds. Changes made
from a delegated administrator account are recorded in that account. See
[organization control changes](docs/changes.md) for the tradeoffs against an
organization trail or CloudTrail Lake.

`aws exemptions --policy-id` needs only `ListRoots` and `DescribePolicy`. With
`--account-id` or `--ou-id`, it needs the `aws policies` permissions plus one
`DescribePolicy` request per unique applicable SCP.

`aws coverage` always traverses the entire organization, so it needs the same
permissions as `aws --account-id all` plus `DescribePolicy`: once for
`--policy-id`, or once per unique applicable SCP for `--action`. It does not
use `ListTargetsForPolicy`. It reports the configured SCP Deny coverage only
and does not evaluate effective permissions.

## Documentation

- [Output formats and organization JSON contract](docs/output.md)
- [Coverage report contract](docs/output.md#coverage-report-document)
- [AWS authentication status contract](docs/auth-status.md)
- [SCP deny exemptions](docs/exemptions.md)
- [Organization control changes from CloudTrail](docs/changes.md)
- [Automation, errors, and exit statuses](docs/automation.md)
- [Releases and changes](https://github.com/ariguillegp/policy-scout/releases)

## Development

[Mise](https://mise.jdx.dev/) pins the development tools used locally and in CI.

```bash
git clone https://github.com/ariguillegp/policy-scout.git
cd policy-scout
mise install
make setup
make test
```

Use `make help` to list the formatting, linting, testing, and build targets.

## Support and feedback

- [Report a bug](https://github.com/ariguillegp/policy-scout/issues/new?template=bug.yml)
- [Request a feature](https://github.com/ariguillegp/policy-scout/issues/new?template=feature.yml)
- Search [existing issues](https://github.com/ariguillegp/policy-scout/issues)

Pull requests are welcome. Please describe the user-visible behavior, include
tests where appropriate, and update the CLI help or documentation when its
contract changes. Community interactions follow the [Code of Conduct](CODE_OF_CONDUCT.md).

## License

Policy Scout is released under the [Apache 2.0 license](LICENSE).
