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
> documents. It does not evaluate SCP Allow/Deny semantics, IAM policies, resource
> policies, permission boundaries, session policies, or effective permissions.

## Features

- Inspect one account, one organizational unit, or the complete organization.
- See each target's path from the organization root.
- Distinguish direct SCP attachments from attachments inherited through ancestors.
- Identify the management account, whose users and roles are not affected by SCPs.
- Produce a terminal-friendly tree or stable, structured JSON for automation.
- Optionally include each unique applicable SCP document once in structured JSON.

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

Retrieve the unique applicable SCP documents when they are needed:

```bash
policy-scout aws --account-id all --include-policy-documents --output-format json
```

This opt-in output uses organization schema v2. Without the flag, Policy Scout
does not call `DescribePolicy` and continues to emit schema v1 exactly as before.

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

# Bound AWS work in CI or another automated environment
policy-scout aws --account-id all --timeout 30s --max-retries 3

# Include a deduplicated catalog of parsed SCP documents (JSON only)
policy-scout aws --account-id all --include-policy-documents --output-format json

# Discover the binary and organization JSON schema versions
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

## Required AWS permissions

The selected identity needs the following permissions, depending on the scope
requested:

- `organizations:ListRoots`
- `organizations:ListChildren` for name search or the entire organization
- `organizations:DescribeAccount` for account search or account inspection
- `organizations:DescribeOrganizationalUnit` for any traversal through OUs
- `organizations:DescribeOrganization` for an account or the entire organization
- `organizations:ListParents`
- `organizations:ListPoliciesForTarget`
- `organizations:DescribePolicy` only with `--include-policy-documents`

`aws search` only needs `ListRoots`, `ListChildren`, and the applicable
`DescribeAccount`/`DescribeOrganizationalUnit` permissions. It does not list
policy attachments or retrieve policy documents.

## Documentation

- [Output formats and organization JSON contract](docs/output.md)
- [AWS authentication status contract](docs/auth-status.md)
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
