# Automation, errors, and exit statuses

Policy Scout is non-interactive and safe to invoke from scripts, CI jobs, and
coding agents. It does not use confirmation prompts, interactive input, a pager,
browser authentication, or colored output.

## Recommended invocation

1. Make AWS credentials available through the default credential chain.
2. Use `--output-format json` explicitly.
3. Set `--timeout` and, when appropriate, `--max-retries`.
4. Add `--include-policy-documents` only when full SCP content is required.
5. Check the exit status before parsing organization traversal output.
6. Use `--error-format json` when stderr will be parsed by software.

```bash
policy-scout --error-format json aws --account-id all \
  --output-format json --timeout 30s --max-retries 3 \
  > organization.json 2> policy-scout-error.json
```

To resolve a human request such as “inspect production” without first writing
and parsing a complete organization inspection, search by exact name and then
require the caller to choose an ID if multiple matches are returned:

```bash
policy-scout --error-format json aws search --name production \
  --output-format json --timeout 30s --max-retries 3 \
  > matches.json 2> policy-scout-error.json
```

Search is case-sensitive and returns all exact account and OU matches with
structured root-to-entity paths. Use `--type account` or
`--type organizational_unit` when the requested entity kind is known. Exit
status `0` with `"matches": []` means the search completed and found nothing;
it is not an error. Agents must not silently select one item when multiple
matches are returned.

For ordinary organization traversal, exit status `0` means stdout contains one
JSON document. A nonzero status means the operation failed and stderr contains a
diagnostic.

> [!IMPORTANT]
> `aws auth status` is different: after successfully resolving an identity, it
> also writes its status document to stdout for ordinary Organizations failures.
> It still returns a nonzero status and writes the classified diagnostic to
> stderr. See the [authentication status contract](auth-status.md).

If Policy Scout suggests an SSO login command, an operator must run it in an
interactive terminal. Agents should report the command rather than execute it.

## Processing successful output

This example writes organization data only on success and then selects account
nodes with `jq`:

```bash
if policy-scout aws --account-id all --output-format json > organization.json; then
  jq '.. | objects | select(.type? == "account")' organization.json
fi
```

The [organization JSON contract](output.md) documents field presence, ordering,
and schema compatibility, including the separate AWS entity search document.

`--include-policy-documents` works with JSON and HTML output. It adds one
`DescribePolicy` request per unique applicable policy ID and requires
`organizations:DescribePolicy`. JSON output uses schema v2 and adds a top-level
policy catalog; HTML embeds metadata and documents in each applicable SCP's
details. Without the flag, there are no `DescribePolicy` requests or additional
permission or AWS cost, and JSON output remains schema v1. As with discovery
failures, a policy retrieval or document-decoding failure leaves stdout empty.

For agents that need only one target or one known SCP, prefer the focused query
documents instead of parsing a complete organization tree:

```bash
policy-scout --error-format json aws policies \
  --account-id 339712974046 --output-format json --timeout 30s \
  > applicable-policies.json 2> policy-scout-error.json

policy-scout --error-format json aws attachments \
  --policy-id p-e5f6g7h8 --output-format json --timeout 30s \
  > attachment-reach.json 2> policy-scout-error.json
```

The [focused query contracts](output.md#focused-query-documents) document their
field presence, management-account behavior, and deterministic ordering. Like
ordinary organization traversal, either command writes its result only after
all required AWS calls and rendering succeed. A nonzero exit status therefore
leaves stdout empty rather than containing a partial JSON document.

To answer "who can change these controls?", request the administrators report.
It lists the management account, the resource-based delegation policy (or
`null`), delegated administrators with their delegated services, and services
with trusted access enabled:

```bash
policy-scout --error-format json aws administrators \
  --output-format json --timeout 30s --max-retries 3 \
  > administrators.json 2> policy-scout-error.json
```

Its contract is documented in [the output reference](output.md#organization-administrators-document).
It reports configuration only and does not evaluate effective permissions. A
nonzero exit status leaves stdout empty.

To see who actually changed those controls, and when, list recent
Organizations events from CloudTrail event history. Changes made from a
delegated administrator account are recorded only in that account, so run it
there too. Its window cannot start more than 90 days ago:

```bash
policy-scout --error-format json aws changes --since 24h \
  --output-format json --timeout 2m --max-retries 5 \
  > changes.json 2> policy-scout-error.json
jq -r '.events[] | "\(.event_time) \(.event_name) \(.caller.arn // .caller.invoked_by)"' changes.json
```

LookupEvents allows two requests per second per account, so the command needs
at least 7 seconds; see [organization control changes](changes.md).

To find which principals, Regions, or other contexts are exempt from SCP deny
statements, use the [exemptions document](exemptions.md). It is static
extraction from policy text, not an effective-permissions evaluation. Like the
focused queries, it writes nothing to stdout on failure. Treat items with
`"interpretable": false` as needing human review:

```bash
policy-scout --error-format json aws exemptions \
  --account-id 339712974046 --output-format json --timeout 30s \
  > exemptions.json 2> policy-scout-error.json
jq '.policies[].deny_statements[].exemptions[] | select(.interpretable | not)' exemptions.json
```

Every current JSON result and diagnostic has an embedded, credential-free
Draft 2020-12 schema. Run `policy-scout schema --help` to discover the twelve
published contracts, including separate organization v1/v2, focused-query, SCP
lint, administrators, deny-exemptions, coverage-report, and control-changes schemas. Validate
each document with the schema emitted by the same binary.

`aws policies` makes calls only for one target, its ancestors, and required
organization metadata. `aws attachments` uses `ListTargetsForPolicy`, then
traverses only directly attached root and OU scopes to calculate inherited
reach. A root attachment requires a full descendant traversal; an OU attachment
requires only that OU's subtree; account-only attachments require no descendant
traversal. Pagination, duplicate API entries, timeout, and retry behavior are
the same as for organization traversal.

## SCP lint in CI

`aws lint` reports SCP hygiene findings for the whole organization. By default
findings do not affect the exit status: `0` means the report on stdout is
complete, whether or not it contains findings. Add `--fail-on` to gate a
pipeline on severity:

```bash
policy-scout --error-format json aws lint --fail-on medium \
  --output-format json --timeout 2m --max-retries 3 \
  > scp-lint.json 2> policy-scout-error.json
status=$?
if [ "$status" -eq 6 ]; then
  jq -r '.findings[] | select(.severity != "low") | "\(.severity) \(.check): \(.message)"' scp-lint.json
fi
```

With `--fail-on low`, `medium`, or `high`, the command exits `6` when at least
one finding has that severity or higher. Exit status `6` is not a failure: the
complete report is on stdout and stderr is empty. Any other nonzero status is
an ordinary failure with an empty stdout and a diagnostic on stderr.

The lint makes one `ListPoliciesForTarget` request per root, OU, and account,
one `ListPolicies` traversal, and one `DescribePolicy` request per SCP in the
organization, so allow a longer `--timeout` than for focused queries in large
organizations. See the [lint report contract](output.md#scp-lint-report) for
the checks and their fields.

## Coverage gates in CI

`aws coverage` reports which accounts an SCP, or a Deny for one IAM action,
does not reach. By default it exits `0` whenever the report is complete, so a
report with gaps is data rather than a failure. Add `--fail-on-gaps` to use it
as a gate:

```bash
policy-scout --error-format json aws coverage \
  --action cloudtrail:StopLogging --fail-on-gaps \
  --output-format json --timeout 2m --max-retries 3 \
  > coverage.json 2> policy-scout-error.json
status=$?
if [ "$status" -eq 6 ]; then
  jq -r '.uncovered_accounts[].account.id' coverage.json
fi
```

Exit status `6` means the report on stdout is complete and
`summary.uncovered` is greater than zero. As with `aws lint --fail-on`, it is
not a failure: stderr is empty. Any other nonzero status is an ordinary
failure with an empty stdout and a diagnostic on stderr.

Accounts that are only conditionally covered, the management account, and
accounts whose state is not `ACTIVE` never trigger exit `6`. To also gate on
conditional coverage, test it explicitly:

```bash
jq -e '.summary.conditionally_covered == 0' coverage.json
```

`aws coverage` traverses the entire organization and lists the SCPs for every
OU and account. With `--action` it also calls `DescribePolicy` once per unique
applicable SCP; with `--policy-id` it calls `DescribePolicy` once for the
selected policy. Set `--timeout` with large organizations in mind.

## GitHub code scanning with SARIF

`--output-format sarif` on `aws lint` and `aws coverage` writes findings that
`github/codeql-action/upload-sarif` can upload to code scanning. Alerts point
to synthetic `aws-organizations/...` paths and keep their identity across
runs; see the [SARIF contract](output.md#sarif-output). Exit status `6` still
applies, so upload the file even when the gate step fails:

```yaml
permissions:
  contents: read
  id-token: write        # for configure-aws-credentials
  security-events: write # for upload-sarif
steps:
  - uses: actions/checkout@v7
  - uses: actions/setup-go@v7
    with:
      go-version: stable
  - uses: aws-actions/configure-aws-credentials@v6
    with:
      role-to-assume: arn:aws:iam::111111111111:role/policy-scout-read-only
      aws-region: us-east-1
  - run: go install github.com/ariguillegp/policy-scout@latest
  - run: policy-scout aws lint --fail-on high --output-format sarif > scp-lint.sarif
  - uses: github/codeql-action/upload-sarif@v4
    if: ${{ !cancelled() }} # also after exit 6
    with:
      sarif_file: scp-lint.sarif
```

For reproducible runs, pin a release that includes SARIF output instead of `@latest`.

Each log sets its own `automationDetails.id`, so lint and each coverage query
can be uploaded from the same workflow without a `category` input. Code scanning
requires GitHub Code Security on private repositories.

## Structured errors

`--error-format json` produces one compact JSON object on stderr. The flag is
independent of `--output-format` and may appear before or after the subcommand.

```json
{
  "schema_version": "1",
  "code": "aws_access_denied",
  "message": "AWS denied the Organizations request.",
  "operation": "ListRoots",
  "retryable": false,
  "request_id": "example-request-id",
  "remediation": "Grant the selected identity the required AWS Organizations read permissions, then retry."
}
```

`operation` and `request_id` are omitted when unavailable. Messages and
remediation are curated and never include credentials or raw credential-provider
errors.

`schema_version` identifies the structured-error contract and is independent
of the exit status and organization schema version. Print its authoritative
schema locally, without AWS credentials or network access:

```bash
policy-scout schema error
```

The schema uses JSON Schema Draft 2020-12 and has canonical identifier
`https://policy-scout.dev/schemas/error/v1`. Its version is also exposed as
`error_schema_version` by `policy-scout version --output-format json`. Use the
schema emitted by the same binary that produced the diagnostic. Consumers must
tolerate additive object fields within a schema version; field removal,
renaming, type or meaning changes, or document restructuring require a new
structured-error schema version. Exit status remains a separate process-level
signal and is intentionally absent from the JSON object.

## Exit statuses

| Exit | Error code | Meaning | Next action |
| ---: | --- | --- | --- |
| `0` | — | Success. | Parse stdout. |
| `1` | `unexpected` | Unexpected local or AWS response failure. | Inspect the diagnostic. |
| `2` | `invalid_invocation` | Invalid command, flag, argument, or input. | Correct the invocation. |
| `3` | `aws_credentials` | Missing, invalid, or expired credentials. | Refresh or configure credentials. |
| `4` | `aws_access_denied` | AWS denied the operation. | Grant the required read permissions. |
| `5` | `aws_transient` | Retryable network, throttling, or AWS service failure. | Retry with backoff. |
| `6` | — | `aws lint --fail-on` found at least one finding at or above the threshold, or `aws coverage --fail-on-gaps` found uncovered accounts. Not a failure; stderr is empty. | Parse stdout and fix or accept the findings or gaps. |

Human-readable stderr remains the default. Retry only transient failures without
first changing the invocation, credentials, or permissions.

## Timeouts and retries

`--timeout <duration>` sets one overall deadline for AWS configuration and
credential loading plus all STS and Organizations calls made by the command.
Durations use Go syntax such as `500ms`, `30s`, and `2m`, and must be greater
than zero.

`--max-retries <count>` limits each AWS request to that many retries after its
initial attempt. `0` disables retries; accepted values are `0` through `10`.
Retryability and backoff remain managed by the AWS SDK.

Omitting either flag does not override that setting. In particular, an omitted
retry limit preserves the AWS SDK default or the AWS environment and shared
configuration value.
