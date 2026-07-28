# Automation, errors, and exit statuses

Policy Scout is non-interactive and safe to invoke from scripts, CI jobs, and
coding agents. It does not use confirmation prompts, interactive input, a pager,
browser authentication, or colored output.

## Recommended invocation

1. Make AWS credentials available through the default credential chain.
2. Use `--output-format json` explicitly.
3. Set `--timeout` and, when appropriate, `--max-retries`.
4. Check the exit status before parsing organization traversal output.
5. Use `--error-format json` when stderr will be parsed by software.

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

## Structured errors

`--error-format json` produces one compact JSON object on stderr. The flag is
independent of `--output-format` and may appear before or after the subcommand.

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

`operation` and `request_id` are omitted when unavailable. Messages and
remediation are curated and never include credentials or raw credential-provider
errors.

## Exit statuses

| Exit | Error code | Meaning | Next action |
| ---: | --- | --- | --- |
| `0` | — | Success. | Parse stdout. |
| `1` | `unexpected` | Unexpected local or AWS response failure. | Inspect the diagnostic. |
| `2` | `invalid_invocation` | Invalid command, flag, argument, or input. | Correct the invocation. |
| `3` | `aws_credentials` | Missing, invalid, or expired credentials. | Refresh or configure credentials. |
| `4` | `aws_access_denied` | AWS denied the operation. | Grant the required read permissions. |
| `5` | `aws_transient` | Retryable network, throttling, or AWS service failure. | Retry with backoff. |

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
