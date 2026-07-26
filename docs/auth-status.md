# AWS authentication status contract

`policy-scout aws auth status` resolves the AWS SDK default credential chain,
calls STS `GetCallerIdentity`, and checks Organizations access with
`DescribeOrganization`.

```bash
policy-scout aws auth status
policy-scout aws auth status --output-format text
policy-scout aws auth status --profile security-audit
```

With JSON output, a completed status is an unwrapped object on stdout. It has no
`schema_version` field. No secret credential values are displayed; `credentials`
contains metadata only.

> [!IMPORTANT]
> If identity resolution succeeds but the Organizations check fails, the command
> writes the status document to stdout, writes a diagnostic to stderr, and returns
> a nonzero exit status. Always check the exit status as well as stdout.

## Fields

| Field | Type | Presence | Meaning |
| --- | --- | --- | --- |
| `ok` | boolean | always | `true` only when identity resolves and Organizations is accessible. |
| `authenticated` | boolean | always | `true` when STS returned a complete identity. |
| `identity` | object | always | Resolved caller identity. |
| `identity.account_id` | string | always | AWS account ID returned by STS. |
| `identity.arn` | string | always | ARN returned by STS. |
| `identity.user_id` | string | always | Unique user or role ID returned by STS. |
| `credentials` | object | always | Credential metadata; never secret values. |
| `credentials.source` | string | always | AWS SDK-reported credential source. |
| `credentials.can_expire` | boolean | always | Whether the credentials can expire. |
| `credentials.expires_at` | string | optional | UTC RFC 3339 timestamp when credentials can expire. |
| `organizations` | object | always | Organizations access result. |
| `organizations.accessible` | boolean | always | Whether `DescribeOrganization` succeeded. |
| `organizations.organization_id` | string | optional | Organization ID when returned after success. |
| `organizations.management_account_id` | string | optional | Management account ID when returned after success. |
| `organizations.error` | string | optional | AWS API or Policy Scout error code after an Organizations failure. |
| `organizations.message` | string | optional | Stable, curated diagnostic accompanying `organizations.error`. |

`ok` is `true` only when both `authenticated` and
`organizations.accessible` are `true`.

## Successful example

Exit status `0`; stdout contains the document and stderr is empty.

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

## Organizations-inaccessible example

Here, identity resolution succeeded but `DescribeOrganization` returned
`AccessDeniedException`. The command exits with status `4` and writes both
streams shown below.

stdout:

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

stderr with `--error-format json`:

```json
{"code":"aws_access_denied","message":"AWS denied the Organizations request.","operation":"DescribeOrganization","retryable":false,"remediation":"Grant the selected identity the required AWS Organizations read permissions, then retry."}
```

The same command with the default human error format writes:

```text
Error [aws_access_denied]: AWS denied the Organizations request.
Operation: DescribeOrganization
Remediation: Grant the selected identity the required AWS Organizations read permissions, then retry.
```

## Exit and stdout semantics

| stdout JSON | `authenticated` | `ok` | Exit | Code | Meaning |
| --- | --- | --- | ---: | --- | --- |
| yes | `true` | `true` | `0` | — | Identity resolved and Organizations accessible. |
| yes | `true` | `false` | `1` | `unexpected` | Organizations returned an unclassified error or malformed response. |
| yes | `true` | `false` | `3` | `aws_credentials` | Organizations rejected expired or invalid credentials. |
| yes | `true` | `false` | `4` | `aws_access_denied` | Organizations denied access. |
| yes | `true` | `false` | `5` | `aws_transient` | Organizations returned a retryable failure. |
| no | — | — | `1` | `unexpected` | STS returned an incomplete identity or an unclassified/canceled failure. |
| no | — | — | `2` | `invalid_invocation` | Invalid flags or arguments. |
| no | — | — | `3` | `aws_credentials` | Configuration, credential retrieval, or STS credential failure. |
| no | — | — | `4` | `aws_access_denied` | STS authorization failure. |
| no | — | — | `5` | `aws_transient` | Transient retrieval/STS failure, timeout, or exhausted retries. |

A status document appears only after STS returns a complete identity and the
Organizations check completes without cancellation, timeout, or retry
exhaustion. A transient configuration or credential-retrieval failure is
`aws_transient`, not `aws_credentials`.

## Compatibility

The auth status document has no `schema_version`; the organization schema does
not cover it. Within a binary version, consumers must tolerate additive object
fields. Removing or renaming fields, changing their types or meanings, or
restructuring the document requires a binary version bump and documentation
update. Use `policy-scout version --output-format json` as the compatibility
anchor.
