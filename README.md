# policy-scout
Explore your cloud security policies (SCPs and Org Policies) quickly from your terminal. The goal is to shorten the debugging lifecycle and quickly understand what policies are applied to what resources within your Cloud Service Provider (CSP). The alternative is to either explore the respective cloud console or run a few commands using the cli (aws, gcloud) and then arranging the results in a useful way to understand what's going on.

## Table of Contents
- [Features](#features)
- [Usage](#usage)
- [Example](#example)
- [Tooling](#tooling)
- [License](#license)
- [Feedback](#feedback)

## Features
* AWS SCPs
  * Given an account ID, displays its location within the AWS organization (path from the root node). The account ID value can be `all` (case insensitive) which will display the entire org tree.
  * Given an account ID, displays all (inherited and directly attached) the SCPs applied to it. If the entire org tree is displayed (`account-id == all`), each account will show the SCPs applied to them.
  * Show an indicator of which account is the management account in the org.
  * Initial supported output format will be `text`, which displays a tree in your preferred terminal. Future iterations will include `json` and `dot`.

* GCP Org Policies
  * Coming soon ...

## Usage
The intended audience of this tool are security practitioners who need to help their clients understand the effect of security policies on their respective cloud accounts. With that in mind, this tool will provide not only the location of the target resource (e.g. AWS account) in the organization, but all the policies applied to it. The easiest way to make sure you have proper access to run this tool is to run it from the organization's management account. Further IAM configurations for more restrictive access will be left to the user at this moment.

```
$ policy-scout
A longer description that spans multiple lines and likely contains
examples and usage of using your application. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.

Usage:
  policy-scout [command]

Available Commands:
  aws         Entrypoint for all AWS interactions
  completion  Generate the autocompletion script for the specified shell
  help        Help about any command

Flags:
  -h, --help     help for policy-scout
  -t, --toggle   Help message for toggle

Use "policy-scout [command] --help" for more information about a command.
...
$ policy-scout aws
Error: required flag(s) "account-id", "output-format" not set
Usage:
  policy-scout aws [flags]

Flags:
      --account-id string            aws account ID that will be analyzed
  -h, --help                         help for aws
  -o, --output-format outputFormat   valid output formats are: "text", "json", "dot"
```

## Example
1. **Path from root node**
```
$ policy-scout aws --account-id 339712974046 --output-format text
|-- Root: [r-cww9]
    |-- OU: Prod [ou-cww9-36h7ub42]
        |-- OU: Finance [ou-cww9-x2atbcle]
            |-- Account: aws-child1 [339712974046] (SCPs: FullAWSAccess, DenyAccessS3)
```
1. **Entire org tree**
```
$ policy-scout aws --account-id all --output-format text
|-- Root: [r-cww9]
    |-- Account: aws-master (Management Account) [975050287149] (SCPs: FullAWSAccess)
    |-- OU: Test [ou-cww9-avlqk41w]
        |-- OU: Product B [ou-cww9-d7yzz1lw]
        |-- OU: Product A [ou-cww9-jilcr7kd]
    |-- OU: Prod [ou-cww9-36h7ub42]
        |-- OU: HR [ou-cww9-31itin1k]
        |-- OU: Finance [ou-cww9-x2atbcle]
            |-- Account: aws-child1 [339712974046] (SCPs: FullAWSAccess, DenyAccessS3)
    |-- OU: Dev [ou-cww9-iwb7qdvl]
        |-- Account: aws-child2 [851725398007] (SCPs: FullAWSAccess)
```

## Tooling
- [Cobra CLI](https://cobra.dev/)
- [GolangCI-Lint](https://golangci-lint.run/)
- [Goreleaser](https://goreleaser.com/)
- [Github Workflows](https://docs.github.com/en/actions/using-workflows)
- [Pre-Commit](https://pre-commit.com/)
- [Editorconfig](https://editorconfig.org/)

## License
Policy-scout is released under the Apache 2.0 license. See [LICENSE](./LICENSE).

## Feedback
Feel free to [open an issue](https://github.com/ariguillegp/policy-scout/issues/new) to report a bug or submit a feature request. PRs are also welcomed!
