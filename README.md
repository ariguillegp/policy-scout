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
1. AWS SCPs
  1. Given an account ID, displays its location within the AWS organization (path from the root node). The account ID value can be `all` (case insensitive) which will display the entire org tree.
  1. Given an account ID, displays all (inherited and directly attached) the SCPs applied to it. If the entire org tree is displayed (`account-id == all`), each account will show the SCPs applied to them.
  1. Show an indicator of which account is the management account in the org.
  1. Initial supported output format will be `text`, which displays a tree in your preferred terminal. Future iterations will include `json` and `dot`.

1. GCP Org Policies
  1. Coming soon ...

## Usage
Usage

## Example
Example

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
Feedback
