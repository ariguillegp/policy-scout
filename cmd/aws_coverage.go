package cmd

import (
	"bytes"
	"context"
	encodingjson "encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/organizations/types"
	"github.com/spf13/cobra"
)

const coverageSchemaVersion = "1"

const (
	coverageQueryTypePolicy = "policy"
	coverageQueryTypeAction = "action"

	coverageExcludedManagementAccount = "management_account"
	coverageExcludedInactiveAccount   = "inactive_account"

	coverageMatchedByAction    = "action"
	coverageMatchedByNotAction = "not_action"

	coverageEffectAllow = "Allow"
	coverageEffectDeny  = "Deny"
)

// coverageActionPattern accepts one concrete IAM action. Wildcards are rejected
// because a partial overlap between two wildcard patterns is not a yes/no answer.
var coverageActionPattern = regexp.MustCompile(`^[A-Za-z0-9-]+:[A-Za-z0-9]+$`)

var (
	coveragePolicyID   string
	coverageAction     string
	coverageFormat     outputFormat = json
	coverageFailOnGaps bool

	awsCoverageCmd = &cobra.Command{
		Use:   "coverage (--policy-id <p-id> | --action <service:Action>)",
		Short: "Find accounts that an SCP or a Deny for one action does not cover",
		Long: `Return one compact, versioned coverage report for every account in the
organization. JSON output is used by default.

With --policy-id, an account is covered when the SCP is attached to it directly
or to one of its root/OU ancestors. With --action, an account is covered when an
applicable SCP has a Deny statement whose Action or NotAction covers the action
for all resources without conditions. IAM wildcards such as "cloudtrail:*" and
"*" are matched case-insensitively. A matching Deny that has a Condition or a
Resource/NotResource scope is reported as conditional coverage, with the policy
and statement, rather than as covered or uncovered.

The management account, which SCPs never restrict, and accounts whose AWS state
is not ACTIVE are reported separately as excluded accounts. This is a
configuration report: Policy Scout does not evaluate SCP Allow lists, IAM
policies, or effective permissions.

The command exits 0 when the report is complete, even when gaps exist. Use
--fail-on-gaps to exit 6 after writing the report when any applicable account
is uncovered. Exit status 6 is not a failure: stderr is empty.`,
		Example: `  policy-scout aws coverage --policy-id p-a1b2c3d4
  policy-scout aws coverage --action cloudtrail:StopLogging
  policy-scout aws coverage --action cloudtrail:StopLogging --output-format text
  policy-scout aws coverage --policy-id p-a1b2c3d4 --fail-on-gaps --timeout 2m --max-retries 3`,
		Args: noArgsValidator,
		RunE: runAWSCoverageCommand,
	}
)

func init() {
	awsCoverageCmd.Flags().StringVar(&coveragePolicyID, "policy-id", "", "exact AWS service control policy ID that every account should receive")
	awsCoverageCmd.Flags().StringVar(&coverageAction, "action", "", `exact IAM action, such as "cloudtrail:StopLogging", that every account should deny`)
	awsCoverageCmd.Flags().BoolVar(&coverageFailOnGaps, "fail-on-gaps", false, "exit 6 after writing the report when any applicable account is uncovered")
	awsCoverageCmd.Flags().VarP(&coverageFormat, "output-format", "o", `output format: "json" or "text"`)
	if err := awsCoverageCmd.RegisterFlagCompletionFunc("output-format", outputFormatCompletion); err != nil {
		panic(err)
	}
	addAWSExecutionFlags(awsCoverageCmd)
	awsCmd.AddCommand(awsCoverageCmd)
}

type coverageQuery struct {
	Type       string `json:"type"`
	PolicyID   string `json:"policy_id,omitempty"`
	PolicyName string `json:"policy_name,omitempty"`
	Action     string `json:"action,omitempty"`
}

type coverageAccountInfo struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	State string `json:"state,omitempty"`
}

type coverageStatementMatch struct {
	Index       int                     `json:"index"`
	Sid         string                  `json:"sid,omitempty"`
	MatchedBy   string                  `json:"matched_by"`
	Condition   encodingjson.RawMessage `json:"condition,omitempty"`
	Resource    []string                `json:"resource,omitempty"`
	NotResource []string                `json:"not_resource,omitempty"`
}

type coverageEvidence struct {
	PolicyID   string                  `json:"policy_id"`
	PolicyName string                  `json:"policy_name"`
	AttachedTo scpAttachmentTarget     `json:"attached_to"`
	Inherited  bool                    `json:"inherited"`
	Statement  *coverageStatementMatch `json:"statement,omitempty"`
}

type coverageAccountResult struct {
	Account  coverageAccountInfo   `json:"account"`
	Path     []scpAttachmentTarget `json:"path"`
	Evidence []coverageEvidence    `json:"evidence"`
}

type coverageExcludedAccount struct {
	Account coverageAccountInfo   `json:"account"`
	Path    []scpAttachmentTarget `json:"path"`
	Reason  string                `json:"reason"`
}

type coverageSummary struct {
	Accounts             int `json:"accounts"`
	Covered              int `json:"covered"`
	ConditionallyCovered int `json:"conditionally_covered"`
	Uncovered            int `json:"uncovered"`
	Excluded             int `json:"excluded"`
}

type coverageResult struct {
	SchemaVersion                string                    `json:"schema_version"`
	Query                        coverageQuery             `json:"query"`
	Summary                      coverageSummary           `json:"summary"`
	UncoveredAccounts            []coverageAccountResult   `json:"uncovered_accounts"`
	ConditionallyCoveredAccounts []coverageAccountResult   `json:"conditionally_covered_accounts"`
	CoveredAccounts              []coverageAccountResult   `json:"covered_accounts"`
	ExcludedAccounts             []coverageExcludedAccount `json:"excluded_accounts"`
}

func runAWSCoverageCommand(cmd *cobra.Command, _ []string) error {
	controls, err := awsExecutionControlsFromCommand(cmd)
	if err != nil {
		return err
	}
	query, err := selectedCoverageQuery(
		coveragePolicyID, cmd.Flags().Changed("policy-id"), coverageAction, cmd.Flags().Changed("action"),
	)
	if err != nil {
		return err
	}
	ctx, cancel := controls.context(cmd.Context())
	defer cancel()
	err = runAWSQuery(ctx, cmd.OutOrStdout(), profile, true, controls.configLoadOptions(), func(
		ctx context.Context, writer io.Writer, client organizationsClient, rootID, rootName, managementAccountID string,
	) error {
		return displayCoverageReport(
			ctx, writer, client, query, rootID, rootName, managementAccountID, coverageFormat, coverageFailOnGaps,
		)
	})
	return controls.explainError(err)
}

// coverageGapError reports that the complete coverage report was written and
// contains uncovered accounts under --fail-on-gaps. It is not a failure
// diagnostic; like aws lint findings, it maps to exit status 6 with empty stderr.
type coverageGapError struct {
	uncovered int
}

func (err *coverageGapError) Error() string {
	return fmt.Sprintf("coverage report found %d uncovered SCP-applicable account(s)", err.uncovered)
}

// displayCoverageReport writes a complete report before returning a coverage-gap
// error, so CI can fail on gaps and still read the report from stdout.
func displayCoverageReport(
	ctx context.Context,
	writer io.Writer,
	client organizationsClient,
	query coverageQuery,
	rootID, rootName, managementAccountID string,
	outputFormat outputFormat,
	failOnGaps bool,
) error {
	result, err := buildCoverageReport(ctx, client, query, rootID, rootName, managementAccountID)
	if err != nil {
		return err
	}
	if err := writeCoverageReport(writer, result, outputFormat); err != nil {
		return err
	}
	if failOnGaps && result.Summary.Uncovered > 0 {
		return &coverageGapError{uncovered: result.Summary.Uncovered}
	}
	return nil
}

func selectedCoverageQuery(policyID string, policySet bool, action string, actionSet bool) (coverageQuery, error) {
	switch {
	case policySet == actionSet:
		return coverageQuery{}, newInvalidInvocationError(errors.New("exactly one of --policy-id or --action is required"))
	case policySet:
		if !validPolicyID(policyID) {
			return coverageQuery{}, newInvalidInvocationError(fmt.Errorf("invalid --policy-id %q: must match p-<8-128 letters, digits, or underscores>", policyID))
		}
		return coverageQuery{Type: coverageQueryTypePolicy, PolicyID: policyID}, nil
	default:
		if !coverageActionPattern.MatchString(action) {
			return coverageQuery{}, newInvalidInvocationError(fmt.Errorf(
				"invalid --action %q: must be one exact IAM action such as cloudtrail:StopLogging, without wildcards", action,
			))
		}
		return coverageQuery{Type: coverageQueryTypeAction, Action: action}, nil
	}
}

func buildCoverageReport(
	ctx context.Context,
	client organizationsClient,
	query coverageQuery,
	rootID, rootName, managementAccountID string,
) (coverageResult, error) {
	if query.Type == coverageQueryTypePolicy {
		// DescribePolicy rejects unknown IDs, so a typo cannot produce an
		// all-accounts-uncovered report, and it supplies the name of an unattached SCP.
		policy, err := describePolicy(ctx, client, query.PolicyID)
		if err != nil {
			return coverageResult{}, fmt.Errorf("describe policy %s: %w", query.PolicyID, err)
		}
		query.PolicyName = policy.Name
	}

	tree, err := buildOrganizationTree(ctx, client, allSelectionType, rootID, rootName, managementAccountID)
	if err != nil {
		return coverageResult{}, err
	}

	statementsByPolicy := map[string][]coverageStatement{}
	if query.Type == coverageQueryTypeAction {
		policies, err := describeApplicablePolicies(ctx, client, tree)
		if err != nil {
			return coverageResult{}, err
		}
		for _, policy := range policies {
			statements, err := parseCoverageStatements(policy.Content)
			if err != nil {
				return coverageResult{}, fmt.Errorf("parse SCP %s document: %w", policy.ID, err)
			}
			statementsByPolicy[policy.ID] = statements
		}
	}

	result := coverageResult{
		SchemaVersion:                coverageSchemaVersion,
		Query:                        query,
		UncoveredAccounts:            []coverageAccountResult{},
		ConditionallyCoveredAccounts: []coverageAccountResult{},
		CoveredAccounts:              []coverageAccountResult{},
		ExcludedAccounts:             []coverageExcludedAccount{},
	}
	var visit func(node organizationNode, path []scpAttachmentTarget) error
	visit = func(node organizationNode, path []scpAttachmentTarget) error {
		path = append(append([]scpAttachmentTarget(nil), path...), scpAttachmentTarget{Type: node.Type, ID: node.ID, Name: node.Name})
		if node.Type != accountEntityType {
			for _, child := range node.Children {
				if err := visit(child, path); err != nil {
					return err
				}
			}
			return nil
		}
		account := coverageAccountInfo{ID: node.ID, Name: node.Name, State: node.AccountState}
		switch {
		case node.ManagementAccount:
			result.ExcludedAccounts = append(result.ExcludedAccounts, coverageExcludedAccount{
				Account: account, Path: path, Reason: coverageExcludedManagementAccount,
			})
			return nil
		case node.AccountState != "" && node.AccountState != string(types.AccountStateActive):
			result.ExcludedAccounts = append(result.ExcludedAccounts, coverageExcludedAccount{
				Account: account, Path: path, Reason: coverageExcludedInactiveAccount,
			})
			return nil
		}
		covered, conditional := coverageEvidenceForAccount(node.SCPAttachments, query, statementsByPolicy)
		entry := coverageAccountResult{Account: account, Path: path}
		switch {
		case len(covered) > 0:
			entry.Evidence = covered
			result.CoveredAccounts = append(result.CoveredAccounts, entry)
		case len(conditional) > 0:
			entry.Evidence = conditional
			result.ConditionallyCoveredAccounts = append(result.ConditionallyCoveredAccounts, entry)
		default:
			entry.Evidence = []coverageEvidence{}
			result.UncoveredAccounts = append(result.UncoveredAccounts, entry)
		}
		return nil
	}
	if err := visit(tree, nil); err != nil {
		return coverageResult{}, err
	}

	for _, accounts := range [][]coverageAccountResult{
		result.UncoveredAccounts, result.ConditionallyCoveredAccounts, result.CoveredAccounts,
	} {
		sort.Slice(accounts, func(i, j int) bool { return accounts[i].Account.ID < accounts[j].Account.ID })
	}
	sort.Slice(result.ExcludedAccounts, func(i, j int) bool {
		return result.ExcludedAccounts[i].Account.ID < result.ExcludedAccounts[j].Account.ID
	})
	result.Summary = coverageSummary{
		Covered:              len(result.CoveredAccounts),
		ConditionallyCovered: len(result.ConditionallyCoveredAccounts),
		Uncovered:            len(result.UncoveredAccounts),
		Excluded:             len(result.ExcludedAccounts),
	}
	result.Summary.Accounts = result.Summary.Covered + result.Summary.ConditionallyCovered +
		result.Summary.Uncovered + result.Summary.Excluded
	return result, nil
}

// coverageEvidenceForAccount returns the unconditional and conditional evidence
// from an account's applicable SCP attachments, in root-to-account order.
func coverageEvidenceForAccount(
	attachments []scpAttachment,
	query coverageQuery,
	statementsByPolicy map[string][]coverageStatement,
) (covered, conditional []coverageEvidence) {
	for _, attachment := range attachments {
		evidence := coverageEvidence{
			PolicyID: attachment.PolicyID, PolicyName: attachment.PolicyName,
			AttachedTo: attachment.AttachedTo, Inherited: attachment.Inherited,
		}
		if query.Type == coverageQueryTypePolicy {
			if attachment.PolicyID == query.PolicyID {
				covered = append(covered, evidence)
			}
			continue
		}
		for index, statement := range statementsByPolicy[attachment.PolicyID] {
			match, unconditional := statement.denies(query.Action)
			if match == "" {
				continue
			}
			item := evidence
			item.Statement = &coverageStatementMatch{Index: index, Sid: statement.Sid, MatchedBy: match}
			if unconditional {
				covered = append(covered, item)
				continue
			}
			if statement.hasCondition() {
				item.Statement.Condition = statement.Condition
			}
			if statement.resourceScoped() {
				item.Statement.Resource = statement.Resource
				item.Statement.NotResource = statement.NotResource
			}
			conditional = append(conditional, item)
		}
	}
	return covered, conditional
}

// coverageStatement is the subset of an SCP statement that determines whether a
// Deny covers an action. Condition is kept verbatim and never interpreted.
type coverageStatement struct {
	Sid         string                  `json:"Sid"`
	Effect      string                  `json:"Effect"`
	Action      coverageStringList      `json:"Action"`
	NotAction   coverageStringList      `json:"NotAction"`
	Resource    coverageStringList      `json:"Resource"`
	NotResource coverageStringList      `json:"NotResource"`
	Condition   encodingjson.RawMessage `json:"Condition"`
}

// coverageStringList decodes an IAM element that may be one string or a string
// array. A nil value means the element is absent.
type coverageStringList []string

func (list *coverageStringList) UnmarshalJSON(data []byte) error {
	var single string
	if err := encodingjson.Unmarshal(data, &single); err == nil {
		*list = coverageStringList{single}
		return nil
	}
	var multiple []string
	if err := encodingjson.Unmarshal(data, &multiple); err != nil || multiple == nil {
		return errors.New("expected a string or an array of strings")
	}
	*list = multiple
	return nil
}

func parseCoverageStatements(content encodingjson.RawMessage) ([]coverageStatement, error) {
	var document struct {
		Statement encodingjson.RawMessage `json:"Statement"`
	}
	if err := encodingjson.Unmarshal(content, &document); err != nil {
		return nil, err
	}
	raw := bytes.TrimSpace(document.Statement)
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
		return nil, errors.New("policy has no Statement")
	}
	if raw[0] == '{' {
		raw = append(append([]byte{'['}, raw...), ']')
	}
	var statements []coverageStatement
	if err := encodingjson.Unmarshal(raw, &statements); err != nil {
		return nil, fmt.Errorf("decode Statement: %w", err)
	}
	for index, statement := range statements {
		if statement.Effect != coverageEffectAllow && statement.Effect != coverageEffectDeny {
			return nil, fmt.Errorf("statement %d has Effect %q, expected Allow or Deny", index, statement.Effect)
		}
		if (statement.Action == nil) == (statement.NotAction == nil) {
			return nil, fmt.Errorf("statement %d must have exactly one of Action or NotAction", index)
		}
	}
	return statements, nil
}

// denies reports how a Deny statement matches action, if at all, and whether it
// applies unconditionally to every resource.
func (statement coverageStatement) denies(action string) (matchedBy string, unconditional bool) {
	if statement.Effect != coverageEffectDeny {
		return "", false
	}
	switch {
	case statement.Action != nil && statement.Action.matches(action):
		matchedBy = coverageMatchedByAction
	case statement.NotAction != nil && !statement.NotAction.matches(action):
		matchedBy = coverageMatchedByNotAction
	default:
		return "", false
	}
	return matchedBy, !statement.hasCondition() && !statement.resourceScoped()
}

func (statement coverageStatement) hasCondition() bool {
	condition := bytes.TrimSpace(statement.Condition)
	if len(condition) == 0 || bytes.Equal(condition, []byte("null")) {
		return false
	}
	var conditions map[string]encodingjson.RawMessage
	return encodingjson.Unmarshal(condition, &conditions) != nil || len(conditions) > 0
}

func (statement coverageStatement) resourceScoped() bool {
	if statement.NotResource != nil {
		return true
	}
	return statement.Resource != nil && !slices.Contains(statement.Resource, "*")
}

func (list coverageStringList) matches(action string) bool {
	for _, pattern := range list {
		if iamWildcardMatch(strings.ToLower(pattern), strings.ToLower(action)) {
			return true
		}
	}
	return false
}

// iamWildcardMatch matches IAM action patterns, where "*" matches any run of
// characters and "?" matches exactly one character.
func iamWildcardMatch(pattern, value string) bool {
	p, v := 0, 0
	star, starValue := -1, 0
	for v < len(value) {
		switch {
		case p < len(pattern) && (pattern[p] == '?' || pattern[p] == value[v]):
			p++
			v++
		case p < len(pattern) && pattern[p] == '*':
			star, starValue = p, v
			p++
		case star >= 0:
			p = star + 1
			starValue++
			v = starValue
		default:
			return false
		}
	}
	for p < len(pattern) && pattern[p] == '*' {
		p++
	}
	return p == len(pattern)
}

func writeCoverageReport(writer io.Writer, result coverageResult, outputFormat outputFormat) error {
	if outputFormat != text {
		return writeJSONDocument(writer, result, "coverage report")
	}
	var output strings.Builder
	if result.Query.Type == coverageQueryTypePolicy {
		fmt.Fprintf(&output, "Coverage of SCP %s [%s]\n", displayText(result.Query.PolicyName), displayText(result.Query.PolicyID))
	} else {
		fmt.Fprintf(&output, "Coverage of Deny for action %s\n", displayText(result.Query.Action))
	}
	summary := result.Summary
	fmt.Fprintf(&output, "Accounts: %d (%d covered, %d conditionally covered, %d uncovered, %d excluded)\n",
		summary.Accounts, summary.Covered, summary.ConditionallyCovered, summary.Uncovered, summary.Excluded)

	writeAccounts := func(heading string, accounts []coverageAccountResult) {
		if len(accounts) == 0 {
			fmt.Fprintf(&output, "%s: none\n", heading)
			return
		}
		fmt.Fprintf(&output, "%s:\n", heading)
		for _, account := range accounts {
			fmt.Fprintf(&output, "- %s\n", coverageAccountText(account.Account, account.Path))
			for _, evidence := range account.Evidence {
				fmt.Fprintf(&output, "    %s\n", coverageEvidenceText(evidence))
			}
		}
	}
	writeAccounts("Uncovered accounts", result.UncoveredAccounts)
	writeAccounts("Conditionally covered accounts", result.ConditionallyCoveredAccounts)
	writeAccounts("Covered accounts", result.CoveredAccounts)
	if len(result.ExcludedAccounts) == 0 {
		output.WriteString("Excluded accounts: none\n")
	} else {
		output.WriteString("Excluded accounts:\n")
		for _, excluded := range result.ExcludedAccounts {
			reason := "management account; SCPs do not apply"
			if excluded.Reason == coverageExcludedInactiveAccount {
				reason = "account state " + displayText(excluded.Account.State)
			}
			fmt.Fprintf(&output, "- %s — %s\n", coverageAccountText(excluded.Account, excluded.Path), reason)
		}
	}
	return writeDocument(writer, []byte(output.String()), "coverage report")
}

func coverageAccountText(account coverageAccountInfo, path []scpAttachmentTarget) string {
	label := displayText(attachmentTargetText(scpAttachmentTarget{Type: accountEntityType, ID: account.ID, Name: account.Name}))
	if len(path) > 1 {
		parents := make([]string, len(path)-1)
		for index, target := range path[:len(path)-1] {
			parents[index] = displayText(attachmentTargetText(target))
		}
		label += " in " + strings.Join(parents, " > ")
	}
	return label
}

func coverageEvidenceText(evidence coverageEvidence) string {
	label := fmt.Sprintf("SCP %s [%s]", displayText(evidence.PolicyName), displayText(evidence.PolicyID))
	if statement := evidence.Statement; statement != nil {
		label += fmt.Sprintf(" statement %d", statement.Index)
		if statement.Sid != "" {
			label += fmt.Sprintf(" (%s)", displayText(statement.Sid))
		}
		if statement.MatchedBy == coverageMatchedByNotAction {
			label += " via NotAction"
		}
	}
	if evidence.Inherited {
		label += " — inherited from " + displayText(attachmentTargetText(evidence.AttachedTo))
	} else {
		label += " — direct"
	}
	if statement := evidence.Statement; statement != nil {
		if len(statement.Condition) > 0 {
			var compact bytes.Buffer
			if encodingjson.Compact(&compact, statement.Condition) == nil {
				label += "; Condition " + displayText(compact.String())
			}
		}
		if len(statement.Resource) > 0 {
			label += "; Resource " + displayText(strings.Join(statement.Resource, ", "))
		}
		if len(statement.NotResource) > 0 {
			label += "; NotResource " + displayText(strings.Join(statement.NotResource, ", "))
		}
	}
	return label
}
