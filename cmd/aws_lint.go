package cmd

import (
	"bytes"
	"context"
	encodingjson "encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	"github.com/aws/aws-sdk-go-v2/service/organizations/types"
	"github.com/spf13/cobra"
)

const (
	lintSchemaVersion = "1"

	// Current AWS Organizations hard quotas for SCPs. The flags exist so the
	// checks can follow a future quota change without a new release.
	defaultSCPAttachmentLimit = 10
	defaultSCPSizeLimit       = 10240

	fullAWSAccessPolicyID = "p-FullAWSAccess"
)

const (
	lintCheckUnattachedPolicy            = "unattached_policy"
	lintCheckAttachmentLimit             = "attachment_limit"
	lintCheckPolicySizeLimit             = "policy_size_limit"
	lintCheckRedundantAttachment         = "redundant_attachment"
	lintCheckAllowNotAction              = "allow_not_action"
	lintCheckAllowNotResource            = "allow_not_resource"
	lintCheckRootAccountFullAccessOnly   = "root_account_full_access_only"
	lintCheckManagementAccountAttachment = "management_account_attachment"
	lintCheckDuplicatePolicyDocument     = "duplicate_policy_document"
	lintSeverityHigh                     = "high"
	lintSeverityMedium                   = "medium"
	lintSeverityLow                      = "low"
	lintFailOnNone                       = "none"
	lintNearLimitPercent                 = 80
)

var lintChecks = []string{
	lintCheckUnattachedPolicy,
	lintCheckAttachmentLimit,
	lintCheckPolicySizeLimit,
	lintCheckRedundantAttachment,
	lintCheckAllowNotAction,
	lintCheckAllowNotResource,
	lintCheckRootAccountFullAccessOnly,
	lintCheckManagementAccountAttachment,
	lintCheckDuplicatePolicyDocument,
}

var lintRationales = map[string]string{
	lintCheckUnattachedPolicy: "An unattached SCP restricts nothing. It can lead reviewers to believe a guardrail is " +
		"enforced and adds clutter to the policy inventory.",
	lintCheckAttachmentLimit: "AWS rejects SCP attachments beyond the per-target limit, and FullAWSAccess counts toward it. " +
		"A target at the limit cannot receive another guardrail until policies are detached or merged.",
	lintCheckPolicySizeLimit: "AWS rejects SCP documents larger than the size limit, counting every character including " +
		"whitespace saved through the API. A document near the limit has little room for new statements or conditions.",
	lintCheckRedundantAttachment: "This SCP contains only Deny statements and is already inherited from an ancestor, so the " +
		"direct attachment adds no restriction while consuming one of the target's limited attachment slots. Detaching " +
		"only one copy does not remove the control.",
	lintCheckAllowNotAction: "Allow with NotAction permits every action except those listed, including actions of services " +
		"AWS launches later. AWS recommends explicit Deny statements for most guardrails.",
	lintCheckAllowNotResource: "Allow with NotResource permits the listed actions on every resource except those listed, " +
		"including resources created later. AWS recommends explicit Deny statements for most guardrails.",
	lintCheckRootAccountFullAccessOnly: "The account is directly under the root and no SCP other than FullAWSAccess applies " +
		"to it, so no SCP guardrail limits its users and roles. Accounts usually receive guardrails from an OU.",
	lintCheckManagementAccountAttachment: "SCPs never affect users or roles in the management account, so this attachment " +
		"has no effect and suggests a guardrail that is not enforced.",
	lintCheckDuplicatePolicyDocument: "SCPs with identical documents are maintained separately and can drift apart. " +
		"Consolidating them keeps one source of truth and frees attachment slots.",
}

type lintSeverity string

func (severity *lintSeverity) String() string { return string(*severity) }

func (severity *lintSeverity) Set(value string) error {
	switch value {
	case lintFailOnNone, lintSeverityLow, lintSeverityMedium, lintSeverityHigh:
		*severity = lintSeverity(value)
		return nil
	default:
		return errors.New(`must be one of "none", "low", "medium", or "high"`)
	}
}

func (severity *lintSeverity) Type() string { return "none|low|medium|high" }

func lintSeverityRank(severity string) int {
	switch severity {
	case lintSeverityHigh:
		return 3
	case lintSeverityMedium:
		return 2
	case lintSeverityLow:
		return 1
	default:
		return 0
	}
}

var (
	lintFormat          outputFormat = json
	lintFailOn                       = lintSeverity(lintFailOnNone)
	lintAttachmentLimit int
	lintSizeLimit       int

	awsLintCmd = &cobra.Command{
		Use:   "lint",
		Short: "Report SCP hygiene findings across the organization",
		Long: `Traverse the entire organization, read every SCP and its document, and
report mechanical SCP configuration findings. Each finding names the check,
its severity, what was found, where, and why it matters. JSON output is used
by default.

Checks: unattached SCPs; roots, OUs, and accounts at or near the per-target
SCP attachment limit; documents at or near the SCP size limit; deny-only SCPs
attached directly and also inherited from an ancestor; Allow statements using
NotAction or NotResource; accounts directly under the root where only
FullAWSAccess applies; SCPs attached directly to the management account; and
SCPs with identical documents. "Near" means at least 80% of the limit.

Policy Scout does not evaluate effective permissions. By default, findings do
not change the exit status. Use --fail-on to exit with status 6 after writing
the complete report when any finding has at least that severity.`,
		Example: `  policy-scout aws lint
  policy-scout aws lint --output-format text
  policy-scout aws lint --fail-on medium --timeout 2m --max-retries 3 > scp-lint.json`,
		Args: noArgsValidator,
		RunE: runAWSLintCommand,
	}
)

func init() {
	awsLintCmd.Flags().VarP(&lintFormat, "output-format", "o", `output format: "json" or "text"`)
	if err := awsLintCmd.RegisterFlagCompletionFunc("output-format", outputFormatCompletion); err != nil {
		panic(err)
	}
	awsLintCmd.Flags().Var(&lintFailOn, "fail-on", `exit with status 6 when a finding has at least this severity: "none", "low", "medium", or "high"`)
	awsLintCmd.Flags().IntVar(&lintAttachmentLimit, "policies-per-target-limit", defaultSCPAttachmentLimit, "maximum SCPs AWS allows directly attached to one root, OU, or account")
	awsLintCmd.Flags().IntVar(&lintSizeLimit, "policy-size-limit", defaultSCPSizeLimit, "maximum SCP document size in characters")
	addAWSExecutionFlags(awsLintCmd)
}

type lintLimits struct {
	PoliciesPerTarget        int `json:"policies_per_target"`
	PolicyDocumentCharacters int `json:"policy_document_characters"`
}

type lintPolicyRef struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	AWSManaged bool   `json:"aws_managed"`
}

type lintEvidence struct {
	AttachedPolicyCount int                   `json:"attached_policy_count,omitempty"`
	AttachedPolicies    []lintPolicyRef       `json:"attached_policies,omitempty"`
	DocumentCharacters  int                   `json:"document_characters,omitempty"`
	Limit               int                   `json:"limit,omitempty"`
	StatementIndex      *int                  `json:"statement_index,omitempty"`
	StatementSID        string                `json:"statement_sid,omitempty"`
	InheritedFrom       []scpAttachmentTarget `json:"inherited_from,omitempty"`
	DuplicatePolicies   []lintPolicyRef       `json:"duplicate_policies,omitempty"`
}

type lintFinding struct {
	Check     string               `json:"check"`
	Severity  string               `json:"severity"`
	Message   string               `json:"message"`
	Rationale string               `json:"rationale"`
	Target    *scpAttachmentTarget `json:"target,omitempty"`
	Policy    *lintPolicyRef       `json:"policy,omitempty"`
	Evidence  lintEvidence         `json:"evidence"`
}

type lintSummary struct {
	Total  int `json:"total"`
	High   int `json:"high"`
	Medium int `json:"medium"`
	Low    int `json:"low"`
}

type lintReport struct {
	SchemaVersion string              `json:"schema_version"`
	Root          scpAttachmentTarget `json:"root"`
	Limits        lintLimits          `json:"limits"`
	Checks        []string            `json:"checks"`
	Summary       lintSummary         `json:"summary"`
	Findings      []lintFinding       `json:"findings"`
}

// lintFindingsError reports that the complete report was written and contains
// findings at or above the --fail-on threshold. It is not a failure diagnostic.
type lintFindingsError struct {
	threshold string
	count     int
}

func (err *lintFindingsError) Error() string {
	return fmt.Sprintf("%d SCP lint findings at or above severity %s", err.count, err.threshold)
}

func runAWSLintCommand(cmd *cobra.Command, _ []string) error {
	controls, err := awsExecutionControlsFromCommand(cmd)
	if err != nil {
		return err
	}
	if lintAttachmentLimit < 1 {
		return newInvalidInvocationError(errors.New("invalid --policies-per-target-limit: must be at least 1"))
	}
	if lintSizeLimit < 1 {
		return newInvalidInvocationError(errors.New("invalid --policy-size-limit: must be at least 1"))
	}
	limits := lintLimits{PoliciesPerTarget: lintAttachmentLimit, PolicyDocumentCharacters: lintSizeLimit}
	ctx, cancel := controls.context(cmd.Context())
	defer cancel()
	err = runAWSQuery(ctx, cmd.OutOrStdout(), profile, true, controls.configLoadOptions(), func(
		ctx context.Context, writer io.Writer, client organizationsClient, rootID, rootName, managementAccountID string,
	) error {
		report, err := buildLintReport(ctx, client, rootID, rootName, managementAccountID, limits)
		if err != nil {
			return err
		}
		if err := writeLintReport(writer, report, lintFormat); err != nil {
			return err
		}
		return lintThresholdError(report, string(lintFailOn))
	})
	return controls.explainError(err)
}

func lintThresholdError(report lintReport, threshold string) error {
	minimum := lintSeverityRank(threshold)
	if minimum == 0 {
		return nil
	}
	count := 0
	for _, finding := range report.Findings {
		if lintSeverityRank(finding.Severity) >= minimum {
			count++
		}
	}
	if count == 0 {
		return nil
	}
	return &lintFindingsError{threshold: threshold, count: count}
}

type lintPolicy struct {
	ref        lintPolicyRef
	content    string
	statements []scpStatement
}

type scpStatement struct {
	Sid         string                  `json:"Sid"`
	Effect      string                  `json:"Effect"`
	NotAction   encodingjson.RawMessage `json:"NotAction"`
	NotResource encodingjson.RawMessage `json:"NotResource"`
}

// lintTarget is one root, OU, or account with its direct SCP IDs and, for SCP
// policy IDs it inherits, the ancestors they are attached to.
type lintTarget struct {
	target       scpAttachmentTarget
	management   bool
	parentIsRoot bool
	direct       []string
	inherited    map[string][]scpAttachmentTarget
}

func buildLintReport(
	ctx context.Context,
	client organizationsClient,
	rootID, rootName, managementAccountID string,
	limits lintLimits,
) (lintReport, error) {
	tree, err := buildOrganizationTree(ctx, client, allSelectionType, rootID, rootName, managementAccountID)
	if err != nil {
		return lintReport{}, err
	}
	rootPolicies, err := listSCPsForTarget(ctx, client, rootID)
	if err != nil {
		return lintReport{}, fmt.Errorf("list SCPs for %s: %w", rootID, err)
	}
	managementPolicies, err := listSCPsForTarget(ctx, client, managementAccountID)
	if err != nil {
		return lintReport{}, fmt.Errorf("list SCPs for %s: %w", managementAccountID, err)
	}
	catalog, err := listServiceControlPolicies(ctx, client)
	if err != nil {
		return lintReport{}, fmt.Errorf("list SCPs: %w", err)
	}
	policies := make([]lintPolicy, len(catalog))
	if err := runOrganizationJobs(ctx, len(catalog), func(jobCtx context.Context, index int) error {
		described, err := describePolicy(jobCtx, client, aws.ToString(catalog[index].Id))
		if err != nil {
			return fmt.Errorf("describe policy %s: %w", aws.ToString(catalog[index].Id), err)
		}
		statements, err := parseSCPStatements(described.Content)
		if err != nil {
			return fmt.Errorf("AWS returned SCP %s with malformed Statement: %w", described.ID, err)
		}
		policies[index] = lintPolicy{
			ref:        lintPolicyRef{ID: described.ID, Name: described.Name, AWSManaged: described.AWSManaged},
			content:    string(described.Content),
			statements: statements,
		}
		return nil
	}); err != nil {
		return lintReport{}, err
	}
	policiesByID := make(map[string]lintPolicy, len(policies))
	for _, policy := range policies {
		policiesByID[policy.ref.ID] = policy
	}

	root := scpAttachmentTarget{Type: rootEntityType, ID: rootID, Name: rootName}
	targets := []lintTarget{{target: root, direct: summaryPolicyIDs(rootPolicies)}}
	var collect func(node organizationNode, parentIsRoot bool)
	collect = func(node organizationNode, parentIsRoot bool) {
		for _, child := range node.Children {
			current := lintTarget{
				target:       scpAttachmentTarget{Type: child.Type, ID: child.ID, Name: child.Name},
				management:   child.ManagementAccount,
				parentIsRoot: parentIsRoot,
				inherited:    make(map[string][]scpAttachmentTarget),
			}
			if child.ManagementAccount {
				current.direct = summaryPolicyIDs(managementPolicies)
			}
			for _, attachment := range child.SCPAttachments {
				if attachment.Inherited {
					current.inherited[attachment.PolicyID] = append(current.inherited[attachment.PolicyID], attachment.AttachedTo)
				} else if !slices.Contains(current.direct, attachment.PolicyID) {
					current.direct = append(current.direct, attachment.PolicyID)
				}
			}
			targets = append(targets, current)
			collect(child, false)
		}
	}
	collect(tree, true)

	var findings []lintFinding
	attached := make(map[string]bool)
	for _, target := range targets {
		for _, policyID := range target.direct {
			if _, found := policiesByID[policyID]; !found {
				return lintReport{}, fmt.Errorf("SCP %s is attached to %s but ListPolicies did not return it", policyID, target.target.ID)
			}
			attached[policyID] = true
		}
		findings = append(findings, lintTargetFindings(target, policiesByID, limits)...)
	}
	for _, policy := range policies {
		findings = append(findings, lintPolicyFindings(policy, attached[policy.ref.ID], limits)...)
	}
	findings = append(findings, lintDuplicateDocuments(policies)...)
	sortLintFindings(findings)

	report := lintReport{
		SchemaVersion: lintSchemaVersion,
		Root:          root,
		Limits:        limits,
		Checks:        lintChecks,
		Findings:      nonNilSlice(findings),
	}
	for _, finding := range findings {
		report.Summary.Total++
		switch finding.Severity {
		case lintSeverityHigh:
			report.Summary.High++
		case lintSeverityMedium:
			report.Summary.Medium++
		case lintSeverityLow:
			report.Summary.Low++
		}
	}
	return report, nil
}

func lintTargetFindings(target lintTarget, policiesByID map[string]lintPolicy, limits lintLimits) []lintFinding {
	var findings []lintFinding
	where := target.target
	label := attachmentTargetText(where)

	if count := len(target.direct); nearLimit(count, limits.PoliciesPerTarget) {
		refs := make([]lintPolicyRef, len(target.direct))
		for index, policyID := range target.direct {
			refs[index] = policiesByID[policyID].ref
		}
		sort.Slice(refs, func(i, j int) bool { return refs[i].ID < refs[j].ID })
		severity, message := lintSeverityLow, fmt.Sprintf(
			"%s has %d of %d allowed directly attached SCPs.", label, count, limits.PoliciesPerTarget,
		)
		if count >= limits.PoliciesPerTarget {
			severity, message = lintSeverityMedium, fmt.Sprintf(
				"%s has %d directly attached SCPs, which reaches the per-target limit of %d.", label, count, limits.PoliciesPerTarget,
			)
		}
		findings = append(findings, newLintFinding(lintCheckAttachmentLimit, severity, message, &where, nil, lintEvidence{
			AttachedPolicyCount: count, AttachedPolicies: refs, Limit: limits.PoliciesPerTarget,
		}))
	}

	if target.management {
		for _, policyID := range target.direct {
			if policyID == fullAWSAccessPolicyID {
				continue
			}
			ref := policiesByID[policyID].ref
			findings = append(findings, newLintFinding(lintCheckManagementAccountAttachment, lintSeverityLow, fmt.Sprintf(
				"SCP %s [%s] is attached directly to the management account %s.", ref.Name, ref.ID, label,
			), &where, &ref, lintEvidence{}))
		}
		return findings
	}

	for _, policyID := range target.direct {
		ancestors := target.inherited[policyID]
		policy := policiesByID[policyID]
		if len(ancestors) == 0 || !denyOnly(policy.statements) {
			continue
		}
		names := make([]string, len(ancestors))
		for index, ancestor := range ancestors {
			names[index] = attachmentTargetText(ancestor)
		}
		ref := policy.ref
		findings = append(findings, newLintFinding(lintCheckRedundantAttachment, lintSeverityLow, fmt.Sprintf(
			"SCP %s [%s] is attached directly to %s and also inherited from %s.",
			ref.Name, ref.ID, label, strings.Join(names, ", "),
		), &where, &ref, lintEvidence{InheritedFrom: ancestors}))
	}

	if target.target.Type == accountEntityType && target.parentIsRoot {
		applicable := map[string]bool{}
		for _, policyID := range target.direct {
			applicable[policyID] = true
		}
		for policyID := range target.inherited {
			applicable[policyID] = true
		}
		if len(applicable) == 1 && applicable[fullAWSAccessPolicyID] {
			findings = append(findings, newLintFinding(lintCheckRootAccountFullAccessOnly, lintSeverityHigh, fmt.Sprintf(
				"%s is directly under the root and only FullAWSAccess applies to it.", label,
			), &where, nil, lintEvidence{}))
		}
	}
	return findings
}

func lintPolicyFindings(policy lintPolicy, attached bool, limits lintLimits) []lintFinding {
	var findings []lintFinding
	ref := policy.ref
	if !attached {
		findings = append(findings, newLintFinding(lintCheckUnattachedPolicy, lintSeverityLow, fmt.Sprintf(
			"SCP %s [%s] is not attached to any root, OU, or account.", ref.Name, ref.ID,
		), nil, &ref, lintEvidence{}))
	}

	if size := utf8.RuneCountInString(policy.content); nearLimit(size, limits.PolicyDocumentCharacters) {
		severity, message := lintSeverityLow, fmt.Sprintf(
			"SCP %s [%s] document is %d of %d allowed characters.", ref.Name, ref.ID, size, limits.PolicyDocumentCharacters,
		)
		if size >= limits.PolicyDocumentCharacters {
			severity, message = lintSeverityMedium, fmt.Sprintf(
				"SCP %s [%s] document is %d characters, which reaches the %d-character limit.",
				ref.Name, ref.ID, size, limits.PolicyDocumentCharacters,
			)
		}
		findings = append(findings, newLintFinding(lintCheckPolicySizeLimit, severity, message, nil, &ref, lintEvidence{
			DocumentCharacters: size, Limit: limits.PolicyDocumentCharacters,
		}))
	}

	for index, statement := range policy.statements {
		if statement.Effect != "Allow" {
			continue
		}
		for _, element := range []struct {
			check, name string
			value       encodingjson.RawMessage
		}{
			{lintCheckAllowNotAction, "NotAction", statement.NotAction},
			{lintCheckAllowNotResource, "NotResource", statement.NotResource},
		} {
			if element.value == nil {
				continue
			}
			statementIndex := index
			findings = append(findings, newLintFinding(element.check, lintSeverityMedium, fmt.Sprintf(
				"SCP %s [%s] statement %s is an Allow statement that uses %s.",
				ref.Name, ref.ID, statementLabel(index, statement.Sid), element.name,
			), nil, &ref, lintEvidence{StatementIndex: &statementIndex, StatementSID: statement.Sid}))
		}
	}
	return findings
}

func lintDuplicateDocuments(policies []lintPolicy) []lintFinding {
	groups := make(map[string][]lintPolicyRef)
	for _, policy := range policies {
		var decoded any
		if err := encodingjson.Unmarshal([]byte(policy.content), &decoded); err != nil {
			continue
		}
		// Marshaling decoded JSON sorts object keys and drops insignificant
		// whitespace, so formatting differences do not hide duplicates.
		canonical, err := encodingjson.Marshal(decoded)
		if err != nil {
			continue
		}
		groups[string(canonical)] = append(groups[string(canonical)], policy.ref)
	}
	var findings []lintFinding
	for _, refs := range groups {
		if len(refs) < 2 {
			continue
		}
		sort.Slice(refs, func(i, j int) bool { return refs[i].ID < refs[j].ID })
		labels := make([]string, len(refs))
		for index, ref := range refs {
			labels[index] = fmt.Sprintf("%s [%s]", ref.Name, ref.ID)
		}
		first := refs[0]
		findings = append(findings, newLintFinding(lintCheckDuplicatePolicyDocument, lintSeverityLow, fmt.Sprintf(
			"SCPs %s have identical policy documents.", strings.Join(labels, ", "),
		), nil, &first, lintEvidence{DuplicatePolicies: refs[1:]}))
	}
	return findings
}

func newLintFinding(
	check, severity, message string,
	target *scpAttachmentTarget,
	policy *lintPolicyRef,
	evidence lintEvidence,
) lintFinding {
	return lintFinding{
		Check: check, Severity: severity, Message: message, Rationale: lintRationales[check],
		Target: target, Policy: policy, Evidence: evidence,
	}
}

func nearLimit(value, limit int) bool {
	return value*100 >= limit*lintNearLimitPercent
}

func denyOnly(statements []scpStatement) bool {
	for _, statement := range statements {
		if statement.Effect != "Deny" {
			return false
		}
	}
	return len(statements) > 0
}

func statementLabel(index int, sid string) string {
	if sid == "" {
		return fmt.Sprintf("%d", index)
	}
	return fmt.Sprintf("%d (Sid %q)", index, sid)
}

func parseSCPStatements(content []byte) ([]scpStatement, error) {
	var document struct {
		Statement encodingjson.RawMessage `json:"Statement"`
	}
	if err := encodingjson.Unmarshal(content, &document); err != nil {
		return nil, err
	}
	raw := bytes.TrimSpace(document.Statement)
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
		return nil, nil
	}
	if raw[0] == '[' {
		var statements []scpStatement
		if err := encodingjson.Unmarshal(raw, &statements); err != nil {
			return nil, err
		}
		return statements, nil
	}
	var statement scpStatement
	if err := encodingjson.Unmarshal(raw, &statement); err != nil {
		return nil, err
	}
	return []scpStatement{statement}, nil
}

func summaryPolicyIDs(policies []types.PolicySummary) []string {
	var ids []string
	for _, policy := range policies {
		if id := aws.ToString(policy.Id); !slices.Contains(ids, id) {
			ids = append(ids, id)
		}
	}
	return ids
}

// listServiceControlPolicies returns every SCP in the organization once, sorted by ID.
func listServiceControlPolicies(ctx context.Context, client organizations.ListPoliciesAPIClient) ([]types.PolicySummary, error) {
	paginator := organizations.NewListPoliciesPaginator(client, &organizations.ListPoliciesInput{
		Filter: types.PolicyTypeServiceControlPolicy,
	})
	byID := make(map[string]types.PolicySummary)
	seenTokens := make(map[string]bool)
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		if err := rejectRepeatedToken(seenTokens, page.NextToken, "ListPolicies"); err != nil {
			return nil, err
		}
		for _, policy := range page.Policies {
			id := aws.ToString(policy.Id)
			if !validPolicyID(id) {
				return nil, fmt.Errorf("AWS returned SCP with invalid ID %q", id)
			}
			if policy.Type != types.PolicyTypeServiceControlPolicy {
				return nil, fmt.Errorf("AWS returned policy %s with type %s, expected SERVICE_CONTROL_POLICY", id, policy.Type)
			}
			byID[id] = policy
		}
	}
	result := make([]types.PolicySummary, 0, len(byID))
	for _, policy := range byID {
		result = append(result, policy)
	}
	sort.Slice(result, func(i, j int) bool { return aws.ToString(result[i].Id) < aws.ToString(result[j].Id) })
	return result, nil
}

func sortLintFindings(findings []lintFinding) {
	targetKey := func(target *scpAttachmentTarget) (int, string) {
		if target == nil {
			return -1, ""
		}
		rank := map[string]int{rootEntityType: 0, organizationalUnitEntityType: 1, accountEntityType: 2}[target.Type]
		return rank, target.ID
	}
	sort.SliceStable(findings, func(i, j int) bool {
		left, right := findings[i], findings[j]
		if rankLeft, rankRight := lintSeverityRank(left.Severity), lintSeverityRank(right.Severity); rankLeft != rankRight {
			return rankLeft > rankRight
		}
		if left.Check != right.Check {
			return left.Check < right.Check
		}
		leftRank, leftID := targetKey(left.Target)
		rightRank, rightID := targetKey(right.Target)
		if leftRank != rightRank {
			return leftRank < rightRank
		}
		if leftID != rightID {
			return leftID < rightID
		}
		if left.Policy != nil && right.Policy != nil && left.Policy.ID != right.Policy.ID {
			return left.Policy.ID < right.Policy.ID
		}
		if left.Evidence.StatementIndex != nil && right.Evidence.StatementIndex != nil {
			return *left.Evidence.StatementIndex < *right.Evidence.StatementIndex
		}
		return false
	})
}

func writeLintReport(writer io.Writer, report lintReport, outputFormat outputFormat) error {
	if outputFormat != text {
		return writeJSONDocument(writer, report, "lint report")
	}
	var output strings.Builder
	header := "SCP lint for " + displayText(attachmentTargetText(report.Root))
	if report.Summary.Total == 0 {
		fmt.Fprintf(&output, "%s: no findings\n", header)
		return writeDocument(writer, []byte(output.String()), "lint report")
	}
	fmt.Fprintf(&output, "%s: %d findings (%d high, %d medium, %d low)\n",
		header, report.Summary.Total, report.Summary.High, report.Summary.Medium, report.Summary.Low)
	for _, finding := range report.Findings {
		fmt.Fprintf(&output, "\n[%s] %s: %s\n", finding.Severity, finding.Check, displayText(finding.Message))
		if finding.Target != nil {
			fmt.Fprintf(&output, "  Where: %s\n", displayText(attachmentTargetText(*finding.Target)))
		}
		if finding.Policy != nil {
			fmt.Fprintf(&output, "  Policy: SCP %s [%s]\n", displayText(finding.Policy.Name), displayText(finding.Policy.ID))
		}
		fmt.Fprintf(&output, "  Why: %s\n", finding.Rationale)
	}
	return writeDocument(writer, []byte(output.String()), "lint report")
}
