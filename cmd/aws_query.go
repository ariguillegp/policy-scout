package cmd

import (
	"context"
	encodingjson "encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	"github.com/aws/aws-sdk-go-v2/service/organizations/types"
	"github.com/spf13/cobra"
)

const (
	policiesQuerySchemaVersion    = "1"
	attachmentsQuerySchemaVersion = "1"
)

var (
	policiesAccountID  string
	policiesOUID       string
	policiesFormat     outputFormat = json
	attachmentPolicyID string
	attachmentsFormat  outputFormat = json

	awsPoliciesCmd = &cobra.Command{
		Use:   "policies (--account-id <12-digit-id> | --ou-id <ou-id>)",
		Short: "Show the SCPs that apply to one account or OU",
		Long: `Return one compact, versioned result containing the selected target, its
root-to-target path, and applicable SCP summaries with direct or inherited
attachment provenance. JSON output is used by default.`,
		Example: `  policy-scout aws policies --account-id 123456789012
  policy-scout aws policies --ou-id ou-abcd-12345678
  policy-scout aws policies --account-id 123456789012 --output-format json --timeout 30s --max-retries 3`,
		Args: noArgsValidator,
		RunE: runAWSPoliciesCommand,
	}
	awsAttachmentsCmd = &cobra.Command{
		Use:   "attachments --policy-id <p-id>",
		Short: "Show where one SCP is attached and inherited",
		Long: `Return one compact, versioned result containing the direct attachment
targets for an exact SCP ID and the accounts and OUs where that attachment is
effective directly or through inheritance. Management accounts can appear as
direct attachment targets but never as affected targets. JSON output is used
by default.`,
		Example: `  policy-scout aws attachments --policy-id p-a1b2c3d4
  policy-scout aws attachments --policy-id p-a1b2c3d4 --output-format json --timeout 30s --max-retries 3`,
		Args: noArgsValidator,
		RunE: runAWSAttachmentsCommand,
	}
)

func init() {
	awsPoliciesCmd.Flags().StringVar(&policiesAccountID, "account-id", "", "exact 12-digit AWS account ID to inspect")
	awsPoliciesCmd.Flags().StringVar(&policiesOUID, "ou-id", "", "exact AWS organizational unit ID to inspect")
	awsPoliciesCmd.Flags().VarP(&policiesFormat, "output-format", "o", `output format: "json" or "text"`)
	if err := awsPoliciesCmd.RegisterFlagCompletionFunc("output-format", outputFormatCompletion); err != nil {
		panic(err)
	}
	addAWSExecutionFlags(awsPoliciesCmd)

	awsAttachmentsCmd.Flags().StringVar(&attachmentPolicyID, "policy-id", "", "exact AWS service control policy ID to inspect")
	awsAttachmentsCmd.Flags().VarP(&attachmentsFormat, "output-format", "o", `output format: "json" or "text"`)
	if err := awsAttachmentsCmd.RegisterFlagCompletionFunc("output-format", outputFormatCompletion); err != nil {
		panic(err)
	}
	addAWSExecutionFlags(awsAttachmentsCmd)
}

type queryTarget struct {
	Type              string `json:"type"`
	ID                string `json:"id"`
	Name              string `json:"name,omitempty"`
	ManagementAccount *bool  `json:"management_account,omitempty"`
	SCPApplicable     bool   `json:"scp_applicable"`
}

type policiesQueryResult struct {
	SchemaVersion string                `json:"schema_version"`
	Target        queryTarget           `json:"target"`
	Path          []scpAttachmentTarget `json:"path"`
	Policies      []scpAttachment       `json:"policies"`
}

type attachmentProvenance struct {
	AttachedTo scpAttachmentTarget `json:"attached_to"`
	Inherited  bool                `json:"inherited"`
}

type affectedTarget struct {
	Target     queryTarget            `json:"target"`
	Provenance []attachmentProvenance `json:"provenance"`
}

type attachmentsQueryResult struct {
	SchemaVersion   string           `json:"schema_version"`
	PolicyID        string           `json:"policy_id"`
	PolicyName      string           `json:"policy_name"`
	DirectTargets   []queryTarget    `json:"direct_targets"`
	AffectedTargets []affectedTarget `json:"affected_targets"`
}

func runAWSPoliciesCommand(cmd *cobra.Command, _ []string) error {
	controls, err := awsExecutionControlsFromCommand(cmd)
	if err != nil {
		return err
	}
	targetID, err := selectedQueryTarget(
		policiesAccountID, cmd.Flags().Changed("account-id"), policiesOUID, cmd.Flags().Changed("ou-id"),
	)
	if err != nil {
		return err
	}
	ctx, cancel := controls.context(cmd.Context())
	defer cancel()
	err = runAWSQuery(ctx, cmd.OutOrStdout(), profile, !strings.HasPrefix(targetID, "ou-"), controls.configLoadOptions(), func(
		ctx context.Context, writer io.Writer, client organizationsClient, rootID, rootName, managementAccountID string,
	) error {
		return displayPoliciesQuery(ctx, writer, client, targetID, rootID, rootName, managementAccountID, policiesFormat)
	})
	return controls.explainError(err)
}

func runAWSAttachmentsCommand(cmd *cobra.Command, _ []string) error {
	controls, err := awsExecutionControlsFromCommand(cmd)
	if err != nil {
		return err
	}
	if !cmd.Flags().Changed("policy-id") || !validPolicyID(attachmentPolicyID) {
		return newInvalidInvocationError(fmt.Errorf("invalid --policy-id %q: must match p-<8-128 letters, digits, or underscores>", attachmentPolicyID))
	}
	ctx, cancel := controls.context(cmd.Context())
	defer cancel()
	err = runAWSQuery(ctx, cmd.OutOrStdout(), profile, true, controls.configLoadOptions(), func(
		ctx context.Context, writer io.Writer, client organizationsClient, rootID, rootName, managementAccountID string,
	) error {
		return displayAttachmentsQuery(ctx, writer, client, attachmentPolicyID, rootID, rootName, managementAccountID, attachmentsFormat)
	})
	return controls.explainError(err)
}

type awsQueryOperation func(context.Context, io.Writer, organizationsClient, string, string, string) error

func runAWSQuery(
	ctx context.Context,
	writer io.Writer,
	selectedProfile string,
	includeManagementAccount bool,
	configOptions []func(*config.LoadOptions) error,
	operation awsQueryOperation,
) (err error) {
	defer func() { err = addSSORemediation(err, selectedProfile) }()
	cfg, err := loadAWSConfig(ctx, selectedProfile, config.LoadDefaultConfig, configOptions...)
	if err != nil {
		return newCredentialsError("LoadDefaultConfig", err)
	}
	if _, err := cfg.Credentials.Retrieve(ctx); err != nil {
		return newCredentialsError("RetrieveCredentials", err)
	}
	client := organizations.NewFromConfig(cfg)
	rootID, rootName, managementAccountID, err := getRootAndManagementAccount(ctx, client, includeManagementAccount)
	if err != nil {
		return err
	}
	return operation(ctx, writer, client, rootID, rootName, managementAccountID)
}

func selectedQueryTarget(accountID string, accountSet bool, ouID string, ouSet bool) (string, error) {
	if accountSet && strings.EqualFold(accountID, allSelectionType) {
		return "", newInvalidInvocationError(errors.New(`invalid --account-id "all": policies requires one exact account or OU ID`))
	}
	return selectedAWSTarget(accountID, accountSet, ouID, ouSet)
}

func displayPoliciesQuery(
	ctx context.Context,
	writer io.Writer,
	client organizationsClient,
	targetID, rootID, rootName, managementAccountID string,
	outputFormat outputFormat,
) error {
	result, err := buildPoliciesQuery(ctx, client, targetID, rootID, rootName, managementAccountID)
	if err != nil {
		return err
	}
	return writePoliciesQuery(writer, result, outputFormat)
}

func buildPoliciesQuery(
	ctx context.Context,
	client organizationsClient,
	targetID, rootID, rootName, managementAccountID string,
) (policiesQueryResult, error) {
	tree, err := buildOrganizationTree(ctx, client, targetID, rootID, rootName, managementAccountID)
	if err != nil {
		return policiesQueryResult{}, err
	}
	target := findOrganizationNode(tree, targetID)
	if target == nil {
		return policiesQueryResult{}, fmt.Errorf("selected target %s was not present in its organization path", targetID)
	}
	path := make([]scpAttachmentTarget, 0)
	for node := &tree; node != nil; {
		path = append(path, scpAttachmentTarget{Type: node.Type, ID: node.ID, Name: node.Name})
		if node.ID == targetID {
			break
		}
		if len(node.Children) != 1 {
			return policiesQueryResult{}, fmt.Errorf("expected one path child below %s, got %d", node.ID, len(node.Children))
		}
		node = &node.Children[0]
	}
	return policiesQueryResult{
		SchemaVersion: policiesQuerySchemaVersion,
		Target:        newQueryTarget(*target),
		Path:          nonNilSlice(path),
		Policies:      nonNilSlice(target.SCPAttachments),
	}, nil
}

func buildAttachmentsQuery(
	ctx context.Context,
	client organizationsClient,
	policyID, rootID, rootName, managementAccountID string,
) (attachmentsQueryResult, error) {
	directAttachments, err := listTargetsForPolicy(ctx, client, policyID)
	if err != nil {
		return attachmentsQueryResult{}, fmt.Errorf("list targets for SCP %s: %w", policyID, err)
	}
	result := attachmentsQueryResult{
		SchemaVersion:   attachmentsQuerySchemaVersion,
		PolicyID:        policyID,
		DirectTargets:   []queryTarget{},
		AffectedTargets: []affectedTarget{},
	}
	directByID := make(map[string]scpAttachmentTarget, len(directAttachments))
	for _, attachment := range directAttachments {
		if attachment.Type == rootEntityType && attachment.ID != rootID {
			return attachmentsQueryResult{}, fmt.Errorf("AWS returned attachment root %s, expected %s", attachment.ID, rootID)
		}
		directByID[attachment.ID] = attachment
		result.DirectTargets = append(result.DirectTargets, queryTargetFromAttachmentTarget(attachment, managementAccountID))
	}
	if len(directAttachments) == 0 {
		return result, nil
	}

	policies, err := listSCPsForTarget(ctx, client, directAttachments[0].ID)
	if err != nil {
		return attachmentsQueryResult{}, fmt.Errorf("resolve SCP summary %s: %w", policyID, err)
	}
	for _, policy := range policies {
		if aws.ToString(policy.Id) != policyID {
			continue
		}
		name := aws.ToString(policy.Name)
		if result.PolicyName != "" && result.PolicyName != name {
			return attachmentsQueryResult{}, fmt.Errorf("SCP %s has conflicting names %q and %q", policyID, result.PolicyName, name)
		}
		result.PolicyName = name
	}
	if result.PolicyName == "" {
		return attachmentsQueryResult{}, fmt.Errorf("AWS returned attachment targets but no SCP %s summary for target %s", policyID, directAttachments[0].ID)
	}

	collector := attachmentReachCollector{
		client:              client,
		managementAccountID: managementAccountID,
		directByID:          directByID,
		affectedByID:        make(map[string]affectedTarget),
		accountParentByID:   make(map[string]string),
	}
	var reachJobs []organizationTraversalJob
	if rootAttachment, found := directByID[rootID]; found {
		rootAttachment.Name = rootName
		reachJobs = append(reachJobs, collector.newJob(rootAttachment, nil, []string{rootID}))
	} else {
		ouPaths := make(map[string][]string)
		for _, attachment := range directAttachments {
			if attachment.Type != organizationalUnitEntityType {
				continue
			}
			path, err := buildAncestorPath(ctx, client, attachment.ID, rootID)
			if err != nil {
				return attachmentsQueryResult{}, fmt.Errorf("build path for direct attachment %s: %w", attachment.ID, err)
			}
			ouPaths[attachment.ID] = path
		}
		for _, attachment := range directAttachments {
			if attachment.Type != organizationalUnitEntityType || hasDirectOUAncestor(ouPaths[attachment.ID], directByID) {
				continue
			}
			reachJobs = append(reachJobs, collector.newJob(attachment, nil, ouPaths[attachment.ID]))
		}
	}
	if err := runOrganizationTraversal(ctx, reachJobs); err != nil {
		return attachmentsQueryResult{}, err
	}

	for _, attachment := range directAttachments {
		if attachment.Type != accountEntityType || attachment.ID == managementAccountID {
			continue
		}
		if _, found := collector.affectedByID[attachment.ID]; !found {
			collector.affectedByID[attachment.ID] = affectedTarget{
				Target:     queryTargetFromAttachmentTarget(attachment, managementAccountID),
				Provenance: []attachmentProvenance{{AttachedTo: attachment, Inherited: false}},
			}
		}
	}
	for _, affected := range collector.affectedByID {
		result.AffectedTargets = append(result.AffectedTargets, affected)
	}
	sort.Slice(result.DirectTargets, func(i, j int) bool { return queryTargetLess(result.DirectTargets[i], result.DirectTargets[j]) })
	sort.Slice(result.AffectedTargets, func(i, j int) bool {
		return queryTargetLess(result.AffectedTargets[i].Target, result.AffectedTargets[j].Target)
	})
	return result, nil
}

func displayAttachmentsQuery(
	ctx context.Context,
	writer io.Writer,
	client organizationsClient,
	policyID, rootID, rootName, managementAccountID string,
	outputFormat outputFormat,
) error {
	result, err := buildAttachmentsQuery(ctx, client, policyID, rootID, rootName, managementAccountID)
	if err != nil {
		return err
	}
	return writeAttachmentsQuery(writer, result, outputFormat)
}

func newQueryTarget(node organizationNode) queryTarget {
	target := queryTarget{
		Type: node.Type, ID: node.ID, Name: node.Name,
		SCPApplicable: !node.ManagementAccount,
	}
	if node.Type == accountEntityType {
		management := node.ManagementAccount
		target.ManagementAccount = &management
	}
	return target
}

func queryTargetFromAttachmentTarget(target scpAttachmentTarget, managementAccountID string) queryTarget {
	return newQueryTarget(organizationNode{
		Type: target.Type, ID: target.ID, Name: target.Name, ManagementAccount: target.ID == managementAccountID,
	})
}

type attachmentReachCollector struct {
	client              organizationsClient
	managementAccountID string
	directByID          map[string]scpAttachmentTarget
	affectedByID        map[string]affectedTarget
	accountParentByID   map[string]string
	mu                  sync.Mutex
}

func (collector *attachmentReachCollector) newJob(
	current scpAttachmentTarget,
	inherited []scpAttachmentTarget,
	ancestors []string,
) organizationTraversalJob {
	sources := append([]scpAttachmentTarget(nil), inherited...)
	if direct, found := collector.directByID[current.ID]; found {
		sources = append(sources, direct)
	}
	return organizationTraversalJob{
		id:        current.ID,
		ancestors: ancestors,
		run: func(ctx context.Context) ([]organizationTraversalJob, error) {
			if current.Type == organizationalUnitEntityType {
				collector.mu.Lock()
				collector.affectedByID[current.ID] = affectedTarget{
					Target:     queryTargetFromAttachmentTarget(current, collector.managementAccountID),
					Provenance: attachmentProvenanceForTarget(sources, current.ID),
				}
				collector.mu.Unlock()
			}

			accounts, err := listAccountsForParent(ctx, collector.client, current.ID)
			if err != nil {
				return nil, fmt.Errorf("list accounts for %s: %w", current.ID, err)
			}
			collector.mu.Lock()
			for _, account := range accounts {
				accountID := aws.ToString(account.Id)
				if existingParentID, found := collector.accountParentByID[accountID]; found && existingParentID != current.ID {
					collector.mu.Unlock()
					firstParentID, secondParentID := existingParentID, current.ID
					if secondParentID < firstParentID {
						firstParentID, secondParentID = secondParentID, firstParentID
					}
					return nil, fmt.Errorf(
						"account %s appears under multiple organization parents %s and %s",
						accountID, firstParentID, secondParentID,
					)
				}
				collector.accountParentByID[accountID] = current.ID
				if accountID == collector.managementAccountID {
					continue
				}
				accountTarget := scpAttachmentTarget{
					Type: accountEntityType, ID: accountID, Name: aws.ToString(account.Name),
				}
				accountSources := append([]scpAttachmentTarget(nil), sources...)
				if direct, found := collector.directByID[accountID]; found {
					accountSources = append(accountSources, direct)
				}
				collector.affectedByID[accountID] = affectedTarget{
					Target:     queryTargetFromAttachmentTarget(accountTarget, collector.managementAccountID),
					Provenance: attachmentProvenanceForTarget(accountSources, accountID),
				}
			}
			collector.mu.Unlock()

			organizationalUnits, err := listOrganizationalUnitsForParent(ctx, collector.client, current.ID)
			if err != nil {
				return nil, fmt.Errorf("list organizational units for %s: %w", current.ID, err)
			}
			children := make([]organizationTraversalJob, 0, len(organizationalUnits))
			for _, ou := range organizationalUnits {
				ouID := aws.ToString(ou.Id)
				children = append(children, collector.newJob(
					scpAttachmentTarget{
						Type: organizationalUnitEntityType, ID: ouID, Name: aws.ToString(ou.Name),
					},
					sources,
					appendPath(ancestors, ouID),
				))
			}
			return children, nil
		},
	}
}

func attachmentProvenanceForTarget(sources []scpAttachmentTarget, targetID string) []attachmentProvenance {
	provenance := make([]attachmentProvenance, len(sources))
	for index, source := range sources {
		provenance[index] = attachmentProvenance{AttachedTo: source, Inherited: source.ID != targetID}
	}
	return provenance
}

func hasDirectOUAncestor(path []string, directByID map[string]scpAttachmentTarget) bool {
	for _, ancestorID := range path[1 : len(path)-1] {
		if target, found := directByID[ancestorID]; found && target.Type == organizationalUnitEntityType {
			return true
		}
	}
	return false
}

func listTargetsForPolicy(
	ctx context.Context,
	client organizations.ListTargetsForPolicyAPIClient,
	policyID string,
) ([]scpAttachmentTarget, error) {
	paginator := organizations.NewListTargetsForPolicyPaginator(client, &organizations.ListTargetsForPolicyInput{PolicyId: &policyID})
	byID := make(map[string]scpAttachmentTarget)
	seenTokens := make(map[string]bool)
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		if err := rejectRepeatedToken(seenTokens, page.NextToken, "ListTargetsForPolicy"); err != nil {
			return nil, err
		}
		for _, target := range page.Targets {
			id := aws.ToString(target.TargetId)
			name := aws.ToString(target.Name)
			targetType, err := policyTargetEntityType(target.Type, id)
			if err != nil {
				return nil, err
			}
			if name == "" {
				return nil, fmt.Errorf("AWS returned policy target %s without a name", id)
			}
			value := scpAttachmentTarget{Type: targetType, ID: id, Name: name}
			if existing, found := byID[id]; found && existing != value {
				return nil, fmt.Errorf("AWS returned conflicting summaries for policy target %s", id)
			}
			byID[id] = value
		}
	}
	result := make([]scpAttachmentTarget, 0, len(byID))
	for _, target := range byID {
		result = append(result, target)
	}
	sort.Slice(result, func(i, j int) bool {
		return queryTargetLess(queryTarget{Type: result[i].Type, ID: result[i].ID}, queryTarget{Type: result[j].Type, ID: result[j].ID})
	})
	return result, nil
}

func policyTargetEntityType(targetType types.TargetType, id string) (string, error) {
	switch targetType {
	case types.TargetTypeRoot:
		if err := validateRootID(id); err != nil {
			return "", fmt.Errorf("AWS returned invalid root policy target %q: %w", id, err)
		}
		return rootEntityType, nil
	case types.TargetTypeOrganizationalUnit:
		if err := validateOrganizationalUnitID(id); err != nil {
			return "", fmt.Errorf("AWS returned invalid organizational unit policy target %q: %w", id, err)
		}
		return organizationalUnitEntityType, nil
	case types.TargetTypeAccount:
		if err := validateStrictAccountID(id); err != nil {
			return "", fmt.Errorf("AWS returned invalid account policy target %q: %w", id, err)
		}
		return accountEntityType, nil
	default:
		return "", fmt.Errorf("AWS returned policy target %s with invalid type %s", id, targetType)
	}
}

func queryTargetLess(left, right queryTarget) bool {
	rank := func(value string) int {
		switch value {
		case rootEntityType:
			return 0
		case accountEntityType:
			return 1
		default:
			return 2
		}
	}
	if rank(left.Type) != rank(right.Type) {
		return rank(left.Type) < rank(right.Type)
	}
	return left.ID < right.ID
}

func writePoliciesQuery(writer io.Writer, result policiesQueryResult, outputFormat outputFormat) error {
	if outputFormat == text {
		var output strings.Builder
		fmt.Fprintf(&output, "Target: %s\n", displayText(attachmentTargetText(scpAttachmentTarget{Type: result.Target.Type, ID: result.Target.ID, Name: result.Target.Name})))
		path := make([]string, len(result.Path))
		for index, target := range result.Path {
			path[index] = displayText(attachmentTargetText(target))
		}
		fmt.Fprintf(&output, "Path: %s\n", strings.Join(path, " > "))
		switch {
		case !result.Target.SCPApplicable:
			output.WriteString("SCPs do not affect this management account's users or roles.\n")
		case len(result.Policies) == 0:
			output.WriteString("SCPs: none\n")
		default:
			for _, policy := range result.Policies {
				fmt.Fprintln(&output, scpAttachmentText(policy))
			}
		}
		return writeDocument(writer, []byte(output.String()), "policies query")
	}
	return writeJSONDocument(writer, result, "policies query")
}

func writeAttachmentsQuery(writer io.Writer, result attachmentsQueryResult, outputFormat outputFormat) error {
	if outputFormat == text {
		var output strings.Builder
		if result.PolicyName == "" {
			fmt.Fprintf(&output, "SCP [%s]\n", displayText(result.PolicyID))
		} else {
			fmt.Fprintf(&output, "SCP %s [%s]\n", displayText(result.PolicyName), displayText(result.PolicyID))
		}
		if len(result.DirectTargets) == 0 {
			output.WriteString("Direct attachments: none\n")
		} else {
			output.WriteString("Direct attachments:\n")
			for _, target := range result.DirectTargets {
				label := displayText(attachmentTargetText(scpAttachmentTarget{Type: target.Type, ID: target.ID, Name: target.Name}))
				if !target.SCPApplicable {
					label += " (management account; not affected)"
				}
				fmt.Fprintf(&output, "- %s\n", label)
			}
		}
		if len(result.AffectedTargets) == 0 {
			output.WriteString("Affected targets: none\n")
		} else {
			output.WriteString("Affected targets:\n")
			for _, affected := range result.AffectedTargets {
				fmt.Fprintf(&output, "- %s\n", displayText(attachmentTargetText(scpAttachmentTarget{Type: affected.Target.Type, ID: affected.Target.ID, Name: affected.Target.Name})))
			}
		}
		return writeDocument(writer, []byte(output.String()), "attachments query")
	}
	return writeJSONDocument(writer, result, "attachments query")
}

func writeJSONDocument(writer io.Writer, value any, operation string) error {
	document, err := encodingjson.MarshalIndent(value, "", "  ")
	if err != nil {
		return fmt.Errorf("encode %s as JSON: %w", operation, err)
	}
	return writeDocument(writer, append(document, '\n'), operation)
}

func writeDocument(writer io.Writer, document []byte, operation string) error {
	written, err := writer.Write(document)
	if err == nil && written != len(document) {
		err = io.ErrShortWrite
	}
	if err != nil {
		return fmt.Errorf("write %s: %w", operation, err)
	}
	return nil
}
