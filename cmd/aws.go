/*
Copyright © 2024 Aristides Gonzalez <aristides@glezpol.com>
*/

// Package cmd contains all the commands included in this utility
package cmd

import (
	"context"
	encodingjson "encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	"github.com/aws/aws-sdk-go-v2/service/organizations/types"
	"github.com/spf13/cobra"
)

// Default indentation increment to build a tree like output.
const indent string = "    "

// Defining a custom enum to restrict output format values.
type outputFormat string

const (
	text outputFormat = "text" //nolint:unused
	json outputFormat = "json" //nolint:unused
)

// String is used both by fmt.Print and by Cobra in help text.
func (e *outputFormat) String() string {
	return string(*e)
}

// Set must have pointer receiver so it doesn't change the value of a copy.
func (e *outputFormat) Set(value string) error {
	switch value {
	case "text", "json":
		*e = outputFormat(value)
		return nil
	default:
		return errors.New(`must be one of "text" or "json"`)
	}
}

// Type is only used in help text.
func (e *outputFormat) Type() string {
	return "outputFormat"
}

func outputFormatCompletion(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) { //nolint:unused
	return []string{
		"text\tdisplays results as a text based tree in your terminal",
		"json\tdisplays results formatted in json",
	}, cobra.ShellCompDirectiveDefault
}

type organizationsClient interface {
	organizations.ListChildrenAPIClient
	organizations.ListParentsAPIClient
	organizations.ListPoliciesForTargetAPIClient
	organizations.ListRootsAPIClient
	DescribeAccount(context.Context, *organizations.DescribeAccountInput, ...func(*organizations.Options)) (*organizations.DescribeAccountOutput, error)
	DescribeOrganizationalUnit(context.Context, *organizations.DescribeOrganizationalUnitInput, ...func(*organizations.Options)) (*organizations.DescribeOrganizationalUnitOutput, error)
	DescribeOrganization(context.Context, *organizations.DescribeOrganizationInput, ...func(*organizations.Options)) (*organizations.DescribeOrganizationOutput, error)
}

var (
	accountID string
	format    outputFormat
	awsCmd    = &cobra.Command{
		Use:   "aws",
		Short: "Entrypoint for all AWS interactions",
		RunE: func(cmd *cobra.Command, args []string) error {
			return describeAccount(cmd.Context(), cmd.OutOrStdout(), accountID)
		},
	}
)

func init() {
	rootCmd.AddCommand(awsCmd)

	awsCmd.Flags().StringVar(&accountID, "account-id", "", "aws account ID that will be analyzed")
	awsCmd.MarkFlagRequired("account-id") //nolint:gosec,errcheck

	awsCmd.Flags().VarP(&format, "output-format", "o", `valid output formats are: "text", "json"`)
	awsCmd.MarkFlagRequired("output-format") //nolint:gosec,errcheck
}

// describeAccount computes the information requested from the target AWS account.
func describeAccount(ctx context.Context, writer io.Writer, targetAccountID string) error {
	if err := validateAccountID(targetAccountID); err != nil {
		return err
	}

	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return fmt.Errorf("load AWS configuration: %w", err)
	}
	client := organizations.NewFromConfig(cfg)

	rootID, err := getRootID(ctx, client)
	if err != nil {
		return fmt.Errorf("get organization root ID: %w", err)
	}

	managementAccountID, err := getManagementAccountID(ctx, client)
	if err != nil {
		return err
	}

	switch format {
	case "json":
		return displayOrganizationTreeJSON(ctx, writer, client, targetAccountID, rootID, managementAccountID)
	default:
		return displayOrganizationTreeText(ctx, writer, client, targetAccountID, rootID, managementAccountID)
	}
}

type organizationJSONNode struct {
	Type              string                 `json:"type"`
	ID                string                 `json:"id"`
	Name              string                 `json:"name,omitempty"`
	ManagementAccount bool                   `json:"management_account,omitempty"`
	SCPs              []string               `json:"scps,omitempty"`
	Children          []organizationJSONNode `json:"children,omitempty"`
}

func displayOrganizationTreeJSON(
	ctx context.Context,
	writer io.Writer,
	client organizationsClient,
	targetAccountID, rootID, managementAccountID string,
) error {
	root := organizationJSONNode{Type: "root", ID: rootID}
	policyCache := map[string][]types.PolicySummary{}

	var err error
	if strings.EqualFold(targetAccountID, "all") {
		root.Children, err = buildOrganizationJSONChildren(
			ctx,
			client,
			rootID,
			managementAccountID,
			[]string{rootID},
			map[string]bool{},
			map[string]bool{},
			policyCache,
		)
	} else {
		root.Children, err = buildAccountPathJSON(ctx, client, targetAccountID, rootID, managementAccountID, policyCache)
	}
	if err != nil {
		return err
	}

	encoder := encodingjson.NewEncoder(writer)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(root); err != nil {
		return fmt.Errorf("encode organization as JSON: %w", err)
	}
	return nil
}

func buildAccountPathJSON(
	ctx context.Context,
	client organizationsClient,
	targetAccountID, rootID, managementAccountID string,
	policyCache map[string][]types.PolicySummary,
) ([]organizationJSONNode, error) {
	account, err := getAccount(ctx, client, targetAccountID)
	if err != nil {
		return nil, fmt.Errorf("describe account %s: %w", targetAccountID, err)
	}

	path := []string{targetAccountID}
	visited := map[string]bool{targetAccountID: true}
	for childID := targetAccountID; childID != rootID; {
		parents, err := listParents(ctx, client, childID)
		if err != nil {
			return nil, fmt.Errorf("list parents for %s: %w", childID, err)
		}
		if len(parents) != 1 {
			return nil, fmt.Errorf("expected exactly one parent for %s, got %d", childID, len(parents))
		}
		parentID := aws.ToString(parents[0].Id)
		if parents[0].Type == types.ParentTypeRoot && parentID != rootID {
			return nil, fmt.Errorf("AWS returned root parent %s, expected %s", parentID, rootID)
		}
		if visited[parentID] {
			return nil, fmt.Errorf("cycle detected in organization hierarchy at %s", parentID)
		}
		visited[parentID] = true
		path = append(path, parentID)
		childID = parentID
	}

	accountPath := make([]string, len(path))
	for index := range path {
		accountPath[len(path)-1-index] = path[index]
	}
	accountNode, err := buildAccountJSONNode(
		ctx, client, targetAccountID, aws.ToString(account.Name), managementAccountID, accountPath, policyCache,
	)
	if err != nil {
		return nil, err
	}

	child := accountNode
	for index := 1; index < len(accountPath)-1; index++ {
		ouID := accountPath[len(accountPath)-1-index]
		ou, err := getOU(ctx, client, ouID)
		if err != nil {
			return nil, fmt.Errorf("get organizational unit %s: %w", ouID, err)
		}
		child = organizationJSONNode{
			Type:     "organizational_unit",
			ID:       ouID,
			Name:     aws.ToString(ou.Name),
			Children: []organizationJSONNode{child},
		}
	}
	return []organizationJSONNode{child}, nil
}

func buildOrganizationJSONChildren(
	ctx context.Context,
	client organizationsClient,
	parentID, managementAccountID string,
	ancestors []string,
	completed, active map[string]bool,
	policyCache map[string][]types.PolicySummary,
) ([]organizationJSONNode, error) {
	if active[parentID] {
		return nil, fmt.Errorf("cycle detected in organization hierarchy at %s", parentID)
	}
	active[parentID] = true
	defer delete(active, parentID)

	var nodes []organizationJSONNode
	accounts, err := listChildren(ctx, client, parentID, types.ChildTypeAccount)
	if err != nil {
		return nil, fmt.Errorf("list accounts for %s: %w", parentID, err)
	}
	for _, child := range accounts {
		accountID := aws.ToString(child.Id)
		if active[accountID] {
			return nil, fmt.Errorf("cycle detected in organization hierarchy at %s", accountID)
		}
		if completed[accountID] {
			continue
		}
		account, err := getAccount(ctx, client, accountID)
		if err != nil {
			return nil, fmt.Errorf("get account %s: %w", accountID, err)
		}
		node, err := buildAccountJSONNode(
			ctx, client, accountID, aws.ToString(account.Name), managementAccountID, appendPath(ancestors, accountID), policyCache,
		)
		if err != nil {
			return nil, err
		}
		nodes = append(nodes, node)
		completed[accountID] = true
	}

	organizationalUnits, err := listChildren(ctx, client, parentID, types.ChildTypeOrganizationalUnit)
	if err != nil {
		return nil, fmt.Errorf("list organizational units for %s: %w", parentID, err)
	}
	for _, child := range organizationalUnits {
		ouID := aws.ToString(child.Id)
		if active[ouID] {
			return nil, fmt.Errorf("cycle detected in organization hierarchy at %s", ouID)
		}
		if completed[ouID] {
			continue
		}
		ou, err := getOU(ctx, client, ouID)
		if err != nil {
			return nil, fmt.Errorf("get organizational unit %s: %w", ouID, err)
		}
		children, err := buildOrganizationJSONChildren(
			ctx, client, ouID, managementAccountID, appendPath(ancestors, ouID), completed, active, policyCache,
		)
		if err != nil {
			return nil, err
		}
		nodes = append(nodes, organizationJSONNode{
			Type:     "organizational_unit",
			ID:       ouID,
			Name:     aws.ToString(ou.Name),
			Children: children,
		})
	}

	completed[parentID] = true
	return nodes, nil
}

func buildAccountJSONNode(
	ctx context.Context,
	client organizationsClient,
	accountID, accountName, managementAccountID string,
	path []string,
	policyCache map[string][]types.PolicySummary,
) (organizationJSONNode, error) {
	node := organizationJSONNode{Type: "account", ID: accountID, Name: accountName}
	if accountID == managementAccountID {
		node.ManagementAccount = true
		return node, nil
	}

	scpNames, err := listSCPsForPath(ctx, client, path, policyCache)
	if err != nil {
		return organizationJSONNode{}, fmt.Errorf("get SCPs for account %s: %w", accountID, err)
	}
	node.SCPs = scpNames
	return node, nil
}

func writeOutput(writer io.Writer, outputFormat string, values ...any) error {
	_, err := fmt.Fprintf(writer, outputFormat, values...)
	return err
}

func displayOrganizationTreeText(
	ctx context.Context,
	writer io.Writer,
	client organizationsClient,
	targetAccountID, rootID, managementAccountID string,
) error {
	if strings.EqualFold(targetAccountID, "all") {
		if err := writeOutput(writer, "|-- Root: [%s]\n", rootID); err != nil {
			return err
		}
		return printEntireOrg(
			ctx,
			writer,
			client,
			rootID,
			indent,
			managementAccountID,
			[]string{rootID},
			map[string]bool{},
			map[string]bool{},
			map[string][]types.PolicySummary{},
		)
	}

	return printPathToAccount(ctx, writer, client, rootID, targetAccountID, managementAccountID)
}

func printPathToAccount(
	ctx context.Context,
	writer io.Writer,
	client organizationsClient,
	rootID, targetAccountID, managementAccountID string,
) error {
	account, err := getAccount(ctx, client, targetAccountID)
	if err != nil {
		return fmt.Errorf("describe account %s: %w", targetAccountID, err)
	}

	path := []string{targetAccountID}
	visited := map[string]bool{targetAccountID: true}
	childID := targetAccountID
	for childID != rootID {
		parents, err := listParents(ctx, client, childID)
		if err != nil {
			return fmt.Errorf("list parents for %s: %w", childID, err)
		}
		if len(parents) != 1 {
			return fmt.Errorf("expected exactly one parent for %s, got %d", childID, len(parents))
		}

		parentID := aws.ToString(parents[0].Id)
		if parents[0].Type == types.ParentTypeRoot && parentID != rootID {
			return fmt.Errorf("AWS returned root parent %s, expected %s", parentID, rootID)
		}
		if visited[parentID] {
			return fmt.Errorf("cycle detected in organization hierarchy at %s", parentID)
		}
		visited[parentID] = true
		path = append(path, parentID)
		childID = parentID
	}

	for left, right := 0, len(path)-1; left < right; left, right = left+1, right-1 {
		path[left], path[right] = path[right], path[left]
	}

	prefix := ""
	for _, entityID := range path {
		switch {
		case entityID == rootID:
			if err := writeOutput(writer, "|-- Root: [%s]\n", entityID); err != nil {
				return err
			}
		case strings.HasPrefix(entityID, "ou-"):
			name, err := getNameByID(ctx, client, entityID)
			if err != nil {
				return fmt.Errorf("get name for %s: %w", entityID, err)
			}
			if err := writeOutput(writer, "%s|-- OU: %s [%s]\n", prefix, name, entityID); err != nil {
				return err
			}
		default:
			if err := printAccount(
				ctx,
				writer,
				client,
				prefix,
				entityID,
				aws.ToString(account.Name),
				managementAccountID,
				path,
				map[string][]types.PolicySummary{},
			); err != nil {
				return err
			}
		}
		prefix += indent
	}

	return nil
}

// printEntireOrg traverses each OU exactly once using depth-first traversal.
func printEntireOrg(
	ctx context.Context,
	writer io.Writer,
	client organizationsClient,
	parentID, prefix, managementAccountID string,
	ancestors []string,
	completed, active map[string]bool,
	policyCache map[string][]types.PolicySummary,
) error {
	if active[parentID] {
		return fmt.Errorf("cycle detected in organization hierarchy at %s", parentID)
	}
	active[parentID] = true
	defer delete(active, parentID)

	childAccounts, err := listChildren(ctx, client, parentID, types.ChildTypeAccount)
	if err != nil {
		return fmt.Errorf("list accounts for %s: %w", parentID, err)
	}
	for _, child := range childAccounts {
		childID := aws.ToString(child.Id)
		if active[childID] {
			return fmt.Errorf("cycle detected in organization hierarchy at %s", childID)
		}
		if completed[childID] {
			continue
		}

		account, err := getAccount(ctx, client, childID)
		if err != nil {
			return fmt.Errorf("get account %s: %w", childID, err)
		}
		accountPath := appendPath(ancestors, childID)
		if err := printAccount(
			ctx,
			writer,
			client,
			prefix,
			childID,
			aws.ToString(account.Name),
			managementAccountID,
			accountPath,
			policyCache,
		); err != nil {
			return err
		}
		completed[childID] = true
	}

	childOUs, err := listChildren(ctx, client, parentID, types.ChildTypeOrganizationalUnit)
	if err != nil {
		return fmt.Errorf("list organizational units for %s: %w", parentID, err)
	}
	for _, child := range childOUs {
		childID := aws.ToString(child.Id)
		if active[childID] {
			return fmt.Errorf("cycle detected in organization hierarchy at %s", childID)
		}
		if completed[childID] {
			continue
		}

		ou, err := getOU(ctx, client, childID)
		if err != nil {
			return fmt.Errorf("get organizational unit %s: %w", childID, err)
		}
		if err := writeOutput(writer, "%s|-- OU: %s [%s]\n", prefix, aws.ToString(ou.Name), childID); err != nil {
			return err
		}
		if err := printEntireOrg(
			ctx,
			writer,
			client,
			childID,
			prefix+indent,
			managementAccountID,
			appendPath(ancestors, childID),
			completed,
			active,
			policyCache,
		); err != nil {
			return err
		}
	}

	completed[parentID] = true
	return nil
}

func appendPath(path []string, entityID string) []string {
	result := make([]string, len(path), len(path)+1)
	copy(result, path)
	return append(result, entityID)
}

func printAccount(
	ctx context.Context,
	writer io.Writer,
	client organizationsClient,
	prefix, accountID, accountName, managementAccountID string,
	path []string,
	policyCache map[string][]types.PolicySummary,
) error {
	if accountID == managementAccountID {
		return writeOutput(
			writer,
			"%s|-- Account: %s (Management Account) [%s] (SCPs: not enforced)\n",
			prefix,
			accountName,
			accountID,
		)
	}

	scpNames, err := listSCPsForPath(ctx, client, path, policyCache)
	if err != nil {
		return fmt.Errorf("get SCPs for account %s: %w", accountID, err)
	}
	return writeOutput(writer, "%s|-- Account: %s [%s] (SCPs: %s)\n", prefix, accountName, accountID, strings.Join(scpNames, ", "))
}

// listChildren lists all children of the requested type, across every response page.
func listChildren(ctx context.Context, client organizations.ListChildrenAPIClient, parentID string, childType types.ChildType) ([]types.Child, error) {
	input := &organizations.ListChildrenInput{ParentId: &parentID, ChildType: childType}
	paginator := organizations.NewListChildrenPaginator(client, input)

	var children []types.Child
	seen := make(map[string]bool)
	seenTokens := make(map[string]bool)
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		if err := rejectRepeatedToken(seenTokens, page.NextToken, "ListChildren"); err != nil {
			return nil, err
		}
		for _, child := range page.Children {
			childID := aws.ToString(child.Id)
			if childID == "" {
				return nil, fmt.Errorf("AWS returned a %s child without an ID for parent %s", childType, parentID)
			}
			if child.Type != childType {
				return nil, fmt.Errorf("AWS returned child %s with type %s, expected %s", childID, child.Type, childType)
			}
			if !seen[childID] {
				seen[childID] = true
				children = append(children, child)
			}
		}
	}
	return children, nil
}

func getAccount(ctx context.Context, client organizationsClient, targetAccountID string) (*types.Account, error) {
	result, err := client.DescribeAccount(ctx, &organizations.DescribeAccountInput{AccountId: &targetAccountID})
	if err != nil {
		return nil, err
	}
	if result == nil || result.Account == nil {
		return nil, errors.New("AWS returned no account details")
	}
	if aws.ToString(result.Account.Id) != targetAccountID {
		return nil, fmt.Errorf("AWS returned account ID %q for requested account %s", aws.ToString(result.Account.Id), targetAccountID)
	}
	if aws.ToString(result.Account.Name) == "" {
		return nil, fmt.Errorf("AWS returned no name for account %s", targetAccountID)
	}
	return result.Account, nil
}

func getOU(ctx context.Context, client organizationsClient, ouID string) (*types.OrganizationalUnit, error) {
	result, err := client.DescribeOrganizationalUnit(ctx, &organizations.DescribeOrganizationalUnitInput{OrganizationalUnitId: &ouID})
	if err != nil {
		return nil, err
	}
	if result == nil || result.OrganizationalUnit == nil {
		return nil, errors.New("AWS returned no organizational unit details")
	}
	if aws.ToString(result.OrganizationalUnit.Id) != ouID {
		return nil, fmt.Errorf(
			"AWS returned organizational unit ID %q for requested organizational unit %s",
			aws.ToString(result.OrganizationalUnit.Id),
			ouID,
		)
	}
	if aws.ToString(result.OrganizationalUnit.Name) == "" {
		return nil, fmt.Errorf("AWS returned no name for organizational unit %s", ouID)
	}
	return result.OrganizationalUnit, nil
}

// listSCPsForTarget lists all SCPs directly attached to targetID across every response page.
func listSCPsForTarget(ctx context.Context, client organizations.ListPoliciesForTargetAPIClient, targetID string) ([]types.PolicySummary, error) {
	input := &organizations.ListPoliciesForTargetInput{TargetId: &targetID, Filter: types.PolicyTypeServiceControlPolicy}
	paginator := organizations.NewListPoliciesForTargetPaginator(client, input)

	var policies []types.PolicySummary
	seenTokens := make(map[string]bool)
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		if err := rejectRepeatedToken(seenTokens, page.NextToken, "ListPoliciesForTarget"); err != nil {
			return nil, err
		}
		for _, policy := range page.Policies {
			if aws.ToString(policy.Id) == "" {
				return nil, fmt.Errorf("AWS returned an SCP without an ID for target %s", targetID)
			}
			if !validPolicyID(aws.ToString(policy.Id)) {
				return nil, fmt.Errorf("AWS returned SCP with invalid ID %q for target %s", aws.ToString(policy.Id), targetID)
			}
			if aws.ToString(policy.Name) == "" {
				return nil, fmt.Errorf("AWS returned SCP %s without a name for target %s", aws.ToString(policy.Id), targetID)
			}
			if policy.Type != types.PolicyTypeServiceControlPolicy {
				return nil, fmt.Errorf("AWS returned policy %s with type %s, expected SERVICE_CONTROL_POLICY", aws.ToString(policy.Id), policy.Type)
			}
			policies = append(policies, policy)
		}
	}
	return policies, nil
}

func getManagementAccountID(ctx context.Context, client organizationsClient) (string, error) {
	result, err := client.DescribeOrganization(ctx, &organizations.DescribeOrganizationInput{})
	if err != nil {
		return "", fmt.Errorf("describe organization: %w", err)
	}
	if result == nil || result.Organization == nil || aws.ToString(result.Organization.MasterAccountId) == "" {
		return "", errors.New("AWS returned no management account ID")
	}
	managementAccountID := aws.ToString(result.Organization.MasterAccountId)
	if err := validateStrictAccountID(managementAccountID); err != nil {
		return "", fmt.Errorf("AWS returned invalid management account ID %q: %w", managementAccountID, err)
	}
	return managementAccountID, nil
}

// getRootID returns the organization's only root after consuming all response pages.
func getRootID(ctx context.Context, client organizations.ListRootsAPIClient) (string, error) {
	paginator := organizations.NewListRootsPaginator(client, &organizations.ListRootsInput{})

	rootIDs := make(map[string]bool)
	seenTokens := make(map[string]bool)
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return "", err
		}
		if err := rejectRepeatedToken(seenTokens, page.NextToken, "ListRoots"); err != nil {
			return "", err
		}
		for _, root := range page.Roots {
			rootID := aws.ToString(root.Id)
			if rootID == "" {
				return "", errors.New("organization root has no ID")
			}
			rootIDs[rootID] = true
		}
	}
	if len(rootIDs) != 1 {
		return "", fmt.Errorf("expected exactly one organization root, got %d", len(rootIDs))
	}
	for rootID := range rootIDs {
		return rootID, nil
	}
	return "", errors.New("no roots found in the organization")
}

func getNameByID(ctx context.Context, client organizationsClient, entityID string) (string, error) {
	if validateAccountID(entityID) == nil {
		account, err := getAccount(ctx, client, entityID)
		if err != nil {
			return "", fmt.Errorf("get account: %w", err)
		}
		return aws.ToString(account.Name), nil
	}
	if strings.HasPrefix(entityID, "r-") {
		return "Root", nil
	}

	ou, err := getOU(ctx, client, entityID)
	if err != nil {
		return "", fmt.Errorf("get OU: %w", err)
	}
	return aws.ToString(ou.Name), nil
}

// listParents consumes every response page for the target entity.
func listParents(ctx context.Context, client organizations.ListParentsAPIClient, entityID string) ([]types.Parent, error) {
	paginator := organizations.NewListParentsPaginator(client, &organizations.ListParentsInput{ChildId: &entityID})

	var parents []types.Parent
	seen := make(map[string]bool)
	seenTokens := make(map[string]bool)
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		if err := rejectRepeatedToken(seenTokens, page.NextToken, "ListParents"); err != nil {
			return nil, err
		}
		for _, parent := range page.Parents {
			parentID := aws.ToString(parent.Id)
			if parentID == "" {
				return nil, fmt.Errorf("AWS returned a parent without an ID for %s", entityID)
			}
			switch parent.Type {
			case types.ParentTypeRoot:
				if !strings.HasPrefix(parentID, "r-") {
					return nil, fmt.Errorf("AWS returned root parent with invalid ID %s for %s", parentID, entityID)
				}
			case types.ParentTypeOrganizationalUnit:
				if !strings.HasPrefix(parentID, "ou-") {
					return nil, fmt.Errorf("AWS returned organizational unit parent with invalid ID %s for %s", parentID, entityID)
				}
			default:
				return nil, fmt.Errorf("AWS returned parent %s with invalid type %s for %s", parentID, parent.Type, entityID)
			}
			if !seen[parentID] {
				seen[parentID] = true
				parents = append(parents, parent)
			}
		}
	}
	return parents, nil
}

// listSCPsForPath lists the direct and inherited SCP names for one known hierarchy path.
func listSCPsForPath(
	ctx context.Context,
	client organizationsClient,
	path []string,
	policyCache map[string][]types.PolicySummary,
) ([]string, error) {
	namesByID := make(map[string]string)
	IDsByName := make(map[string]string)
	var scpNames []string
	for _, entityID := range path {
		policies, found := policyCache[entityID]
		if !found {
			var err error
			policies, err = listSCPsForTarget(ctx, client, entityID)
			if err != nil {
				return nil, fmt.Errorf("list SCPs for %s: %w", entityID, err)
			}
			policyCache[entityID] = policies
		}
		for _, policy := range policies {
			policyID := aws.ToString(policy.Id)
			policyName := aws.ToString(policy.Name)
			if existingName, found := namesByID[policyID]; found && existingName != policyName {
				return nil, fmt.Errorf("SCP %s has conflicting names %q and %q", policyID, existingName, policyName)
			}
			if existingID, found := IDsByName[policyName]; found && existingID != policyID {
				return nil, fmt.Errorf("SCP name %q has conflicting IDs %s and %s", policyName, existingID, policyID)
			}
			if _, found := namesByID[policyID]; !found {
				namesByID[policyID] = policyName
				IDsByName[policyName] = policyID
				scpNames = append(scpNames, policyName)
			}
		}
	}
	sort.Strings(scpNames)
	return scpNames, nil
}

func validateAccountID(value string) error {
	if strings.EqualFold(value, "all") {
		return nil
	}
	return validateStrictAccountID(value)
}

func validateStrictAccountID(value string) error {
	if len(value) != 12 {
		return errors.New("account ID must be exactly 12 digits")
	}
	for _, character := range value {
		if character < '0' || character > '9' {
			return errors.New("account ID must be exactly 12 digits")
		}
	}
	return nil
}

func rejectRepeatedToken(seen map[string]bool, token *string, operation string) error {
	value := aws.ToString(token)
	if value == "" {
		return nil
	}
	if seen[value] {
		return fmt.Errorf("%s returned repeated pagination token %q", operation, value)
	}
	seen[value] = true
	return nil
}

func validPolicyID(policyID string) bool {
	if !strings.HasPrefix(policyID, "p-") || len(policyID) < 10 || len(policyID) > 130 {
		return false
	}
	for _, character := range policyID[2:] {
		if (character < '0' || character > '9') &&
			(character < 'A' || character > 'Z') &&
			(character < 'a' || character > 'z') &&
			character != '_' {
			return false
		}
	}
	return true
}
