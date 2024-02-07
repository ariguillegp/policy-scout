/*
Copyright © 2024 Aristides Gonzalez <aristides@glezpol.com>
*/

// Package cmd contains all the commands included in this utility
package cmd

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	"github.com/aws/aws-sdk-go-v2/service/organizations/types"
	"github.com/spf13/cobra"
)

const indent string = "    "

// Defining a custom enum to restrict output format values.
type outputFormat string

const (
	text outputFormat = "text" //nolint:unused
	json outputFormat = "json" //nolint:unused
	dot  outputFormat = "dot"  //nolint:unused
)

// String is used both by fmt.Print and by Cobra in help text.
func (e *outputFormat) String() string {
	return string(*e)
}

// Set must have pointer receiver so it doesn't change the value of a copy.
func (e *outputFormat) Set(v string) error {
	switch v {
	case "text", "json", "dot":
		*e = outputFormat(v)
		return nil
	default:
		return errors.New(`must be one of "text", "json", or "dot"`)
	}
}

// Type is only used in help text.
func (e *outputFormat) Type() string {
	return "outputFormat"
}

// myEnumCompletion should probably live next to the myEnum definition.
func outputFormatCompletion(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) { //nolint:unused
	return []string{
		"text\tdisplays results as a text based tree in yout terminal",
		"json\tdisplays results formatted in json",
		"dot\tgenerates a dot file with the results",
	}, cobra.ShellCompDirectiveDefault
}

// awsCmd represents the aws command.
var (
	accountID string // AWS account ID that wil be verified
	format    outputFormat
	awsCmd    = &cobra.Command{
		Use:   "aws",
		Short: "Entrypoint for all AWS interactions",
		Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return describeAccount(accountID)
		},
	}
)

func init() {
	rootCmd.AddCommand(awsCmd)

	// Not using shorthand value for account id for the sake of UX
	awsCmd.Flags().StringVar(&accountID, "account-id", "", "aws account ID that will be analyzed")
	awsCmd.MarkFlagRequired("account-id") //nolint:gosec,errcheck

	awsCmd.Flags().VarP(&format, "output-format", "o", `valid output formats are: "text", "json", "dot"`)
	awsCmd.MarkFlagRequired("output-format") //nolint:gosec,errcheck
}

// describeAccount computes the information requested from the target AWS account.
func describeAccount(targetAccountID string) error {
	// Load AWS config
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		return err
	}

	// Creating organizations client with local AWS config
	client := organizations.NewFromConfig(cfg)

	// Get the root ID of AWS the organization
	rootID, err := getRootID(client)
	if err != nil {
		return fmt.Errorf("couldn't get organization's root ID: %v", err)
	}

	// Make sure the output is properly formatted
	switch format {
	case "dot":
		return displayOrganizationTreeDot()
	case "json":
		return displayOrganizationTreeJSON()
	default: // (text) Using default even though format is an enum to prevent an LSP error (missing return)
		return displayOrganizationTreeText(client, targetAccountID, rootID, "", map[string]bool{})
	}
}

// TODO. JSON Output implementation.
func displayOrganizationTreeJSON() error {
	fmt.Println("JSON Output")
	return nil
}

// TODO. Dot (graphviz) Output implementation.
func displayOrganizationTreeDot() error {
	fmt.Println("Dot Output")
	return nil
}

// Text based output.
func displayOrganizationTreeText(client *organizations.Client, targetAccountID, rootID, prefix string, visited map[string]bool) error {
	if strings.ToLower(targetAccountID) == "all" {
		fmt.Printf("%s|-- Root: [%s]\n", prefix, rootID)
		return printEntireOrg(client, rootID, prefix+indent, visited)
	} else {
		return printPathToAccount(client, rootID, targetAccountID)
	}
}

func printPathToAccount(client *organizations.Client, rootID string, targetAccountID string) error {
	type node struct {
		path []string
		id   string
	}

	// Org processing will start from the root node (id: r-xxxxx).
	queue := []node{
		{
			path: []string{rootID},
			id:   rootID,
		},
	}

	// While we still have nodes to process
	for len(queue) > 0 {
		// Pull the next node from the processing queue
		currentNode := queue[0]
		queue = queue[1:]

		// List accounts
		childAccounts, err := listChildren(client, currentNode.id, types.ChildTypeAccount)
		if err != nil {
			return fmt.Errorf("error listing accounts: %w", err)
		}

		// List organizational units
		childOUs, err := listChildren(client, currentNode.id, types.ChildTypeOrganizationalUnit)
		if err != nil {
			return fmt.Errorf("error listing organizational units: %w", err)
		}

		// Check if the target account ID is among the children
		for _, child := range childAccounts {
			childID := *child.Id
			// tracking path from root node
			newPath := append(currentNode.path, childID) // nolint:gocritic

			// If the current child matches the target ID, return the path
			if childID == targetAccountID {
				prefix := ""
				for _, id := range newPath {
					// to get account and OU names
					name, err := getNameByID(client, id)
					if err != nil {
						return fmt.Errorf("error getting name for id [%s]: %v", id, err)
					}
					// displays tree like output
					switch {
					case strings.HasPrefix(id, "r-"):
						fmt.Printf("%s|-- Root: [%s]\n", "", id)
					case strings.HasPrefix(id, "ou-"):
						fmt.Printf("%s|-- OU: %s [%s]\n", prefix, name, id)
					default:
						// The org management account will be highlighted in the resulting dataset
						isManagementAccount := isManagementAccount(client, id)
						if isManagementAccount {
							name += " (Management Account)"
						}
						allSCPs, err := listAllSCPsForChild(client, id)
						if err != nil {
							return fmt.Errorf("error listing SCPs: %w", err)
						}

						// using a map here to remove duplicated SCPs (common with inherited policies)
						// in this case I don't really care about the values, just the keys in the map
						unique := make(map[string]bool)
						// just to make it easier to display via strings.Join instead of an additional loop
						var scpNames []string
						for _, scp := range allSCPs {
							if _, ok := unique[*scp.Name]; !ok {
								unique[*scp.Name] = true
								scpNames = append(scpNames, *scp.Name)
							}
						}

						fmt.Printf("%s|-- Account: %s [%s] (SCPs: %s)\n", prefix, name, id, strings.Join(scpNames, ", "))
					}
					prefix += "    "
				}
				return nil
			}
		}

		for _, child := range childOUs {
			childID := *child.Id
			// tracking path from root node.
			newPath := append(currentNode.path, childID) // nolint:gocritic
			// Enqueue the child node for further exploration.
			queue = append(queue, node{path: newPath, id: childID})
		}
	}

	// If the target account ID was not found, return an error.
	fmt.Printf("Target account ID %s was not found in the organization", targetAccountID)
	return nil
}

// Traverses the org tree using BFS and prints it completely.
func printEntireOrg(client *organizations.Client, rootID, prefix string, visited map[string]bool) error {
	toBeProcessed := []string{rootID}

	for len(toBeProcessed) > 0 {
		parentID := toBeProcessed[0]
		toBeProcessed = toBeProcessed[1:]

		// List accounts
		childAccounts, err := listChildren(client, parentID, types.ChildTypeAccount)
		if err != nil {
			return fmt.Errorf("error listing accounts: %w", err)
		}

		// List organizational units
		childOUs, err := listChildren(client, parentID, types.ChildTypeOrganizationalUnit)
		if err != nil {
			return fmt.Errorf("error listing organizational units: %w", err)
		}

		// Display accounts in a tree-like format.
		for _, child := range childAccounts {
			childID := *child.Id
			// Don't process the same entities (accounts | OUs) more then once.
			if visited[childID] {
				continue
			}

			// The org management account will be highlighted in the resulting dataset.
			isManagementAccount := isManagementAccount(client, childID)
			accountName, err := getNameByID(client, childID)
			if err != nil {
				return fmt.Errorf("error getting name for id %s: %v", childID, err)
			}

			if isManagementAccount {
				accountName += " (Management Account)"
			}

			allSCPs, err := listAllSCPsForChild(client, childID)
			if err != nil {
				return fmt.Errorf("error listing SCPs: %w", err)
			}

			// using a map here to remove duplicated SCPs (common with inherited policies)
			// in this case I don't really care about the values, just the keys in the map
			unique := make(map[string]bool)
			// just to make it easier to display via strings.Join instead of an additional loop
			var scpNames []string
			for _, scp := range allSCPs {
				if _, ok := unique[*scp.Name]; !ok {
					unique[*scp.Name] = true
					scpNames = append(scpNames, *scp.Name)
				}
			}

			fmt.Printf("%s|-- Account: %s [%s] (SCPs: %s)\n", prefix, accountName, childID, strings.Join(scpNames, ", "))

			// Mark the account as processed
			visited[childID] = true
		}

		// Display OUs in a tree-like format
		for _, child := range childOUs {
			childID := *child.Id
			if visited[childID] {
				continue
			}

			ouName, err := getNameByID(client, childID)
			if err != nil {
				return fmt.Errorf("error getting name for id %s: %v", childID, err)
			}

			fmt.Printf("%s|-- OU: %s [%s]\n", prefix, ouName, childID)

			// Mark the OU as processed
			visited[childID] = true

			// Add child OU to the queue for further processing
			// Only the OU nodes have children (another OUs or member accounts)
			toBeProcessed = append(toBeProcessed, childID)

			// // Make a recursive call with an updated prefix and processedEntities
			if err := printEntireOrg(client, childID, prefix+"    ", visited); err != nil {
				return err
			}
		}
	}
	return nil
}

// Lists all children of current node. childtype determines whether we return accounts or OUs.
func listChildren(client *organizations.Client, parentID string, childType types.ChildType) ([]types.Child, error) {
	input := &organizations.ListChildrenInput{
		ParentId:  &parentID,
		ChildType: childType,
	}

	result, err := client.ListChildren(context.TODO(), input)
	if err != nil {
		return nil, err
	}

	return result.Children, nil
}

// To obtain more account metadata.
func getAccount(client *organizations.Client, accountID string) (*types.Account, error) {
	input := &organizations.DescribeAccountInput{
		AccountId: &accountID,
	}

	result, err := client.DescribeAccount(context.TODO(), input)
	if err != nil {
		return nil, err
	}

	return result.Account, nil
}

// To obtain more OU metadata.
func getOU(client *organizations.Client, ouID string) (*types.OrganizationalUnit, error) {
	input := &organizations.DescribeOrganizationalUnitInput{
		OrganizationalUnitId: &ouID,
	}

	result, err := client.DescribeOrganizationalUnit(context.TODO(), input)
	if err != nil {
		return nil, err
	}

	return result.OrganizationalUnit, nil
}

// Lists all the SCPs directly attached to targetID (OU or account).
func listSCPsForTarget(client *organizations.Client, targetID string) ([]types.PolicySummary, error) {
	input := &organizations.ListPoliciesForTargetInput{
		TargetId: &targetID,
		Filter:   types.PolicyTypeServiceControlPolicy,
	}

	result, err := client.ListPoliciesForTarget(context.TODO(), input)
	if err != nil {
		return nil, err
	}

	return result.Policies, nil
}

// Decides whether accountID corresponds to the management acccount of the org.
func isManagementAccount(client *organizations.Client, accountID string) bool {
	input := &organizations.DescribeOrganizationInput{}

	result, err := client.DescribeOrganization(context.TODO(), input)
	if err != nil {
		return false
	}

	return *result.Organization.MasterAccountId == accountID
}

// Get root ID deom your AWS.
func getRootID(client *organizations.Client) (string, error) {
	roots, err := client.ListRoots(context.TODO(), &organizations.ListRootsInput{})
	if err != nil {
		return "", err
	}

	if len(roots.Roots) == 0 {
		return "", fmt.Errorf("no roots found in the organization")
	}

	return *roots.Roots[0].Id, nil
}

// Obtains resource name given its ID. Useful for returning info to the users.
func getNameByID(client *organizations.Client, entityID string) (string, error) {
	// Check if the entityID is a valid AWS account ID
	if _, err := strconv.Atoi(entityID); err == nil && len(entityID) == 12 {
		account, err := getAccount(client, entityID)
		if err != nil {
			return "", fmt.Errorf("error getting account: %w", err)
		}
		return *account.Name, nil
	} else if strings.HasPrefix(entityID, "r-") {
		return "Root", nil
	} else {
		// Assume it's an organizational unit
		ou, err := getOU(client, entityID)
		if err != nil {
			return "", fmt.Errorf("error getting OU: %w", err)
		}
		return *ou.Name, nil
	}
}

// Recursive function to list all SCPs associated with a child and its parent OUs.
func listAllSCPsForChild(client *organizations.Client, childID string) ([]types.PolicySummary, error) {
	var allSCPs []types.PolicySummary

	// List SCPs directly attached to the child
	directSCPs, err := listSCPsForTarget(client, childID)
	if err != nil {
		return nil, err
	}
	allSCPs = append(allSCPs, directSCPs...)

	// List parent OUs of the child
	if !strings.HasPrefix(childID, "r-") {
		parentOUs, err := listParentOUs(client, childID)
		if err != nil {
			return nil, err
		}

		// Recursively list SCPs for each parent OU
		for _, ou := range parentOUs {
			ouSCPs, err := listAllSCPsForChild(client, *ou.Id)
			if err != nil {
				return nil, err
			}
			allSCPs = append(allSCPs, ouSCPs...)
		}
	}

	return allSCPs, nil
}

// List parent OUs for a given entity ID.
func listParentOUs(client *organizations.Client, entityID string) ([]types.OrganizationalUnit, error) {
	var parentOUs []types.OrganizationalUnit

	// List parent OUs
	response, err := client.ListParents(context.TODO(), &organizations.ListParentsInput{
		ChildId: &entityID,
	})
	if err != nil {
		return nil, err
	}

	// Extract parent OUs from the response
	for _, ou := range response.Parents {
		parentOUs = append(parentOUs, types.OrganizationalUnit{Id: ou.Id})
	}

	return parentOUs, nil
}
