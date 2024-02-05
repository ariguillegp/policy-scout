/*
Copyright © 2024 Aristides Gonzalez <aristides@glezpol.com>
*/

// Package cmd contains all the commands included in this utility
package cmd

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	"github.com/aws/aws-sdk-go-v2/service/organizations/types"
	"github.com/spf13/cobra"
)

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

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// awsCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:

	// Not using shorthand value for account id for the sake of UX
	awsCmd.Flags().StringVar(&accountID, "account-id", "", "aws account ID that will be analyzed")
	awsCmd.MarkFlagRequired("account-id") //nolint:gosec,errcheck

	awsCmd.Flags().VarP(&format, "output-format", "o", `valid output formats are: "text", "json", "dot"`)
	awsCmd.MarkFlagRequired("output-format") //nolint:gosec,errcheck
}

// describeAccount computes the information requested from the target AWS account.
func describeAccount(id string) error {
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		return err
	}

	// Creating organizations client with local AWS config
	client := organizations.NewFromConfig(cfg)

	// Get the root ID of the organization
	rootID, err := getRootID(client)
	if err != nil {
		return fmt.Errorf("couldn't get organization's root ID: %v", err)
	}

	switch format {
	case "dot":
		return displayOrganizationTreeDot()
	case "json":
		return displayOrganizationTreeJSON()
	default: // (text) Using default even though format is an enum to prevent an LSP error (missing return)
		return displayOrganizationTreeText(client, id, rootID, "", map[string]bool{})
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
func displayOrganizationTreeText(client *organizations.Client, targetAccountID, rootID, prefix string, processedEntities map[string]bool) error {
	queue := []string{rootID}

	for len(queue) > 0 {
		parentID := queue[0]
		queue = queue[1:]

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

		if strings.ToLower(targetAccountID) == "all" {
			// Display accounts in a tree-like format
			for _, child := range childAccounts {
				// Don't process the same entities (accounts | OUs) more then once
				if processedEntities[*child.Id] {
					continue
				}

				account, err := getAccount(client, *child.Id)
				if err != nil {
					return fmt.Errorf("error getting account: %w", err)
				}

				// The org management account will be highlighted in the resulting dataset
				isManagementAccount := isManagementAccount(client, *account.Id)
				accountName := *account.Name

				if isManagementAccount {
					accountName += " (Management Account)"
				}

				scps, err := listSCPsForTarget(client, *account.Id)
				if err != nil {
					return fmt.Errorf("error listing SCPs: %w", err)
				}

				var scpNames []string
				for _, scp := range scps {
					scpNames = append(scpNames, *scp.Name)
				}

				fmt.Printf("%s|-- Account: %s (SCPs: %s)\n", prefix, accountName, strings.Join(scpNames, ", "))

				// Mark the account as processed
				processedEntities[*child.Id] = true
			}

			// Display OUs in a tree-like format
			for _, child := range childOUs {
				if processedEntities[*child.Id] {
					continue
				}

				ou, err := getOU(client, *child.Id)
				if err != nil {
					return fmt.Errorf("error getting OU: %w", err)
				}

				ouName := *ou.Name
				scps, err := listSCPsForTarget(client, *ou.Id)
				if err != nil {
					return fmt.Errorf("error listing SCPs: %w", err)
				}

				var scpNames []string
				for _, scp := range scps {
					scpNames = append(scpNames, *scp.Name)
				}

				fmt.Printf("%s|-- OU: %s (SCPs: %s)\n", prefix, ouName, strings.Join(scpNames, ", "))

				// Mark the OU as processed
				processedEntities[*child.Id] = true

				// Add child OU to the queue for further processing
				// Only the OU nodes have children (another OUs or member accounts)
				queue = append(queue, *ou.Id)

				// Make a recursive call with an updated prefix and processedEntities
				if err := displayOrganizationTreeText(client, targetAccountID, *ou.Id, prefix+"    ", processedEntities); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

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

func getRootID(client *organizations.Client) (string, error) {
	roots, err := client.ListRoots(context.TODO(), &organizations.ListRootsInput{})
	if err != nil {
		return "", fmt.Errorf("listing organization roots: %v", err)
	}
	if roots.NextToken != nil {
		return "", errors.New("more than one root isn't supported yet")
	}

	return *roots.Roots[0].Id, nil
}

func isManagementAccount(client *organizations.Client, accountID string) bool {
	input := &organizations.DescribeOrganizationInput{}

	result, err := client.DescribeOrganization(context.TODO(), input)
	if err != nil {
		return false
	}

	return *result.Organization.MasterAccountId == accountID
}
