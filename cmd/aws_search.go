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
	"github.com/spf13/cobra"
)

const awsSearchJSONSchemaVersion = "1"

type searchEntityType string

const (
	searchAccounts            searchEntityType = accountEntityType
	searchOrganizationalUnits searchEntityType = organizationalUnitEntityType
)

func (entityType *searchEntityType) String() string { return string(*entityType) }

func (entityType *searchEntityType) Set(value string) error {
	switch searchEntityType(value) {
	case searchAccounts, searchOrganizationalUnits:
		*entityType = searchEntityType(value)
		return nil
	default:
		return errors.New(`must be one of "account" or "organizational_unit"`)
	}
}

func (entityType *searchEntityType) Type() string { return "account|organizational_unit" }

type organizationSearchClient interface {
	hierarchyListClient
	organizations.ListRootsAPIClient
}

type organizationSearchPathEntity struct {
	Type string `json:"type"`
	ID   string `json:"id"`
	Name string `json:"name,omitempty"`
}

type organizationSearchMatch struct {
	Type string                         `json:"type"`
	ID   string                         `json:"id"`
	Name string                         `json:"name"`
	Path []organizationSearchPathEntity `json:"path"`
}

type organizationSearchQuery struct {
	Name string `json:"name"`
	Type string `json:"type,omitempty"`
}

type organizationSearchResult struct {
	SchemaVersion string                    `json:"schema_version"`
	Query         organizationSearchQuery   `json:"query"`
	Matches       []organizationSearchMatch `json:"matches"`
}

type organizationSearchTask struct {
	parentID   string
	parentPath []organizationSearchPathEntity
}

type organizationSearchEntity struct {
	id         string
	entityType string
	parentPath []organizationSearchPathEntity
}

type organizationSearchTaskResult struct {
	matches  []organizationSearchMatch
	entities []organizationSearchEntity
	children []organizationSearchTask
}

var (
	awsSearchName   string
	awsSearchType   searchEntityType
	awsSearchFormat outputFormat = json
	awsSearchCmd                 = &cobra.Command{
		Use:   "search --name <exact-name>",
		Short: "Find AWS accounts and OUs by exact name",
		Long: `Find every AWS account or organizational unit whose name exactly equals
--name. Matching is case-sensitive. Duplicate names are returned as separate
matches; Policy Scout never selects one automatically.

Each JSON result includes a structured, unambiguous path from the organization
root. Use --type to search only accounts or only organizational units. JSON is
the default output format. Search inspects hierarchy and entity metadata only;
it does not list policy attachments or retrieve policy documents.`,
		Example: `  policy-scout aws search --name production
  policy-scout aws search --name production --type account
  policy-scout aws search --name production --type organizational_unit
  policy-scout aws search --name production --output-format text
  policy-scout aws search --name production --timeout 30s --max-retries 3`,
		Args: noArgsValidator,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runAWSSearchCommand(cmd)
		},
	}
)

func init() {
	awsSearchCmd.Flags().StringVar(&awsSearchName, "name", "", "exact, case-sensitive entity name to match (required)")
	awsSearchCmd.Flags().Var(&awsSearchType, "type", `entity type filter: "account" or "organizational_unit"`)
	awsSearchCmd.Flags().VarP(&awsSearchFormat, "output-format", "o", `output format: "json" or "text"`)
	if err := awsSearchCmd.RegisterFlagCompletionFunc("output-format", outputFormatCompletion); err != nil {
		panic(err)
	}
	addAWSExecutionFlags(awsSearchCmd)
}

func runAWSSearchCommand(cmd *cobra.Command) error {
	name, entityType, err := validateOrganizationSearchInvocation(
		awsSearchName,
		cmd.Flags().Changed("name"),
		awsSearchType,
		cmd.Flags().Changed("type"),
	)
	if err != nil {
		return err
	}
	controls, err := awsExecutionControlsFromCommand(cmd)
	if err != nil {
		return err
	}

	ctx, cancel := controls.context(cmd.Context())
	defer cancel()
	err = searchAWSOrganization(
		ctx,
		cmd.OutOrStdout(),
		name,
		entityType,
		profile,
		awsSearchFormat,
		controls.configLoadOptions()...,
	)
	return controls.explainError(err)
}

func validateOrganizationSearchInvocation(
	name string,
	nameSet bool,
	entityType searchEntityType,
	typeSet bool,
) (string, searchEntityType, error) {
	if !nameSet || name == "" {
		return "", "", newInvalidInvocationError(errors.New("--name must be provided and must not be empty"))
	}
	if typeSet && entityType != searchAccounts && entityType != searchOrganizationalUnits {
		return "", "", newInvalidInvocationError(errors.New(`--type must be one of "account" or "organizational_unit"`))
	}
	return name, entityType, nil
}

func searchAWSOrganization(
	ctx context.Context,
	writer io.Writer,
	name string,
	entityType searchEntityType,
	selectedProfile string,
	outputFormat outputFormat,
	configOptions ...func(*config.LoadOptions) error,
) (err error) {
	defer func() {
		err = addSSORemediation(err, selectedProfile)
	}()

	cfg, err := loadAWSConfig(ctx, selectedProfile, config.LoadDefaultConfig, configOptions...)
	if err != nil {
		return newCredentialsError("LoadDefaultConfig", err)
	}
	if _, err := cfg.Credentials.Retrieve(ctx); err != nil {
		return newCredentialsError("RetrieveCredentials", err)
	}
	return displayOrganizationSearch(ctx, writer, organizations.NewFromConfig(cfg), name, entityType, outputFormat)
}

func displayOrganizationSearch(
	ctx context.Context,
	writer io.Writer,
	client organizationSearchClient,
	name string,
	entityType searchEntityType,
	outputFormat outputFormat,
) error {
	result, err := discoverOrganizationEntities(ctx, client, name, entityType)
	if err != nil {
		return err
	}
	document, err := renderOrganizationSearch(result, outputFormat)
	if err != nil {
		return err
	}
	written, err := writer.Write(document)
	if err == nil && written != len(document) {
		err = io.ErrShortWrite
	}
	return err
}

func discoverOrganizationEntities(
	ctx context.Context,
	client organizationSearchClient,
	name string,
	entityType searchEntityType,
) (organizationSearchResult, error) {
	rootID, rootName, err := getRoot(ctx, client)
	if err != nil {
		return organizationSearchResult{}, fmt.Errorf("get organization root: %w", err)
	}
	result := organizationSearchResult{
		SchemaVersion: awsSearchJSONSchemaVersion,
		Query:         organizationSearchQuery{Name: name, Type: string(entityType)},
		Matches:       []organizationSearchMatch{},
	}
	rootPath := []organizationSearchPathEntity{{Type: rootEntityType, ID: rootID, Name: rootName}}
	seen := map[string]string{rootID: rootID}
	if err := discoverOrganizationChildren(ctx, client, rootID, rootPath, name, entityType, seen, &result.Matches); err != nil {
		return organizationSearchResult{}, err
	}
	sort.Slice(result.Matches, func(left, right int) bool {
		leftRank := searchEntityTypeRank(result.Matches[left].Type)
		rightRank := searchEntityTypeRank(result.Matches[right].Type)
		if leftRank != rightRank {
			return leftRank < rightRank
		}
		return result.Matches[left].ID < result.Matches[right].ID
	})
	return result, nil
}

func discoverOrganizationChildren(
	ctx context.Context,
	client organizationSearchClient,
	parentID string,
	parentPath []organizationSearchPathEntity,
	name string,
	entityType searchEntityType,
	seen map[string]string,
	matches *[]organizationSearchMatch,
) error {
	tasks := []organizationSearchTask{{parentID: parentID, parentPath: parentPath}}
	for len(tasks) > 0 {
		results := make([]organizationSearchTaskResult, len(tasks))
		if err := runOrganizationJobs(ctx, len(tasks), func(jobCtx context.Context, index int) error {
			result, err := runOrganizationSearchTask(jobCtx, client, tasks[index], name, entityType)
			if err != nil {
				return err
			}
			results[index] = result
			return nil
		}); err != nil {
			return err
		}

		tasks = nil
		for _, result := range results {
			for _, entity := range result.entities {
				if entity.entityType == organizationalUnitEntityType {
					if err := validateOrganizationalUnitForRoot(entity.id, parentPath[0].ID); err != nil {
						return fmt.Errorf("AWS returned invalid organizational unit %s: %w", entity.id, err)
					}
				}
				if err := recordSearchEntityPath(seen, entity.id, entity.parentPath); err != nil {
					return err
				}
			}
			*matches = append(*matches, result.matches...)
			tasks = append(tasks, result.children...)
		}
	}
	return nil
}

func runOrganizationSearchTask(
	ctx context.Context,
	client organizationSearchClient,
	task organizationSearchTask,
	name string,
	entityType searchEntityType,
) (organizationSearchTaskResult, error) {
	result := organizationSearchTaskResult{}
	if entityType != searchOrganizationalUnits {
		accounts, err := listAccountsForParent(ctx, client, task.parentID)
		if err != nil {
			return result, fmt.Errorf("list accounts for %s: %w", task.parentID, err)
		}
		for _, account := range accounts {
			accountID := aws.ToString(account.Id)
			accountName := aws.ToString(account.Name)
			result.entities = append(result.entities, organizationSearchEntity{
				id: accountID, entityType: accountEntityType, parentPath: task.parentPath,
			})
			if accountName == name {
				path := appendSearchPath(task.parentPath, organizationSearchPathEntity{
					Type: accountEntityType, ID: accountID, Name: accountName,
				})
				result.matches = append(result.matches, organizationSearchMatch{
					Type: accountEntityType, ID: accountID, Name: accountName, Path: path,
				})
			}
		}
	}
	organizationalUnits, err := listOrganizationalUnitsForParent(ctx, client, task.parentID)
	if err != nil {
		return result, fmt.Errorf("list organizational units for %s: %w", task.parentID, err)
	}
	for _, ou := range organizationalUnits {
		ouID := aws.ToString(ou.Id)
		ouName := aws.ToString(ou.Name)
		result.entities = append(result.entities, organizationSearchEntity{
			id: ouID, entityType: organizationalUnitEntityType, parentPath: task.parentPath,
		})
		path := appendSearchPath(task.parentPath, organizationSearchPathEntity{
			Type: organizationalUnitEntityType, ID: ouID, Name: ouName,
		})
		if entityType != searchAccounts && ouName == name {
			result.matches = append(result.matches, organizationSearchMatch{
				Type: organizationalUnitEntityType, ID: ouID, Name: ouName, Path: path,
			})
		}
		result.children = append(result.children, organizationSearchTask{parentID: ouID, parentPath: path})
	}
	return result, nil
}

func recordSearchEntityPath(seen map[string]string, entityID string, parentPath []organizationSearchPathEntity) error {
	pathIDs := make([]string, len(parentPath))
	for index := range parentPath {
		pathIDs[index] = parentPath[index].ID
	}
	path := strings.Join(pathIDs, "/")
	if previous, found := seen[entityID]; found {
		return fmt.Errorf("AWS returned entity %s more than once under paths %s and %s", entityID, previous, path)
	}
	seen[entityID] = path
	return nil
}

func appendSearchPath(path []organizationSearchPathEntity, entity organizationSearchPathEntity) []organizationSearchPathEntity {
	result := make([]organizationSearchPathEntity, len(path)+1)
	copy(result, path)
	result[len(path)] = entity
	return result
}

func searchEntityTypeRank(entityType string) int {
	if entityType == accountEntityType {
		return 0
	}
	return 1
}

func renderOrganizationSearch(result organizationSearchResult, outputFormat outputFormat) ([]byte, error) {
	switch outputFormat {
	case json:
		encoded, err := encodingjson.MarshalIndent(result, "", "  ")
		if err != nil {
			return nil, fmt.Errorf("encode organization search result: %w", err)
		}
		return append(encoded, '\n'), nil
	case text:
		var output strings.Builder
		fmt.Fprintf(&output, "Exact matches for \"%s\": %d\n", displayText(result.Query.Name), len(result.Matches))
		for _, match := range result.Matches {
			fmt.Fprintf(&output, "%s %s [%s]\n", searchTextType(match.Type), displayText(match.Name), displayText(match.ID))
			output.WriteString("  Path: ")
			for index, entity := range match.Path {
				if index > 0 {
					output.WriteString(" / ")
				}
				fmt.Fprintf(&output, "%s [%s]", displayText(searchPathTextName(entity)), displayText(entity.ID))
			}
			output.WriteByte('\n')
		}
		return []byte(output.String()), nil
	default:
		return nil, fmt.Errorf("unsupported output format %q", outputFormat)
	}
}

func searchTextType(entityType string) string {
	if entityType == accountEntityType {
		return accountEntityLabel
	}
	return organizationalUnitEntityLabel
}

func searchPathTextName(entity organizationSearchPathEntity) string {
	if entity.Name != "" {
		return entity.Name
	}
	if entity.Type == rootEntityType {
		return rootEntityLabel
	}
	return searchTextType(entity.Type)
}
