package cmd

import (
	"context"
	"fmt"
	"io"
	"slices"
	"sort"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/account"
	accounttypes "github.com/aws/aws-sdk-go-v2/service/account/types"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	"github.com/aws/aws-sdk-go-v2/service/organizations/types"
	"github.com/spf13/cobra"
)

const regionDriftSchemaVersion = "1"

// Region restriction kinds describe how a Deny statement uses aws:RequestedRegion.
const (
	// regionRestrictionAllowList denies every Region except the listed ones.
	regionRestrictionAllowList = "allow_list"
	// regionRestrictionDenyList denies only the listed Regions.
	regionRestrictionDenyList = "deny_list"
)

var (
	regionDriftFormat           outputFormat = json
	regionDriftFailOnBlindSpots bool

	awsRegionDriftCmd = &cobra.Command{
		Use:   "region-drift",
		Short: "Compare each account's enabled Regions with the Regions its SCPs allow",
		Long: `Return one compact, versioned Region drift report for every account in the
organization. JSON output is used by default.

Enabled Regions come from the AWS Account Management ListRegions API, called
with each member account's ID. Region restrictions come from the
aws:RequestedRegion conditions in the Deny statements of each account's
applicable SCPs, attached directly or inherited, using the same static
extraction as "aws exemptions". For each account the report lists:

  - enabled Regions that the SCPs allow;
  - blind spots: enabled Regions that no Region restriction denies;
  - enabled Regions that a Region restriction denies;
  - Regions that an allow list permits but the account has not enabled
    (informational);
  - whether no Region restriction applies at all.

A restriction counts only when its Deny covers every action, or every action
except a NotAction carve-out such as global services, for every resource.
Other carve-outs in the statement, such as an exempt administrator role, are
listed but not evaluated. Region conditions that cannot be interpreted cleanly,
and Region Denies scoped to some actions or resources, are reported with the
policy, statement, and a reason instead of being guessed at.

The management account, which SCPs never restrict, and accounts whose AWS state
is not ACTIVE are listed separately as excluded accounts; ListRegions is not
called for them. This is a configuration report: Policy Scout does not evaluate
IAM policies or effective permissions.

AWS permits ListRegions for another account only from the management account or
a delegated administrator for Account Management, with trusted access enabled.

The command exits 0 when the report is complete, even when blind spots exist.
Use --fail-on-blind-spots to exit 6 after writing the report when any applicable
account has a blind spot. Exit status 6 is not a failure: stderr is empty.`,
		Example: `  policy-scout aws region-drift
  policy-scout aws region-drift --output-format text
  policy-scout aws region-drift --fail-on-blind-spots --timeout 5m --max-retries 3`,
		Args: noArgsValidator,
		RunE: runAWSRegionDriftCommand,
	}
)

func init() {
	awsRegionDriftCmd.Flags().BoolVar(&regionDriftFailOnBlindSpots, "fail-on-blind-spots", false,
		"exit 6 after writing the report when any applicable account has an enabled Region that no SCP denies")
	awsRegionDriftCmd.Flags().VarP(&regionDriftFormat, "output-format", "o", `output format: "json" or "text"`)
	if err := awsRegionDriftCmd.RegisterFlagCompletionFunc("output-format", outputFormatCompletion); err != nil {
		panic(err)
	}
	addAWSExecutionFlags(awsRegionDriftCmd)
	awsCmd.AddCommand(awsRegionDriftCmd)
}

type regionDriftEnabledRegion struct {
	Region    string `json:"region"`
	OptStatus string `json:"opt_status"`
}

// regionDriftSource identifies the SCP attachment and Deny statement behind a
// restriction.
type regionDriftSource struct {
	PolicyID   string              `json:"policy_id"`
	PolicyName string              `json:"policy_name"`
	AttachedTo scpAttachmentTarget `json:"attached_to"`
	Inherited  bool                `json:"inherited"`
	Statement  int                 `json:"statement_index"`
	Sid        string              `json:"sid,omitempty"`
}

type regionDriftRestriction struct {
	regionDriftSource
	Kind      string      `json:"kind"`
	Operator  string      `json:"operator"`
	Regions   []string    `json:"regions"`
	CarveOuts []exemption `json:"carve_outs"`
}

type regionDriftUninterpretable struct {
	regionDriftSource
	Operator string   `json:"operator,omitempty"`
	Key      string   `json:"key,omitempty"`
	Values   []string `json:"values,omitempty"`
	Reason   string   `json:"reason"`
}

type regionDriftAccount struct {
	Account                     coverageAccountInfo          `json:"account"`
	Path                        []scpAttachmentTarget        `json:"path"`
	NoRegionRestriction         bool                         `json:"no_region_restriction"`
	EnabledRegions              []regionDriftEnabledRegion   `json:"enabled_regions"`
	EnabledAllowedRegions       []string                     `json:"enabled_allowed_regions"`
	BlindSpotRegions            []string                     `json:"blind_spot_regions"`
	EnabledDeniedRegions        []string                     `json:"enabled_denied_regions"`
	AllowedDisabledRegions      []string                     `json:"allowed_disabled_regions"`
	Restrictions                []regionDriftRestriction     `json:"restrictions"`
	UninterpretableRestrictions []regionDriftUninterpretable `json:"uninterpretable_restrictions"`
}

type regionDriftSummary struct {
	Accounts                        int `json:"accounts"`
	Restricted                      int `json:"restricted"`
	Unrestricted                    int `json:"unrestricted"`
	WithBlindSpots                  int `json:"with_blind_spots"`
	WithUninterpretableRestrictions int `json:"with_uninterpretable_restrictions"`
	Excluded                        int `json:"excluded"`
}

type regionDriftResult struct {
	SchemaVersion    string                    `json:"schema_version"`
	Summary          regionDriftSummary        `json:"summary"`
	Accounts         []regionDriftAccount      `json:"accounts"`
	ExcludedAccounts []coverageExcludedAccount `json:"excluded_accounts"`
}

type regionDriftRegionsClient interface {
	account.ListRegionsAPIClient
}

func runAWSRegionDriftCommand(cmd *cobra.Command, _ []string) error {
	controls, err := awsExecutionControlsFromCommand(cmd)
	if err != nil {
		return err
	}
	ctx, cancel := controls.context(cmd.Context())
	defer cancel()
	err = inspectAWSRegionDrift(ctx, cmd.OutOrStdout(), profile, regionDriftFormat, regionDriftFailOnBlindSpots, controls.configLoadOptions()...)
	return controls.explainError(err)
}

func inspectAWSRegionDrift(
	ctx context.Context,
	writer io.Writer,
	selectedProfile string,
	outputFormat outputFormat,
	failOnBlindSpots bool,
	configOptions ...func(*config.LoadOptions) error,
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
	rootID, rootName, managementAccountID, err := getRootAndManagementAccount(ctx, client, true)
	if err != nil {
		return err
	}
	return displayRegionDriftReport(
		ctx, writer, client, account.NewFromConfig(cfg), rootID, rootName, managementAccountID, outputFormat, failOnBlindSpots,
	)
}

// regionDriftBlindSpotError reports that the complete report was written and
// found blind spots under --fail-on-blind-spots. Like coverageGapError, it maps
// to exit status 6 with empty stderr.
type regionDriftBlindSpotError struct {
	accounts int
}

func (err *regionDriftBlindSpotError) Error() string {
	return fmt.Sprintf("region drift report found %d account(s) with blind-spot Regions", err.accounts)
}

func displayRegionDriftReport(
	ctx context.Context,
	writer io.Writer,
	client organizationsClient,
	regionsClient regionDriftRegionsClient,
	rootID, rootName, managementAccountID string,
	outputFormat outputFormat,
	failOnBlindSpots bool,
) error {
	result, err := buildRegionDriftReport(ctx, client, regionsClient, rootID, rootName, managementAccountID)
	if err != nil {
		return err
	}
	if err := writeRegionDriftReport(writer, result, outputFormat); err != nil {
		return err
	}
	if failOnBlindSpots && result.Summary.WithBlindSpots > 0 {
		return &regionDriftBlindSpotError{accounts: result.Summary.WithBlindSpots}
	}
	return nil
}

// regionRule is one interpretable account-wide Region restriction in an SCP.
type regionRule struct {
	statement denyStatement
	condition exemption
	kind      string
	carveOuts []exemption
}

// regionUnclear is a Region condition that is reported instead of interpreted.
type regionUnclear struct {
	statement denyStatement
	condition exemption
	reason    string
}

type policyRegionRules struct {
	rules   []regionRule
	unclear []regionUnclear
}

func buildRegionDriftReport(
	ctx context.Context,
	client organizationsClient,
	regionsClient regionDriftRegionsClient,
	rootID, rootName, managementAccountID string,
) (regionDriftResult, error) {
	tree, err := buildOrganizationTree(ctx, client, allSelectionType, rootID, rootName, managementAccountID)
	if err != nil {
		return regionDriftResult{}, err
	}
	policies, err := describeApplicablePolicies(ctx, client, tree)
	if err != nil {
		return regionDriftResult{}, err
	}
	rulesByPolicy := make(map[string]policyRegionRules, len(policies))
	for _, policy := range policies {
		rules, err := extractRegionRules(policy)
		if err != nil {
			return regionDriftResult{}, fmt.Errorf("policy %s: %w", policy.ID, err)
		}
		rulesByPolicy[policy.ID] = rules
	}

	result := regionDriftResult{
		SchemaVersion:    regionDriftSchemaVersion,
		Accounts:         []regionDriftAccount{},
		ExcludedAccounts: []coverageExcludedAccount{},
	}
	var applicable []organizationNode
	var paths [][]scpAttachmentTarget
	var visit func(node organizationNode, path []scpAttachmentTarget)
	visit = func(node organizationNode, path []scpAttachmentTarget) {
		path = append(append([]scpAttachmentTarget(nil), path...), scpAttachmentTarget{Type: node.Type, ID: node.ID, Name: node.Name})
		if node.Type != accountEntityType {
			for _, child := range node.Children {
				visit(child, path)
			}
			return
		}
		info := coverageAccountInfo{ID: node.ID, Name: node.Name, State: node.AccountState}
		switch {
		case node.ManagementAccount:
			result.ExcludedAccounts = append(result.ExcludedAccounts, coverageExcludedAccount{
				Account: info, Path: path, Reason: coverageExcludedManagementAccount,
			})
		case node.AccountState != "" && node.AccountState != string(types.AccountStateActive):
			result.ExcludedAccounts = append(result.ExcludedAccounts, coverageExcludedAccount{
				Account: info, Path: path, Reason: coverageExcludedInactiveAccount,
			})
		default:
			applicable = append(applicable, node)
			paths = append(paths, path)
		}
	}
	visit(tree, nil)

	regionsByAccount := make([][]accounttypes.Region, len(applicable))
	err = runOrganizationJobs(ctx, len(applicable), func(jobCtx context.Context, index int) error {
		regions, err := listAccountRegions(jobCtx, regionsClient, applicable[index].ID)
		if err != nil {
			return fmt.Errorf("list Regions for account %s: %w", applicable[index].ID, err)
		}
		regionsByAccount[index] = regions
		return nil
	})
	if err != nil {
		return regionDriftResult{}, err
	}

	for index, node := range applicable {
		entry := regionDriftForAccount(node, regionsByAccount[index], rulesByPolicy)
		entry.Path = paths[index]
		result.Accounts = append(result.Accounts, entry)
		summary := &result.Summary
		if entry.NoRegionRestriction {
			summary.Unrestricted++
		} else {
			summary.Restricted++
		}
		if len(entry.BlindSpotRegions) > 0 {
			summary.WithBlindSpots++
		}
		if len(entry.UninterpretableRestrictions) > 0 {
			summary.WithUninterpretableRestrictions++
		}
	}
	sort.Slice(result.Accounts, func(i, j int) bool { return result.Accounts[i].Account.ID < result.Accounts[j].Account.ID })
	sort.Slice(result.ExcludedAccounts, func(i, j int) bool {
		return result.ExcludedAccounts[i].Account.ID < result.ExcludedAccounts[j].Account.ID
	})
	result.Summary.Excluded = len(result.ExcludedAccounts)
	result.Summary.Accounts = len(result.Accounts) + result.Summary.Excluded
	return result, nil
}

func listAccountRegions(ctx context.Context, client regionDriftRegionsClient, accountID string) ([]accounttypes.Region, error) {
	paginator := account.NewListRegionsPaginator(client, &account.ListRegionsInput{AccountId: aws.String(accountID)})
	var regions []accounttypes.Region
	seenTokens := make(map[string]bool)
	seenRegions := make(map[string]bool)
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		if err := rejectRepeatedToken(seenTokens, page.NextToken, "ListRegions"); err != nil {
			return nil, err
		}
		for _, region := range page.Regions {
			name := aws.ToString(region.RegionName)
			if name == "" {
				return nil, fmt.Errorf("AWS returned a Region without a name for account %s", accountID)
			}
			if seenRegions[name] {
				return nil, fmt.Errorf("AWS returned Region %s more than once for account %s", name, accountID)
			}
			seenRegions[name] = true
			regions = append(regions, region)
		}
	}
	return regions, nil
}

// regionEnabled treats transitional states as enabled: an ENABLING or
// DISABLING Region may still accept requests, so it must not hide a blind spot.
func regionEnabled(status accounttypes.RegionOptStatus) bool {
	return status != accounttypes.RegionOptStatusDisabled
}

// extractRegionRules finds aws:RequestedRegion conditions in an SCP's Deny
// statements. It reuses the exemptions extractor for the conditions and the
// coverage statement parser for each Deny's Action and Resource scope.
func extractRegionRules(policy organizationPolicy) (policyRegionRules, error) {
	statements, err := extractDenyExemptions(policy.Content)
	if err != nil {
		return policyRegionRules{}, err
	}
	scopes, scopeErr := parseCoverageStatements(policy.Content)
	var rules policyRegionRules
	for _, statement := range statements {
		var regionConditions, carveOuts []exemption
		for _, item := range statement.Exemptions {
			if item.Source == exemptionSourceCondition && item.Category == "region" {
				regionConditions = append(regionConditions, item)
			} else {
				carveOuts = append(carveOuts, item)
			}
		}
		if len(regionConditions) == 0 {
			continue
		}
		unclear := func(reason string) {
			for _, condition := range regionConditions {
				rules.unclear = append(rules.unclear, regionUnclear{statement: statement, condition: condition, reason: reason})
			}
		}
		if len(regionConditions) > 1 {
			unclear("statement has more than one aws:RequestedRegion condition, which is not interpreted")
			continue
		}
		condition := regionConditions[0]
		if !condition.Interpretable {
			unclear(condition.Reason)
			continue
		}
		kind, reason := regionRestrictionKind(condition)
		if reason == "" {
			reason = regionStatementScopeProblem(scopes, scopeErr, statement.Index)
		}
		if reason != "" {
			unclear(reason)
			continue
		}
		rules.rules = append(rules.rules, regionRule{
			statement: statement, condition: condition, kind: kind, carveOuts: nonNilSlice(carveOuts),
		})
	}
	return rules, nil
}

func regionRestrictionKind(condition exemption) (kind, reason string) {
	for _, value := range condition.Values {
		if strings.Contains(value, "${") {
			return "", "policy variables in aws:RequestedRegion values are not interpreted"
		}
	}
	switch strings.TrimSuffix(condition.Operator, "IfExists") {
	case "StringNotEquals", "StringNotEqualsIgnoreCase", "StringNotLike":
		return regionRestrictionAllowList, ""
	case "StringEquals", "StringEqualsIgnoreCase", "StringLike":
		return regionRestrictionDenyList, ""
	}
	return "", "only string operators are interpreted for aws:RequestedRegion"
}

// regionStatementScopeProblem explains why a Deny is not an account-wide Region
// restriction, or returns "" when it denies every action (or every action except
// NotAction carve-outs) for every resource (or every resource except NotResource).
func regionStatementScopeProblem(scopes []coverageStatement, scopeErr error, index int) string {
	if scopeErr != nil || index >= len(scopes) {
		return "statement Action or Resource could not be read"
	}
	scope := scopes[index]
	if scope.Action != nil && !slices.Contains(scope.Action, "*") {
		return fmt.Sprintf("Deny applies only to actions %s, not to every action", strings.Join(scope.Action, ", "))
	}
	if scope.Resource != nil && !slices.Contains(scope.Resource, "*") {
		return fmt.Sprintf("Deny applies only to resources %s, not to every resource", strings.Join(scope.Resource, ", "))
	}
	return ""
}

// matches reports whether region satisfies the restriction's condition values.
func (rule regionRule) matches(region string) bool {
	operator := strings.TrimSuffix(rule.condition.Operator, "IfExists")
	for _, value := range rule.condition.Values {
		switch {
		case strings.HasSuffix(operator, "IgnoreCase"):
			if strings.EqualFold(value, region) {
				return true
			}
		case strings.HasSuffix(operator, "Like"):
			if iamWildcardMatch(value, region) {
				return true
			}
		case value == region:
			return true
		}
	}
	return false
}

// denies reports whether the restriction denies requests to region.
func (rule regionRule) denies(region string) bool {
	if rule.kind == regionRestrictionAllowList {
		return !rule.matches(region)
	}
	return rule.matches(region)
}

func regionDriftForAccount(
	node organizationNode,
	regions []accounttypes.Region,
	rulesByPolicy map[string]policyRegionRules,
) regionDriftAccount {
	entry := regionDriftAccount{
		Account:                     coverageAccountInfo{ID: node.ID, Name: node.Name, State: node.AccountState},
		EnabledRegions:              []regionDriftEnabledRegion{},
		EnabledAllowedRegions:       []string{},
		BlindSpotRegions:            []string{},
		EnabledDeniedRegions:        []string{},
		AllowedDisabledRegions:      []string{},
		Restrictions:                []regionDriftRestriction{},
		UninterpretableRestrictions: []regionDriftUninterpretable{},
	}
	var rules []regionRule
	for _, attachment := range node.SCPAttachments {
		policyRules := rulesByPolicy[attachment.PolicyID]
		source := func(statement denyStatement) regionDriftSource {
			return regionDriftSource{
				PolicyID: attachment.PolicyID, PolicyName: attachment.PolicyName,
				AttachedTo: attachment.AttachedTo, Inherited: attachment.Inherited,
				Statement: statement.Index, Sid: statement.Sid,
			}
		}
		for _, rule := range policyRules.rules {
			rules = append(rules, rule)
			entry.Restrictions = append(entry.Restrictions, regionDriftRestriction{
				regionDriftSource: source(rule.statement), Kind: rule.kind, Operator: rule.condition.Operator,
				Regions: rule.condition.Values, CarveOuts: rule.carveOuts,
			})
		}
		for _, unclear := range policyRules.unclear {
			entry.UninterpretableRestrictions = append(entry.UninterpretableRestrictions, regionDriftUninterpretable{
				regionDriftSource: source(unclear.statement), Operator: unclear.condition.Operator,
				Key: unclear.condition.Key, Values: unclear.condition.Values, Reason: unclear.reason,
			})
		}
	}
	entry.NoRegionRestriction = len(rules) == 0
	hasAllowList := slices.ContainsFunc(rules, func(rule regionRule) bool { return rule.kind == regionRestrictionAllowList })

	sorted := slices.Clone(regions)
	sort.Slice(sorted, func(i, j int) bool { return aws.ToString(sorted[i].RegionName) < aws.ToString(sorted[j].RegionName) })
	for _, region := range sorted {
		name := aws.ToString(region.RegionName)
		denied := slices.ContainsFunc(rules, func(rule regionRule) bool { return rule.denies(name) })
		enabled := regionEnabled(region.RegionOptStatus)
		if enabled {
			entry.EnabledRegions = append(entry.EnabledRegions, regionDriftEnabledRegion{Region: name, OptStatus: string(region.RegionOptStatus)})
		}
		switch {
		case enabled && denied:
			entry.EnabledDeniedRegions = append(entry.EnabledDeniedRegions, name)
		case enabled && hasAllowList:
			entry.EnabledAllowedRegions = append(entry.EnabledAllowedRegions, name)
		case enabled:
			entry.BlindSpotRegions = append(entry.BlindSpotRegions, name)
		case hasAllowList && !denied:
			entry.AllowedDisabledRegions = append(entry.AllowedDisabledRegions, name)
		}
	}
	return entry
}

func writeRegionDriftReport(writer io.Writer, result regionDriftResult, outputFormat outputFormat) error {
	if outputFormat != text {
		return writeJSONDocument(writer, result, "region drift report")
	}
	var output strings.Builder
	summary := result.Summary
	fmt.Fprintf(&output, "Accounts: %d (%d restricted, %d unrestricted, %d with blind spots, %d with uninterpretable restrictions, %d excluded)\n",
		summary.Accounts, summary.Restricted, summary.Unrestricted, summary.WithBlindSpots,
		summary.WithUninterpretableRestrictions, summary.Excluded)
	regionList := func(regions []string) string {
		if len(regions) == 0 {
			return "none"
		}
		return displayText(strings.Join(regions, ", "))
	}
	for _, entry := range result.Accounts {
		fmt.Fprintf(&output, "\n%s\n", coverageAccountText(entry.Account, entry.Path))
		if entry.NoRegionRestriction {
			output.WriteString("  Region restrictions: none\n")
		}
		for _, restriction := range entry.Restrictions {
			verb := "allows only"
			if restriction.Kind == regionRestrictionDenyList {
				verb = "denies"
			}
			fmt.Fprintf(&output, "  %s: %s %s [%s]\n", regionDriftSourceText(restriction.regionDriftSource), verb,
				regionList(restriction.Regions), displayText(restriction.Operator))
			for _, carveOut := range restriction.CarveOuts {
				fmt.Fprintf(&output, "      carve-out: %s\n", exemptionText(carveOut))
			}
		}
		for _, unclear := range entry.UninterpretableRestrictions {
			subject := strings.TrimSpace(unclear.Operator + " " + unclear.Key)
			if len(unclear.Values) > 0 {
				subject += " " + strings.Join(unclear.Values, ", ")
			}
			fmt.Fprintf(&output, "  %s: not interpretable: %s: %s\n", regionDriftSourceText(unclear.regionDriftSource),
				displayText(subject), displayText(unclear.Reason))
		}
		fmt.Fprintf(&output, "  Enabled and allowed: %s\n", regionList(entry.EnabledAllowedRegions))
		fmt.Fprintf(&output, "  Blind spots (enabled, not denied): %s\n", regionList(entry.BlindSpotRegions))
		fmt.Fprintf(&output, "  Enabled but denied: %s\n", regionList(entry.EnabledDeniedRegions))
		fmt.Fprintf(&output, "  Allowed but disabled: %s\n", regionList(entry.AllowedDisabledRegions))
	}
	output.WriteString("\n")
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
	return writeDocument(writer, []byte(output.String()), "region drift report")
}

func regionDriftSourceText(source regionDriftSource) string {
	label := fmt.Sprintf("SCP %s [%s] statement %d", displayText(source.PolicyName), displayText(source.PolicyID), source.Statement)
	if source.Sid != "" {
		label += " (" + displayText(source.Sid) + ")"
	}
	if source.Inherited {
		return label + ", inherited from " + displayText(attachmentTargetText(source.AttachedTo))
	}
	return label + ", direct"
}
