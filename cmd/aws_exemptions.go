package cmd

import (
	"bytes"
	"context"
	encodingjson "encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/spf13/cobra"
)

const exemptionsQuerySchemaVersion = "1"

const policySelectionType = "policy"

// Exemption sources identify which part of a Deny statement creates a carve-out.
const (
	exemptionSourceCondition   = "condition"
	exemptionSourceNotAction   = "not_action"
	exemptionSourceNotResource = "not_resource"
	exemptionSourceStatement   = "statement"
)

// Exemption conditions describe the request context that avoids a Deny statement.
const (
	exemptWhenMatchesValues      = "matches_values"
	exemptWhenDoesNotMatchValues = "does_not_match_values"
	exemptWhenKeyPresent         = "key_present"
	exemptWhenKeyAbsent          = "key_absent"
)

var (
	exemptionsPolicyID  string
	exemptionsAccountID string
	exemptionsOUID      string
	exemptionsFormat    outputFormat = json

	awsExemptionsCmd = &cobra.Command{
		Use:   "exemptions (--policy-id <p-id> | --account-id <12-digit-id> | --ou-id <ou-id>)",
		Short: "Show principals, regions, and other contexts exempt from SCP denies",
		Long: `Return one compact, versioned result listing the carve-outs written into
the Deny statements of SCP documents: condition keys whose values avoid the
deny (for example an ArnNotLike aws:PrincipalArn break-glass role or a
StringNotEquals aws:RequestedRegion allow list), and NotAction or NotResource
elements. Each exemption names its source policy and statement.

Select one SCP with --policy-id, or one account or OU with --account-id or
--ou-id to report exemptions in every SCP that applies there directly or
through inheritance. Policy documents are retrieved with DescribePolicy.

This is static extraction from policy text. Policy Scout does not evaluate
effective permissions, and another statement or policy may still deny a request
exempted here. Conditions that cannot be interpreted cleanly are reported with
"interpretable": false and a reason instead of a guess. JSON output is used by
default.`,
		Example: `  policy-scout aws exemptions --policy-id p-a1b2c3d4
  policy-scout aws exemptions --account-id 123456789012
  policy-scout aws exemptions --ou-id ou-abcd-12345678 --output-format text
  policy-scout aws exemptions --account-id 123456789012 --output-format json --timeout 30s --max-retries 3`,
		Args: noArgsValidator,
		RunE: runAWSExemptionsCommand,
	}
)

func init() {
	awsExemptionsCmd.Flags().StringVar(&exemptionsPolicyID, "policy-id", "", "exact AWS service control policy ID to inspect")
	awsExemptionsCmd.Flags().StringVar(&exemptionsAccountID, "account-id", "", "exact 12-digit AWS account ID whose applicable SCPs are inspected")
	awsExemptionsCmd.Flags().StringVar(&exemptionsOUID, "ou-id", "", "exact AWS organizational unit ID whose applicable SCPs are inspected")
	awsExemptionsCmd.Flags().VarP(&exemptionsFormat, "output-format", "o", `output format: "json" or "text"`)
	if err := awsExemptionsCmd.RegisterFlagCompletionFunc("output-format", outputFormatCompletion); err != nil {
		panic(err)
	}
	addAWSExecutionFlags(awsExemptionsCmd)
}

type exemptionsSelection struct {
	Type     string `json:"type"`
	PolicyID string `json:"policy_id,omitempty"`
	TargetID string `json:"target_id,omitempty"`
}

type exemptionsQueryResult struct {
	SchemaVersion string                `json:"schema_version"`
	Selection     exemptionsSelection   `json:"selection"`
	Target        *queryTarget          `json:"target,omitempty"`
	Path          []scpAttachmentTarget `json:"path,omitempty"`
	Policies      []policyExemptions    `json:"policies"`
}

type policyExemptions struct {
	PolicyID       string                 `json:"policy_id"`
	PolicyName     string                 `json:"policy_name"`
	Provenance     []attachmentProvenance `json:"provenance,omitempty"`
	DenyStatements []denyStatement        `json:"deny_statements"`
}

type denyStatement struct {
	Index      int         `json:"index"`
	Sid        string      `json:"sid,omitempty"`
	Exemptions []exemption `json:"exemptions"`
}

type exemption struct {
	Source            string   `json:"source"`
	Category          string   `json:"category,omitempty"`
	Operator          string   `json:"operator,omitempty"`
	Key               string   `json:"key,omitempty"`
	Values            []string `json:"values,omitempty"`
	ExemptWhen        string   `json:"exempt_when,omitempty"`
	ExemptIfKeyAbsent *bool    `json:"exempt_if_key_absent,omitempty"`
	Interpretable     bool     `json:"interpretable"`
	Reason            string   `json:"reason,omitempty"`
}

func runAWSExemptionsCommand(cmd *cobra.Command, _ []string) error {
	controls, err := awsExecutionControlsFromCommand(cmd)
	if err != nil {
		return err
	}
	selection, err := selectedExemptionsQuery(
		exemptionsPolicyID, cmd.Flags().Changed("policy-id"),
		exemptionsAccountID, cmd.Flags().Changed("account-id"),
		exemptionsOUID, cmd.Flags().Changed("ou-id"),
	)
	if err != nil {
		return err
	}
	ctx, cancel := controls.context(cmd.Context())
	defer cancel()
	err = runAWSQuery(ctx, cmd.OutOrStdout(), profile, selection.Type == accountEntityType, controls.configLoadOptions(), func(
		ctx context.Context, writer io.Writer, client organizationsClient, rootID, rootName, managementAccountID string,
	) error {
		var result exemptionsQueryResult
		var err error
		if selection.Type == policySelectionType {
			result, err = buildPolicyExemptionsQuery(ctx, client, selection.PolicyID)
		} else {
			result, err = buildTargetExemptionsQuery(ctx, client, selection.TargetID, rootID, rootName, managementAccountID)
		}
		if err != nil {
			return err
		}
		return writeExemptionsQuery(writer, result, exemptionsFormat)
	})
	return controls.explainError(err)
}

func selectedExemptionsQuery(
	policyID string, policySet bool,
	accountID string, accountSet bool,
	ouID string, ouSet bool,
) (exemptionsSelection, error) {
	switch {
	case policySet && (accountSet || ouSet):
		return exemptionsSelection{}, newInvalidInvocationError(errors.New("--policy-id is mutually exclusive with --account-id and --ou-id"))
	case policySet:
		if !validPolicyID(policyID) {
			return exemptionsSelection{}, newInvalidInvocationError(fmt.Errorf("invalid --policy-id %q: must match p-<8-128 letters, digits, or underscores>", policyID))
		}
		return exemptionsSelection{Type: policySelectionType, PolicyID: policyID}, nil
	case !accountSet && !ouSet:
		return exemptionsSelection{}, newInvalidInvocationError(errors.New("exemptions requires exactly one of --policy-id, --account-id, or --ou-id"))
	case accountSet && strings.EqualFold(accountID, allSelectionType):
		return exemptionsSelection{}, newInvalidInvocationError(errors.New(`invalid --account-id "all": exemptions requires one exact account or OU ID`))
	}
	targetID, err := selectedAWSTarget(accountID, accountSet, ouID, ouSet)
	if err != nil {
		return exemptionsSelection{}, err
	}
	return exemptionsSelection{Type: entityType(targetID), TargetID: targetID}, nil
}

func buildPolicyExemptionsQuery(ctx context.Context, client organizationsClient, policyID string) (exemptionsQueryResult, error) {
	policy, err := describePolicy(ctx, client, policyID)
	if err != nil {
		return exemptionsQueryResult{}, fmt.Errorf("describe policy %s: %w", policyID, err)
	}
	statements, err := extractDenyExemptions(policy.Content)
	if err != nil {
		return exemptionsQueryResult{}, fmt.Errorf("policy %s: %w", policyID, err)
	}
	return exemptionsQueryResult{
		SchemaVersion: exemptionsQuerySchemaVersion,
		Selection:     exemptionsSelection{Type: policySelectionType, PolicyID: policyID},
		Policies: []policyExemptions{{
			PolicyID: policy.ID, PolicyName: policy.Name, DenyStatements: statements,
		}},
	}, nil
}

func buildTargetExemptionsQuery(
	ctx context.Context,
	client organizationsClient,
	targetID, rootID, rootName, managementAccountID string,
) (exemptionsQueryResult, error) {
	applicable, err := buildPoliciesQuery(ctx, client, targetID, rootID, rootName, managementAccountID)
	if err != nil {
		return exemptionsQueryResult{}, err
	}
	result := exemptionsQueryResult{
		SchemaVersion: exemptionsQuerySchemaVersion,
		Selection:     exemptionsSelection{Type: applicable.Target.Type, TargetID: targetID},
		Target:        &applicable.Target,
		Path:          applicable.Path,
		Policies:      []policyExemptions{},
	}
	if len(applicable.Policies) == 0 {
		return result, nil
	}
	documents, err := describeApplicablePolicies(ctx, client, organizationNode{SCPAttachments: applicable.Policies})
	if err != nil {
		return exemptionsQueryResult{}, err
	}
	documentsByID := make(map[string]organizationPolicy, len(documents))
	for _, document := range documents {
		documentsByID[document.ID] = document
	}
	indexByID := make(map[string]int)
	for _, attachment := range applicable.Policies {
		provenance := attachmentProvenance{AttachedTo: attachment.AttachedTo, Inherited: attachment.Inherited}
		if index, found := indexByID[attachment.PolicyID]; found {
			result.Policies[index].Provenance = append(result.Policies[index].Provenance, provenance)
			continue
		}
		statements, err := extractDenyExemptions(documentsByID[attachment.PolicyID].Content)
		if err != nil {
			return exemptionsQueryResult{}, fmt.Errorf("policy %s: %w", attachment.PolicyID, err)
		}
		indexByID[attachment.PolicyID] = len(result.Policies)
		result.Policies = append(result.Policies, policyExemptions{
			PolicyID:       attachment.PolicyID,
			PolicyName:     attachment.PolicyName,
			Provenance:     []attachmentProvenance{provenance},
			DenyStatements: statements,
		})
	}
	return result, nil
}

// extractDenyExemptions statically lists the carve-outs in each Deny statement.
// A Deny statement applies only when every condition holds, so each listed
// exemption is independently sufficient to avoid that one statement.
func extractDenyExemptions(content encodingjson.RawMessage) ([]denyStatement, error) {
	var document map[string]any
	decoder := encodingjson.NewDecoder(bytes.NewReader(content))
	decoder.UseNumber()
	if err := decoder.Decode(&document); err != nil || document == nil {
		return nil, errors.New("policy content is not a JSON object")
	}
	var rawStatements []any
	switch value := document["Statement"].(type) {
	case []any:
		rawStatements = value
	case map[string]any:
		rawStatements = []any{value}
	case nil:
		rawStatements = nil
	default:
		rawStatements = []any{value}
	}
	statements := make([]denyStatement, 0)
	for index, rawStatement := range rawStatements {
		statement, ok := rawStatement.(map[string]any)
		if !ok {
			statements = append(statements, uninterpretableStatement(index, "", "statement is not a JSON object"))
			continue
		}
		sid, _ := statement["Sid"].(string)
		effect, _ := statement["Effect"].(string)
		if effect == "Allow" {
			continue
		}
		if effect != "Deny" {
			statements = append(statements, uninterpretableStatement(index, sid, "statement Effect is not \"Allow\" or \"Deny\""))
			continue
		}
		statements = append(statements, denyStatement{Index: index, Sid: sid, Exemptions: statementExemptions(statement)})
	}
	return statements, nil
}

func uninterpretableStatement(index int, sid, reason string) denyStatement {
	return denyStatement{Index: index, Sid: sid, Exemptions: []exemption{{
		Source: exemptionSourceStatement, Interpretable: false, Reason: reason,
	}}}
}

func statementExemptions(statement map[string]any) []exemption {
	exemptions := make([]exemption, 0)
	for _, element := range []string{"Principal", "NotPrincipal"} {
		if _, found := statement[element]; found {
			exemptions = append(exemptions, exemption{
				Source: exemptionSourceStatement, Interpretable: false,
				Reason: element + " is not supported in SCPs and is not interpreted",
			})
		}
	}
	for _, element := range []struct{ name, source string }{
		{"NotAction", exemptionSourceNotAction},
		{"NotResource", exemptionSourceNotResource},
	} {
		raw, found := statement[element.name]
		if !found {
			continue
		}
		values, ok := policyStrings(raw, false)
		if !ok {
			exemptions = append(exemptions, exemption{
				Source: element.source, Interpretable: false,
				Reason: element.name + " is not a string or a non-empty array of strings",
			})
			continue
		}
		exemptions = append(exemptions, exemption{
			Source: element.source, Values: values, ExemptWhen: exemptWhenMatchesValues, Interpretable: true,
		})
	}
	raw, found := statement["Condition"]
	if !found {
		return exemptions
	}
	conditions, ok := raw.(map[string]any)
	if !ok {
		return append(exemptions, exemption{
			Source: exemptionSourceCondition, Interpretable: false, Reason: "Condition is not a JSON object",
		})
	}
	operators := sortedKeys(conditions)
	for _, operator := range operators {
		keys, ok := conditions[operator].(map[string]any)
		if !ok {
			exemptions = append(exemptions, exemption{
				Source: exemptionSourceCondition, Operator: operator, Interpretable: false,
				Reason: "condition operator value is not a JSON object of condition keys",
			})
			continue
		}
		for _, key := range sortedKeys(keys) {
			exemptions = append(exemptions, conditionExemption(operator, key, keys[key]))
		}
	}
	return exemptions
}

func sortedKeys(values map[string]any) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

var (
	matchingConditionOperators = map[string]bool{
		"StringEquals": true, "StringEqualsIgnoreCase": true, "StringLike": true,
		"ArnEquals": true, "ArnLike": true, "Bool": true, "IpAddress": true,
	}
	negatedConditionOperators = map[string]bool{
		"StringNotEquals": true, "StringNotEqualsIgnoreCase": true, "StringNotLike": true,
		"ArnNotEquals": true, "ArnNotLike": true, "NotIpAddress": true,
	}
	// Multivalued global keys need ForAnyValue/ForAllValues semantics, which are
	// not interpreted.
	multivaluedConditionKeys = map[string]bool{
		"aws:tagkeys": true, "aws:calledvia": true, "aws:principalservicenameslist": true,
	}
)

func conditionExemption(operator, key string, rawValues any) exemption {
	result := exemption{
		Source: exemptionSourceCondition, Category: conditionKeyCategory(key), Operator: operator, Key: key,
	}
	values, ok := policyStrings(rawValues, true)
	if ok {
		result.Values = values
	}
	reject := func(reason string) exemption {
		result.Interpretable = false
		result.Reason = reason
		return result
	}
	if strings.HasPrefix(operator, "ForAnyValue:") || strings.HasPrefix(operator, "ForAllValues:") {
		return reject("set operator qualifiers ForAnyValue and ForAllValues are not interpreted")
	}
	if multivaluedConditionKeys[strings.ToLower(key)] {
		return reject("multivalued condition key without a set operator qualifier is not interpreted")
	}
	if !ok {
		return reject("condition values are not a string, boolean, number, or non-empty array of them")
	}
	ifExists := strings.HasSuffix(operator, "IfExists")
	base := strings.TrimSuffix(operator, "IfExists")
	switch {
	case base == "Null":
		if ifExists || len(values) != 1 || (values[0] != "true" && values[0] != "false") {
			return reject(`Null requires exactly one "true" or "false" value`)
		}
		// Null "true" denies when the key is absent, so presence avoids the deny.
		denyWhenAbsent := values[0] == "true"
		result.ExemptWhen = exemptWhenKeyPresent
		if !denyWhenAbsent {
			result.ExemptWhen = exemptWhenKeyAbsent
		}
		result.ExemptIfKeyAbsent = boolPointer(!denyWhenAbsent)
	case negatedConditionOperators[base]:
		// A negated operator is true when the key is absent, so the deny still applies.
		result.ExemptWhen = exemptWhenMatchesValues
		result.ExemptIfKeyAbsent = boolPointer(false)
	case matchingConditionOperators[base]:
		// A matching operator is false when the key is absent unless IfExists is used.
		result.ExemptWhen = exemptWhenDoesNotMatchValues
		result.ExemptIfKeyAbsent = boolPointer(!ifExists)
	case strings.HasPrefix(base, "Numeric") || strings.HasPrefix(base, "Date") || strings.HasPrefix(base, "Binary"):
		return reject("numeric, date, and binary comparison operators are not interpreted")
	default:
		return reject("unrecognized condition operator")
	}
	result.Interpretable = true
	return result
}

func boolPointer(value bool) *bool { return &value }

// policyStrings normalizes a policy element value to strings. Condition values
// may also be JSON booleans or numbers, which keep their literal text.
func policyStrings(raw any, allowScalars bool) ([]string, bool) {
	scalar := func(value any) (string, bool) {
		switch typed := value.(type) {
		case string:
			return typed, true
		case bool:
			if allowScalars {
				return fmt.Sprint(typed), true
			}
		case encodingjson.Number:
			if allowScalars {
				return typed.String(), true
			}
		}
		return "", false
	}
	if items, isArray := raw.([]any); isArray {
		if len(items) == 0 {
			return nil, false
		}
		values := make([]string, len(items))
		for index, item := range items {
			value, ok := scalar(item)
			if !ok {
				return nil, false
			}
			values[index] = value
		}
		return values, true
	}
	value, ok := scalar(raw)
	if !ok {
		return nil, false
	}
	return []string{value}, true
}

func conditionKeyCategory(key string) string {
	lower := strings.ToLower(key)
	switch lower {
	case "aws:principalarn", "aws:userid", "aws:username", "aws:principaltype",
		"aws:principalisawsservice", "aws:principalservicename":
		return "principal"
	case "aws:principalaccount":
		return "principal_account"
	case "aws:principalorgid", "aws:principalorgpaths":
		return "principal_organization"
	case "aws:requestedregion":
		return "region"
	case "aws:resourceaccount", "aws:resourceorgid", "aws:resourceorgpaths":
		return "resource_owner"
	case "aws:sourceip", "aws:sourcevpc", "aws:sourcevpce", "aws:vpcsourceip":
		return "network"
	case "aws:viaawsservice", "aws:calledvia", "aws:calledviafirst", "aws:calledvialast":
		return "service_call"
	}
	switch {
	case strings.HasPrefix(lower, "aws:principaltag/"):
		return "principal_tag"
	case strings.Contains(lower, ":resourcetag/"):
		return "resource_tag"
	case strings.Contains(lower, ":requesttag/"):
		return "request_tag"
	}
	return "other"
}

func writeExemptionsQuery(writer io.Writer, result exemptionsQueryResult, outputFormat outputFormat) error {
	if outputFormat != text {
		return writeJSONDocument(writer, result, "exemptions query")
	}
	var output strings.Builder
	if result.Target != nil {
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
		}
	}
	for _, policy := range result.Policies {
		fmt.Fprintf(&output, "SCP %s [%s]", displayText(policy.PolicyName), displayText(policy.PolicyID))
		for index, provenance := range policy.Provenance {
			separator := ", "
			if index == 0 {
				separator = " — "
			}
			if provenance.Inherited {
				fmt.Fprintf(&output, "%sinherited from %s", separator, displayText(attachmentTargetText(provenance.AttachedTo)))
			} else {
				fmt.Fprintf(&output, "%sdirect", separator)
			}
		}
		output.WriteString("\n")
		if len(policy.DenyStatements) == 0 {
			output.WriteString("  Deny statements: none\n")
		}
		for _, statement := range policy.DenyStatements {
			label := fmt.Sprintf("Deny statement %d", statement.Index)
			if statement.Sid != "" {
				label += " (" + displayText(statement.Sid) + ")"
			}
			if len(statement.Exemptions) == 0 {
				fmt.Fprintf(&output, "  %s: no exemptions\n", label)
				continue
			}
			fmt.Fprintf(&output, "  %s:\n", label)
			for _, item := range statement.Exemptions {
				fmt.Fprintf(&output, "    - %s\n", exemptionText(item))
			}
		}
	}
	return writeDocument(writer, []byte(output.String()), "exemptions query")
}

func exemptionText(item exemption) string {
	values := displayText(strings.Join(item.Values, ", "))
	if !item.Interpretable {
		subject := item.Source
		if item.Source == exemptionSourceCondition {
			subject = strings.TrimSpace("condition " + item.Operator + " " + item.Key)
		}
		return fmt.Sprintf("not interpretable: %s: %s", displayText(subject), displayText(item.Reason))
	}
	switch item.Source {
	case exemptionSourceNotAction:
		return "exempt actions (NotAction): " + values
	case exemptionSourceNotResource:
		return "exempt resources (NotResource): " + values
	}
	var condition string
	switch item.ExemptWhen {
	case exemptWhenMatchesValues:
		condition = "matches " + values
	case exemptWhenDoesNotMatchValues:
		condition = "does not match " + values
	case exemptWhenKeyPresent:
		condition = "is present"
	case exemptWhenKeyAbsent:
		condition = "is absent"
	}
	line := fmt.Sprintf("%s exempt when %s %s [%s]", item.Category, displayText(item.Key), condition, displayText(item.Operator))
	if item.ExemptIfKeyAbsent != nil && *item.ExemptIfKeyAbsent && item.ExemptWhen != exemptWhenKeyAbsent {
		line += "; also exempt when the key is absent"
	}
	return line
}
