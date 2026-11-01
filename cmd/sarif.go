package cmd

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/spf13/cobra"
)

const (
	sarif = "sarif"

	sarifVersion   = "2.1.0"
	sarifSchemaURI = "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json"
	sarifToolName  = "Policy Scout"
	sarifToolURI   = "https://github.com/ariguillegp/policy-scout"

	// sarifURIPrefix starts the synthetic, repository-relative artifact URI of
	// every AWS Organizations entity. GitHub code scanning requires a physical
	// location to display a result, and the codeql-action upload rejects
	// absolute URIs whose scheme differs from the checkout's file:// root, so
	// an ARN cannot be used.
	sarifURIPrefix  = "aws-organizations"
	sarifPolicyKind = "policy"

	coverageRuleUncovered   = "uncovered_account"
	coverageRuleConditional = "conditionally_covered_account"
)

// findingsOutputFormat adds SARIF to the text and JSON formats for commands
// whose results are findings that code scanning tools can track across runs.
type findingsOutputFormat string

func (e *findingsOutputFormat) String() string { return string(*e) }

func (e *findingsOutputFormat) Set(value string) error {
	switch value {
	case text, json, sarif:
		*e = findingsOutputFormat(value)
		return nil
	default:
		return errors.New(`must be one of "text", "json", or "sarif"`)
	}
}

func (e *findingsOutputFormat) Type() string { return "text|json|sarif" }

func findingsOutputFormatCompletion(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) { //nolint:unused
	completions, directive := outputFormatCompletion(cmd, args, toComplete)
	return append(completions, "sarif\tdisplays findings as a SARIF 2.1.0 log for code scanning"), directive
}

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool              sarifTool              `json:"tool"`
	AutomationDetails sarifAutomationDetails `json:"automationDetails"`
	Results           []sarifResult          `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifAutomationDetails struct {
	ID string `json:"id"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifRule struct {
	ID                   string                 `json:"id"`
	Name                 string                 `json:"name"`
	ShortDescription     sarifText              `json:"shortDescription"`
	FullDescription      sarifText              `json:"fullDescription"`
	Help                 sarifText              `json:"help"`
	DefaultConfiguration sarifRuleConfiguration `json:"defaultConfiguration"`
	Properties           sarifRuleProperties    `json:"properties"`
}

type sarifRuleConfiguration struct {
	Level string `json:"level"`
}

type sarifRuleProperties struct {
	Tags      []string `json:"tags"`
	Precision string   `json:"precision"`
}

type sarifResult struct {
	RuleID              string            `json:"ruleId"`
	RuleIndex           int               `json:"ruleIndex"`
	Level               string            `json:"level"`
	Message             sarifText         `json:"message"`
	Locations           []sarifLocation   `json:"locations"`
	PartialFingerprints map[string]string `json:"partialFingerprints"`
	Properties          any               `json:"properties"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation  `json:"physicalLocation"`
	LogicalLocations []sarifLogicalLocation `json:"logicalLocations"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation struct {
		URI string `json:"uri"`
	} `json:"artifactLocation"`
	Region struct {
		StartLine int `json:"startLine"`
	} `json:"region"`
}

type sarifLogicalLocation struct {
	Name               string `json:"name"`
	FullyQualifiedName string `json:"fullyQualifiedName"`
	Kind               string `json:"kind"`
}

// sarifRuleSpec is the per-rule metadata that a command contributes.
type sarifRuleSpec struct {
	id, name, short, full, help, level string
}

func newSARIFLog(automationID string, specs []sarifRuleSpec, results []sarifResult) sarifLog {
	rules := make([]sarifRule, len(specs))
	for index, spec := range specs {
		rules[index] = sarifRule{
			ID: spec.id, Name: spec.name,
			ShortDescription: sarifText{spec.short}, FullDescription: sarifText{spec.full}, Help: sarifText{spec.help},
			DefaultConfiguration: sarifRuleConfiguration{Level: spec.level},
			Properties:           sarifRuleProperties{Tags: []string{"security", "aws", "scp"}, Precision: "very-high"},
		}
	}
	return sarifLog{
		Schema: sarifSchemaURI, Version: sarifVersion,
		Runs: []sarifRun{{
			Tool:              sarifTool{Driver: sarifDriver{Name: sarifToolName, Version: version, InformationURI: sarifToolURI, Rules: rules}},
			AutomationDetails: sarifAutomationDetails{ID: automationID},
			Results:           nonNilSlice(results),
		}},
	}
}

func newSARIFResult(ruleIndex int, ruleID, level, message, rootID, kind, id string, identity []string, properties any) sarifResult {
	path := strings.Join([]string{sarifURIPrefix, rootID, kind, id}, "/")
	location := sarifLocation{LogicalLocations: []sarifLogicalLocation{{Name: id, FullyQualifiedName: path, Kind: "resource"}}}
	location.PhysicalLocation.ArtifactLocation.URI = path
	location.PhysicalLocation.Region.StartLine = 1
	// GitHub matches alerts across runs by primaryLocationLineHash. Hashing only
	// stable AWS identifiers keeps an alert open, rather than reopened, when a
	// name, message, count, or severity changes.
	digest := sha256.Sum256([]byte(strings.Join(append([]string{ruleID, rootID}, identity...), "\x00")))
	return sarifResult{
		RuleID: ruleID, RuleIndex: ruleIndex, Level: level,
		// SARIF reserves "{" and "}" for message placeholders (§3.11.5).
		Message:             sarifText{strings.NewReplacer("{", "{{", "}", "}}").Replace(message)},
		Locations:           []sarifLocation{location},
		PartialFingerprints: map[string]string{"primaryLocationLineHash": hex.EncodeToString(digest[:8]) + ":1"},
		Properties:          properties,
	}
}

var lintSARIFLevels = map[string]string{lintSeverityHigh: "error", lintSeverityMedium: "warning", lintSeverityLow: "note"}

// lintSARIFRules gives each check its SARIF short description, remediation help,
// and default severity; full descriptions are the check rationales.
var lintSARIFRules = map[string]struct{ short, help, severity string }{
	lintCheckUnattachedPolicy: {
		"SCP is not attached to any root, OU, or account",
		"Attach the SCP where the guardrail is intended, or delete it if it is no longer needed.", lintSeverityLow,
	},
	lintCheckAttachmentLimit: {
		"Target is at or near the SCP attachment limit",
		"Merge SCPs that share a purpose, or move common guardrails to an ancestor OU, to free attachment slots.", lintSeverityMedium,
	},
	lintCheckPolicySizeLimit: {
		"SCP document is at or near the size limit",
		"Remove whitespace saved through the API, merge repeated statements, or split the policy into separate SCPs.", lintSeverityMedium,
	},
	lintCheckRedundantAttachment: {
		"Deny-only SCP is attached directly and also inherited",
		"Detach the direct attachment if the inherited attachment is the intended control.", lintSeverityLow,
	},
	lintCheckAllowNotAction: {
		"SCP Allow statement uses NotAction",
		"Replace the Allow statement with an explicit Deny statement that names the actions to block.", lintSeverityMedium,
	},
	lintCheckAllowNotResource: {
		"SCP Allow statement uses NotResource",
		"Replace the Allow statement with an explicit Deny statement that names the resources to protect.", lintSeverityMedium,
	},
	lintCheckRootAccountFullAccessOnly: {
		"Account under the root has only FullAWSAccess",
		"Move the account into an OU that has guardrail SCPs, or attach guardrail SCPs to the account.", lintSeverityHigh,
	},
	lintCheckManagementAccountAttachment: {
		"SCP is attached directly to the management account",
		"Detach the SCP from the management account, and protect that account with IAM controls instead.", lintSeverityLow,
	},
	lintCheckDuplicatePolicyDocument: {
		"SCPs have identical policy documents",
		"Keep one of the SCPs, attach it wherever the copies are attached, and delete the copies.", lintSeverityLow,
	},
}

type lintSARIFProperties struct {
	Severity string               `json:"severity"`
	Target   *scpAttachmentTarget `json:"target,omitempty"`
	Policy   *lintPolicyRef       `json:"policy,omitempty"`
	Evidence lintEvidence         `json:"evidence"`
}

func lintSARIF(report lintReport) sarifLog {
	specs := make([]sarifRuleSpec, len(report.Checks))
	ruleIndex := make(map[string]int, len(report.Checks))
	for index, check := range report.Checks {
		rule := lintSARIFRules[check]
		specs[index] = sarifRuleSpec{
			id: "aws-lint/" + check, name: check, short: rule.short, full: lintRationales[check], help: rule.help,
			level: lintSARIFLevels[rule.severity],
		}
		ruleIndex[check] = index
	}
	results := make([]sarifResult, len(report.Findings))
	for index, finding := range report.Findings {
		var identity []string
		kind, id := sarifPolicyKind, ""
		if finding.Target != nil {
			kind, id = finding.Target.Type, finding.Target.ID
			identity = append(identity, kind, id)
		}
		if finding.Policy != nil {
			if id == "" {
				id = finding.Policy.ID
			}
			identity = append(identity, sarifPolicyKind, finding.Policy.ID)
		}
		if finding.Evidence.StatementIndex != nil {
			identity = append(identity, fmt.Sprintf("statement %d", *finding.Evidence.StatementIndex))
		}
		results[index] = newSARIFResult(
			ruleIndex[finding.Check], specs[ruleIndex[finding.Check]].id, lintSARIFLevels[finding.Severity],
			finding.Message, report.Root.ID, kind, id, identity,
			lintSARIFProperties{Severity: finding.Severity, Target: finding.Target, Policy: finding.Policy, Evidence: finding.Evidence},
		)
	}
	return newSARIFLog("policy-scout/aws-lint/"+report.Root.ID+"/", specs, results)
}

var coverageSARIFRules = []sarifRuleSpec{
	{
		id: "aws-coverage/" + coverageRuleUncovered, name: coverageRuleUncovered, level: "error",
		short: "Account is not covered by the required SCP control",
		full: "No SCP that applies to this account directly or through inheritance provides the requested control: " +
			"the selected SCP, or a Deny for the selected action that applies to all resources without conditions. " +
			"The account's users and roles are not restricted by it.",
		help: "Attach the SCP to the account or one of its OUs, or add an unconditional Deny for the action to an SCP that applies to the account.",
	},
	{
		id: "aws-coverage/" + coverageRuleConditional, name: coverageRuleConditional, level: "warning",
		short: "Account is only conditionally covered by an SCP Deny",
		full: "Every Deny for the selected action that applies to this account has a Condition or a Resource or NotResource " +
			"scope, so some requests for the action are not denied. Policy Scout does not evaluate conditions.",
		help: "Review the Condition and resource scope in the result evidence. If the carve-out is unintended, add an " +
			"unconditional Deny for the action to an SCP that applies to the account.",
	},
}

func coverageSARIF(result coverageResult) sarifLog {
	query := result.Query
	selector := query.PolicyID
	needs := fmt.Sprintf("does not receive SCP %s [%s] directly or through inheritance", query.PolicyName, query.PolicyID)
	if query.Type == coverageQueryTypeAction {
		// IAM action names are case-insensitive, so the casing given on the
		// command line must not change alert identity.
		selector = strings.ToLower(query.Action)
		needs = fmt.Sprintf("has no applicable SCP that denies %s for all resources without conditions", query.Action)
	}
	rootID := coverageSARIFRootID(result)
	var results []sarifResult
	for ruleIndex, accounts := range [][]coverageAccountResult{result.UncoveredAccounts, result.ConditionallyCoveredAccounts} {
		rule := coverageSARIFRules[ruleIndex]
		for _, account := range accounts {
			message := fmt.Sprintf("%s %s.", coverageAccountText(account.Account, account.Path), needs)
			if ruleIndex == 1 {
				evidence := make([]string, len(account.Evidence))
				for index, item := range account.Evidence {
					evidence[index] = coverageEvidenceText(item)
				}
				message = fmt.Sprintf("%s is only conditionally covered for %s: %s.",
					coverageAccountText(account.Account, account.Path), query.Action, strings.Join(evidence, "; "))
			}
			results = append(results, newSARIFResult(
				ruleIndex, rule.id, rule.level, message, rootID, accountEntityType, account.Account.ID,
				[]string{query.Type, selector, account.Account.ID}, account,
			))
		}
	}
	return newSARIFLog(fmt.Sprintf("policy-scout/aws-coverage/%s/%s/%s/", rootID, query.Type, selector), coverageSARIFRules, results)
}

// coverageSARIFRootID returns the organization root from any account path. The
// management account is always excluded, so even a report without gaps has one.
func coverageSARIFRootID(result coverageResult) string {
	for _, accounts := range [][]coverageAccountResult{result.UncoveredAccounts, result.ConditionallyCoveredAccounts, result.CoveredAccounts} {
		for _, account := range accounts {
			return account.Path[0].ID
		}
	}
	for _, account := range result.ExcludedAccounts {
		return account.Path[0].ID
	}
	return ""
}
