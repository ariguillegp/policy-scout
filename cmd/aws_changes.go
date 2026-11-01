package cmd

import (
	"context"
	encodingjson "encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	cloudtrailtypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/spf13/cobra"
)

const (
	changesSchemaVersion = "1"
	changesSource        = "cloudtrail:LookupEvents"
	organizationsSource  = "organizations.amazonaws.com"
	// AWS Organizations records its CloudTrail events only in US East (N. Virginia).
	defaultChangesRegion = "us-east-1"
	// LookupEvents returns management events from the last 90 days only.
	lookupEventsRetention = 90 * 24 * time.Hour
	// LookupEvents is limited to two requests per second per account and Region.
	lookupEventsInterval = 500 * time.Millisecond
)

// controlChangeEventNames are the Organizations write events that change
// guardrails or who administers them. Each is queried with its own
// LookupEvents request series because a lookup accepts only one attribute.
var controlChangeEventNames = []string{
	"CreatePolicy",
	"UpdatePolicy",
	"DeletePolicy",
	"AttachPolicy",
	"DetachPolicy",
	"EnablePolicyType",
	"DisablePolicyType",
	"MoveAccount",
	"RegisterDelegatedAdministrator",
	"DeregisterDelegatedAdministrator",
	"PutResourcePolicy",
	"DeleteResourcePolicy",
	"EnableAWSServiceAccess",
	"DisableAWSServiceAccess",
}

var (
	changesFormat    outputFormat = json
	changesStartTime string
	changesEndTime   string
	changesSince     time.Duration
	changesPolicyID  string
	changesTargetID  string
	changesRegion    string

	awsChangesCmd = &cobra.Command{
		Use:   "changes",
		Short: "Show who changed organization controls and when, from CloudTrail",
		Long: `Return one compact, versioned result listing recent AWS Organizations events
that change organization controls: SCP creation, updates, deletion, attachment
and detachment, policy type enablement, account moves, delegated administrator
registration, resource-based delegation policy changes, and trusted service
access. Each event reports the caller identity, time, source IP, event name,
affected policy or target, and request ID. Failed attempts are included with
their error code. JSON output is used by default.

Events come from CloudTrail event history through LookupEvents in us-east-1,
where AWS Organizations records its events. LookupEvents covers only the last
90 days of management events, only for the account whose credentials are used,
and is limited to two requests per second; Policy Scout paces its requests to
that limit. Calls made from a delegated administrator account are recorded in
that account's event history, not the management account's. For older events
or every account, query an organization trail or CloudTrail Lake instead.

The window defaults to the last 90 days. --policy-id and --target-id filter the
returned events; they do not reduce the number of LookupEvents requests.`,
		Example: `  policy-scout aws changes
  policy-scout aws changes --since 168h --output-format text
  policy-scout aws changes --policy-id p-a1b2c3d4
  policy-scout aws changes --target-id ou-cww9-x2atbcle --start-time 2026-10-01T00:00:00Z --end-time 2026-10-15T00:00:00Z`,
		Args: noArgsValidator,
		RunE: runAWSChangesCommand,
	}
)

func init() {
	flags := awsChangesCmd.Flags()
	flags.StringVar(&changesStartTime, "start-time", "", "earliest event time, RFC 3339 (default 90 days ago, the LookupEvents limit)")
	flags.StringVar(&changesEndTime, "end-time", "", "latest event time, RFC 3339 (default now)")
	flags.DurationVar(&changesSince, "since", 0, "look back this long from now instead of --start-time (for example, 168h)")
	flags.StringVar(&changesPolicyID, "policy-id", "", "only events for this SCP or policy ID")
	flags.StringVar(&changesTargetID, "target-id", "", "only events for this account, OU, or root ID, including account moves into or out of an OU or root")
	flags.StringVar(&changesRegion, "region", defaultChangesRegion, "Region whose CloudTrail event history records Organizations events (us-gov-west-1 for AWS GovCloud (US))")
	flags.VarP(&changesFormat, "output-format", "o", `output format: "json" or "text"`)
	if err := awsChangesCmd.RegisterFlagCompletionFunc("output-format", outputFormatCompletion); err != nil {
		panic(err)
	}
	addAWSExecutionFlags(awsChangesCmd)
}

type changesQuery struct {
	Region    string
	StartTime time.Time
	EndTime   time.Time
	PolicyID  string
	TargetID  string
}

type changeCaller struct {
	Type             string `json:"type,omitempty"`
	ARN              string `json:"arn,omitempty"`
	AccountID        string `json:"account_id,omitempty"`
	PrincipalID      string `json:"principal_id,omitempty"`
	UserName         string `json:"user_name,omitempty"`
	SessionIssuerARN string `json:"session_issuer_arn,omitempty"`
	InvokedBy        string `json:"invoked_by,omitempty"`
}

type changePolicy struct {
	ID   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
	Type string `json:"type,omitempty"`
}

type changeTarget struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

type controlChange struct {
	EventID             string        `json:"event_id"`
	EventTime           string        `json:"event_time"`
	EventName           string        `json:"event_name"`
	RequestID           string        `json:"request_id,omitempty"`
	SourceIP            string        `json:"source_ip,omitempty"`
	Caller              changeCaller  `json:"caller"`
	Policy              *changePolicy `json:"policy,omitempty"`
	ResourcePolicyID    string        `json:"resource_policy_id,omitempty"`
	Target              *changeTarget `json:"target,omitempty"`
	SourceParentID      string        `json:"source_parent_id,omitempty"`
	DestinationParentID string        `json:"destination_parent_id,omitempty"`
	ServicePrincipal    string        `json:"service_principal,omitempty"`
	ErrorCode           string        `json:"error_code,omitempty"`
	ErrorMessage        string        `json:"error_message,omitempty"`

	eventTime time.Time
}

type changesResult struct {
	SchemaVersion string          `json:"schema_version"`
	Source        string          `json:"source"`
	AccountID     string          `json:"account_id"`
	Region        string          `json:"region"`
	StartTime     string          `json:"start_time"`
	EndTime       string          `json:"end_time"`
	PolicyID      string          `json:"policy_id,omitempty"`
	TargetID      string          `json:"target_id,omitempty"`
	EventNames    []string        `json:"event_names"`
	Events        []controlChange `json:"events"`
}

func runAWSChangesCommand(cmd *cobra.Command, _ []string) error {
	controls, err := awsExecutionControlsFromCommand(cmd)
	if err != nil {
		return err
	}
	query, err := changesQueryFromFlags(cmd, time.Now())
	if err != nil {
		return newInvalidInvocationError(err)
	}
	ctx, cancel := controls.context(cmd.Context())
	defer cancel()
	err = inspectAWSChanges(ctx, cmd.OutOrStdout(), profile, query, changesFormat, controls.configLoadOptions()...)
	return controls.explainError(err)
}

func changesQueryFromFlags(cmd *cobra.Command, now time.Time) (changesQuery, error) {
	now = now.UTC().Truncate(time.Second)
	query := changesQuery{
		Region: strings.TrimSpace(changesRegion), EndTime: now, StartTime: now.Add(-lookupEventsRetention),
		PolicyID: changesPolicyID, TargetID: changesTargetID,
	}
	if query.Region == "" {
		return changesQuery{}, errors.New("invalid --region: must not be empty")
	}
	if cmd.Flags().Changed("since") && cmd.Flags().Changed("start-time") {
		return changesQuery{}, errors.New("--since and --start-time cannot be used together")
	}
	if changesEndTime != "" {
		end, err := time.Parse(time.RFC3339, changesEndTime)
		if err != nil {
			return changesQuery{}, fmt.Errorf("invalid --end-time %q: must be an RFC 3339 time such as 2026-10-01T00:00:00Z", changesEndTime)
		}
		query.EndTime = end.UTC()
	}
	if changesStartTime != "" {
		start, err := time.Parse(time.RFC3339, changesStartTime)
		if err != nil {
			return changesQuery{}, fmt.Errorf("invalid --start-time %q: must be an RFC 3339 time such as 2026-10-01T00:00:00Z", changesStartTime)
		}
		query.StartTime = start.UTC()
	}
	if cmd.Flags().Changed("since") {
		if changesSince <= 0 {
			return changesQuery{}, errors.New("invalid --since: must be greater than zero")
		}
		query.StartTime = now.Add(-changesSince)
	}
	earliest := now.Add(-lookupEventsRetention)
	if query.StartTime.Before(earliest) {
		return changesQuery{}, fmt.Errorf(
			"start time %s is outside the CloudTrail LookupEvents window: event history covers only the last 90 days (since %s); query an organization trail or CloudTrail Lake for older events",
			query.StartTime.Format(time.RFC3339), earliest.Format(time.RFC3339),
		)
	}
	if !query.StartTime.Before(query.EndTime) {
		return changesQuery{}, fmt.Errorf("start time %s must be before end time %s",
			query.StartTime.Format(time.RFC3339), query.EndTime.Format(time.RFC3339))
	}
	if query.PolicyID != "" && !validPolicyID(query.PolicyID) {
		return changesQuery{}, fmt.Errorf("invalid --policy-id %q: must match p-<8-128 letters, digits, or underscores>", query.PolicyID)
	}
	if query.TargetID != "" {
		var err error
		switch entityType(query.TargetID) {
		case rootEntityType:
			err = validateRootID(query.TargetID)
		case organizationalUnitEntityType:
			err = validateOrganizationalUnitID(query.TargetID)
		default:
			err = validateStrictAccountID(query.TargetID)
		}
		if err != nil {
			return changesQuery{}, fmt.Errorf("invalid --target-id %q: must be a 12-digit account ID, an OU ID, or a root ID", query.TargetID)
		}
	}
	return query, nil
}

func inspectAWSChanges(
	ctx context.Context,
	writer io.Writer,
	selectedProfile string,
	query changesQuery,
	outputFormat outputFormat,
	configOptions ...func(*config.LoadOptions) error,
) (err error) {
	defer func() { err = addSSORemediation(err, selectedProfile) }()
	configOptions = append(configOptions, config.WithRegion(query.Region))
	cfg, err := loadAWSConfig(ctx, selectedProfile, config.LoadDefaultConfig, configOptions...)
	if err != nil {
		return newCredentialsError("LoadDefaultConfig", err)
	}
	if _, err := cfg.Credentials.Retrieve(ctx); err != nil {
		return newCredentialsError("RetrieveCredentials", err)
	}
	result, err := buildChanges(ctx, sts.NewFromConfig(cfg), cloudtrail.NewFromConfig(cfg), query, lookupEventsInterval)
	if err != nil {
		return err
	}
	return writeChanges(writer, result, outputFormat)
}

// buildChanges looks up each control-change event name in turn, waiting at
// least interval between LookupEvents requests.
func buildChanges(
	ctx context.Context,
	identity stsClient,
	client cloudtrail.LookupEventsAPIClient,
	query changesQuery,
	interval time.Duration,
) (changesResult, error) {
	caller, err := identity.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return changesResult{}, fmt.Errorf("get caller identity: %w", err)
	}
	accountID := ""
	if caller != nil {
		accountID = aws.ToString(caller.Account)
	}
	if err := validateStrictAccountID(accountID); err != nil {
		return changesResult{}, fmt.Errorf("AWS returned invalid caller account ID %q: %w", accountID, err)
	}

	pace := newRequestPacer(interval)
	byID := make(map[string]controlChange)
	for _, eventName := range controlChangeEventNames {
		paginator := cloudtrail.NewLookupEventsPaginator(client, &cloudtrail.LookupEventsInput{
			LookupAttributes: []cloudtrailtypes.LookupAttribute{{
				AttributeKey: cloudtrailtypes.LookupAttributeKeyEventName, AttributeValue: aws.String(eventName),
			}},
			StartTime: aws.Time(query.StartTime), EndTime: aws.Time(query.EndTime),
		})
		seenTokens := make(map[string]bool)
		for paginator.HasMorePages() {
			if err := pace(ctx); err != nil {
				return changesResult{}, err
			}
			page, err := paginator.NextPage(ctx)
			if err != nil {
				return changesResult{}, fmt.Errorf("look up %s events: %w", eventName, err)
			}
			if err := rejectRepeatedToken(seenTokens, page.NextToken, "LookupEvents"); err != nil {
				return changesResult{}, err
			}
			for _, event := range page.Events {
				change, relevant, err := parseControlChange(event, eventName)
				if err != nil {
					return changesResult{}, err
				}
				if relevant && change.matches(query) {
					byID[change.EventID] = change
				}
			}
		}
	}

	events := make([]controlChange, 0, len(byID))
	for _, change := range byID {
		events = append(events, change)
	}
	sort.Slice(events, func(i, j int) bool {
		if !events[i].eventTime.Equal(events[j].eventTime) {
			return events[i].eventTime.After(events[j].eventTime)
		}
		return events[i].EventID < events[j].EventID
	})
	return changesResult{
		SchemaVersion: changesSchemaVersion,
		Source:        changesSource,
		AccountID:     accountID,
		Region:        query.Region,
		StartTime:     query.StartTime.Format(time.RFC3339),
		EndTime:       query.EndTime.Format(time.RFC3339),
		PolicyID:      query.PolicyID,
		TargetID:      query.TargetID,
		EventNames:    append([]string(nil), controlChangeEventNames...),
		Events:        events,
	}, nil
}

func newRequestPacer(interval time.Duration) func(context.Context) error {
	var last time.Time
	return func(ctx context.Context) error {
		if interval > 0 && !last.IsZero() {
			if delay := time.Until(last.Add(interval)); delay > 0 {
				timer := time.NewTimer(delay)
				defer timer.Stop()
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-timer.C:
				}
			}
		}
		last = time.Now()
		return nil
	}
}

// cloudTrailRecord holds the parts of a CloudTrail event record that identify
// the caller and the affected Organizations entities.
type cloudTrailRecord struct {
	EventSource     string `json:"eventSource"`
	EventName       string `json:"eventName"`
	RequestID       string `json:"requestID"`
	SourceIPAddress string `json:"sourceIPAddress"`
	ErrorCode       string `json:"errorCode"`
	ErrorMessage    string `json:"errorMessage"`
	UserIdentity    struct {
		Type           string `json:"type"`
		PrincipalID    string `json:"principalId"`
		ARN            string `json:"arn"`
		AccountID      string `json:"accountId"`
		UserName       string `json:"userName"`
		InvokedBy      string `json:"invokedBy"`
		SessionContext struct {
			SessionIssuer struct {
				ARN string `json:"arn"`
			} `json:"sessionIssuer"`
		} `json:"sessionContext"`
	} `json:"userIdentity"`
	RequestParameters *struct {
		PolicyID            string `json:"policyId"`
		Name                string `json:"name"`
		Type                string `json:"type"`
		PolicyType          string `json:"policyType"`
		TargetID            string `json:"targetId"`
		RootID              string `json:"rootId"`
		AccountID           string `json:"accountId"`
		SourceParentID      string `json:"sourceParentId"`
		DestinationParentID string `json:"destinationParentId"`
		ServicePrincipal    string `json:"servicePrincipal"`
	} `json:"requestParameters"`
	ResponseElements *struct {
		Policy *struct {
			PolicySummary struct {
				ID   string `json:"id"`
				Name string `json:"name"`
				Type string `json:"type"`
			} `json:"policySummary"`
		} `json:"policy"`
		ResourcePolicy *struct {
			ResourcePolicySummary struct {
				ID string `json:"id"`
			} `json:"resourcePolicySummary"`
		} `json:"resourcePolicy"`
	} `json:"responseElements"`
}

// parseControlChange reports relevant=false for events from other services
// that share an Organizations event name, such as IAM CreatePolicy.
func parseControlChange(event cloudtrailtypes.Event, eventName string) (controlChange, bool, error) {
	eventID := aws.ToString(event.EventId)
	if eventID == "" {
		return controlChange{}, false, errors.New("AWS returned a CloudTrail event without an event ID")
	}
	if event.EventTime == nil {
		return controlChange{}, false, fmt.Errorf("AWS returned CloudTrail event %s without an event time", eventID)
	}
	var record cloudTrailRecord
	if err := encodingjson.Unmarshal([]byte(aws.ToString(event.CloudTrailEvent)), &record); err != nil {
		return controlChange{}, false, fmt.Errorf("AWS returned malformed CloudTrail event %s", eventID)
	}
	if record.EventSource != organizationsSource || record.EventName != eventName {
		return controlChange{}, false, nil
	}

	identity := record.UserIdentity
	change := controlChange{
		EventID:      eventID,
		EventTime:    event.EventTime.UTC().Format(time.RFC3339),
		EventName:    eventName,
		RequestID:    record.RequestID,
		SourceIP:     record.SourceIPAddress,
		ErrorCode:    record.ErrorCode,
		ErrorMessage: record.ErrorMessage,
		Caller: changeCaller{
			Type: identity.Type, ARN: identity.ARN, AccountID: identity.AccountID, PrincipalID: identity.PrincipalID,
			UserName: identity.UserName, SessionIssuerARN: identity.SessionContext.SessionIssuer.ARN, InvokedBy: identity.InvokedBy,
		},
		eventTime: event.EventTime.UTC(),
	}

	policy := changePolicy{}
	if parameters := record.RequestParameters; parameters != nil {
		policy = changePolicy{ID: parameters.PolicyID, Name: parameters.Name, Type: parameters.Type}
		if parameters.PolicyType != "" {
			policy.Type = parameters.PolicyType
		}
		for _, targetID := range []string{parameters.TargetID, parameters.AccountID, parameters.RootID} {
			if targetID != "" {
				change.Target = &changeTarget{Type: entityType(targetID), ID: targetID}
				break
			}
		}
		change.SourceParentID = parameters.SourceParentID
		change.DestinationParentID = parameters.DestinationParentID
		change.ServicePrincipal = parameters.ServicePrincipal
	}
	if response := record.ResponseElements; response != nil {
		if response.Policy != nil {
			summary := response.Policy.PolicySummary
			policy = changePolicy{
				ID: firstNonEmpty(summary.ID, policy.ID), Name: firstNonEmpty(summary.Name, policy.Name), Type: firstNonEmpty(summary.Type, policy.Type),
			}
		}
		if response.ResourcePolicy != nil {
			change.ResourcePolicyID = response.ResourcePolicy.ResourcePolicySummary.ID
		}
	}
	if policy != (changePolicy{}) {
		change.Policy = &policy
	}
	return change, true, nil
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func (change controlChange) matches(query changesQuery) bool {
	if query.PolicyID != "" && (change.Policy == nil || change.Policy.ID != query.PolicyID) {
		return false
	}
	if query.TargetID == "" {
		return true
	}
	return (change.Target != nil && change.Target.ID == query.TargetID) ||
		change.SourceParentID == query.TargetID || change.DestinationParentID == query.TargetID
}

func writeChanges(writer io.Writer, result changesResult, outputFormat outputFormat) error {
	if outputFormat != text {
		return writeJSONDocument(writer, result, "changes query")
	}

	var output strings.Builder
	fmt.Fprintf(&output, "Organization control changes in CloudTrail event history for account %s (%s)\n",
		displayText(result.AccountID), displayText(result.Region))
	fmt.Fprintf(&output, "Window: %s to %s\n", displayText(result.StartTime), displayText(result.EndTime))
	if result.PolicyID != "" {
		fmt.Fprintf(&output, "Policy filter: %s\n", displayText(result.PolicyID))
	}
	if result.TargetID != "" {
		fmt.Fprintf(&output, "Target filter: %s\n", displayText(result.TargetID))
	}
	if len(result.Events) == 0 {
		output.WriteString("Events: none\n")
	}
	for _, change := range result.Events {
		heading := change.EventTime + " " + change.EventName
		if change.ErrorCode != "" {
			heading += " (failed: " + change.ErrorCode + ")"
		}
		fmt.Fprintf(&output, "%s\n", displayText(heading))
		writeChangeLine(&output, "Caller", callerText(change.Caller))
		writeChangeLine(&output, "Source IP", change.SourceIP)
		if change.Policy != nil {
			writeChangeLine(&output, "Policy", policyText(*change.Policy))
		}
		writeChangeLine(&output, "Resource policy", change.ResourcePolicyID)
		if change.Target != nil {
			writeChangeLine(&output, "Target", attachmentTargetText(scpAttachmentTarget{Type: change.Target.Type, ID: change.Target.ID}))
		}
		if change.SourceParentID != "" || change.DestinationParentID != "" {
			writeChangeLine(&output, "Moved", change.SourceParentID+" -> "+change.DestinationParentID)
		}
		writeChangeLine(&output, "Service", change.ServicePrincipal)
		writeChangeLine(&output, "Request ID", change.RequestID)
	}
	output.WriteString("Event history only: LookupEvents covers the last 90 days for this account and Region; " +
		"changes made from delegated administrator accounts are recorded in those accounts.\n")
	return writeDocument(writer, []byte(output.String()), "changes query")
}

func writeChangeLine(output *strings.Builder, label, value string) {
	if value != "" {
		fmt.Fprintf(output, "%s%s: %s\n", indent, label, displayText(value))
	}
}

func callerText(caller changeCaller) string {
	identity := firstNonEmpty(caller.ARN, caller.InvokedBy, caller.PrincipalID, caller.UserName)
	if caller.Type == "" {
		return identity
	}
	if identity == "" {
		return caller.Type
	}
	return caller.Type + " " + identity
}

func policyText(policy changePolicy) string {
	label := policy.Name
	if policy.ID != "" {
		label = strings.TrimSpace(label + " [" + policy.ID + "]")
	}
	if policy.Type == "" {
		return label
	}
	if label == "" {
		return policy.Type
	}
	return label + " (" + policy.Type + ")"
}
