package cmd

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	cloudtrailtypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"
)

const (
	changesManagementAccount = "111111111111"
	changesWorkloadAccount   = "333333333333"
	changesGuardPolicy       = "p-e5f6g7h8"
	changesOtherPolicy       = "p-a1b2c3d4"
	changesSourceOU          = "ou-cww9-aaaaaaaa"
	changesDestinationOU     = "ou-cww9-x2atbcle"
	changesRootID            = "r-cww9"
	changesAdminRole         = `"userIdentity":{"type":"AssumedRole","principalId":"AROAEXAMPLE:alice","arn":"arn:aws:sts::111111111111:assumed-role/OrgAdmin/alice","accountId":"111111111111","sessionContext":{"sessionIssuer":{"type":"Role","arn":"arn:aws:iam::111111111111:role/OrgAdmin"}}}`
)

var (
	changesStart = time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	changesEnd   = time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
)

type fakeLookupEventsClient struct {
	mu       sync.Mutex
	inputs   []cloudtrail.LookupEventsInput
	calls    []time.Time
	lookupFn func(context.Context, *cloudtrail.LookupEventsInput) (*cloudtrail.LookupEventsOutput, error)
}

func (fake *fakeLookupEventsClient) LookupEvents(
	ctx context.Context, input *cloudtrail.LookupEventsInput, _ ...func(*cloudtrail.Options),
) (*cloudtrail.LookupEventsOutput, error) {
	fake.mu.Lock()
	fake.inputs = append(fake.inputs, *input)
	fake.calls = append(fake.calls, time.Now())
	fake.mu.Unlock()
	return fake.lookupFn(ctx, input)
}

func changesSTSClient() *fakeSTSClient {
	return &fakeSTSClient{getCallerIdentityFn: func(context.Context, *sts.GetCallerIdentityInput) (*sts.GetCallerIdentityOutput, error) {
		return &sts.GetCallerIdentityOutput{Account: aws.String(changesManagementAccount), Arn: aws.String("arn:caller")}, nil
	}}
}

func cloudTrailEvent(id string, at time.Time, record string) cloudtrailtypes.Event {
	return cloudtrailtypes.Event{EventId: aws.String(id), EventTime: aws.Time(at), CloudTrailEvent: aws.String(record)}
}

// changesFixtureClient returns realistic Organizations records for several
// event names. AttachPolicy spans two pages that repeat one event and are
// returned oldest first, and CreatePolicy includes an IAM event with the same
// name that must be ignored.
func changesFixtureClient() *fakeLookupEventsClient {
	at := func(day, hour int) time.Time { return time.Date(2026, 10, day, hour, 0, 0, 0, time.UTC) }
	attachOU := cloudTrailEvent("evt-attach-ou", at(20, 9), `{"eventSource":"organizations.amazonaws.com","eventName":"AttachPolicy",`+changesAdminRole+
		`,"sourceIPAddress":"203.0.113.10","requestID":"req-attach-ou","requestParameters":{"policyId":"p-e5f6g7h8","targetId":"ou-cww9-x2atbcle"},"responseElements":null}`)
	attachAccount := cloudTrailEvent("evt-attach-account", at(21, 9), `{"eventSource":"organizations.amazonaws.com","eventName":"AttachPolicy",`+changesAdminRole+
		`,"sourceIPAddress":"203.0.113.10","requestID":"req-attach-account","requestParameters":{"policyId":"p-a1b2c3d4","targetId":"333333333333"}}`)
	events := map[string][][]cloudtrailtypes.Event{
		"AttachPolicy": {{attachOU}, {attachAccount, attachOU}},
		"CreatePolicy": {{
			cloudTrailEvent("evt-create", at(19, 8), `{"eventSource":"organizations.amazonaws.com","eventName":"CreatePolicy",`+changesAdminRole+
				`,"sourceIPAddress":"203.0.113.10","requestID":"req-create","requestParameters":{"name":"DenyRegions","type":"SERVICE_CONTROL_POLICY","content":"{}"},`+
				`"responseElements":{"policy":{"policySummary":{"id":"p-e5f6g7h8","name":"DenyRegions","type":"SERVICE_CONTROL_POLICY"},"content":"{}"}}}`),
			cloudTrailEvent("evt-iam-create", at(25, 8), `{"eventSource":"iam.amazonaws.com","eventName":"CreatePolicy","requestParameters":{"policyName":"x"}}`),
		}},
		"DeletePolicy": {{
			cloudTrailEvent("evt-delete-denied", at(22, 7), `{"eventSource":"organizations.amazonaws.com","eventName":"DeletePolicy",`+
				`"userIdentity":{"type":"IAMUser","principalId":"AIDAEXAMPLE","arn":"arn:aws:iam::111111111111:user/bob","accountId":"111111111111","userName":"bob"},`+
				`"sourceIPAddress":"198.51.100.7","requestID":"req-delete","errorCode":"AccessDeniedException","errorMessage":"not authorized","requestParameters":{"policyId":"p-a1b2c3d4"}}`),
		}},
		"EnablePolicyType": {{
			cloudTrailEvent("evt-enable-type", at(2, 12), `{"eventSource":"organizations.amazonaws.com","eventName":"EnablePolicyType",`+changesAdminRole+
				`,"sourceIPAddress":"203.0.113.10","requestID":"req-enable-type","requestParameters":{"rootId":"r-cww9","policyType":"SERVICE_CONTROL_POLICY"}}`),
		}},
		"MoveAccount": {{
			cloudTrailEvent("evt-move", at(23, 15), `{"eventSource":"organizations.amazonaws.com","eventName":"MoveAccount",`+changesAdminRole+
				`,"sourceIPAddress":"203.0.113.10","requestID":"req-move","requestParameters":{"accountId":"333333333333","sourceParentId":"ou-cww9-aaaaaaaa","destinationParentId":"ou-cww9-x2atbcle"}}`),
		}},
		"RegisterDelegatedAdministrator": {{
			cloudTrailEvent("evt-register", at(3, 10), `{"eventSource":"organizations.amazonaws.com","eventName":"RegisterDelegatedAdministrator",`+
				`"userIdentity":{"type":"AWSService","invokedBy":"securityhub.amazonaws.com"},"sourceIPAddress":"securityhub.amazonaws.com","requestID":"req-register",`+
				`"requestParameters":{"accountId":"222222222222","servicePrincipal":"securityhub.amazonaws.com"}}`),
		}},
		"PutResourcePolicy": {{
			cloudTrailEvent("evt-put-rp", at(4, 10), `{"eventSource":"organizations.amazonaws.com","eventName":"PutResourcePolicy",`+changesAdminRole+
				`,"sourceIPAddress":"203.0.113.10","requestID":"req-put-rp","requestParameters":{"content":"{}"},"responseElements":{"resourcePolicy":{"resourcePolicySummary":{"id":"rp-example1","arn":"arn:rp"}}}}`),
		}},
	}
	return &fakeLookupEventsClient{lookupFn: func(_ context.Context, input *cloudtrail.LookupEventsInput) (*cloudtrail.LookupEventsOutput, error) {
		pages := events[aws.ToString(input.LookupAttributes[0].AttributeValue)]
		if len(pages) == 0 {
			return &cloudtrail.LookupEventsOutput{}, nil
		}
		if input.NextToken == nil {
			output := &cloudtrail.LookupEventsOutput{Events: pages[0]}
			if len(pages) > 1 {
				output.NextToken = aws.String("page-2")
			}
			return output, nil
		}
		return &cloudtrail.LookupEventsOutput{Events: pages[1]}, nil
	}}
}

func changesFixtureQuery() changesQuery {
	return changesQuery{Region: "us-east-1", StartTime: changesStart, EndTime: changesEnd}
}

func changeIDs(events []controlChange) []string {
	ids := make([]string, 0, len(events))
	for _, event := range events {
		ids = append(ids, event.EventID)
	}
	return ids
}

func TestChangesReportsOrganizationEventsNewestFirst(t *testing.T) {
	t.Parallel()

	client := changesFixtureClient()
	result, err := buildChanges(context.Background(), changesSTSClient(), client, changesFixtureQuery(), 0)
	if err != nil {
		t.Fatalf("build changes: %v", err)
	}

	// Every event name is looked up separately within the requested window.
	var looked []string
	for _, input := range client.inputs {
		if len(input.LookupAttributes) != 1 || input.LookupAttributes[0].AttributeKey != cloudtrailtypes.LookupAttributeKeyEventName {
			t.Fatalf("lookup attributes = %+v, want exactly one EventName attribute", input.LookupAttributes)
		}
		if !aws.ToTime(input.StartTime).Equal(changesStart) || !aws.ToTime(input.EndTime).Equal(changesEnd) {
			t.Fatalf("lookup window = %v to %v, want %v to %v", input.StartTime, input.EndTime, changesStart, changesEnd)
		}
		if input.NextToken == nil {
			looked = append(looked, aws.ToString(input.LookupAttributes[0].AttributeValue))
		}
	}
	if !reflect.DeepEqual(looked, controlChangeEventNames) || len(controlChangeEventNames) != 14 {
		t.Fatalf("looked up %v, want each of the 14 control-change events once", looked)
	}

	admin := changeCaller{
		Type: "AssumedRole", ARN: "arn:aws:sts::111111111111:assumed-role/OrgAdmin/alice", AccountID: changesManagementAccount,
		PrincipalID: "AROAEXAMPLE:alice", SessionIssuerARN: "arn:aws:iam::111111111111:role/OrgAdmin",
	}
	want := []controlChange{
		{
			EventID: "evt-move", EventTime: "2026-10-23T15:00:00Z", EventName: "MoveAccount", RequestID: "req-move", SourceIP: "203.0.113.10",
			Caller: admin, Target: &changeTarget{Type: accountEntityType, ID: changesWorkloadAccount},
			SourceParentID: changesSourceOU, DestinationParentID: changesDestinationOU,
		},
		{
			EventID: "evt-delete-denied", EventTime: "2026-10-22T07:00:00Z", EventName: "DeletePolicy", RequestID: "req-delete", SourceIP: "198.51.100.7",
			Caller: changeCaller{
				Type: "IAMUser", ARN: "arn:aws:iam::111111111111:user/bob", AccountID: changesManagementAccount, PrincipalID: "AIDAEXAMPLE", UserName: "bob",
			},
			Policy: &changePolicy{ID: changesOtherPolicy}, ErrorCode: "AccessDeniedException", ErrorMessage: "not authorized",
		},
		{
			EventID: "evt-attach-account", EventTime: "2026-10-21T09:00:00Z", EventName: "AttachPolicy", RequestID: "req-attach-account",
			SourceIP: "203.0.113.10", Caller: admin, Policy: &changePolicy{ID: changesOtherPolicy},
			Target: &changeTarget{Type: accountEntityType, ID: changesWorkloadAccount},
		},
		{
			EventID: "evt-attach-ou", EventTime: "2026-10-20T09:00:00Z", EventName: "AttachPolicy", RequestID: "req-attach-ou",
			SourceIP: "203.0.113.10", Caller: admin, Policy: &changePolicy{ID: changesGuardPolicy},
			Target: &changeTarget{Type: organizationalUnitEntityType, ID: changesDestinationOU},
		},
		{
			EventID: "evt-create", EventTime: "2026-10-19T08:00:00Z", EventName: "CreatePolicy", RequestID: "req-create", SourceIP: "203.0.113.10",
			Caller: admin, Policy: &changePolicy{ID: changesGuardPolicy, Name: "DenyRegions", Type: "SERVICE_CONTROL_POLICY"},
		},
		{
			EventID: "evt-put-rp", EventTime: "2026-10-04T10:00:00Z", EventName: "PutResourcePolicy", RequestID: "req-put-rp", SourceIP: "203.0.113.10",
			Caller: admin, ResourcePolicyID: "rp-example1",
		},
		{
			EventID: "evt-register", EventTime: "2026-10-03T10:00:00Z", EventName: "RegisterDelegatedAdministrator", RequestID: "req-register",
			SourceIP: "securityhub.amazonaws.com", Caller: changeCaller{Type: "AWSService", InvokedBy: "securityhub.amazonaws.com"},
			Target: &changeTarget{Type: accountEntityType, ID: "222222222222"}, ServicePrincipal: "securityhub.amazonaws.com",
		},
		{
			EventID: "evt-enable-type", EventTime: "2026-10-02T12:00:00Z", EventName: "EnablePolicyType", RequestID: "req-enable-type",
			SourceIP: "203.0.113.10", Caller: admin, Policy: &changePolicy{Type: "SERVICE_CONTROL_POLICY"},
			Target: &changeTarget{Type: rootEntityType, ID: changesRootID},
		},
	}
	for index := range result.Events {
		result.Events[index].eventTime = time.Time{}
	}
	if !reflect.DeepEqual(result.Events, want) {
		t.Fatalf("events = %v, want %v", changeIDs(result.Events), changeIDs(want))
	}
	if result.AccountID != changesManagementAccount || result.Region != "us-east-1" || result.Source != "cloudtrail:LookupEvents" ||
		result.StartTime != "2026-10-01T00:00:00Z" || result.EndTime != "2026-11-01T00:00:00Z" {
		t.Fatalf("result metadata = %+v", result)
	}
}

func TestChangesFiltersByPolicyAndTarget(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		policyID, targetID string
		want               []string
	}{
		// CreatePolicy carries the new policy ID only in its response.
		"policy":  {policyID: changesGuardPolicy, want: []string{"evt-attach-ou", "evt-create"}},
		"account": {targetID: changesWorkloadAccount, want: []string{"evt-move", "evt-attach-account"}},
		// An account moved into the OU changes what the OU's SCPs govern.
		"organizational unit":   {targetID: changesDestinationOU, want: []string{"evt-move", "evt-attach-ou"}},
		"move source":           {targetID: changesSourceOU, want: []string{"evt-move"}},
		"root":                  {targetID: changesRootID, want: []string{"evt-enable-type"}},
		"policy and target":     {policyID: changesOtherPolicy, targetID: changesWorkloadAccount, want: []string{"evt-attach-account"}},
		"policy without events": {policyID: "p-zzzzzzzz", want: []string{}},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			query := changesFixtureQuery()
			query.PolicyID, query.TargetID = test.policyID, test.targetID
			result, err := buildChanges(context.Background(), changesSTSClient(), changesFixtureClient(), query, 0)
			if err != nil {
				t.Fatalf("build changes: %v", err)
			}
			if got := changeIDs(result.Events); !reflect.DeepEqual(got, test.want) {
				t.Fatalf("events = %v, want %v", got, test.want)
			}
			if result.PolicyID != test.policyID || result.TargetID != test.targetID {
				t.Fatalf("result filters = %q/%q, want %q/%q", result.PolicyID, result.TargetID, test.policyID, test.targetID)
			}
		})
	}
}

func TestChangesPacesLookupEventsRequests(t *testing.T) {
	t.Parallel()

	client := changesFixtureClient()
	interval := 20 * time.Millisecond
	if _, err := buildChanges(context.Background(), changesSTSClient(), client, changesFixtureQuery(), interval); err != nil {
		t.Fatalf("build changes: %v", err)
	}
	if len(client.calls) != len(controlChangeEventNames)+1 {
		t.Fatalf("LookupEvents calls = %d, want one per event name plus one extra page", len(client.calls))
	}
	for index := 1; index < len(client.calls); index++ {
		if gap := client.calls[index].Sub(client.calls[index-1]); gap < interval {
			t.Fatalf("request %d followed the previous one after %s, want at least %s", index, gap, interval)
		}
	}
}

func TestChangesFailuresWriteNoPartialOutput(t *testing.T) {
	t.Parallel()

	tests := map[string]func(*fakeLookupEventsClient){
		"malformed event record": func(client *fakeLookupEventsClient) {
			client.lookupFn = func(context.Context, *cloudtrail.LookupEventsInput) (*cloudtrail.LookupEventsOutput, error) {
				return &cloudtrail.LookupEventsOutput{Events: []cloudtrailtypes.Event{cloudTrailEvent("evt-bad", changesStart, "{")}}, nil
			}
		},
		"missing event ID": func(client *fakeLookupEventsClient) {
			client.lookupFn = func(context.Context, *cloudtrail.LookupEventsInput) (*cloudtrail.LookupEventsOutput, error) {
				return &cloudtrail.LookupEventsOutput{Events: []cloudtrailtypes.Event{{EventTime: aws.Time(changesStart), CloudTrailEvent: aws.String("{}")}}}, nil
			}
		},
		"repeated pagination token": func(client *fakeLookupEventsClient) {
			client.lookupFn = func(context.Context, *cloudtrail.LookupEventsInput) (*cloudtrail.LookupEventsOutput, error) {
				return &cloudtrail.LookupEventsOutput{NextToken: aws.String("same")}, nil
			}
		},
		"late lookup failure": func(client *fakeLookupEventsClient) {
			lookup := client.lookupFn
			client.lookupFn = func(ctx context.Context, input *cloudtrail.LookupEventsInput) (*cloudtrail.LookupEventsOutput, error) {
				if aws.ToString(input.LookupAttributes[0].AttributeValue) == "DisableAWSServiceAccess" {
					return nil, errors.New("late failure")
				}
				return lookup(ctx, input)
			}
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			client := changesFixtureClient()
			mutate(client)
			result, err := buildChanges(context.Background(), changesSTSClient(), client, changesFixtureQuery(), 0)
			if err == nil {
				t.Fatalf("expected an error, got %+v", result)
			}
		})
	}
}

func TestChangesAccessDeniedIsClassifiedAsCloudTrail(t *testing.T) {
	t.Parallel()

	client := changesFixtureClient()
	client.lookupFn = func(context.Context, *cloudtrail.LookupEventsInput) (*cloudtrail.LookupEventsOutput, error) {
		return nil, &smithy.OperationError{
			ServiceID: "CloudTrail", OperationName: "LookupEvents",
			Err: &smithy.GenericAPIError{Code: "AccessDeniedException", Message: "denied", Fault: smithy.FaultClient},
		}
	}
	_, err := buildChanges(context.Background(), changesSTSClient(), client, changesFixtureQuery(), 0)
	diagnostic := classifyError(err)
	if diagnostic.Code != errorCodeAuthorization || diagnostic.ExitCode != exitAuthorization || diagnostic.Operation != "LookupEvents" ||
		!strings.Contains(diagnostic.Remediation, "cloudtrail:LookupEvents") {
		t.Fatalf("diagnostic = %#v, want aws_access_denied for LookupEvents naming cloudtrail:LookupEvents", diagnostic)
	}
}

func TestChangesTextOutputSummarizesEventsAndEscapesValues(t *testing.T) {
	t.Parallel()

	query := changesFixtureQuery()
	query.TargetID = changesDestinationOU
	result, err := buildChanges(context.Background(), changesSTSClient(), changesFixtureClient(), query, 0)
	if err != nil {
		t.Fatal(err)
	}
	result.Events[0].Caller.ARN = "arn:alice\x1b[31m"
	var output bytes.Buffer
	if err := writeChanges(&output, result, text); err != nil {
		t.Fatalf("write text: %v", err)
	}
	got := output.String()
	if strings.Contains(got, "\x1b") {
		t.Fatalf("text output contains raw terminal controls: %q", got)
	}
	want := "Organization control changes in CloudTrail event history for account 111111111111 (us-east-1)\n" +
		"Window: 2026-10-01T00:00:00Z to 2026-11-01T00:00:00Z\n" +
		"Target filter: ou-cww9-x2atbcle\n" +
		"2026-10-23T15:00:00Z MoveAccount\n" +
		"    Caller: AssumedRole arn:alice\\x1b[31m\n" +
		"    Source IP: 203.0.113.10\n" +
		"    Target: Account [333333333333]\n" +
		"    Moved: ou-cww9-aaaaaaaa -> ou-cww9-x2atbcle\n" +
		"    Request ID: req-move\n" +
		"2026-10-20T09:00:00Z AttachPolicy\n" +
		"    Caller: AssumedRole arn:aws:sts::111111111111:assumed-role/OrgAdmin/alice\n" +
		"    Source IP: 203.0.113.10\n" +
		"    Policy: [p-e5f6g7h8]\n" +
		"    Target: OU [ou-cww9-x2atbcle]\n" +
		"    Request ID: req-attach-ou\n" +
		"Event history only:"
	if !strings.HasPrefix(got, want) {
		t.Fatalf("text output =\n%s\nwant prefix\n%s", got, want)
	}

	result.Events = nil
	output.Reset()
	if err := writeChanges(&output, result, text); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "Events: none\n") {
		t.Fatalf("empty text output lacks explicit none:\n%s", output.String())
	}
}
