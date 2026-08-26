/*
Copyright © 2024 Aristides Gonzalez <aristides@glezpol.com>
*/

package cmd

import (
	"strings"
	"testing"
)

func TestOrganizationOutputFormatSupportsHTML(t *testing.T) {
	t.Parallel()

	for _, value := range []string{text, json, html} {
		var format organizationOutputFormat
		if err := format.Set(value); err != nil {
			t.Fatalf("set organization output format %q: %v", value, err)
		}
		if format.String() != value {
			t.Fatalf("got organization output format %q, want %q", format.String(), value)
		}
	}

	var format organizationOutputFormat
	if err := format.Set("dot"); err == nil {
		t.Fatal("expected dot output format to be rejected")
	}
}

func TestRenderOrganizationTreeHTMLBuildsCollapsibleEscapedDocument(t *testing.T) {
	t.Parallel()

	root := organizationNode{
		SchemaVersion: organizationPolicyDocumentsJSONSchemaVersion,
		Selection:     organizationSelection{Type: allSelectionType},
		Type:          rootEntityType,
		ID:            "r-root",
		Name:          "Root & Main",
		Policies: []organizationPolicy{{
			ID:          "p-deny",
			Name:        "Deny <script>",
			Description: "Blocks <unsafe> access",
			ARN:         "arn:aws:organizations::123:policy/p-deny",
			Content:     []byte(`{"Statement":[{"Resource":"<script>alert(1)</script>"}]}`),
		}},
		Children: []organizationNode{{
			Type: accountEntityType,
			ID:   "123456789012",
			Name: "App <Production>",
			SCPAttachments: []scpAttachment{{
				PolicyID:   "p-deny",
				PolicyName: "Deny <script>",
				AttachedTo: scpAttachmentTarget{Type: rootEntityType, ID: "r-root", Name: "Root & <Main>"},
				Inherited:  true,
			}},
		}},
	}
	root.Policies[0].Content = []byte("{\"Statement\":[{\"Resource\":\"<script>alert(1)</script>\"}]}")

	document := string(renderOrganizationTreeHTML(root))
	for _, expected := range []string{
		"<!doctype html>",
		"Full AWS organization",
		"Schema version</dt><dd>2",
		`<details class="entity root" open>`,
		`<details class="entity account">`,
		`<details class="scp">`,
		"App &lt;Production&gt;",
		"Deny &lt;script&gt;",
		"Blocks &lt;unsafe&gt; access",
		"Policy document",
		"&lt;script&gt;alert(1)&lt;/script&gt;",
		"Attached to ID",
		"inherited from Root Root &amp; &lt;Main&gt; [r-root]",
		"@media (max-width: 40rem)",
	} {
		if !strings.Contains(document, expected) {
			t.Errorf("HTML output missing %q:\n%s", expected, document)
		}
	}
	if strings.Contains(document, "<script>alert(1)</script>") {
		t.Fatal("HTML output contains an unescaped policy document")
	}
	if strings.Count(document, "<details") != strings.Count(document, "</details>") {
		t.Fatal("HTML output has unbalanced details elements")
	}
}

func TestRenderOrganizationTreeHTMLExplainsUnexpandedSelectedOU(t *testing.T) {
	t.Parallel()

	document := string(renderOrganizationTreeHTML(organizationNode{
		SchemaVersion: organizationJSONSchemaVersion,
		Selection: organizationSelection{
			Type:     organizationalUnitEntityType,
			TargetID: "ou-root-12345678",
		},
		Type: rootEntityType,
		ID:   "r-root",
		Children: []organizationNode{{
			Type: organizationalUnitEntityType,
			ID:   "ou-root-12345678",
			Name: "Selected OU",
		}},
	}))
	if !strings.Contains(document, "Descendants were not requested for this selected OU.") {
		t.Fatalf("HTML output implies selected OU has no children:\n%s", document)
	}
}

func TestRenderOrganizationTreeHTMLPreservesSCPNamesWithoutAttachments(t *testing.T) {
	t.Parallel()

	document := string(renderOrganizationTreeHTML(organizationNode{
		SchemaVersion: organizationJSONSchemaVersion,
		Selection:     organizationSelection{Type: allSelectionType},
		Type:          rootEntityType,
		ID:            "r-root",
		Children: []organizationNode{{
			Type: organizationalUnitEntityType,
			ID:   "ou-root-12345678",
			Name: "Legacy",
			SCPs: []string{"DenyS3", "FullAWSAccess"},
		}},
	}))
	if !strings.Contains(document, "Applicable SCPs: DenyS3, FullAWSAccess") {
		t.Fatalf("HTML output omitted fallback SCP names:\n%s", document)
	}
}
