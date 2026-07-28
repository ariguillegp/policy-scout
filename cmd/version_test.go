package cmd

import (
	"bytes"
	encodingjson "encoding/json"
	"reflect"
	"testing"
)

func TestVersionJSON(t *testing.T) {
	oldVersion := version
	version = "1.2.3"
	t.Cleanup(func() { version = oldVersion })

	var output bytes.Buffer
	if err := printVersion(&output, json); err != nil {
		t.Fatalf("print version JSON: %v", err)
	}

	var result versionInfo
	if err := encodingjson.Unmarshal(output.Bytes(), &result); err != nil {
		t.Fatalf("decode version JSON: %v", err)
	}
	if result.Version != "1.2.3" {
		t.Fatalf("version is %q, want 1.2.3", result.Version)
	}
	if result.OrganizationSchemaVersion != organizationJSONSchemaVersion {
		t.Fatalf(
			"organization schema version is %q, want %q",
			result.OrganizationSchemaVersion,
			organizationJSONSchemaVersion,
		)
	}
	wantVersions := []string{organizationJSONSchemaVersion, organizationPolicyDocumentsJSONSchemaVersion}
	if !reflect.DeepEqual(result.OrganizationSchemaVersions, wantVersions) {
		t.Fatalf("organization schema versions are %v, want %v", result.OrganizationSchemaVersions, wantVersions)
	}
}

func TestDevelopmentVersion(t *testing.T) {
	if version == "" {
		t.Fatal("development version must not be empty")
	}
}
