package report

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
)

func finding(check, tool, rule, severity, location string, line int) Finding {
	f := Finding{Check: check, Tool: tool, Rule: rule, Severity: severity, Message: rule + " found", Location: location, Line: line}
	f.Identify()
	return f
}

type sarifOutput struct {
	Schema  string `json:"$schema"`
	Version string `json:"version"`
	Runs    []struct {
		Tool struct {
			Driver struct {
				Name  string `json:"name"`
				Rules []struct {
					ID                   string                 `json:"id"`
					DefaultConfiguration struct{ Level string } `json:"defaultConfiguration"`
					Properties           map[string]any         `json:"properties"`
				} `json:"rules"`
			} `json:"driver"`
		} `json:"tool"`
		AutomationDetails struct{ ID string } `json:"automationDetails"`
		Invocations       []struct {
			ExecutionSuccessful bool `json:"executionSuccessful"`
		} `json:"invocations"`
		Results []struct {
			RuleID    string                `json:"ruleId"`
			RuleIndex int                   `json:"ruleIndex"`
			Level     string                `json:"level"`
			Message   struct{ Text string } `json:"message"`
			Locations []struct {
				PhysicalLocation struct {
					ArtifactLocation struct{ URI, URIBaseID string } `json:"artifactLocation"`
					Region           *struct{ StartLine int }        `json:"region"`
				} `json:"physicalLocation"`
			} `json:"locations"`
			Properties map[string]any `json:"properties"`
		} `json:"results"`
	} `json:"runs"`
}

func TestSARIFOutputForCodeScanning(t *testing.T) {
	t.Parallel()
	secret := finding("secrets", "gitleaks", "generic-api-key", "high", "site/lib/site.ts", 23)
	critical := finding("dependencies", "trivy", "CVE-1", "critical", "site/pnpm-lock.yaml", 1)
	low := finding("dependencies", "trivy", "CVE-2", "low", "a b.json", 0)
	r := Report{SchemaVersion: "1", Version: "test", Target: "/repo", Checks: []Check{
		{Name: "secrets", Tool: "gitleaks", Status: "completed", Findings: []Finding{secret}},
		{Name: "dependencies", Tool: "trivy", Status: "completed", Findings: []Finding{critical, low}},
		{Name: "source", Tool: "opengrep", Status: "failed", Findings: []Finding{finding("source", "opengrep", "eval", "high", "a.js", 2)}},
		{Name: "infra", Tool: "trivy", Status: "completed", Findings: []Finding{}},
	}}
	var out strings.Builder
	if err := Write(&out, r, "sarif"); err != nil {
		t.Fatal(err)
	}
	var doc sarifOutput
	if err := json.Unmarshal([]byte(out.String()), &doc); err != nil {
		t.Fatalf("output is not JSON: %v\n%s", err, out.String())
	}
	if doc.Version != "2.1.0" || !strings.Contains(doc.Schema, "sarif-2.1.0") {
		t.Fatalf("not SARIF 2.1.0: %q %q", doc.Version, doc.Schema)
	}
	var categories []string
	for _, run := range doc.Runs {
		categories = append(categories, run.AutomationDetails.ID)
		if run.Tool.Driver.Name != "pug" || len(run.Invocations) != 1 || !run.Invocations[0].ExecutionSuccessful {
			t.Fatalf("run %q: driver %q, invocations %+v", run.AutomationDetails.ID, run.Tool.Driver.Name, run.Invocations)
		}
		for _, result := range run.Results {
			if rule := run.Tool.Driver.Rules[result.RuleIndex]; rule.ID != result.RuleID {
				t.Fatalf("result %s points at rule %s", result.RuleID, rule.ID)
			}
		}
	}
	if want := []string{"pug/secrets/", "pug/dependencies/", "pug/infra/"}; !slices.Equal(categories, want) {
		t.Fatalf("categories = %q, want %q", categories, want)
	}

	secrets := doc.Runs[0]
	result := secrets.Results[0]
	location := result.Locations[0].PhysicalLocation
	if result.RuleID != "gitleaks/generic-api-key" || result.Level != "error" || result.Message.Text != "generic-api-key found" ||
		location.ArtifactLocation.URI != "site/lib/site.ts" || location.ArtifactLocation.URIBaseID != "%SRCROOT%" ||
		location.Region == nil || location.Region.StartLine != 23 || result.Properties["pugId"] != secret.ID {
		t.Fatalf("secret result = %+v", result)
	}
	if score := secrets.Tool.Driver.Rules[0].Properties["security-severity"]; score != "8.0" {
		t.Fatalf("high security-severity = %v", score)
	}

	dependencies := doc.Runs[1]
	levels := map[string]string{}
	scores := map[string]any{}
	for _, result := range dependencies.Results {
		levels[result.RuleID] = result.Level
	}
	for _, rule := range dependencies.Tool.Driver.Rules {
		scores[rule.ID] = rule.Properties["security-severity"]
	}
	if levels["trivy/CVE-1"] != "error" || scores["trivy/CVE-1"] != "9.5" || levels["trivy/CVE-2"] != "note" || scores["trivy/CVE-2"] != "2.0" {
		t.Fatalf("levels %v, scores %v", levels, scores)
	}
	for _, result := range dependencies.Results {
		if result.RuleID != "trivy/CVE-2" {
			continue
		}
		location := result.Locations[0].PhysicalLocation
		if location.ArtifactLocation.URI != "a%20b.json" || location.Region != nil {
			t.Fatalf("a finding without a line must have an encoded URI and no region: %+v", location)
		}
	}
	if len(doc.Runs[2].Results) != 0 {
		t.Fatalf("clean check reported results: %+v", doc.Runs[2].Results)
	}
}
