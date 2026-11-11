package scanner

import (
	"strings"
	"testing"
)

func TestSARIFEvidence(t *testing.T) {
	t.Parallel()
	data := []byte(`{"version":"2.1.0","runs":[{"tool":{"driver":{"rules":[{"id":"CVE-test","properties":{"security-severity":"9.8"}}]}},"results":[{"ruleId":"CVE-test","level":"warning","message":{"text":"bad package"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"package%20lock.json"},"region":{"startLine":7}}}]}]}]}`)
	findings, err := parseSARIF(data, "trivy")
	if err != nil || len(findings) != 1 {
		t.Fatalf("findings = %+v, error = %v", findings, err)
	}
	finding := findings[0]
	if finding.Severity != "critical" || finding.Location != "package lock.json" || finding.Line != 7 {
		t.Fatalf("severity/location lost: %+v", finding)
	}
	secret, err := parseSARIF(data, "gitleaks")
	if err != nil || strings.Contains(secret[0].Message, "bad package") || secret[0].Severity != "high" {
		t.Fatalf("secret message was not withheld: %+v, %v", secret, err)
	}
}

func TestMalformedReportsNeverPassAsClean(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		tool string
		data string
	}{
		{name: "empty SARIF", tool: "sarif", data: `{}`},
		{name: "missing runs", tool: "sarif", data: `{"version":"2.1.0","runs":[]}`},
		{name: "failed invocation", tool: "sarif", data: `{"version":"2.1.0","runs":[{"invocations":[{"executionSuccessful":false}]}]}`},
		{name: "execution error notification", tool: "sarif", data: `{"version":"2.1.0","runs":[{"invocations":[{"executionSuccessful":true,"toolExecutionNotifications":[{"level":"error"}]}]}]}`},
		{name: "bad result", tool: "sarif", data: `{"version":"2.1.0","runs":[{"results":[{}]}]}`},
		{name: "truncated actionlint", tool: "actions", data: `[{`},
		{name: "nuclei log noise", tool: "nuclei", data: "[INF] no templates loaded"},
		{name: "no API cases", tool: "api", data: `<testsuites/>`},
		{name: "API error", tool: "api", data: `<testsuite><testcase name="GET /"><error/></testcase></testsuite>`},
		{name: "API skip", tool: "api", data: `<testsuite><testcase name="GET /"><skipped/></testcase></testsuite>`},
		{name: "empty ZAP", tool: "zap", data: `{"site":[]}`},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var err error
			switch tt.tool {
			case "sarif":
				_, err = parseSARIF([]byte(tt.data), "test")
			case "actions":
				_, err = parseActionlint([]byte(tt.data))
			case "nuclei":
				_, err = parseNuclei([]byte(tt.data))
			case "api":
				_, err = parseJUnit([]byte(tt.data))
			case "zap":
				_, err = parseZAP([]byte(tt.data))
			}
			if err == nil {
				t.Fatal("malformed or incomplete report accepted as clean")
			}
		})
	}
}

func TestApplicationFindings(t *testing.T) {
	t.Parallel()
	api, err := parseJUnit([]byte(`<testsuites><testsuite><testcase name="GET /items"><failure message="Server returned 500">raw request with secret</failure></testcase></testsuite></testsuites>`))
	if err != nil || len(api) != 1 || api[0].Message != "Server returned 500" {
		t.Fatalf("API result = %+v, %v", api, err)
	}
	nuclei, err := parseNuclei([]byte(`{"template-id":"exposed-file","matched-at":"http://localhost/test","info":{"name":"Exposed file","severity":"high"},"request":"SECRET"}` + "\n"))
	if err != nil || len(nuclei) != 1 || strings.Contains(nuclei[0].Message, "SECRET") {
		t.Fatalf("nuclei result = %+v, %v", nuclei, err)
	}
	zap, err := parseZAP([]byte(`{"site":[{"alerts":[{"pluginid":"40018","name":"SQL Injection","riskcode":"3","instances":[{"uri":"http://localhost/items"}]}]}]}`))
	if err != nil || len(zap) != 1 || zap[0].Severity != "high" {
		t.Fatalf("ZAP result = %+v, %v", zap, err)
	}
}

func TestParsersLeaveIdentificationToRunCheck(t *testing.T) {
	t.Parallel()
	findings, err := parseActionlint([]byte(`[{"message":"bad","filepath":"ci.yml","line":3,"kind":"syntax"}]`))
	if err != nil || len(findings) != 1 || findings[0].Fingerprint != "" || findings[0].ID != "" {
		t.Fatalf("parser fingerprinted before the check was set: %+v, %v", findings, err)
	}
}
