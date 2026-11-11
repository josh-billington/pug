package scanner

import (
	"bufio"
	"bytes"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/josh-billington/pug/internal/report"
	"github.com/josh-billington/pug/internal/tools"
)

type sarifDocument struct {
	Version string `json:"version"`
	Runs    []struct {
		Tool struct {
			Driver struct {
				Rules []struct {
					ID         string         `json:"id"`
					Properties map[string]any `json:"properties"`
				} `json:"rules"`
			} `json:"driver"`
		} `json:"tool"`
		Invocations []struct {
			ExecutionSuccessful *bool `json:"executionSuccessful"`
			Notifications       []struct {
				Level string `json:"level"`
			} `json:"toolExecutionNotifications"`
		} `json:"invocations"`
		Results []struct {
			RuleID  string `json:"ruleId"`
			Level   string `json:"level"`
			Message struct {
				Text string `json:"text"`
			} `json:"message"`
			Locations []struct {
				PhysicalLocation struct {
					ArtifactLocation struct {
						URI string `json:"uri"`
					} `json:"artifactLocation"`
					Region struct {
						StartLine int `json:"startLine"`
					} `json:"region"`
				} `json:"physicalLocation"`
			} `json:"locations"`
		} `json:"results"`
	} `json:"runs"`
}

func parseSARIF(data []byte, tool string) ([]report.Finding, error) {
	var doc sarifDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("decode SARIF: %w", err)
	}
	if doc.Version != "2.1.0" || len(doc.Runs) == 0 {
		return nil, fmt.Errorf("expected SARIF 2.1.0 with at least one run")
	}
	findings := []report.Finding{}
	for _, run := range doc.Runs {
		for _, invocation := range run.Invocations {
			if invocation.ExecutionSuccessful != nil && !*invocation.ExecutionSuccessful {
				return findings, fmt.Errorf("SARIF reports an unsuccessful scanner invocation")
			}
			for _, notification := range invocation.Notifications {
				if notification.Level == "error" {
					return findings, fmt.Errorf("SARIF reports a scanner execution error")
				}
			}
		}
		severities := map[string]string{}
		for _, rule := range run.Tool.Driver.Rules {
			value, ok := rule.Properties["security-severity"]
			if ok {
				score, err := strconv.ParseFloat(fmt.Sprint(value), 64)
				if err == nil {
					severity := "info"
					switch {
					case score >= 9:
						severity = "critical"
					case score >= 7:
						severity = "high"
					case score >= 4:
						severity = "medium"
					case score > 0:
						severity = "low"
					}
					severities[rule.ID] = severity
				}
			}
		}
		for _, result := range run.Results {
			if result.RuleID == "" || result.Message.Text == "" {
				return findings, fmt.Errorf("SARIF result missing ruleId or message")
			}
			severity := severities[result.RuleID]
			if severity == "" {
				severity = map[string]string{"error": "high", "warning": "medium", "note": "low", "none": "info"}[result.Level]
				if severity == "" {
					severity = "medium"
				}
			}
			finding := report.Finding{Tool: tool, Rule: tools.Sanitize(result.RuleID), Severity: severity, Message: tools.Sanitize(result.Message.Text)}
			if tool == "gitleaks" {
				finding.Severity = "high"
				finding.Message = "Potential secret detected; secret value withheld"
			}
			if len(result.Locations) > 0 {
				location := result.Locations[0].PhysicalLocation
				uri, err := url.PathUnescape(location.ArtifactLocation.URI)
				if err != nil {
					return findings, fmt.Errorf("invalid SARIF location URI: %w", err)
				}
				finding.Location = tools.Sanitize(uri)
				finding.Line = location.Region.StartLine
			}
			findings = append(findings, finding)
		}
	}
	return findings, nil
}

func parseActionlint(data []byte) ([]report.Finding, error) {
	var items []struct {
		Message string `json:"message"`
		File    string `json:"filepath"`
		Line    int    `json:"line"`
		Kind    string `json:"kind"`
	}
	if err := json.Unmarshal(data, &items); err != nil {
		return nil, fmt.Errorf("decode actionlint JSON: %w", err)
	}
	// actionlint emits null when no diagnostics are found.
	findings := []report.Finding{}
	for _, item := range items {
		if item.Message == "" || item.Kind == "" {
			return findings, fmt.Errorf("actionlint diagnostic missing message or kind")
		}
		finding := report.Finding{
			Tool: "actionlint", Rule: tools.Sanitize(item.Kind), Severity: "medium",
			Message: tools.Sanitize(item.Message), Location: tools.Sanitize(item.File), Line: item.Line,
		}
		findings = append(findings, finding)
	}
	return findings, nil
}

func parseNuclei(data []byte) ([]report.Finding, error) {
	findings := []report.Finding{}
	lines := bufio.NewScanner(bytes.NewReader(data))
	lines.Buffer(make([]byte, 4096), 2<<20)
	for lines.Scan() {
		if len(bytes.TrimSpace(lines.Bytes())) == 0 {
			continue
		}
		var item struct {
			Template string `json:"template-id"`
			Matcher  string `json:"matcher-name"`
			Matched  string `json:"matched-at"`
			Info     struct {
				Name     string `json:"name"`
				Severity string `json:"severity"`
			} `json:"info"`
		}
		if err := json.Unmarshal(lines.Bytes(), &item); err != nil {
			return findings, fmt.Errorf("decode nuclei JSONL: %w", err)
		}
		if item.Template == "" || item.Matched == "" || item.Info.Name == "" {
			return findings, fmt.Errorf("nuclei result missing template, location, or name")
		}
		finding := report.Finding{
			Tool: "nuclei", Rule: tools.Sanitize(item.Template + "/" + item.Matcher),
			Severity: strings.ToLower(item.Info.Severity), Message: tools.Sanitize(item.Info.Name), Location: tools.Sanitize(item.Matched),
		}
		findings = append(findings, finding)
	}
	return findings, lines.Err()
}

type junitSuite struct {
	Cases []struct {
		Name     string `xml:"name,attr"`
		Class    string `xml:"classname,attr"`
		Failures []struct {
			Message string `xml:"message,attr"`
		} `xml:"failure"`
		Errors  []struct{} `xml:"error"`
		Skipped []struct{} `xml:"skipped"`
	} `xml:"testcase"`
	Suites []junitSuite `xml:"testsuite"`
}

func parseJUnit(data []byte) ([]report.Finding, error) {
	var doc junitSuite
	if err := xml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("decode Schemathesis JUnit: %w", err)
	}
	findings := []report.Finding{}
	cases, incomplete := 0, false
	var walk func(junitSuite)
	walk = func(suite junitSuite) {
		for _, item := range suite.Cases {
			cases++
			if len(item.Errors) > 0 || len(item.Skipped) > 0 {
				incomplete = true
			}
			for _, failure := range item.Failures {
				finding := report.Finding{
					Tool: "schemathesis", Rule: "api-contract", Severity: "medium",
					Message: tools.Sanitize(failure.Message), Location: tools.Sanitize(item.Class + " " + item.Name),
				}
				if finding.Message == "" {
					finding.Message = "API contract or fuzzing check failed; rerun Schemathesis for reproduction details"
				}
				findings = append(findings, finding)
			}
		}
		for _, child := range suite.Suites {
			walk(child)
		}
	}
	walk(doc)
	if cases == 0 || incomplete {
		return findings, fmt.Errorf("API tests incomplete: %d cases; errors or skipped cases: %t", cases, incomplete)
	}
	return findings, nil
}

func parseZAP(data []byte) ([]report.Finding, error) {
	var doc struct {
		Sites []struct {
			Alerts []struct {
				Plugin    string `json:"pluginid"`
				Name      string `json:"name"`
				Risk      string `json:"riskcode"`
				Instances []struct {
					URI string `json:"uri"`
				} `json:"instances"`
			} `json:"alerts"`
		} `json:"site"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("decode ZAP report: %w", err)
	}
	if len(doc.Sites) == 0 {
		return nil, fmt.Errorf("ZAP report contains no tested sites")
	}
	findings := []report.Finding{}
	for _, site := range doc.Sites {
		for _, alert := range site.Alerts {
			severity, ok := map[string]string{"0": "info", "1": "low", "2": "medium", "3": "high"}[alert.Risk]
			if !ok || alert.Plugin == "" || alert.Name == "" || len(alert.Instances) == 0 {
				return findings, fmt.Errorf("invalid ZAP alert")
			}
			for _, instance := range alert.Instances {
				finding := report.Finding{
					Tool: "zap", Rule: tools.Sanitize(alert.Plugin), Severity: severity,
					Message: tools.Sanitize(alert.Name), Location: tools.Sanitize(instance.URI),
				}
				findings = append(findings, finding)
			}
		}
	}
	return findings, nil
}
