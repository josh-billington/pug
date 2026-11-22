package report

import (
	"encoding/json"
	"io"
	"net/url"
)

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool              sarifTool         `json:"tool"`
	AutomationDetails sarifAutomation   `json:"automationDetails"`
	Invocations       []sarifInvocation `json:"invocations"`
	Results           []sarifResult     `json:"results"`
	Properties        map[string]string `json:"properties"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version,omitempty"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID                   string            `json:"id"`
	ShortDescription     sarifMessage      `json:"shortDescription"`
	DefaultConfiguration sarifRuleConfig   `json:"defaultConfiguration"`
	Properties           sarifRuleProperty `json:"properties"`
}

type sarifRuleConfig struct {
	Level string `json:"level"`
}

type sarifRuleProperty struct {
	SecuritySeverity string   `json:"security-severity,omitempty"`
	Tags             []string `json:"tags"`
}

type sarifAutomation struct {
	ID string `json:"id"`
}

type sarifInvocation struct {
	ExecutionSuccessful bool `json:"executionSuccessful"`
}

type sarifResult struct {
	RuleID     string            `json:"ruleId"`
	RuleIndex  int               `json:"ruleIndex"`
	Level      string            `json:"level"`
	Message    sarifMessage      `json:"message"`
	Locations  []sarifLocation   `json:"locations,omitempty"`
	Properties map[string]string `json:"properties"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
	Region           *sarifRegion  `json:"region,omitempty"`
}

type sarifArtifact struct {
	URI       string `json:"uri"`
	URIBaseID string `json:"uriBaseId"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
}

// Code scanning buckets security-severity: critical above 9.0, high 7.0-8.9, medium 4.0-6.9, low 0.1-3.9.
var sarifSeverity = map[string]struct{ level, score string }{
	"critical": {"error", "9.5"},
	"high":     {"error", "8.0"},
	"medium":   {"warning", "5.5"},
	"low":      {"note", "2.0"},
	"info":     {"note", ""},
}

func severityOf(severity string) struct{ level, score string } {
	if mapped, ok := sarifSeverity[severity]; ok {
		return mapped
	}
	return sarifSeverity["info"]
}

func writeSARIF(w io.Writer, r Report) error {
	log := sarifLog{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs:    []sarifRun{},
	}
	for _, check := range r.Checks {
		// Code scanning closes alerts missing from a category it analyzed, so an incomplete check gets no run.
		if check.Status != "completed" {
			continue
		}
		run := sarifRun{
			Tool: sarifTool{Driver: sarifDriver{
				Name: "pug", Version: r.Version, InformationURI: "https://github.com/josh-billington/pug", Rules: []sarifRule{},
			}},
			AutomationDetails: sarifAutomation{ID: "pug/" + check.Name + "/"},
			Invocations:       []sarifInvocation{{ExecutionSuccessful: true}},
			Results:           []sarifResult{},
			Properties:        map[string]string{"check": check.Name, "scanner": check.Tool, "scannerVersion": check.Version},
		}
		type seenRule struct {
			driverIndex int
			maxSeverity string
		}
		rules := map[string]seenRule{}
		for _, finding := range check.Findings {
			// Code scanning keys rules by tool and ID across categories, and every run's tool is pug.
			id := finding.Tool + "/" + finding.Rule
			mapped := severityOf(finding.Severity)
			rule, seen := rules[id]
			if !seen {
				rule.driverIndex = len(run.Tool.Driver.Rules)
				run.Tool.Driver.Rules = append(run.Tool.Driver.Rules, sarifRule{
					ID: id, ShortDescription: sarifMessage{Text: finding.Rule},
					Properties: sarifRuleProperty{Tags: []string{"security", check.Name}},
				})
			}
			if !seen || SeverityRank(finding.Severity) > SeverityRank(rule.maxSeverity) {
				rule.maxSeverity = finding.Severity
				driverRule := &run.Tool.Driver.Rules[rule.driverIndex]
				driverRule.DefaultConfiguration.Level, driverRule.Properties.SecuritySeverity = mapped.level, mapped.score
			}
			rules[id] = rule
			result := sarifResult{
				RuleID: id, RuleIndex: rule.driverIndex, Level: mapped.level, Message: sarifMessage{Text: finding.Message},
				Properties: map[string]string{"pugId": finding.ID},
			}
			if finding.Location != "" {
				location := sarifPhysicalLocation{ArtifactLocation: sarifArtifact{
					URI: (&url.URL{Path: finding.Location}).EscapedPath(), URIBaseID: "%SRCROOT%",
				}}
				if finding.Line > 0 {
					location.Region = &sarifRegion{StartLine: finding.Line}
				}
				result.Locations = []sarifLocation{{PhysicalLocation: location}}
			}
			run.Results = append(run.Results, result)
		}
		log.Runs = append(log.Runs, run)
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(log)
}
