// Package report defines the evidence contract consumed by humans and coding agents.
package report

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/josh-billington/pug/internal/tools"
)

type Finding struct {
	ID          string `json:"id"`
	Check       string `json:"check"`
	Tool        string `json:"tool"`
	Rule        string `json:"rule"`
	Severity    string `json:"severity"`
	Message     string `json:"message"`
	Location    string `json:"location,omitempty"`
	Line        int    `json:"line,omitempty"`
	Fingerprint string `json:"fingerprint"`
}

type Check struct {
	Name           string    `json:"name"`
	Tool           string    `json:"tool"`
	Version        string    `json:"version,omitempty"`
	Status         string    `json:"status"`
	Reason         string    `json:"reason,omitempty"`
	Command        []string  `json:"command,omitempty"`
	StartedAt      time.Time `json:"started_at"`
	DurationMS     int64     `json:"duration_ms"`
	ExitCode       int       `json:"exit_code"`
	EvidenceSHA256 string    `json:"evidence_sha256,omitempty"`
	Findings       []Finding `json:"findings"`
}

type CoverageGap struct {
	Check  string `json:"check"`
	Reason string `json:"reason"`
}

type Report struct {
	SchemaVersion string        `json:"schema_version"`
	Version       string        `json:"pug_version"`
	Target        string        `json:"target"`
	StartedAt     time.Time     `json:"started_at"`
	FinishedAt    time.Time     `json:"finished_at"`
	Complete      bool          `json:"complete"`
	Checks        []Check       `json:"checks"`
	NotTested     []CoverageGap `json:"not_tested"`
	Limitations   []string      `json:"limitations"`
}

func Digest(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

func (f *Finding) Identify() {
	f.Fingerprint = Digest([]byte(strings.Join([]string{
		f.Check, f.Tool, f.Rule, f.Location, fmt.Sprint(f.Line), f.Message,
	}, "\x00")))
	f.ID = f.Fingerprint[:16]
}

func (r *Report) Finalize(requested map[string]bool, all []string) {
	r.Complete = true
	r.NotTested = []CoverageGap{}
	seen := map[string]bool{}
	for _, check := range r.Checks {
		seen[check.Name] = true
		if check.Status != "completed" {
			r.NotTested = append(r.NotTested, CoverageGap{Check: check.Name, Reason: check.Reason})
			if requested[check.Name] {
				r.Complete = false
			}
		}
	}
	for _, name := range all {
		if !seen[name] {
			r.NotTested = append(r.NotTested, CoverageGap{Check: name, Reason: "not requested"})
		}
	}
	r.FinishedAt = time.Now().UTC()
}

func (r Report) Findings() []Finding {
	findings := []Finding{}
	seen := map[string]bool{}
	for _, check := range r.Checks {
		for _, finding := range check.Findings {
			if !seen[finding.Fingerprint] {
				findings = append(findings, finding)
				seen[finding.Fingerprint] = true
			}
		}
	}
	sort.Slice(findings, func(i, j int) bool { return findings[i].Fingerprint < findings[j].Fingerprint })
	return findings
}

func SeverityRank(severity string) int {
	switch strings.ToLower(severity) {
	case "critical":
		return 5
	case "high":
		return 4
	case "medium":
		return 3
	case "low":
		return 2
	default:
		return 1
	}
}

func (r Report) HasFindings(threshold string) bool {
	for _, finding := range r.Findings() {
		if SeverityRank(finding.Severity) >= SeverityRank(threshold) {
			return true
		}
	}
	return false
}

func Write(w io.Writer, r Report, format string) error {
	if format == "json" {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(r)
	}
	var text strings.Builder
	fmt.Fprintf(&text, "PUG — %s\nRequested checks complete: %t\n\n", r.Target, r.Complete)
	for _, check := range r.Checks {
		fmt.Fprintf(&text, "%-14s %-12s %d findings (%s)\n", check.Name, check.Status, len(check.Findings), check.Tool)
		if check.Reason != "" {
			fmt.Fprintf(&text, "  %s\n", check.Reason)
		}
	}
	for _, finding := range r.Findings() {
		fmt.Fprintf(&text, "\n[%s] %s — %s\n  %s:%d  %s\n",
			finding.Severity, finding.Rule, finding.Message, finding.Location, finding.Line, finding.ID)
	}
	text.WriteString("\nNOT TESTED\n")
	for _, gap := range r.NotTested {
		fmt.Fprintf(&text, "- %s: %s\n", gap.Check, gap.Reason)
	}
	text.WriteString("\nLIMITATIONS\n")
	for _, limitation := range r.Limitations {
		fmt.Fprintf(&text, "- %s\n", limitation)
	}
	_, err := io.WriteString(w, tools.SanitizeText(text.String()))
	return err
}

// Save replaces a report atomically and never follows an existing destination symlink.
func Save(path string, r Report, format string) error {
	file, err := os.CreateTemp(filepath.Dir(path), ".pug-report-*")
	if err != nil {
		return fmt.Errorf("create report: %w", err)
	}
	defer os.Remove(file.Name())
	if err := Write(file, r, format); err != nil {
		file.Close()
		return fmt.Errorf("write report: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close report: %w", err)
	}
	if err := os.Rename(file.Name(), path); err != nil {
		return fmt.Errorf("save report: %w", err)
	}
	return nil
}

func Load(path string) (Report, error) {
	file, err := os.Open(path)
	if err != nil {
		return Report{}, fmt.Errorf("open report: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > 32<<20 {
		return Report{}, fmt.Errorf("report must be a regular file no larger than 32 MiB")
	}
	dec := json.NewDecoder(io.LimitReader(file, 32<<20))
	var r Report
	if err := dec.Decode(&r); err != nil {
		return Report{}, fmt.Errorf("decode report: %w", err)
	}
	if r.SchemaVersion != "1" {
		return Report{}, fmt.Errorf("unsupported report schema %q", r.SchemaVersion)
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return Report{}, fmt.Errorf("report must contain exactly one JSON document")
	}
	if r.Target == "" || r.Checks == nil {
		return Report{}, fmt.Errorf("report is missing its target or checks")
	}
	seen := map[string]bool{}
	for _, check := range r.Checks {
		if check.Name == "" || seen[check.Name] {
			return Report{}, fmt.Errorf("report has missing or repeated check names")
		}
		seen[check.Name] = true
		switch check.Status {
		case "completed", "failed", "unavailable", "skipped":
		default:
			return Report{}, fmt.Errorf("report has invalid check status %q", check.Status)
		}
		for _, finding := range check.Findings {
			original := finding.Fingerprint
			finding.Identify()
			if finding.Check != check.Name || original != finding.Fingerprint {
				return Report{}, fmt.Errorf("report has an invalid finding fingerprint or check reference")
			}
		}
	}
	return r, nil
}
