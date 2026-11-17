package report

import "fmt"

type Diff struct {
	New        []Finding `json:"new"`
	Persistent []Finding `json:"persistent"`
	Absent     []Finding `json:"absent"`
	Unverified []Finding `json:"unverified"`
	Note       string    `json:"note"`
}

func Compare(before, after Report) (Diff, error) {
	if before.Target != after.Target {
		return Diff{}, fmt.Errorf("cannot compare reports for different targets")
	}
	diff := Diff{
		New: []Finding{}, Persistent: []Finding{}, Absent: []Finding{}, Unverified: []Finding{},
		Note: "Absent means not observed in a completed check that ran the same rules, not proven fixed. Database changes and moved lines can change fingerprints.",
	}
	old := map[string]Finding{}
	current := map[string]bool{}
	previousRules := map[string]*RuleProvenance{}
	// verifies holds the AFTER checks that can show a BEFORE finding is gone:
	// completed, and running the same rules as the BEFORE check.
	verifies := map[string]bool{}
	previous := before.Findings()
	for _, finding := range previous {
		old[finding.Fingerprint] = finding
	}
	for _, check := range before.Checks {
		previousRules[check.Name] = check.Rules
	}
	for _, check := range after.Checks {
		verifies[check.Name] = check.Status == "completed" && sameRules(previousRules[check.Name], check.Rules)
	}
	for _, finding := range after.Findings() {
		current[finding.Fingerprint] = true
		if _, exists := old[finding.Fingerprint]; exists {
			diff.Persistent = append(diff.Persistent, finding)
			continue
		}
		diff.New = append(diff.New, finding)
	}
	for _, finding := range previous {
		if current[finding.Fingerprint] {
			continue
		}
		if verifies[finding.Check] {
			diff.Absent = append(diff.Absent, finding)
			continue
		}
		diff.Unverified = append(diff.Unverified, finding)
	}
	return diff, nil
}

func sameRules(a, b *RuleProvenance) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.SHA256 == b.SHA256
}
