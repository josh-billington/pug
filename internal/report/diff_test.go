package report

import "testing"

func TestDiffDoesNotTreatFailedChecksAsFixes(t *testing.T) {
	t.Parallel()
	f := Finding{Check: "secrets", Tool: "gitleaks", Rule: "token", Location: "config", Severity: "high"}
	f.Identify()
	before := Report{Target: "/repo", Checks: []Check{{Name: "secrets", Status: "completed", Findings: []Finding{f}}}}
	cases := []struct {
		name       string
		check      Check
		absent     int
		unverified int
	}{
		{name: "failed", check: Check{Name: "secrets", Status: "failed"}, unverified: 1},
		{name: "unavailable", check: Check{Name: "secrets", Status: "unavailable"}, unverified: 1},
		{name: "not requested", check: Check{Name: "infra", Status: "completed"}, unverified: 1},
		{name: "completed", check: Check{Name: "secrets", Status: "completed"}, absent: 1},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			diff, err := Compare(before, Report{Target: "/repo", Checks: []Check{tt.check}})
			if err != nil || len(diff.Absent) != tt.absent || len(diff.Unverified) != tt.unverified {
				t.Fatalf("incorrect comparison: %+v, %v", diff, err)
			}
		})
	}
	if _, err := Compare(before, Report{Target: "/other-repo"}); err == nil {
		t.Fatal("different targets compared")
	}
}

func TestDiffDoesNotTreatRuleChangesAsFixes(t *testing.T) {
	t.Parallel()
	f := Finding{Check: "source", Tool: "opengrep", Rule: "amplify.python.lang.eval", Location: "app.py", Line: 2, Severity: "high"}
	f.Identify()
	audit := &RuleProvenance{Specs: []string{"amplify:security-audit"}, SHA256: "aaa"}
	cases := []struct {
		name       string
		before     *RuleProvenance
		after      *RuleProvenance
		absent     int
		unverified int
	}{
		{name: "same rules", before: audit, after: &RuleProvenance{Specs: []string{"amplify:security-audit"}, SHA256: "aaa"}, absent: 1},
		{name: "different rules", before: audit, after: &RuleProvenance{Specs: []string{"amplify:secrets"}, SHA256: "bbb"}, unverified: 1},
		{name: "same specs with different rules", before: audit, after: &RuleProvenance{Specs: []string{"amplify:security-audit"}, SHA256: "bbb"}, unverified: 1},
		{name: "report without provenance", before: nil, after: audit, unverified: 1},
		{name: "later report without provenance", before: audit, after: nil, unverified: 1},
		{name: "neither has provenance", before: nil, after: nil, absent: 1},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			before := Report{Target: "/repo", Checks: []Check{{Name: "source", Status: "completed", Rules: tt.before, Findings: []Finding{f}}}}
			after := Report{Target: "/repo", Checks: []Check{{Name: "source", Status: "completed", Rules: tt.after, Findings: []Finding{}}}}
			diff, err := Compare(before, after)
			if err != nil || len(diff.Absent) != tt.absent || len(diff.Unverified) != tt.unverified {
				t.Fatalf("incorrect comparison: %+v, %v", diff, err)
			}
		})
	}
}
