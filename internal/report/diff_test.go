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
