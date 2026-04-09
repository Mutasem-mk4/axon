package policy

import (
	"context"
	"testing"

	"github.com/secfacts/secfacts/internal/domain/evidence"
)

func TestCompareCategorizesFindingsByFingerprint(t *testing.T) {
	t.Parallel()

	service := Service{}
	current := []evidence.Finding{
		{ID: "new", Identity: evidence.Identity{FingerprintV1: "new"}},
		{ID: "existing", Identity: evidence.Identity{FingerprintV1: "same"}},
	}
	baseline := []evidence.Finding{
		{ID: "old", Identity: evidence.Identity{FingerprintV1: "same"}},
		{ID: "fixed", Identity: evidence.Identity{FingerprintV1: "fixed"}},
	}

	diff := service.Compare(current, baseline)
	if len(diff.New) != 1 || diff.New[0].ID != "new" {
		t.Fatalf("expected one new finding, got %#v", diff.New)
	}
	if len(diff.Existing) != 1 || diff.Existing[0].ID != "existing" {
		t.Fatalf("expected one existing finding, got %#v", diff.Existing)
	}
	if len(diff.Fixed) != 1 || diff.Fixed[0].ID != "fixed" {
		t.Fatalf("expected one fixed finding, got %#v", diff.Fixed)
	}
}

func TestEvaluateRespectsFailOnNewOnlyAndAllowlist(t *testing.T) {
	t.Parallel()

	service := Service{}
	findings := []evidence.Finding{
		{
			ID: "new-high",
			Severity: evidence.Severity{
				Label: evidence.SeverityHigh,
			},
			Identity: evidence.Identity{
				FingerprintV1: "new-high",
			},
		},
		{
			ID: "existing-critical",
			Severity: evidence.Severity{
				Label: evidence.SeverityCritical,
			},
			Identity: evidence.Identity{
				FingerprintV1: "existing-critical",
			},
		},
	}

	diff := BaselineDiff{
		New:      findings[:1],
		Existing: findings[1:],
	}

	decision, err := service.Evaluate(context.Background(), findings, diff, Policy{
		FailOnSeverity: evidence.SeverityCritical,
		FailOnNewOnly:  true,
		Allowlist: []AllowlistEntry{
			{FingerprintV1: "new-high"},
		},
	})
	if err != nil {
		t.Fatalf("Evaluate returned error: %v", err)
	}
	if !decision.Passed {
		t.Fatalf("expected policy to pass, got violations %#v", decision.Violations)
	}
	if len(decision.EvaluatedFindings) != 0 {
		t.Fatalf("expected allowlisted new findings to be removed, got %#v", decision.EvaluatedFindings)
	}
}
