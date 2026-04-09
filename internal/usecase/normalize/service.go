package normalize

import (
	"context"
	"fmt"
	"math"
	"path/filepath"
	"strconv"
	"strings"

	sferr "github.com/secfacts/secfacts/internal/domain/errors"
	"github.com/secfacts/secfacts/internal/domain/evidence"
)

const opNormalize = "normalize.Service.Normalize"

type Service struct {
	IdentityBuilder evidence.IdentityBuilder
}

func (s Service) Normalize(_ context.Context, finding evidence.Finding) (evidence.Finding, error) {
	if s.IdentityBuilder == nil {
		return evidence.Finding{}, sferr.New(sferr.CodeInvalidConfig, opNormalize, "identity builder is required")
	}

	finding.SchemaVersion = evidence.SchemaVersion
	finding.Kind = normalizeKind(finding.Kind)

	severity, err := normalizeSeverity(finding)
	if err != nil {
		return evidence.Finding{}, sferr.Wrap(sferr.CodeNormalizeFailed, opNormalize, err, "normalize severity")
	}
	finding.Severity = severity

	finding.Rule.ID = strings.TrimSpace(finding.Rule.ID)
	finding.Rule.Name = strings.TrimSpace(finding.Rule.Name)
	finding.Title = strings.TrimSpace(finding.Title)
	finding.Description = strings.TrimSpace(finding.Description)
	finding.PrimaryLocation.URI = normalizeLocationPath(finding.PrimaryLocation.URI)
	for index := range finding.Locations {
		finding.Locations[index].URI = normalizeLocationPath(finding.Locations[index].URI)
	}

	finding.RootCauseHints = appendNormalizedHints(finding)
	finding.Identity = s.IdentityBuilder.Build(finding)
	if finding.ID == "" {
		finding.ID = finding.Identity.FingerprintV1
	}

	return finding, nil
}

func normalizeSeverity(finding evidence.Finding) (evidence.Severity, error) {
	score, vector := severityInputs(finding)
	return evidence.NewSeverity(score, vector)
}

func severityInputs(finding evidence.Finding) (float64, string) {
	score := clampScore(finding.Severity.Score)
	vector := strings.TrimSpace(finding.Severity.Vector)
	label := string(finding.Severity.Label)
	if label == "" {
		label = annotationValue(finding, "severity.label")
	}

	if score > 0 {
		return score, vector
	}
	if isInformationalLabel(label) {
		return 0, vector
	}
	if finding.Vulnerability != nil {
		if score := clampScore(finding.Vulnerability.CVSSScore); score >= 0 {
			return score, fallbackVector(vector, finding.Vulnerability.CVSSVector)
		}
	}

	for _, key := range []string{"severity.score", "cvss.score"} {
		if score, ok := annotationScore(finding, key); ok {
			return score, vector
		}
	}
	if strings.TrimSpace(label) != "" {
		return severityScoreFromLabel(label), vector
	}
	if score == 0 {
		return 0, vector
	}

	return severityScoreFromLabel(label), vector
}

func severityScoreFromLabel(label string) float64 {
	switch strings.ToLower(strings.TrimSpace(label)) {
	case "critical":
		return 9
	case "high":
		return 7
	case "medium", "moderate":
		return 5
	case "low":
		return 2
	case "info", "informational", "note":
		return 0
	default:
		return 0
	}
}

func isInformationalLabel(label string) bool {
	switch strings.ToLower(strings.TrimSpace(label)) {
	case "info", "informational", "note":
		return true
	default:
		return false
	}
}

func annotationScore(f evidence.Finding, key string) (float64, bool) {
	raw := annotationValue(f, key)
	if raw == "" {
		return 0, false
	}

	value, err := strconv.ParseFloat(strings.TrimSpace(raw), 64)
	if err != nil {
		return 0, false
	}

	return clampScore(value), true
}

func clampScore(score float64) float64 {
	if math.IsNaN(score) || math.IsInf(score, 0) {
		return -1
	}
	if score < 0 {
		return -1
	}
	if score > 10 {
		return 10
	}

	return score
}

func fallbackVector(primary string, secondary string) string {
	if strings.TrimSpace(primary) != "" {
		return primary
	}

	return strings.TrimSpace(secondary)
}

func normalizeKind(kind evidence.Kind) evidence.Kind {
	switch strings.ToLower(strings.TrimSpace(string(kind))) {
	case string(evidence.KindSAST):
		return evidence.KindSAST
	case string(evidence.KindDAST):
		return evidence.KindDAST
	case string(evidence.KindSCA):
		return evidence.KindSCA
	case string(evidence.KindCloud):
		return evidence.KindCloud
	case string(evidence.KindSecrets):
		return evidence.KindSecrets
	default:
		return kind
	}
}

func appendNormalizedHints(finding evidence.Finding) []evidence.RootCauseHint {
	hints := append([]evidence.RootCauseHint(nil), finding.RootCauseHints...)

	switch finding.Kind {
	case evidence.KindSCA:
		if finding.Package != nil {
			key := finding.Package.Name
			if finding.Package.PackageURL != "" {
				key = finding.Package.PackageURL
			}
			if key != "" {
				hints = append(hints, evidence.RootCauseHint{
					Type:  "dependency",
					Key:   "package",
					Value: key,
				})
			}
		}
	case evidence.KindSAST:
		if finding.Rule.ID != "" && finding.PrimaryLocation.URI != "" {
			hints = append(hints, evidence.RootCauseHint{
				Type:  "code_path",
				Key:   "rule_path",
				Value: fmt.Sprintf("%s|%s", finding.Rule.ID, finding.PrimaryLocation.URI),
			})
		}
	}

	if finding.Image != nil && finding.Image.BaseDigest != "" {
		hints = append(hints, evidence.RootCauseHint{
			Type:  "base_image",
			Key:   "image",
			Value: finding.Image.BaseDigest,
		})
	}

	return deduplicateHints(hints)
}

func deduplicateHints(hints []evidence.RootCauseHint) []evidence.RootCauseHint {
	seen := make(map[string]struct{}, len(hints))
	result := make([]evidence.RootCauseHint, 0, len(hints))

	for _, hint := range hints {
		compound := strings.Join([]string{hint.Type, hint.Key, hint.Value}, "|")
		if _, exists := seen[compound]; exists {
			continue
		}

		seen[compound] = struct{}{}
		result = append(result, hint)
	}

	return result
}

func normalizeLocationPath(value string) string {
	if strings.TrimSpace(value) == "" {
		return ""
	}

	return strings.ToLower(filepath.ToSlash(strings.TrimSpace(value)))
}

func annotationValue(finding evidence.Finding, key string) string {
	if len(finding.Annotations) == 0 {
		return ""
	}

	return strings.TrimSpace(finding.Annotations[key])
}
