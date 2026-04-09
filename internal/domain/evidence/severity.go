package evidence

import (
	"fmt"
	"math"
)

func NewSeverity(score float64, vector string) (Severity, error) {
	if math.IsNaN(score) || math.IsInf(score, 0) {
		return Severity{}, fmt.Errorf("severity score must be finite")
	}
	if score < 0 || score > 10 {
		return Severity{}, fmt.Errorf("severity score must be between 0.0 and 10.0")
	}

	return Severity{
		Score:  score,
		Label:  SeverityLabelFromScore(score),
		Vector: vector,
	}, nil
}

func SeverityLabelFromScore(score float64) SeverityLabel {
	switch {
	case score == 0:
		return SeverityInfo
	case score < 4:
		return SeverityLow
	case score < 7:
		return SeverityMedium
	case score < 9:
		return SeverityHigh
	default:
		return SeverityCritical
	}
}
