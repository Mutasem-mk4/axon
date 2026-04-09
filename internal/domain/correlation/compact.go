package correlation

import "github.com/secfacts/secfacts/internal/domain/evidence"

type CompactFinding struct {
	ID               string
	SeverityScore    float64
	CorrelationKey   string
	CorrelationType  string
	CorrelationTitle string
	FindingIndex     int
}

func Compact(f evidence.Finding, index int) CompactFinding {
	key, kind, title := correlationKey(f)
	return CompactFinding{
		ID:               f.CanonicalID(),
		SeverityScore:    f.Severity.Score,
		CorrelationKey:   key,
		CorrelationType:  kind,
		CorrelationTitle: title,
		FindingIndex:     index,
	}
}
