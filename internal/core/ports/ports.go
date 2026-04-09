package ports

import (
	"context"
	"github.com/secfacts/secfacts/internal/core/domain"
	"io"
)

// Parser defines how raw tool output is converted into the Internal Evidence Model.
type Parser interface {
	// Name returns the provider identifier of the parser (e.g., "sarif", "trivy").
	Name() string
	// Parse streams raw data from the reader and returns a channel of Evidence.
	Parse(ctx context.Context, r io.Reader) (<-chan domain.Evidence, <-chan error)
}

// Normalizer handles the deduplication and correlation pipeline for processed evidence.
type Normalizer interface {
	// Process consumes processed evidence and emits a consolidated/correlated stream.
	Process(ctx context.Context, in <-chan domain.Evidence) (<-chan domain.Evidence, <-chan error)
}

// Correlator transforms deduplicated findings into logical root-cause issues.
type Correlator interface {
	// Correlate takes a stream of deduplicated evidence and groups them into logical issues.
	Correlate(ctx context.Context, in <-chan domain.Evidence) (<-chan domain.Issue, <-chan error)
}

// Exporter writes the correlated Issues to the provided output destination.
type Exporter interface {
	// Export formats and writes the issues to the io.Writer.
	Export(ctx context.Context, w io.Writer, issues []domain.Issue) error
}
