package ports

import (
	"context"
	"io"

	"github.com/secfacts/secfacts/internal/domain/evidence"
)

type ExportOptions struct {
	Pretty       bool
	AWSAccountID string
	AWSRegion    string
	ProductARN   string
	GeneratorID  string
}

type ExportRequest struct {
	Document evidence.Document
	Writer   io.Writer
	Options  ExportOptions
}

type Exporter interface {
	Format() string
	Export(ctx context.Context, req ExportRequest) error
}
