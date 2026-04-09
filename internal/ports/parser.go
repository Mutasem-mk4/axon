package ports

import (
	"context"
	"io"

	"github.com/secfacts/secfacts/internal/domain/evidence"
)

type ParseRequest struct {
	Source   evidence.SourceDescriptor
	Filename string
	Reader   io.Reader
}

type FindingSink interface {
	WriteFinding(ctx context.Context, finding evidence.Finding) error
}

type Parser interface {
	Provider() string
	Supports(filename string) bool
	Parse(ctx context.Context, req ParseRequest, sink FindingSink) error
}
