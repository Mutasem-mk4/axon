package iemjson

import (
	"context"
	"encoding/json"

	sferr "github.com/secfacts/secfacts/internal/domain/errors"
	"github.com/secfacts/secfacts/internal/ports"
)

const (
	format   = "json"
	opExport = "iemjson.Exporter.Export"
)

type Exporter struct{}

func (Exporter) Format() string {
	return format
}

func (Exporter) Export(ctx context.Context, req ports.ExportRequest) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if req.Writer == nil {
		return sferr.New(sferr.CodeInvalidArgument, opExport, "writer is required")
	}

	encoder := json.NewEncoder(req.Writer)
	if req.Options.Pretty {
		encoder.SetIndent("", "  ")
	}

	if err := encoder.Encode(req.Document); err != nil {
		return sferr.Wrap(sferr.CodeExportFailed, opExport, err, "encode document")
	}

	return nil
}
