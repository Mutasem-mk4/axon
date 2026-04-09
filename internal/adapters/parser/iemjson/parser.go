package iemjson

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"path/filepath"
	"strings"

	sferr "github.com/secfacts/secfacts/internal/domain/errors"
	"github.com/secfacts/secfacts/internal/domain/evidence"
	"github.com/secfacts/secfacts/internal/ports"
)

const opParse = "iemjson.Parser.Parse"

type Parser struct{}

func (Parser) Provider() string {
	return "iemjson"
}

func (Parser) Supports(filename string) bool {
	ext := strings.ToLower(filepath.Ext(filename))
	return ext == ".json" || ext == ".jsonl" || ext == ".ndjson"
}

func (Parser) Parse(ctx context.Context, req ports.ParseRequest, sink ports.FindingSink) error {
	switch strings.ToLower(filepath.Ext(req.Filename)) {
	case ".jsonl", ".ndjson":
		return parseLineDelimited(ctx, req, sink)
	default:
		return parseStructuredJSON(ctx, req, sink)
	}
}

func parseStructuredJSON(ctx context.Context, req ports.ParseRequest, sink ports.FindingSink) error {
	decoder := json.NewDecoder(req.Reader)

	token, err := decoder.Token()
	if err != nil {
		if err == io.EOF {
			return nil
		}

		return sferr.Wrap(sferr.CodeParseFailed, opParse, err, "read opening token")
	}

	delim, ok := token.(json.Delim)
	if !ok {
		return sferr.New(sferr.CodeUnsupportedInput, opParse, "expected JSON array or object input")
	}

	switch delim {
	case '[':
		return parseFindingArray(ctx, decoder, req, sink)
	case '{':
		return parseDocumentObject(ctx, decoder, req, sink)
	default:
		return sferr.New(sferr.CodeUnsupportedInput, opParse, "expected top-level array or object")
	}
}

func parseFindingArray(ctx context.Context, decoder *json.Decoder, req ports.ParseRequest, sink ports.FindingSink) error {
	for decoder.More() {
		if err := ctx.Err(); err != nil {
			return err
		}

		var finding evidence.Finding
		if err := decoder.Decode(&finding); err != nil {
			return sferr.Wrap(sferr.CodeParseFailed, opParse, err, "decode finding")
		}

		if err := writeFinding(ctx, req, sink, finding); err != nil {
			return err
		}
	}

	if _, err := decoder.Token(); err != nil {
		return sferr.Wrap(sferr.CodeParseFailed, opParse, err, "read closing token")
	}

	return nil
}

func parseDocumentObject(ctx context.Context, decoder *json.Decoder, req ports.ParseRequest, sink ports.FindingSink) error {
	for decoder.More() {
		keyToken, err := decoder.Token()
		if err != nil {
			return sferr.Wrap(sferr.CodeParseFailed, opParse, err, "decode document key")
		}

		key, ok := keyToken.(string)
		if !ok {
			return sferr.New(sferr.CodeParseFailed, opParse, "document key is not a string")
		}

		if !strings.EqualFold(key, "findings") {
			var discard json.RawMessage
			if err := decoder.Decode(&discard); err != nil {
				return sferr.Wrap(sferr.CodeParseFailed, opParse, err, "discard document field")
			}
			continue
		}

		token, err := decoder.Token()
		if err != nil {
			return sferr.Wrap(sferr.CodeParseFailed, opParse, err, "read findings token")
		}

		delim, ok := token.(json.Delim)
		if !ok || delim != '[' {
			return sferr.New(sferr.CodeParseFailed, opParse, "document findings field must be an array")
		}

		if err := parseFindingArray(ctx, decoder, req, sink); err != nil {
			return err
		}
	}

	if _, err := decoder.Token(); err != nil {
		return sferr.Wrap(sferr.CodeParseFailed, opParse, err, "read document closing token")
	}

	return nil
}

func parseLineDelimited(ctx context.Context, req ports.ParseRequest, sink ports.FindingSink) error {
	scanner := bufio.NewScanner(req.Reader)
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)

	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			return err
		}

		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		var finding evidence.Finding
		if err := json.Unmarshal([]byte(line), &finding); err != nil {
			return sferr.Wrap(sferr.CodeParseFailed, opParse, err, "decode line-delimited finding")
		}

		if err := writeFinding(ctx, req, sink, finding); err != nil {
			return err
		}
	}

	if err := scanner.Err(); err != nil {
		return sferr.Wrap(sferr.CodeParseFailed, opParse, err, "scan line-delimited input")
	}

	return nil
}

func writeFinding(ctx context.Context, req ports.ParseRequest, sink ports.FindingSink, finding evidence.Finding) error {
	finding.SchemaVersion = evidence.SchemaVersion
	if finding.Source.Provider == "" {
		finding.Source.Provider = req.Source.Provider
	}
	if finding.Source.Scanner == "" {
		finding.Source.Scanner = req.Source.ToolName
	}
	if finding.Source.ScannerVersion == "" {
		finding.Source.ScannerVersion = req.Source.ToolVersion
	}

	return sink.WriteFinding(ctx, finding)
}
