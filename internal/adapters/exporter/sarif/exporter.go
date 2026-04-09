package sarif

import (
	"context"
	"encoding/json"

	sferr "github.com/secfacts/secfacts/internal/domain/errors"
	"github.com/secfacts/secfacts/internal/domain/evidence"
	"github.com/secfacts/secfacts/internal/ports"
)

const (
	format    = "sarif"
	version   = "2.1.0"
	schemaURI = "https://json.schemastore.org/sarif-2.1.0.json"
	opExport  = "sarif.Exporter.Export"
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

	report := fromDocument(req.Document)

	encoder := json.NewEncoder(req.Writer)
	if req.Options.Pretty {
		encoder.SetIndent("", "  ")
	}

	if err := encoder.Encode(report); err != nil {
		return sferr.Wrap(sferr.CodeExportFailed, opExport, err, "encode SARIF report")
	}

	return nil
}

type report struct {
	Version string `json:"version"`
	Schema  string `json:"$schema"`
	Runs    []run  `json:"runs"`
}

type run struct {
	Tool    tool     `json:"tool"`
	Results []result `json:"results"`
}

type tool struct {
	Driver driver `json:"driver"`
}

type driver struct {
	Name           string                `json:"name"`
	Version        string                `json:"version,omitempty"`
	InformationURI string                `json:"informationUri,omitempty"`
	Rules          []reportingDescriptor `json:"rules,omitempty"`
}

type reportingDescriptor struct {
	ID               string  `json:"id"`
	Name             string  `json:"name,omitempty"`
	ShortDescription message `json:"shortDescription,omitempty"`
}

type result struct {
	RuleID              string            `json:"ruleId,omitempty"`
	Level               string            `json:"level"`
	Message             message           `json:"message"`
	Locations           []location        `json:"locations,omitempty"`
	PartialFingerprints map[string]string `json:"partialFingerprints,omitempty"`
	Properties          map[string]any    `json:"properties,omitempty"`
}

type message struct {
	Text string `json:"text"`
}

type location struct {
	PhysicalLocation physicalLocation `json:"physicalLocation"`
}

type physicalLocation struct {
	ArtifactLocation artifactLocation `json:"artifactLocation"`
	Region           region           `json:"region,omitempty"`
}

type artifactLocation struct {
	URI string `json:"uri"`
}

type region struct {
	StartLine   int `json:"startLine,omitempty"`
	StartColumn int `json:"startColumn,omitempty"`
	EndLine     int `json:"endLine,omitempty"`
	EndColumn   int `json:"endColumn,omitempty"`
}

func fromDocument(document evidence.Document) report {
	rules := make(map[string]reportingDescriptor)
	results := make([]result, 0, len(document.Findings))

	for _, finding := range document.Findings {
		if finding.Rule.ID != "" {
			rules[finding.Rule.ID] = reportingDescriptor{
				ID:   finding.Rule.ID,
				Name: finding.Rule.Name,
				ShortDescription: message{
					Text: finding.Title,
				},
			}
		}

		results = append(results, result{
			RuleID:    finding.Rule.ID,
			Level:     sarifLevel(finding.Severity),
			Message:   message{Text: finding.Title},
			Locations: buildLocations(finding),
			PartialFingerprints: map[string]string{
				"dedupKey":       finding.Identity.DedupKey,
				"fingerprintV1":  finding.Identity.FingerprintV1,
				"naturalKeyHash": finding.Identity.NaturalKey,
			},
			Properties: map[string]any{
				"kind":           finding.Kind,
				"severity_score": finding.Severity.Score,
				"provider":       finding.Source.Provider,
			},
		})
	}

	descriptors := make([]reportingDescriptor, 0, len(rules))
	for _, descriptor := range rules {
		descriptors = append(descriptors, descriptor)
	}

	return report{
		Version: version,
		Schema:  schemaURI,
		Runs: []run{{
			Tool: tool{
				Driver: driver{
					Name:    document.Source.ToolName,
					Version: document.Source.ToolVersion,
					Rules:   descriptors,
				},
			},
			Results: results,
		}},
	}
}

func sarifLevel(severity evidence.Severity) string {
	switch {
	case severity.Score >= 7:
		return "error"
	case severity.Score >= 4:
		return "warning"
	default:
		return "note"
	}
}

func buildLocations(finding evidence.Finding) []location {
	if finding.PrimaryLocation.URI == "" {
		return nil
	}

	return []location{{
		PhysicalLocation: physicalLocation{
			ArtifactLocation: artifactLocation{
				URI: finding.PrimaryLocation.URI,
			},
			Region: region{
				StartLine:   finding.PrimaryLocation.Line,
				StartColumn: finding.PrimaryLocation.Column,
				EndLine:     finding.PrimaryLocation.EndLine,
				EndColumn:   finding.PrimaryLocation.EndColumn,
			},
		},
	}}
}
