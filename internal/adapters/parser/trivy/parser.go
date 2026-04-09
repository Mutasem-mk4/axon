package trivy

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

const opParse = "trivy.Parser.Parse"

type Parser struct{}

type report struct {
	ArtifactName string         `json:"ArtifactName"`
	ArtifactType string         `json:"ArtifactType"`
	Metadata     reportMetadata `json:"Metadata"`
	Results      []result       `json:"Results"`
}

type reportMetadata struct {
	ImageID string `json:"ImageID"`
	DiffID  string `json:"DiffID"`
}

type result struct {
	Target          string          `json:"Target"`
	Class           string          `json:"Class"`
	Type            string          `json:"Type"`
	Vulnerabilities []vulnerability `json:"Vulnerabilities"`
	Secrets         []secret        `json:"Secrets"`
}

type vulnerability struct {
	VulnerabilityID  string   `json:"VulnerabilityID"`
	PkgName          string   `json:"PkgName"`
	InstalledVersion string   `json:"InstalledVersion"`
	FixedVersion     string   `json:"FixedVersion"`
	Severity         string   `json:"Severity"`
	Title            string   `json:"Title"`
	Description      string   `json:"Description"`
	PrimaryURL       string   `json:"PrimaryURL"`
	References       []string `json:"References"`
	CweIDs           []string `json:"CweIDs"`
	PkgIdentifier    pkgID    `json:"PkgIdentifier"`
	CVSS             cvssMap  `json:"CVSS"`
}

type pkgID struct {
	PURL string `json:"PURL"`
}

type cvssMap map[string]cvss

type cvss struct {
	V3Score  float64 `json:"V3Score"`
	V3Vector string  `json:"V3Vector"`
}

type secret struct {
	RuleID      string `json:"RuleID"`
	Category    string `json:"Category"`
	Severity    string `json:"Severity"`
	Title       string `json:"Title"`
	Match       string `json:"Match"`
	StartLine   int    `json:"StartLine"`
	EndLine     int    `json:"EndLine"`
	Fingerprint string `json:"Fingerprint"`
}

func (Parser) Provider() string {
	return "trivy"
}

func (Parser) Supports(filename string) bool {
	return strings.EqualFold(filepath.Ext(filename), ".json")
}

func (Parser) Parse(ctx context.Context, req ports.ParseRequest, sink ports.FindingSink) error {
	reader := bufio.NewReader(req.Reader)
	peek, err := reader.Peek(1)
	if err != nil {
		if err == io.EOF {
			return nil
		}

		return sferr.Wrap(sferr.CodeParseFailed, opParse, err, "peek opening token")
	}
	if len(peek) == 0 || peek[0] != '{' {
		return sferr.New(sferr.CodeUnsupportedInput, opParse, "trivy report must be a JSON object")
	}

	decoder := json.NewDecoder(reader)
	var doc report
	if err := decoder.Decode(&doc); err != nil {
		return sferr.Wrap(sferr.CodeParseFailed, opParse, err, "decode trivy report")
	}

	if len(doc.Results) == 0 {
		return sferr.New(sferr.CodeUnsupportedInput, opParse, "trivy report results are missing")
	}

	supported := false
	for _, result := range doc.Results {
		if err := ctx.Err(); err != nil {
			return err
		}

		for _, item := range result.Vulnerabilities {
			supported = true
			if err := sink.WriteFinding(ctx, mapVulnerability(req, doc, result, item)); err != nil {
				return err
			}
		}

		for _, item := range result.Secrets {
			supported = true
			if err := sink.WriteFinding(ctx, mapSecret(req, doc, result, item)); err != nil {
				return err
			}
		}
	}

	if !supported {
		return sferr.New(sferr.CodeUnsupportedInput, opParse, "trivy report contains no supported finding types")
	}

	return nil
}

func mapVulnerability(req ports.ParseRequest, doc report, result result, item vulnerability) evidence.Finding {
	score, vector := bestCVSS(item.CVSS)
	refs := make([]evidence.Reference, 0, len(item.References)+1)
	if item.PrimaryURL != "" {
		refs = append(refs, evidence.Reference{Type: "advisory", URL: item.PrimaryURL})
	}
	for _, reference := range item.References {
		if strings.TrimSpace(reference) == "" {
			continue
		}
		refs = append(refs, evidence.Reference{Type: "reference", URL: reference})
	}

	return evidence.Finding{
		SchemaVersion: evidence.SchemaVersion,
		Kind:          evidence.KindSCA,
		Title:         firstNonEmpty(item.Title, item.VulnerabilityID, "trivy vulnerability"),
		Description:   item.Description,
		Severity: evidence.Severity{
			Label:  toSeverityLabel(item.Severity),
			Score:  score,
			Vector: vector,
		},
		Rule: evidence.Rule{
			ID:       item.VulnerabilityID,
			Name:     firstNonEmpty(item.Title, item.VulnerabilityID),
			Category: "vulnerability",
		},
		Artifact: evidence.Artifact{
			Type: doc.ArtifactType,
			Name: firstNonEmpty(doc.ArtifactName, result.Target),
		},
		Package: &evidence.Package{
			Type:         result.Type,
			Name:         item.PkgName,
			Version:      item.InstalledVersion,
			FixedVersion: item.FixedVersion,
			PackageURL:   item.PkgIdentifier.PURL,
		},
		Vulnerability: &evidence.Vulnerability{
			ID:         item.VulnerabilityID,
			CWE:        append([]string(nil), item.CweIDs...),
			CVSSScore:  score,
			CVSSVector: vector,
		},
		Image:      mapImage(doc),
		References: refs,
		Source: evidence.SourceRecord{
			Provider:       req.Source.Provider,
			Scanner:        firstNonEmpty(req.Source.ToolName, "trivy"),
			ScannerVersion: req.Source.ToolVersion,
			FindingID:      item.VulnerabilityID,
		},
	}
}

func mapSecret(req ports.ParseRequest, doc report, result result, item secret) evidence.Finding {
	return evidence.Finding{
		SchemaVersion: evidence.SchemaVersion,
		Kind:          evidence.KindSecrets,
		Title:         firstNonEmpty(item.Title, item.RuleID, "trivy secret"),
		Description:   firstNonEmpty(item.Category, "secret finding"),
		Severity: evidence.Severity{
			Label: toSeverityLabel(item.Severity),
		},
		Rule: evidence.Rule{
			ID:       item.RuleID,
			Name:     firstNonEmpty(item.Title, item.RuleID),
			Category: "secret",
		},
		PrimaryLocation: evidence.Location{
			URI:     result.Target,
			Line:    item.StartLine,
			EndLine: item.EndLine,
		},
		Artifact: evidence.Artifact{
			Type: "file",
			Name: result.Target,
		},
		Secret: &evidence.Secret{
			Type:        firstNonEmpty(item.Category, "secret"),
			Provider:    "trivy",
			Fingerprint: firstNonEmpty(item.Fingerprint, item.RuleID+"|"+result.Target+"|"+item.Match),
			Redacted:    redactSecret(item.Match),
		},
		Image: mapImage(doc),
		Source: evidence.SourceRecord{
			Provider:       req.Source.Provider,
			Scanner:        firstNonEmpty(req.Source.ToolName, "trivy"),
			ScannerVersion: req.Source.ToolVersion,
			FindingID:      item.RuleID,
		},
	}
}

func bestCVSS(values cvssMap) (float64, string) {
	for _, candidate := range values {
		if candidate.V3Score > 0 {
			return candidate.V3Score, candidate.V3Vector
		}
	}

	return 0, ""
}

func mapImage(doc report) *evidence.Image {
	if strings.TrimSpace(doc.Metadata.ImageID) == "" && strings.TrimSpace(doc.ArtifactName) == "" {
		return nil
	}

	return &evidence.Image{
		Repository: doc.ArtifactName,
		Digest:     doc.Metadata.ImageID,
		BaseDigest: doc.Metadata.DiffID,
	}
}

func toSeverityLabel(value string) evidence.SeverityLabel {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "critical":
		return evidence.SeverityCritical
	case "high":
		return evidence.SeverityHigh
	case "medium":
		return evidence.SeverityMedium
	case "low":
		return evidence.SeverityLow
	default:
		return evidence.SeverityInfo
	}
}

func redactSecret(value string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return ""
	}
	if len(trimmed) <= 6 {
		return "***"
	}

	return trimmed[:3] + "***" + trimmed[len(trimmed)-3:]
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}

	return ""
}
