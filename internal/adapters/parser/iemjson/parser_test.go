package iemjson

import (
	"context"
	"strings"
	"testing"

	"github.com/secfacts/secfacts/internal/domain/evidence"
	"github.com/secfacts/secfacts/internal/ports"
)

func TestParserParsesFindingArray(t *testing.T) {
	t.Parallel()

	parser := Parser{}
	var findings []evidence.Finding

	err := parser.Parse(context.Background(), ports.ParseRequest{
		Filename: "sample.json",
		Reader: strings.NewReader(`[
			{
				"Kind":"sca",
				"Severity":{"Label":"high"},
				"Package":{"Name":"openssl","PackageURL":"pkg:apk/alpine/openssl@1.0.2"},
				"Vulnerability":{"ID":"CVE-2024-0001","CVSSScore":8.2}
			}
		]`),
	}, sinkFunc(func(_ context.Context, finding evidence.Finding) error {
		findings = append(findings, finding)
		return nil
	}))
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Vulnerability == nil || findings[0].Vulnerability.CVSSScore != 8.2 {
		t.Fatalf("expected vulnerability CVSS score 8.2, got %#v", findings[0].Vulnerability)
	}
}

type sinkFunc func(context.Context, evidence.Finding) error

func (f sinkFunc) WriteFinding(ctx context.Context, finding evidence.Finding) error {
	return f(ctx, finding)
}
