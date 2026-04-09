package trivy

import (
	"context"
	"strings"
	"testing"

	"github.com/secfacts/secfacts/internal/domain/evidence"
	"github.com/secfacts/secfacts/internal/ports"
)

func TestParserParsesVulnerabilitiesAndSecrets(t *testing.T) {
	t.Parallel()

	input := `{
  "ArtifactName": "alpine:3.19",
  "ArtifactType": "container_image",
  "Metadata": {
    "ImageID": "sha256:deadbeef"
  },
  "Results": [
    {
      "Target": "alpine:3.19 (alpine 3.19.1)",
      "Class": "os-pkgs",
      "Type": "alpine",
      "Vulnerabilities": [
        {
          "VulnerabilityID": "CVE-2024-0001",
          "PkgName": "openssl",
          "InstalledVersion": "1.0.2",
          "FixedVersion": "1.0.3",
          "Severity": "HIGH",
          "Title": "OpenSSL vulnerability",
          "Description": "openssl issue",
          "PrimaryURL": "https://example.com/cve",
          "PkgIdentifier": {
            "PURL": "pkg:apk/alpine/openssl@1.0.2"
          },
          "CVSS": {
            "nvd": {
              "V3Score": 8.2,
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
            }
          }
        }
      ]
    },
    {
      "Target": "app/config/.env",
      "Class": "secret",
      "Secrets": [
        {
          "RuleID": "aws-access-key-id",
          "Category": "AWS",
          "Severity": "CRITICAL",
          "Title": "AWS secret detected",
          "Match": "AKIA1234567890TEST",
          "StartLine": 12,
          "EndLine": 12,
          "Fingerprint": "secret-fp"
        }
      ]
    }
  ]
}`

	findings := make([]evidence.Finding, 0, 2)
	err := Parser{}.Parse(context.Background(), ports.ParseRequest{
		Filename: "trivy-report.json",
		Reader:   strings.NewReader(input),
		Source: evidence.SourceDescriptor{
			Provider:    "trivy",
			ToolName:    "trivy",
			ToolVersion: "0.50.0",
		},
	}, sinkFunc(func(_ context.Context, finding evidence.Finding) error {
		findings = append(findings, finding)
		return nil
	}))
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}
	if findings[0].Kind != evidence.KindSCA || findings[0].Package == nil || findings[0].Vulnerability == nil {
		t.Fatalf("unexpected vulnerability finding: %#v", findings[0])
	}
	if findings[1].Kind != evidence.KindSecrets || findings[1].Secret == nil {
		t.Fatalf("unexpected secret finding: %#v", findings[1])
	}
}

type sinkFunc func(context.Context, evidence.Finding) error

func (f sinkFunc) WriteFinding(ctx context.Context, finding evidence.Finding) error {
	return f(ctx, finding)
}
