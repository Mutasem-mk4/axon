package ingest

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/secfacts/secfacts/internal/adapters/parser/iemjson"
	"github.com/secfacts/secfacts/internal/domain/correlation"
	"github.com/secfacts/secfacts/internal/domain/dedup"
	"github.com/secfacts/secfacts/internal/domain/evidence"
	"github.com/secfacts/secfacts/internal/ports"
	"github.com/secfacts/secfacts/internal/usecase/normalize"
)

func BenchmarkServiceRun(b *testing.B) {
	for _, size := range []int{1000, 10000, 100000} {
		b.Run(strconv.Itoa(size), func(b *testing.B) {
			path := benchmarkDatasetPath(b, size)
			service := benchmarkService()

			b.ReportAllocs()
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				_, err := service.Run(context.Background(), Request{
					Inputs: []Input{{
						Path: path,
						Source: evidence.SourceDescriptor{
							Provider:    "benchmark",
							ToolName:    "benchmark",
							ToolVersion: "1.0.0",
						},
					}},
					Output: ports.ExportRequest{
						Writer: io.Discard,
					},
				})
				if err != nil {
					b.Fatalf("Run returned error: %v", err)
				}
			}
		})
	}
}

func benchmarkService() Service {
	identityBuilder := evidence.DefaultIdentityBuilder{}

	return Service{
		Parsers: []ports.Parser{
			iemjson.Parser{},
		},
		Normalizer:   normalize.Service{IdentityBuilder: identityBuilder},
		Deduplicator: dedup.Service{Builder: identityBuilder},
		Correlator:   correlation.Service{},
		Config: Config{
			DiscoveryWorkers: 1,
			ParseWorkers:     4,
			NormalizeWorkers: 4,
			DiscoveryBuffer:  64,
			FindingBuffer:    1024,
		},
	}
}

func benchmarkDatasetPath(tb testing.TB, size int) string {
	tb.Helper()

	dir := tb.TempDir()
	path := filepath.Join(dir, "findings.json")
	file, err := os.Create(path)
	if err != nil {
		tb.Fatalf("Create returned error: %v", err)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	if _, err := file.WriteString("["); err != nil {
		tb.Fatalf("WriteString returned error: %v", err)
	}

	for i := 0; i < size; i++ {
		if i > 0 {
			if _, err := file.WriteString(","); err != nil {
				tb.Fatalf("WriteString returned error: %v", err)
			}
		}

		finding := evidence.Finding{
			Kind:  evidence.KindSCA,
			Title: "benchmark finding " + strconv.Itoa(i),
			Severity: evidence.Severity{
				Label: evidence.SeverityHigh,
				Score: 7.5,
			},
			Rule: evidence.Rule{
				ID: "CVE-2024-" + strconv.Itoa(i),
			},
			Package: &evidence.Package{
				Name:       "pkg-" + strconv.Itoa(i),
				Version:    "1.0.0",
				PackageURL: "pkg:generic/pkg-" + strconv.Itoa(i) + "@1.0.0",
			},
			Vulnerability: &evidence.Vulnerability{
				ID:        "CVE-2024-" + strconv.Itoa(i),
				CVSSScore: 7.5,
			},
		}

		if err := encoder.Encode(finding); err != nil {
			tb.Fatalf("Encode returned error: %v", err)
		}

		if _, err := file.Seek(-1, io.SeekCurrent); err != nil {
			tb.Fatalf("Seek returned error: %v", err)
		}
	}

	if _, err := file.WriteString("]"); err != nil {
		tb.Fatalf("WriteString returned error: %v", err)
	}

	return path
}
