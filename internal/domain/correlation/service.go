package correlation

import (
	"context"
	"fmt"
	"sort"

	"github.com/secfacts/secfacts/internal/domain/evidence"
)

const opCorrelate = "correlation.Service.Correlate"

type Service struct{}

func (Service) Correlate(_ context.Context, findings []evidence.Finding) ([]evidence.RootCauseCluster, error) {
	clusters := make(map[string]*evidence.RootCauseCluster)

	for _, finding := range findings {
		clusterKey, clusterType, title := correlationKey(finding)
		if clusterKey == "" {
			continue
		}

		id := fmt.Sprintf("%s|%s", clusterType, clusterKey)
		cluster, exists := clusters[id]
		if !exists {
			cluster = &evidence.RootCauseCluster{
				ID:    id,
				Key:   clusterKey,
				Type:  clusterType,
				Title: title,
			}
			clusters[id] = cluster
		}

		cluster.FindingIDs = append(cluster.FindingIDs, finding.ID)
		if shouldReplaceRepresentative(cluster.Representative, finding) {
			cluster.Representative = finding
		}
	}

	result := make([]evidence.RootCauseCluster, 0, len(clusters))
	for _, cluster := range clusters {
		if len(cluster.FindingIDs) < 2 {
			continue
		}

		sort.Strings(cluster.FindingIDs)
		result = append(result, *cluster)
	}

	sort.Slice(result, func(i int, j int) bool {
		if result[i].Type != result[j].Type {
			return result[i].Type < result[j].Type
		}

		return result[i].Key < result[j].Key
	})

	return result, nil
}

func correlationKey(f evidence.Finding) (string, string, string) {
	if f.Kind == evidence.KindSCA && f.Package != nil && f.Vulnerability != nil {
		vulnerabilityID := f.Vulnerability.ID
		if vulnerabilityID == "" && len(f.Vulnerability.Aliases) > 0 {
			vulnerabilityID = f.Vulnerability.Aliases[0]
		}
		if vulnerabilityID != "" && f.Package.Name != "" {
			key := vulnerabilityID + "|" + f.Package.Name
			return key, "sca_package_vulnerability", "dependency vulnerability: " + key
		}
	}

	if f.Kind == evidence.KindSAST && f.Rule.ID != "" && f.PrimaryLocation.URI != "" {
		key := f.Rule.ID + "|" + f.PrimaryLocation.URI
		return key, "sast_rule_file", "code path: " + key
	}

	for _, hint := range f.RootCauseHints {
		if hint.Type == "" || hint.Value == "" {
			continue
		}

		return hint.Value, hint.Type, hint.Type + ": " + hint.Value
	}

	if f.Image != nil && f.Image.BaseDigest != "" {
		return f.Image.BaseDigest, "base_image", "base image: " + f.Image.BaseDigest
	}

	if f.Package != nil && f.Vulnerability != nil {
		key := f.Package.PackageURL
		if key == "" {
			key = f.Package.Name
		}
		if key != "" {
			return key, "dependency", "dependency: " + key
		}
	}

	return "", "", ""
}

func shouldReplaceRepresentative(current evidence.Finding, candidate evidence.Finding) bool {
	if current.ID == "" {
		return true
	}

	return candidate.Severity.Score > current.Severity.Score
}
