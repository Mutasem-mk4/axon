package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

func DedupMaterial(f Finding) string {
	parts := []string{
		strings.ToLower(strings.TrimSpace(string(f.Kind))),
		strings.ToLower(strings.TrimSpace(f.Rule.ID)),
		normalizedVulnerabilityID(f),
		strings.ToLower(strings.TrimSpace(f.PackageName())),
		strings.ToLower(strings.TrimSpace(f.PackageVersion())),
		strings.ToLower(strings.TrimSpace(f.PrimaryLocation.URI)),
		strings.ToLower(strings.TrimSpace(f.Artifact.Name)),
		strings.ToLower(strings.TrimSpace(f.CloudResourceID())),
		strings.ToLower(strings.TrimSpace(f.SecretFingerprint())),
	}

	return strings.Join(parts, "|")
}

func DedupHash(f Finding) string {
	sum := sha256.Sum256([]byte(DedupMaterial(f)))
	return hex.EncodeToString(sum[:])
}

func (f Finding) PackageName() string {
	if f.Package == nil {
		return ""
	}

	return f.Package.Name
}

func (f Finding) PackageVersion() string {
	if f.Package == nil {
		return ""
	}

	return f.Package.Version
}

func (f Finding) CloudResourceID() string {
	if f.Cloud == nil {
		return ""
	}

	if f.Cloud.ResourceARN != "" {
		return f.Cloud.ResourceARN
	}

	return f.Cloud.ResourceID
}

func (f Finding) SecretFingerprint() string {
	if f.Secret == nil {
		return ""
	}

	return f.Secret.Fingerprint
}

func normalizedVulnerabilityID(f Finding) string {
	if f.Vulnerability == nil {
		return ""
	}

	return strings.ToLower(strings.TrimSpace(f.Vulnerability.ID))
}
