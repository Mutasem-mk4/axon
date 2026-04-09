package dedup

import (
	"context"

	sferr "github.com/secfacts/secfacts/internal/domain/errors"
	"github.com/secfacts/secfacts/internal/domain/evidence"
)

const opFingerprint = "dedup.Service.Fingerprint"

type Service struct {
	Builder evidence.IdentityBuilder
}

func (s Service) Fingerprint(_ context.Context, finding evidence.Finding) (evidence.Identity, error) {
	if s.Builder == nil {
		return evidence.Identity{}, sferr.New(sferr.CodeInvalidConfig, opFingerprint, "identity builder is required")
	}
	if finding.Identity.DedupKey != "" && finding.Identity.FingerprintV1 != "" && finding.Identity.NaturalKey != "" {
		return finding.Identity, nil
	}

	return s.Builder.Build(finding), nil
}
