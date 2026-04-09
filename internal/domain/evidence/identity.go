package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
)

const (
	identityNaturalKeyVersion = "natural/v1"
	identityFingerprintV1     = "fingerprint/v1"
	identityDedupKeyVersion   = "dedup/v1"
)

type IdentityBuilder interface {
	Build(f Finding) Identity
	BuildNaturalKey(f Finding) string
	BuildFingerprintV1(f Finding) string
	BuildDedupKey(f Finding) string
}

type DefaultIdentityBuilder struct{}

var identityBufferPool = sync.Pool{
	New: func() any {
		buffer := make([]byte, 0, 256)
		return &buffer
	},
}

func (DefaultIdentityBuilder) Build(f Finding) Identity {
	material := buildNaturalKeyMaterial(f)
	defer releaseIdentityBuffer(material)

	fingerprint := hashIdentityBytes(identityFingerprintV1, material)

	return Identity{
		NaturalKey:    hashIdentityBytes(identityNaturalKeyVersion, material),
		FingerprintV1: fingerprint,
		DedupKey:      hashIdentityString(identityDedupKeyVersion, fingerprint),
	}
}

func (DefaultIdentityBuilder) BuildNaturalKey(f Finding) string {
	material := buildNaturalKeyMaterial(f)
	defer releaseIdentityBuffer(material)

	return hashIdentityBytes(identityNaturalKeyVersion, material)
}

func (DefaultIdentityBuilder) BuildFingerprintV1(f Finding) string {
	material := buildNaturalKeyMaterial(f)
	defer releaseIdentityBuffer(material)

	return hashIdentityBytes(identityFingerprintV1, material)
}

func (b DefaultIdentityBuilder) BuildDedupKey(f Finding) string {
	return hashIdentityString(identityDedupKeyVersion, b.BuildFingerprintV1(f))
}

func buildNaturalKeyMaterial(f Finding) []byte {
	buffer := acquireIdentityBuffer()

	switch f.Kind {
	case KindSAST:
		appendNormalizedSegment(buffer, string(f.Kind))
		appendNormalizedSegment(buffer, f.Rule.ID)
		appendNormalizedPathSegment(buffer, f.PrimaryLocation.URI)
		appendNormalizedLineSegment(buffer, f.PrimaryLocation.Line)
		appendNormalizedSegment(buffer, annotationValue(f, "sast.source"))
		appendNormalizedSegment(buffer, annotationValue(f, "sast.sink"))
		appendNormalizedSegment(buffer, annotationValue(f, "sast.function"))
		appendNormalizedSegment(buffer, f.PrimaryLocation.SnippetDigest)
	case KindSCA:
		appendNormalizedSegment(buffer, string(f.Kind))
		appendNormalizedSegment(buffer, vulnerabilityID(f))
		appendNormalizedSegment(buffer, packageURL(f))
		appendNormalizedSegment(buffer, f.PackageName())
		appendNormalizedSegment(buffer, f.PackageVersion())
		appendNormalizedSegment(buffer, f.FixedVersion())
	default:
		appendNormalizedSegment(buffer, string(f.Kind))
		appendNormalizedSegment(buffer, f.Rule.ID)
		appendNormalizedSegment(buffer, vulnerabilityID(f))
		appendNormalizedPathSegment(buffer, f.PrimaryLocation.URI)
		appendNormalizedLineSegment(buffer, f.PrimaryLocation.Line)
		appendNormalizedSegment(buffer, f.Artifact.Name)
		appendNormalizedSegment(buffer, f.CloudResourceID())
		appendNormalizedSegment(buffer, f.SecretFingerprint())
		appendNormalizedSegment(buffer, imageDigest(f))
		appendNormalizedSegment(buffer, packageURL(f))
		appendNormalizedSegment(buffer, f.PrimaryLocation.SnippetDigest)
	}

	return *buffer
}

func hashIdentityBytes(version string, material []byte) string {
	sum := sha256WithVersion(version, material)
	return hex.EncodeToString(sum[:])
}

func hashIdentityString(version string, material string) string {
	sum := sha256WithVersion(version, []byte(material))
	return hex.EncodeToString(sum[:])
}

func sha256WithVersion(version string, material []byte) [32]byte {
	buffer := acquireIdentityBuffer()
	defer releaseIdentityBuffer(*buffer)

	*buffer = append(*buffer, version...)
	*buffer = append(*buffer, '|')
	*buffer = append(*buffer, material...)

	return sha256.Sum256(*buffer)
}

func ParseSHA256Hex(value string) ([32]byte, bool) {
	var decoded [32]byte
	if len(value) != 64 {
		return decoded, false
	}

	for i := 0; i < len(decoded); i++ {
		hi, ok := fromHexNibble(value[i*2])
		if !ok {
			return decoded, false
		}
		lo, ok := fromHexNibble(value[i*2+1])
		if !ok {
			return decoded, false
		}

		decoded[i] = (hi << 4) | lo
	}

	return decoded, true
}

func fromHexNibble(ch byte) (byte, bool) {
	switch {
	case ch >= '0' && ch <= '9':
		return ch - '0', true
	case ch >= 'a' && ch <= 'f':
		return ch - 'a' + 10, true
	case ch >= 'A' && ch <= 'F':
		return ch - 'A' + 10, true
	default:
		return 0, false
	}
}

func acquireIdentityBuffer() *[]byte {
	buffer := identityBufferPool.Get().(*[]byte)
	*buffer = (*buffer)[:0]
	return buffer
}

func releaseIdentityBuffer(buffer []byte) {
	buffer = buffer[:0]
	identityBufferPool.Put(&buffer)
}

func appendNormalizedSegment(buffer *[]byte, value string) {
	if len(*buffer) > 0 {
		*buffer = append(*buffer, '|')
	}

	appendLowerTrimmed(buffer, value)
}

func appendNormalizedPathSegment(buffer *[]byte, value string) {
	if len(*buffer) > 0 {
		*buffer = append(*buffer, '|')
	}

	appendLowerTrimmedPath(buffer, value)
}

func appendNormalizedLineSegment(buffer *[]byte, line int) {
	if len(*buffer) > 0 {
		*buffer = append(*buffer, '|')
	}

	if line <= 0 {
		return
	}

	*buffer = strconv.AppendInt(*buffer, int64(line), 10)
}

func appendLowerTrimmed(buffer *[]byte, value string) {
	start, end := trimBounds(value)
	for i := start; i < end; i++ {
		ch := value[i]
		if ch >= 'A' && ch <= 'Z' {
			ch += 'a' - 'A'
		}
		*buffer = append(*buffer, ch)
	}
}

func appendLowerTrimmedPath(buffer *[]byte, value string) {
	start, end := trimBounds(value)
	if start == end {
		return
	}

	normalized := filepath.ToSlash(value[start:end])
	for i := 0; i < len(normalized); i++ {
		ch := normalized[i]
		if ch >= 'A' && ch <= 'Z' {
			ch += 'a' - 'A'
		}
		*buffer = append(*buffer, ch)
	}
}

func trimBounds(value string) (int, int) {
	start := 0
	end := len(value)

	for start < end {
		switch value[start] {
		case ' ', '\n', '\r', '\t':
			start++
		default:
			goto trimEnd
		}
	}

trimEnd:
	for end > start {
		switch value[end-1] {
		case ' ', '\n', '\r', '\t':
			end--
		default:
			return start, end
		}
	}

	return start, end
}

func normalizePath(value string) string {
	if value == "" {
		return ""
	}

	trimmed := filepath.ToSlash(strings.TrimSpace(value))
	return strings.ToLower(trimmed)
}

func normalizeValue(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func normalizeLine(line int) string {
	if line <= 0 {
		return ""
	}

	return strconv.Itoa(line)
}

func annotationValue(f Finding, key string) string {
	if len(f.Annotations) == 0 {
		return ""
	}

	return f.Annotations[key]
}

func vulnerabilityID(f Finding) string {
	if f.Vulnerability == nil {
		return ""
	}

	if f.Vulnerability.ID != "" {
		return f.Vulnerability.ID
	}

	if len(f.Vulnerability.Aliases) == 0 {
		return ""
	}

	aliases := append([]string(nil), f.Vulnerability.Aliases...)
	sort.Strings(aliases)

	return aliases[0]
}

func packageURL(f Finding) string {
	if f.Package == nil {
		return ""
	}

	return f.Package.PackageURL
}

func imageDigest(f Finding) string {
	if f.Image == nil {
		return ""
	}

	if f.Image.Digest != "" {
		return f.Image.Digest
	}

	return f.Image.BaseDigest
}

func (f Finding) FixedVersion() string {
	if f.Package == nil {
		return ""
	}

	return f.Package.FixedVersion
}
