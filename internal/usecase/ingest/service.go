package ingest

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sync/errgroup"

	sferr "github.com/secfacts/secfacts/internal/domain/errors"
	"github.com/secfacts/secfacts/internal/domain/evidence"
	"github.com/secfacts/secfacts/internal/ports"
)

const opRun = "ingest.Service.Run"

type Service struct {
	Parsers      []ports.Parser
	Normalizer   ports.Normalizer
	Deduplicator ports.Deduplicator
	Correlator   ports.Correlator
	Exporter     ports.Exporter
	Observer     ports.Observer
	Config       Config
}

type Config struct {
	DiscoveryWorkers int
	ParseWorkers     int
	NormalizeWorkers int
	DiscoveryBuffer  int
	FindingBuffer    int
}

type Request struct {
	Inputs []Input
	Output ports.ExportRequest
}

type Input struct {
	Path   string
	Source evidence.SourceDescriptor
}

type discoveredFile struct {
	path   string
	source evidence.SourceDescriptor
}

type findingEnvelope struct {
	finding evidence.Finding
}

var envelopePool = sync.Pool{
	New: func() any {
		return &findingEnvelope{}
	},
}

func (s Service) Run(ctx context.Context, req Request) (evidence.Document, error) {
	if err := s.validate(); err != nil {
		return evidence.Document{}, err
	}

	cfg := s.withDefaults()
	group, groupCtx := errgroup.WithContext(ctx)

	discoveredCh := make(chan discoveredFile, cfg.DiscoveryBuffer)
	parsedCh := make(chan *findingEnvelope, cfg.FindingBuffer)
	normalizedCh := make(chan *findingEnvelope, cfg.FindingBuffer)
	var discoveredFiles atomic.Int64
	var parsedFindings atomic.Int64
	var totalFindings atomic.Int64
	var parseWG sync.WaitGroup
	var normalizeWG sync.WaitGroup

	group.Go(func() error {
		defer close(discoveredCh)
		return s.runDiscovery(groupCtx, req.Inputs, discoveredCh, cfg.DiscoveryWorkers, &discoveredFiles)
	})

	for i := 0; i < cfg.ParseWorkers; i++ {
		parseWG.Add(1)
		group.Go(func() error {
			defer parseWG.Done()
			return s.runParse(groupCtx, discoveredCh, parsedCh, &parsedFindings)
		})
	}

	group.Go(func() error {
		parseWG.Wait()
		defer close(parsedCh)
		return nil
	})

	for i := 0; i < cfg.NormalizeWorkers; i++ {
		normalizeWG.Add(1)
		group.Go(func() error {
			defer normalizeWG.Done()
			return s.runNormalize(groupCtx, parsedCh, normalizedCh)
		})
	}

	uniqueCh := make(chan evidence.Finding, cfg.FindingBuffer)
	group.Go(func() error {
		defer close(uniqueCh)
		return s.runDeduplicate(groupCtx, normalizedCh, uniqueCh, &totalFindings)
	})

	findings := make([]evidence.Finding, 0, len(req.Inputs))
	group.Go(func() error {
		normalizeWG.Wait()
		defer close(normalizedCh)
		return nil
	})

	group.Go(func() error {
		for {
			select {
			case <-groupCtx.Done():
				return groupCtx.Err()
			case finding, ok := <-uniqueCh:
				if !ok {
					return nil
				}

				findings = append(findings, finding)
			}
		}
	})

	if err := group.Wait(); err != nil {
		return evidence.Document{}, err
	}

	if s.Observer != nil {
		s.Observer.OnFilesDiscovered(ctx, int(discoveredFiles.Load()))
		s.Observer.OnFindingsParsed(ctx, int(parsedFindings.Load()))
		s.Observer.OnFindingsDeduplicated(ctx, int(totalFindings.Load()), len(findings))
	}

	correlations, err := s.Correlator.Correlate(ctx, findings)
	if err != nil {
		return evidence.Document{}, sferr.Wrap(sferr.CodeCorrelateFailed, opRun, err, "correlate findings")
	}

	document := evidence.Document{
		SchemaVersion: evidence.SchemaVersion,
		GeneratedAt:   time.Now().UTC(),
		Source:        primarySource(req.Inputs),
		Summary: evidence.Summary{
			TotalFindings:      int(totalFindings.Load()),
			UniqueFindings:     len(findings),
			CorrelatedFindings: countCorrelated(correlations),
		},
		Findings:     findings,
		Correlations: correlations,
	}

	if s.Exporter != nil && req.Output.Writer != nil {
		req.Output.Document = document
		if err := s.Exporter.Export(ctx, req.Output); err != nil {
			return evidence.Document{}, sferr.Wrap(sferr.CodeExportFailed, opRun, err, "export findings")
		}
		if s.Observer != nil {
			s.Observer.OnExportCompleted(ctx, s.Exporter.Format(), len(document.Findings))
		}
	}

	return document, nil
}

func (s Service) validate() error {
	switch {
	case len(s.Parsers) == 0:
		return sferr.New(sferr.CodeInvalidConfig, opRun, "at least one parser is required")
	case s.Normalizer == nil:
		return sferr.New(sferr.CodeInvalidConfig, opRun, "normalizer is required")
	case s.Deduplicator == nil:
		return sferr.New(sferr.CodeInvalidConfig, opRun, "deduplicator is required")
	case s.Correlator == nil:
		return sferr.New(sferr.CodeInvalidConfig, opRun, "correlator is required")
	default:
		return nil
	}
}

func (s Service) withDefaults() Config {
	cfg := s.Config
	if cfg.DiscoveryWorkers <= 0 {
		cfg.DiscoveryWorkers = 1
	}
	if cfg.ParseWorkers <= 0 {
		cfg.ParseWorkers = 2
	}
	if cfg.NormalizeWorkers <= 0 {
		cfg.NormalizeWorkers = 4
	}
	if cfg.DiscoveryBuffer <= 0 {
		cfg.DiscoveryBuffer = 64
	}
	if cfg.FindingBuffer <= 0 {
		cfg.FindingBuffer = 512
	}

	return cfg
}

func (s Service) runDiscovery(ctx context.Context, inputs []Input, out chan<- discoveredFile, workers int, discoveredFiles *atomic.Int64) error {
	jobs := make(chan Input, len(inputs))
	for _, input := range inputs {
		jobs <- input
	}
	close(jobs)

	group, groupCtx := errgroup.WithContext(ctx)
	for i := 0; i < workers; i++ {
		group.Go(func() error {
			for {
				select {
				case <-groupCtx.Done():
					return groupCtx.Err()
				case input, ok := <-jobs:
					if !ok {
						return nil
					}

					if err := discoverInput(groupCtx, input, out, discoveredFiles); err != nil {
						return err
					}
				}
			}
		})
	}

	return group.Wait()
}

func (s Service) runParse(ctx context.Context, in <-chan discoveredFile, out chan<- *findingEnvelope, parsedFindings *atomic.Int64) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case file, ok := <-in:
			if !ok {
				return nil
			}

			if err := s.parseFile(ctx, file, out, parsedFindings); err != nil {
				return err
			}
		}
	}
}

func (s Service) parseFile(ctx context.Context, file discoveredFile, out chan<- *findingEnvelope, parsedFindings *atomic.Int64) error {
	parsers := selectParsers(s.Parsers, file.path)
	if len(parsers) == 0 {
		return sferr.New(sferr.CodeUnsupportedInput, opRun, "no parser supports input: "+file.path)
	}

	var lastErr error
	for _, parser := range parsers {
		handle, err := os.Open(file.path)
		if err != nil {
			return sferr.Wrap(sferr.CodeIO, opRun, err, "open input")
		}

		sink := parserSinkFunc(func(ctx context.Context, finding evidence.Finding) error {
			envelope := envelopePool.Get().(*findingEnvelope)
			envelope.finding = finding
			parsedFindings.Add(1)

			select {
			case <-ctx.Done():
				releaseEnvelope(envelope)
				return ctx.Err()
			case out <- envelope:
				return nil
			}
		})

		err = parser.Parse(ctx, ports.ParseRequest{
			Source:   file.source,
			Filename: file.path,
			Reader:   handle,
		}, sink)
		_ = handle.Close()
		if err == nil {
			return nil
		}
		if sferr.IsCode(err, sferr.CodeUnsupportedInput) {
			lastErr = err
			continue
		}

		return sferr.Wrap(sferr.CodeParseFailed, opRun, err, "parse input")
	}

	if lastErr != nil {
		return sferr.Wrap(sferr.CodeParseFailed, opRun, lastErr, "parse input")
	}

	return sferr.New(sferr.CodeUnsupportedInput, opRun, "no parser supports input: "+file.path)
}

func (s Service) runNormalize(ctx context.Context, in <-chan *findingEnvelope, out chan<- *findingEnvelope) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case envelope, ok := <-in:
			if !ok {
				return nil
			}

			finding, err := s.Normalizer.Normalize(ctx, envelope.finding)
			if err != nil {
				releaseEnvelope(envelope)
				return sferr.Wrap(sferr.CodeNormalizeFailed, opRun, err, "normalize finding")
			}

			identity, err := s.Deduplicator.Fingerprint(ctx, finding)
			if err != nil {
				releaseEnvelope(envelope)
				return sferr.Wrap(sferr.CodeDedupFailed, opRun, err, "fingerprint finding")
			}

			finding.Identity = identity
			envelope.finding = finding

			select {
			case <-ctx.Done():
				releaseEnvelope(envelope)
				return ctx.Err()
			case out <- envelope:
			}
		}
	}
}

func (s Service) runDeduplicate(ctx context.Context, in <-chan *findingEnvelope, out chan<- evidence.Finding, totalFindings *atomic.Int64) error {
	initialCapacity := s.Config.FindingBuffer
	if initialCapacity <= 0 {
		initialCapacity = 512
	}
	seen := make(map[[32]byte]struct{}, initialCapacity)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case envelope, ok := <-in:
			if !ok {
				return nil
			}

			finding := envelope.finding
			totalFindings.Add(1)
			key, ok := evidence.ParseSHA256Hex(finding.Identity.DedupKey)
			if !ok {
				releaseEnvelope(envelope)
				return sferr.New(sferr.CodeDedupFailed, opRun, "invalid dedup key encoding")
			}
			if _, exists := seen[key]; exists {
				releaseEnvelope(envelope)
				continue
			}

			seen[key] = struct{}{}
			releaseEnvelope(envelope)

			select {
			case <-ctx.Done():
				return ctx.Err()
			case out <- finding:
			}
		}
	}
}

func selectParsers(parsers []ports.Parser, filename string) []ports.Parser {
	name := strings.ToLower(filename)
	selected := make([]ports.Parser, 0, len(parsers))
	for _, parser := range parsers {
		if parser.Supports(name) {
			selected = append(selected, parser)
		}
	}

	return selected
}

func sourceForPath(source evidence.SourceDescriptor, path string) evidence.SourceDescriptor {
	source.URI = path
	return source
}

func releaseEnvelope(envelope *findingEnvelope) {
	envelope.finding = evidence.Finding{}
	envelopePool.Put(envelope)
}

func discoverInput(ctx context.Context, input Input, out chan<- discoveredFile, discoveredFiles *atomic.Int64) error {
	info, err := os.Stat(input.Path)
	if err != nil {
		return sferr.Wrap(sferr.CodeDiscoveryFailed, opRun, err, "stat input")
	}

	if !info.IsDir() {
		discoveredFiles.Add(1)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case out <- discoveredFile{path: input.Path, source: sourceForPath(input.Source, input.Path)}:
			return nil
		}
	}

	err = filepath.WalkDir(input.Path, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		discoveredFiles.Add(1)

		select {
		case <-ctx.Done():
			return ctx.Err()
		case out <- discoveredFile{path: path, source: sourceForPath(input.Source, path)}:
			return nil
		}
	})
	if err != nil {
		return sferr.Wrap(sferr.CodeDiscoveryFailed, opRun, err, "walk input directory")
	}

	return nil
}

func countCorrelated(clusters []evidence.RootCauseCluster) int {
	total := 0
	for _, cluster := range clusters {
		total += len(cluster.FindingIDs)
	}

	return total
}

func primarySource(inputs []Input) evidence.SourceDescriptor {
	if len(inputs) == 0 {
		return evidence.SourceDescriptor{}
	}

	return inputs[0].Source
}

type parserSinkFunc func(ctx context.Context, finding evidence.Finding) error

func (f parserSinkFunc) WriteFinding(ctx context.Context, finding evidence.Finding) error {
	return f(ctx, finding)
}
