package app

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"text/tabwriter"

	"github.com/rs/zerolog"
	"github.com/spf13/cobra"

	"github.com/secfacts/secfacts/internal/adapters/baseline"
	"github.com/secfacts/secfacts/internal/adapters/exporter/asff"
	iemexporter "github.com/secfacts/secfacts/internal/adapters/exporter/iemjson"
	"github.com/secfacts/secfacts/internal/adapters/exporter/sarif"
	"github.com/secfacts/secfacts/internal/adapters/parser/iemjson"
	"github.com/secfacts/secfacts/internal/adapters/parser/trivy"
	policyyaml "github.com/secfacts/secfacts/internal/adapters/policy"
	"github.com/secfacts/secfacts/internal/adapters/registry"
	"github.com/secfacts/secfacts/internal/bootstrap"
	"github.com/secfacts/secfacts/internal/domain/correlation"
	"github.com/secfacts/secfacts/internal/domain/dedup"
	sferr "github.com/secfacts/secfacts/internal/domain/errors"
	"github.com/secfacts/secfacts/internal/domain/evidence"
	domainpolicy "github.com/secfacts/secfacts/internal/domain/policy"
	"github.com/secfacts/secfacts/internal/ports"
	"github.com/secfacts/secfacts/internal/usecase/evaluate"
	"github.com/secfacts/secfacts/internal/usecase/ingest"
	"github.com/secfacts/secfacts/internal/usecase/normalize"
	"github.com/secfacts/secfacts/pkg/version"
)

func Run() int {
	cfg := bootstrap.LoadConfig()
	logger := bootstrap.NewLogger(cfg)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cmd, err := newRootCommand(ctx, cfg, logger)
	if err != nil {
		logger.Error().
			Str("code", string(sferr.CodeOf(err))).
			Err(err).
			Msg("initialize command")
		return 1
	}

	if err := cmd.ExecuteContext(ctx); err != nil {
		logger.Error().
			Str("code", string(sferr.CodeOf(err))).
			Err(err).
			Msg("command failed")
		if sferr.IsCode(err, sferr.CodePolicyViolation) {
			return 2
		}
		return 1
	}

	return 0
}

func newRootCommand(ctx context.Context, cfg bootstrap.Config, logger zerolog.Logger) (*cobra.Command, error) {
	parserRegistry, exporterRegistry, err := newRegistries()
	if err != nil {
		return nil, err
	}

	cmd := &cobra.Command{
		Use:           "secfacts",
		Short:         "Normalize security evidence into a canonical internal model.",
		SilenceUsage:  true,
		SilenceErrors: true,
		Version:       version.String(),
		RunE: func(cmd *cobra.Command, _ []string) error {
			return cmd.Help()
		},
	}

	cmd.SetContext(ctx)
	cmd.PersistentFlags().String("log-level", cfg.LogLevel, "Log level: debug, info, warn, error")
	cmd.PersistentFlags().String("log-format", cfg.LogFormat, "Log format: console or json")
	cmd.PersistentFlags().Int("workers", cfg.Workers, "Maximum concurrent workers for ingestion")

	cmd.AddCommand(newNormalizeCommand(cfg, logger, parserRegistry, exporterRegistry))

	return cmd, nil
}

func newNormalizeCommand(
	cfg bootstrap.Config,
	logger zerolog.Logger,
	parserRegistry *registry.ParserRegistry,
	exporterRegistry *registry.ExporterRegistry,
) *cobra.Command {
	var outputPath string
	var format string
	var pretty bool
	var provider string
	var toolName string
	var toolVersion string
	var failOnSeverity string
	var baselinePath string
	var policyPath string
	var awsAccountID string
	var awsRegion string
	var awsProductARN string
	var awsGeneratorID string
	var quiet bool
	var concurrency int

	cmd := &cobra.Command{
		Use:   "normalize <report> [report...]",
		Short: "Normalize one or more security reports into the internal evidence model.",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if concurrency <= 0 {
				return sferr.New(sferr.CodeInvalidArgument, "normalize", "concurrency must be greater than zero")
			}

			exporter, err := exporterRegistry.ByFormat(format)
			if err != nil {
				return err
			}

			writer, closeWriter, err := outputWriter(outputPath)
			if err != nil {
				return err
			}
			defer closeWriter()

			source := evidence.SourceDescriptor{
				Provider:    provider,
				ToolName:    toolName,
				ToolVersion: toolVersion,
				Format:      "auto",
			}

			inputs := make([]ingest.Input, 0, len(args))
			for _, arg := range args {
				inputs = append(inputs, ingest.Input{
					Path:   arg,
					Source: source,
				})
			}

			progress := progressObserver{logger: logger, quiet: quiet}
			identityBuilder := evidence.DefaultIdentityBuilder{}
			normalizer := normalize.Service{IdentityBuilder: identityBuilder}
			deduplicator := dedup.Service{Builder: identityBuilder}
			correlator := correlation.Service{}

			service := ingest.Service{
				Parsers:      parserRegistry.All(),
				Normalizer:   normalizer,
				Deduplicator: deduplicator,
				Correlator:   correlator,
				Exporter:     exporter,
				Observer:     progress,
				Config: ingest.Config{
					DiscoveryWorkers: 1,
					ParseWorkers:     concurrency,
					NormalizeWorkers: concurrency,
					DiscoveryBuffer:  64,
					FindingBuffer:    512,
				},
			}

			if !quiet {
				logger.Info().
					Str("format", format).
					Str("output", defaultOutputLabel(outputPath)).
					Int("concurrency", concurrency).
					Strs("inputs", args).
					Msg("starting normalization")
			}

			document, err := service.Run(cmd.Context(), ingest.Request{
				Inputs: inputs,
				Output: ports.ExportRequest{
					Writer: writer,
					Options: ports.ExportOptions{
						Pretty:       pretty,
						AWSAccountID: awsAccountID,
						AWSRegion:    awsRegion,
						ProductARN:   awsProductARN,
						GeneratorID:  awsGeneratorID,
					},
				},
			})
			if err != nil {
				return err
			}

			policy, err := loadPolicy(policyPath)
			if err != nil {
				return err
			}
			mergePolicyFlags(&policy, failOnSeverity)

			if shouldEvaluate(policy, baselinePath) {
				baselineDocument, err := loadBaseline(cmd.Context(), baselinePath)
				if err != nil {
					return err
				}

				decision, err := evaluate.Service{
					Engine: domainpolicy.Service{},
				}.Run(cmd.Context(), evaluate.Request{
					Document: document,
					Baseline: baselineDocument,
					Policy:   policy,
				})
				if err != nil {
					return err
				}

				logger.Info().
					Int("new_findings", len(decision.NewFindings)).
					Int("existing_findings", len(decision.ExistingFindings)).
					Int("fixed_findings", len(decision.FixedFindings)).
					Bool("passed", decision.Passed).
					Msg("policy evaluation completed")

				if !decision.Passed {
					renderSummaryTable(cmd.ErrOrStderr(), document)
					return sferr.New(sferr.CodePolicyViolation, "normalize", summarizeViolations(decision.Violations))
				}
			}

			renderSummaryTable(cmd.ErrOrStderr(), document)
			if !quiet {
				logger.Info().Msg("normalization completed")
			}
			return nil
		},
	}

	cmd.Flags().IntVar(&concurrency, "concurrency", runtime.NumCPU(), "Worker-pool concurrency for parse and normalize stages")
	cmd.Flags().StringVarP(&outputPath, "output", "o", "", "Write output to file instead of stdout")
	cmd.Flags().StringVar(&format, "format", "json", "Output format: json, sarif, or asff")
	cmd.Flags().BoolVar(&pretty, "pretty", true, "Pretty-print exported output")
	cmd.Flags().BoolVar(&quiet, "quiet", false, "Suppress progress logs and only emit essential summary output")
	cmd.Flags().StringVar(&provider, "provider", "secfacts", "Logical source provider for ingested findings")
	cmd.Flags().StringVar(&toolName, "tool-name", "secfacts", "Scanner or producer name used in the source metadata")
	cmd.Flags().StringVar(&toolVersion, "tool-version", version.Version, "Scanner or producer version used in the source metadata")
	cmd.Flags().StringVar(&failOnSeverity, "fail-on-severity", "", "Fail if findings meet or exceed this severity: low, medium, high, critical")
	cmd.Flags().StringVar(&baselinePath, "baseline", "", "Path to a previous secfacts IEM JSON export for incremental comparison")
	cmd.Flags().StringVar(&policyPath, "policy", "", "Path to a YAML policy file")
	cmd.Flags().StringVar(&awsAccountID, "aws-account-id", "", "AWS account ID for ASFF exports; falls back to SECFACTS_AWS_ACCOUNT_ID")
	cmd.Flags().StringVar(&awsRegion, "aws-region", "", "AWS region for ASFF exports; falls back to SECFACTS_AWS_REGION")
	cmd.Flags().StringVar(&awsProductARN, "aws-product-arn", "", "AWS Security Hub product ARN for ASFF exports; falls back to SECFACTS_AWS_PRODUCT_ARN")
	cmd.Flags().StringVar(&awsGeneratorID, "aws-generator-id", "", "Generator ID for ASFF exports; falls back to SECFACTS_AWS_GENERATOR_ID")

	return cmd
}

func newRegistries() (*registry.ParserRegistry, *registry.ExporterRegistry, error) {
	parserRegistry, err := registry.NewParserRegistry(
		trivy.Parser{},
		iemjson.Parser{},
	)
	if err != nil {
		return nil, nil, err
	}

	exporterRegistry, err := registry.NewExporterRegistry(
		iemexporter.Exporter{},
		asff.Exporter{},
		sarif.Exporter{},
	)
	if err != nil {
		return nil, nil, err
	}

	return parserRegistry, exporterRegistry, nil
}

func outputWriter(path string) (*os.File, func(), error) {
	if path == "" {
		return os.Stdout, func() {}, nil
	}

	file, err := os.Create(path)
	if err != nil {
		return nil, nil, sferr.Wrap(sferr.CodeIO, "normalize.outputWriter", err, "create output file")
	}

	return file, func() {
		_ = file.Close()
	}, nil
}

func defaultOutputLabel(path string) string {
	if path == "" {
		return "stdout"
	}

	return path
}

func loadPolicy(path string) (domainpolicy.Policy, error) {
	if path == "" {
		return domainpolicy.Policy{}, nil
	}

	return policyyaml.LoadFile(path)
}

func mergePolicyFlags(policy *domainpolicy.Policy, failOnSeverity string) {
	if strings.TrimSpace(failOnSeverity) != "" {
		policy.FailOnSeverity = evidence.SeverityLabel(strings.ToLower(strings.TrimSpace(failOnSeverity)))
	}
}

func shouldEvaluate(policy domainpolicy.Policy, baselinePath string) bool {
	if strings.TrimSpace(baselinePath) != "" {
		return true
	}

	return strings.TrimSpace(string(policy.FailOnSeverity)) != "" ||
		len(policy.MaxCountThresholds) > 0 ||
		len(policy.Allowlist) > 0 ||
		policy.FailOnNewOnly
}

func loadBaseline(ctx context.Context, path string) (evidence.Document, error) {
	if strings.TrimSpace(path) == "" {
		return evidence.Document{}, nil
	}

	return baseline.LoadIEMJSON(ctx, path, iemjson.Parser{})
}

func summarizeViolations(violations []domainpolicy.Violation) string {
	if len(violations) == 0 {
		return "policy violation"
	}

	messages := make([]string, 0, len(violations))
	for _, violation := range violations {
		messages = append(messages, violation.Message)
	}

	return strings.Join(messages, "; ")
}

type progressObserver struct {
	logger zerolog.Logger
	quiet  bool
}

func (o progressObserver) OnFilesDiscovered(_ context.Context, count int) {
	if o.quiet {
		return
	}
	o.logger.Info().Int("files", count).Msg("discovered files")
}

func (o progressObserver) OnFindingsParsed(_ context.Context, count int) {
	if o.quiet {
		return
	}
	o.logger.Info().Int("findings", count).Msg("parsed findings")
}

func (o progressObserver) OnFindingsDeduplicated(_ context.Context, total int, unique int) {
	if o.quiet {
		return
	}
	o.logger.Info().
		Int("total_findings", total).
		Int("unique_findings", unique).
		Msg("deduplicated findings")
}

func (o progressObserver) OnExportCompleted(_ context.Context, format string, findings int) {
	if o.quiet {
		return
	}
	o.logger.Info().
		Str("format", format).
		Int("findings", findings).
		Msg("export completed")
}

func renderSummaryTable(out io.Writer, document evidence.Document) {
	if out == nil {
		return
	}

	bySeverity := map[evidence.SeverityLabel]map[evidence.Kind]int{
		evidence.SeverityCritical: {},
		evidence.SeverityHigh:     {},
		evidence.SeverityMedium:   {},
		evidence.SeverityLow:      {},
		evidence.SeverityInfo:     {},
	}

	for _, finding := range document.Findings {
		label := finding.Severity.Label
		if _, ok := bySeverity[label]; !ok {
			bySeverity[label] = make(map[evidence.Kind]int)
		}
		bySeverity[label][finding.Kind]++
	}

	kinds := []evidence.Kind{
		evidence.KindSCA,
		evidence.KindSAST,
		evidence.KindDAST,
		evidence.KindCloud,
		evidence.KindSecrets,
	}
	labels := []evidence.SeverityLabel{
		evidence.SeverityCritical,
		evidence.SeverityHigh,
		evidence.SeverityMedium,
		evidence.SeverityLow,
		evidence.SeverityInfo,
	}

	tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(out, "")
	_, _ = fmt.Fprintln(out, "Summary")
	_, _ = fmt.Fprintf(tw, "Severity\tTotal\tSCA\tSAST\tDAST\tCloud\tSecrets\n")

	for _, label := range labels {
		counts := bySeverity[label]
		total := 0
		row := make([]int, 0, len(kinds))
		for _, kind := range kinds {
			value := counts[kind]
			row = append(row, value)
			total += value
		}
		_, _ = fmt.Fprintf(
			tw,
			"%s\t%d\t%d\t%d\t%d\t%d\t%d\n",
			strings.ToUpper(string(label)),
			total,
			row[0],
			row[1],
			row[2],
			row[3],
			row[4],
		)
	}

	_, _ = fmt.Fprintf(tw, "TOTAL\t%d\t%d\t%d\t%d\t%d\t%d\n",
		len(document.Findings),
		totalByKind(document.Findings, evidence.KindSCA),
		totalByKind(document.Findings, evidence.KindSAST),
		totalByKind(document.Findings, evidence.KindDAST),
		totalByKind(document.Findings, evidence.KindCloud),
		totalByKind(document.Findings, evidence.KindSecrets),
	)
	_ = tw.Flush()
}

func totalByKind(findings []evidence.Finding, kind evidence.Kind) int {
	total := 0
	for _, finding := range findings {
		if finding.Kind == kind {
			total++
		}
	}

	return total
}

func ExitWithError(err error) {
	if err == nil {
		return
	}

	_, _ = fmt.Fprintln(os.Stderr, sferr.Format(err))
}
