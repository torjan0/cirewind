package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/torjan0/cirewind/internal/analyze"
	"github.com/torjan0/cirewind/internal/archive"
	"github.com/torjan0/cirewind/internal/buildinfo"
	"github.com/torjan0/cirewind/internal/casegen"
	"github.com/torjan0/cirewind/internal/collect"
	"github.com/torjan0/cirewind/internal/demodata"
	"github.com/torjan0/cirewind/internal/githubapi"
	"github.com/torjan0/cirewind/internal/incident"
	"github.com/torjan0/cirewind/internal/literalmatch"
	"github.com/torjan0/cirewind/internal/livecollect"
	"github.com/torjan0/cirewind/internal/model"
	"github.com/torjan0/cirewind/internal/report"
)

type liveCollectionRunner interface {
	CollectInto(context.Context, livecollect.Request, livecollect.Sink) (livecollect.Result, error)
}

type commandDependencies struct {
	newGitHubClient func() (livecollect.API, error)
}

func productionCommandDependencies() commandDependencies {
	return commandDependencies{newGitHubClient: func() (livecollect.API, error) {
		return githubapi.New(githubapi.EnvToken(), githubapi.WithUserAgent(buildinfo.UserAgent()))
	}}
}

func (d commandDependencies) githubClient() (livecollect.API, error) {
	if d.newGitHubClient == nil {
		return nil, errors.New("GitHub.com client factory is unavailable")
	}
	return d.newGitHubClient()
}

func runReplay(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	options, err := parseReplay(args, stderr)
	if err != nil {
		return err
	}
	pack, err := loadIncidentPack(ctx, options.Incident)
	if err != nil {
		return err
	}
	archiveStore, err := archive.OpenReplay(ctx, options.Archive)
	if err != nil {
		return fmt.Errorf("open replay archive: %w", err)
	}
	snapshot, snapshotErr := archiveStore.Snapshot(ctx)
	if snapshotErr != nil {
		return errors.Join(snapshotErr, archiveStore.Close())
	}
	analysisTime := time.Now().UTC().Round(0)
	if options.FixedCollectionTime != nil {
		analysisTime = *options.FixedCollectionTime
	}
	var rawSource casegen.RawSource
	if options.RawLogs {
		rawSource = archiveStore
		fmt.Fprintln(stderr, "warning: retained raw logs may contain sensitive application output that GitHub did not mask")
	}
	derived, generateErr := deriveAndGenerateCase(ctx, casePipelineRequest{
		Snapshot: snapshot, Pack: pack, AnalysisTime: analysisTime, Mode: analyze.ModeReplay,
		Output: options.Output, Raw: options.RawLogs, LiteralSource: archiveStore, RawSource: rawSource,
	})
	closeErr := archiveStore.Close()
	if generateErr != nil || closeErr != nil {
		if generateErr != nil {
			generateErr = fmt.Errorf("replay case: %w", generateErr)
		}
		return errors.Join(generateErr, closeErr)
	}
	printCaseSummary(stdout, derived)
	fmt.Fprintf(stdout, "case: %s\n", sanitizeTerminalValue(options.Output))
	return nil
}

func runArchive(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	return runArchiveWithDependencies(ctx, args, stdout, stderr, productionCommandDependencies())
}

func runArchiveWithDependencies(ctx context.Context, args []string, stdout, stderr io.Writer, dependencies commandDependencies) error {
	options, err := parseArchive(args, stderr)
	if err != nil {
		return err
	}
	if options.ImportFixture == "" {
		return runNetworkArchive(ctx, options, stdout, stderr, dependencies)
	}
	var snapshot archive.Snapshot
	switch options.ImportFixture {
	case "synthetic", "builtin:synthetic":
		snapshot, err = demodata.Snapshot(ctx)
	default:
		f, openErr := openRegular(options.ImportFixture)
		if openErr != nil {
			return fmt.Errorf("open archive fixture: %w", openErr)
		}
		snapshot, err = archive.DecodeSnapshot(f)
		closeErr := f.Close()
		if err == nil {
			err = closeErr
		}
	}
	if err != nil {
		return fmt.Errorf("load archive fixture: %w", err)
	}
	destination, err := archive.Import(ctx, options.Store, snapshot)
	if err != nil {
		return fmt.Errorf("import archive fixture: %w", err)
	}
	if err := destination.Close(); err != nil {
		return fmt.Errorf("close archive: %w", err)
	}
	fmt.Fprintf(stdout, "archive: %s\nfacts: %d\nevidence observations: %d\nnetwork requests: 0\n", sanitizeTerminalValue(options.Store), len(snapshot.Facts), len(snapshot.Evidence))
	return nil
}

func runInvestigate(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	return runInvestigateWithDependencies(ctx, args, stdout, stderr, productionCommandDependencies())
}

func runInvestigateWithDependencies(ctx context.Context, args []string, stdout, stderr io.Writer, dependencies commandDependencies) error {
	options, err := parseInvestigate(args, stderr)
	if err != nil {
		return err
	}
	return runNetworkInvestigation(ctx, options, stdout, stderr, dependencies)
}

func runNetworkInvestigation(ctx context.Context, options investigateOptions, stdout, stderr io.Writer, dependencies commandDependencies) error {
	client, err := dependencies.githubClient()
	if err != nil {
		return fmt.Errorf("configure GitHub.com client: %w", err)
	}
	now := time.Now
	runner := livecollect.Collector{API: client, Now: now}
	return runNetworkInvestigationWithRunner(ctx, options, stdout, stderr, runner, now)
}

func runNetworkInvestigationWithRunner(ctx context.Context, options investigateOptions, stdout, stderr io.Writer, runner liveCollectionRunner, now func() time.Time) error {
	if runner == nil {
		return errors.New("live collection runner is nil")
	}
	if now == nil {
		now = time.Now
	}
	pack, err := loadIncidentPack(ctx, options.Incident)
	if err != nil {
		return err
	}
	interval, err := collect.NewInterval(options.From, options.To)
	if err != nil {
		return fmt.Errorf("incident interval: %w", err)
	}
	if _, err := os.Lstat(options.Output); err == nil {
		return fmt.Errorf("case output already exists: %s", filepath.Clean(options.Output))
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect case output: %w", err)
	}
	temporary, err := os.MkdirTemp("", "cirewind-investigate-")
	if err != nil {
		return fmt.Errorf("create private investigation staging directory: %w", err)
	}
	defer func() { _ = os.RemoveAll(temporary) }()
	if err := os.Chmod(temporary, 0o700); err != nil {
		return fmt.Errorf("protect investigation staging directory: %w", err)
	}
	createdAt := now().UTC().Round(0)
	createdInstant, err := model.NewInstant(createdAt)
	if err != nil {
		return fmt.Errorf("investigation clock: %w", err)
	}
	archiveStore, err := archive.Create(ctx, filepath.Join(temporary, "collection.db"), archive.Options{CreatedAt: createdInstant})
	if err != nil {
		return fmt.Errorf("create investigation archive: %w", err)
	}
	if options.Verbose {
		fmt.Fprintln(stderr, "collecting read-only GitHub.com evidence")
	}
	if options.RawLogs {
		fmt.Fprintln(stderr, "warning: retained raw logs may contain sensitive application output that GitHub did not mask")
	}
	request := livecollect.Request{
		Organization: options.Targets.Organization,
		Repositories: append([]string(nil), options.Targets.Repositories...),
		Interval:     interval, Purpose: livecollect.PurposeInvestigate,
		Concurrency: options.Concurrent, RawRetention: options.RawLogs, AuthKind: "environment",
	}
	result, collectErr := runner.CollectInto(ctx, request, archiveStore)
	snapshot, snapshotErr := archiveStore.Snapshot(ctx)
	if collectErr != nil || snapshotErr != nil {
		return errors.Join(collectErr, snapshotErr, archiveStore.Close())
	}
	analysisTime := now().UTC().Round(0)
	derived, generateErr := deriveAndGenerateCase(ctx, casePipelineRequest{
		Snapshot: snapshot, Pack: pack, AnalysisTime: analysisTime, Mode: analyze.ModeInvestigate,
		Output: options.Output, Raw: options.RawLogs, LiteralSource: archiveStore, RawSource: archiveStore,
	})
	closeErr := archiveStore.Close()
	if generateErr != nil || closeErr != nil {
		if generateErr != nil {
			generateErr = fmt.Errorf("investigation case: %w", generateErr)
		}
		return errors.Join(generateErr, closeErr)
	}
	if options.Quiet {
		printCoverageOnly(stdout, derived)
	} else {
		printCaseSummary(stdout, derived)
		fmt.Fprintf(stdout, "collection gaps: %d\ncase: %s\n", len(result.Gaps), sanitizeTerminalValue(options.Output))
	}
	return nil
}

// casePipelineRequest is the in-process boundary shared by replay,
// investigation, and the credential-free synthetic demo. It deliberately has
// no transport, authentication, environment, or process-execution capability.
type casePipelineRequest struct {
	Snapshot       archive.Snapshot
	Pack           *incident.ValidatedPack
	AnalysisTime   time.Time
	Mode           string
	Output         string
	Raw            bool
	LiteralSource  literalmatch.RawSource
	RawSource      casegen.RawSource
	BeforeGenerate func(archive.Snapshot, report.Case) error
}

func deriveAndGenerateCase(ctx context.Context, request casePipelineRequest) (report.Case, error) {
	if err := ctx.Err(); err != nil {
		return report.Case{}, err
	}
	rawDerived, err := analyze.DeriveWithRaw(ctx, request.Snapshot, request.Pack, request.AnalysisTime, request.Mode, request.LiteralSource, literalmatch.Options{})
	if err != nil {
		return report.Case{}, fmt.Errorf("derive findings: %w", err)
	}
	snapshot := rawDerived.Snapshot
	caseValue := rawDerived.Analysis.Case
	rawMaterialized := request.Raw
	caseValue.Metadata.RawMaterialized = &rawMaterialized
	if !request.Raw {
		markRawNotMaterialized(&snapshot)
	}
	if err := ctx.Err(); err != nil {
		return report.Case{}, err
	}
	if request.BeforeGenerate != nil {
		if err := request.BeforeGenerate(snapshot, caseValue); err != nil {
			return report.Case{}, fmt.Errorf("validate derived case: %w", err)
		}
	}
	if err := casegen.Generate(ctx, casegen.Options{
		Output: request.Output, Raw: request.Raw, RawSource: request.RawSource,
		Snapshot: snapshot, Pack: request.Pack, Case: caseValue,
	}); err != nil {
		return report.Case{}, fmt.Errorf("generate case: %w", err)
	}
	return caseValue, nil
}

func runNetworkArchive(ctx context.Context, options archiveOptions, stdout, stderr io.Writer, dependencies commandDependencies) error {
	client, err := dependencies.githubClient()
	if err != nil {
		return fmt.Errorf("configure GitHub.com client: %w", err)
	}
	now := time.Now
	runner := livecollect.Collector{API: client, Now: now}
	return runNetworkArchiveWithRunner(ctx, options, stdout, stderr, runner, now)
}

func runNetworkArchiveWithRunner(ctx context.Context, options archiveOptions, stdout, stderr io.Writer, runner liveCollectionRunner, now func() time.Time) error {
	if runner == nil {
		return errors.New("live collection runner is nil")
	}
	if now == nil {
		now = time.Now
	}
	explicitInterval := options.From != nil
	from, to := options.From, options.To
	if from == nil {
		resolvedTo := to
		if resolvedTo.IsZero() {
			resolvedTo = now().UTC().Round(0)
		}
		resolvedFrom := resolvedTo.Add(-options.Since)
		from, to = &resolvedFrom, resolvedTo
	}
	interval, err := collect.NewInterval(*from, to)
	if err != nil {
		return fmt.Errorf("archive interval: %w", err)
	}
	archiveStore, created, err := openOrCreateArchive(ctx, options.Store, now().UTC().Round(0))
	if err != nil {
		return err
	}
	schedule := livecollect.ArchiveScheduleInitial
	checkpoints := []archive.Checkpoint{}
	if !created && explicitInterval {
		schedule = livecollect.ArchiveSchedulePreserve
	} else if !created {
		schedule = livecollect.ArchiveScheduleResume
		checkpoints, err = archiveStore.Checkpoints(ctx)
		if err != nil {
			return errors.Join(fmt.Errorf("read archive checkpoints: %w", err), archiveStore.Close())
		}
	}
	if options.Verbose {
		fmt.Fprintln(stderr, "collecting read-only GitHub.com evidence")
	}
	if options.RawLogs {
		fmt.Fprintln(stderr, "warning: retained raw logs may contain sensitive application output that GitHub did not mask; preserve the archive database and its .raw sidecar together")
	}
	request := livecollect.Request{
		Organization: options.Targets.Organization,
		Repositories: append([]string(nil), options.Targets.Repositories...),
		Interval:     interval, Purpose: livecollect.PurposeArchive,
		Concurrency: options.Concurrent, RawRetention: options.RawLogs, AuthKind: "environment",
		ArchiveSchedule: schedule, ArchiveCheckpoints: checkpoints,
	}
	result, collectErr := runner.CollectInto(ctx, request, archiveStore)
	snapshot, snapshotErr := archiveStore.Snapshot(ctx)
	closeErr := archiveStore.Close()
	if collectErr != nil || snapshotErr != nil || closeErr != nil {
		return errors.Join(collectErr, snapshotErr, closeErr)
	}
	coverage := "complete"
	if len(result.Gaps) != 0 {
		coverage = "PARTIAL"
	}
	if options.Quiet {
		fmt.Fprintf(stdout, "coverage: %s\n", coverage)
		return nil
	}
	action := "updated"
	if created {
		action = "created"
	}
	fmt.Fprintf(stdout, "coverage: %s\narchive: %s (%s)\nfacts: %d\nevidence observations: %d\ncollection gaps: %d\n",
		coverage, sanitizeTerminalValue(options.Store), action, len(snapshot.Facts), len(snapshot.Evidence), len(result.Gaps))
	return nil
}

func markRawNotMaterialized(snapshot *archive.Snapshot) {
	for index := range snapshot.Capabilities {
		capability := &snapshot.Capabilities[index]
		if capability.Name != "raw_logs" || capability.Status == archive.CapabilityGap {
			continue
		}
		details := make(map[string]string, len(capability.Details)+1)
		for key, value := range capability.Details {
			details[key] = value
		}
		details["case_materialization"] = "not-requested"
		capability.Status = archive.CapabilityHashOnly
		capability.Details = details
	}
}

func openOrCreateArchive(ctx context.Context, path string, createdAt time.Time) (*archive.Archive, bool, error) {
	info, err := os.Lstat(path)
	if err == nil {
		if !info.Mode().IsRegular() {
			return nil, false, errors.New("archive store must be a regular file, not a symlink or special file")
		}
		opened, openErr := archive.Open(ctx, path)
		if openErr != nil {
			return nil, false, fmt.Errorf("open archive: %w", openErr)
		}
		return opened, false, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, false, fmt.Errorf("inspect archive: %w", err)
	}
	createdInstant, instantErr := model.NewInstant(createdAt)
	if instantErr != nil {
		return nil, false, fmt.Errorf("archive creation time: %w", instantErr)
	}
	created, createErr := archive.Create(ctx, path, archive.Options{CreatedAt: createdInstant})
	if createErr != nil {
		return nil, false, fmt.Errorf("create archive: %w", createErr)
	}
	return created, true, nil
}

func loadIncidentPack(ctx context.Context, path string) (*incident.ValidatedPack, error) {
	f, err := openRegular(path)
	if err != nil {
		return nil, fmt.Errorf("open incident pack: %w", err)
	}
	pack, validateErr := incident.ValidateReader(ctx, f)
	closeErr := f.Close()
	if validateErr != nil || closeErr != nil {
		return nil, errors.Join(validateErr, closeErr)
	}
	return pack, nil
}

func openRegular(path string) (*os.File, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("input must be a regular file, not a symlink or special file")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	opened, statErr := f.Stat()
	if statErr != nil {
		_ = f.Close()
		return nil, statErr
	}
	if !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
		_ = f.Close()
		return nil, errors.New("input changed while opening or is not a regular file")
	}
	return f, nil
}

func printCaseSummary(writer io.Writer, caseValue report.Case) {
	coverage := "complete"
	if caseValue.Metadata.Coverage.Partial {
		coverage = "PARTIAL"
	}
	fmt.Fprintf(writer, "coverage: %s\nfindings: %d\n", coverage, len(caseValue.Findings))
	counts := make(map[string]int)
	for _, finding := range caseValue.Findings {
		counts[finding.State]++
	}
	for _, state := range model.FindingStates() {
		if count := counts[string(state)]; count != 0 {
			fmt.Fprintf(writer, "%s: %d\n", state, count)
		}
	}
}

func printCoverageOnly(writer io.Writer, caseValue report.Case) {
	coverage := "complete"
	if caseValue.Metadata.Coverage.Partial {
		coverage = "PARTIAL"
	}
	fmt.Fprintf(writer, "coverage: %s\n", coverage)
}
