package cli

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/torjan0/cirewind/internal/archive"
	"github.com/torjan0/cirewind/internal/casefile"
	"github.com/torjan0/cirewind/internal/collect"
	"github.com/torjan0/cirewind/internal/demodata"
	"github.com/torjan0/cirewind/internal/evidence"
	"github.com/torjan0/cirewind/internal/livecollect"
	"github.com/torjan0/cirewind/internal/model"
)

type fixtureCollectionRunner struct {
	requests       []livecollect.Request
	emitCheckpoint bool
}

type recordingNoopRunner struct {
	requests []livecollect.Request
}

func (r *recordingNoopRunner) CollectInto(_ context.Context, request livecollect.Request, _ livecollect.Sink) (livecollect.Result, error) {
	r.requests = append(r.requests, request)
	discovery, err := collect.ExpandIncidentDiscoveryWindow(request.Interval)
	if err != nil {
		return livecollect.Result{}, err
	}
	return livecollect.Result{Requested: request.Interval, Discovery: discovery, Gaps: []collect.Gap{}}, nil
}

type globalGapRunner struct{}

func (globalGapRunner) CollectInto(ctx context.Context, request livecollect.Request, sink livecollect.Sink) (livecollect.Result, error) {
	discovery, err := collect.ExpandIncidentDiscoveryWindow(request.Interval)
	if err != nil {
		return livecollect.Result{}, err
	}
	unit := model.CoverageUnit{
		Kind: model.CoverageRepositoryVisibility, Scope: model.CoverageScope{},
		LogicalKey: "organization:acme:repository-visibility", RequiredForNegative: true,
	}
	unit.ID, err = evidence.NewCoverageUnitID(unit)
	if err != nil {
		return livecollect.Result{}, err
	}
	assessment := model.CoverageAssessment{
		UnitID: unit.ID, Status: model.CoverageGap,
		Gap:         &model.CoverageGapDetail{Reason: model.GapForbidden, Material: true, PermissionRelated: boolPointerForTest(true), SanitizedMessage: "organization repository enumeration was denied"},
		EvidenceIDs: []model.EvidenceID{},
	}
	assessment.ID, err = evidence.NewCoverageAssessmentID(assessment)
	if err != nil {
		return livecollect.Result{}, err
	}
	fact, err := archive.NormalizeFact(archive.Fact{Kind: archive.FactCoverageGap, EvidenceIDs: []model.EvidenceID{}, CoverageGap: &archive.CoverageGapFact{Unit: unit, Assessment: assessment}})
	if err != nil {
		return livecollect.Result{}, err
	}
	when := model.MustInstant(time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC))
	batch := archive.Batch{
		Collections: []archive.CollectionSession{{
			ID: "collection:global-cli-gap", Mode: string(request.Purpose), APIVersion: "2026-03-10", AuthKind: "environment",
			StartedAt: when, EndedAt: when,
			Scope:  archive.CollectionScope{Organization: request.Organization, Repositories: []model.RepositoryID{}, RequestedEventWindow: testCollectionWindow(request.Interval, model.ApproximationExact), DiscoveryEventWindow: testCollectionWindow(discovery, model.ApproximationConservativeExpanded)},
			Limits: map[string]uint64{},
		}},
		Payloads: []archive.Payload{}, Evidence: []evidence.Envelope{}, Facts: []archive.Fact{fact},
		Capabilities: []archive.Capability{{Name: "repository_visibility", Status: archive.CapabilityGap, Details: map[string]string{"accessible_count": "0", "denied_count": "1", "requested_total_known": "false"}}},
		Checkpoints:  []archive.Checkpoint{},
	}
	if err := sink.Append(ctx, batch); err != nil {
		return livecollect.Result{}, err
	}
	gap := collect.Gap{Reason: collect.GapForbidden, Scope: "organization_repositories", Material: true, Diagnostic: "organization repository enumeration was denied"}
	return livecollect.Result{Requested: request.Interval, Discovery: discovery, Batch: batch, Gaps: []collect.Gap{gap}}, nil
}

func boolPointerForTest(value bool) *bool { return &value }

func (r *fixtureCollectionRunner) CollectInto(ctx context.Context, request livecollect.Request, sink livecollect.Sink) (livecollect.Result, error) {
	r.requests = append(r.requests, request)
	snapshot, err := demodata.Snapshot(ctx)
	if err != nil {
		return livecollect.Result{}, err
	}
	discovery, err := collect.ExpandIncidentDiscoveryWindow(request.Interval)
	if err != nil {
		return livecollect.Result{}, err
	}
	snapshot.Collections[0].Mode = string(request.Purpose)
	snapshot.Collections[0].Scope.RequestedEventWindow = testCollectionWindow(request.Interval, model.ApproximationExact)
	snapshot.Collections[0].Scope.DiscoveryEventWindow = testCollectionWindow(discovery, model.ApproximationConservativeExpanded)
	if r.emitCheckpoint {
		watermark := model.MustInstant(request.Interval.To)
		created := snapshot.Collections[0].StartedAt
		refreshed := watermark
		snapshot.Checkpoints = []archive.Checkpoint{{
			RepositoryID: 101, DiscoveryWatermark: &watermark,
			OverlapSeconds: uint32(collect.DefaultArchiveOverlap / time.Second), WatchHorizonDays: uint32(collect.ProvisionalParentLookback / (24 * time.Hour)),
			LastSuccessfulCollection: snapshot.Collections[0].ID,
			WatchedParents:           []archive.WatchedParent{{RunID: 1001, CreatedAt: created, LastRefreshedAt: &refreshed}},
		}}
	}
	batch := archive.Batch{
		Collections:  snapshot.Collections,
		Payloads:     snapshot.Payloads,
		Evidence:     snapshot.Evidence,
		Facts:        snapshot.Facts,
		Capabilities: snapshot.Capabilities,
		Checkpoints:  snapshot.Checkpoints,
	}
	if err := sink.Append(ctx, batch); err != nil {
		return livecollect.Result{}, err
	}
	return livecollect.Result{Requested: request.Interval, Discovery: discovery, Batch: batch, Gaps: []collect.Gap{}}, nil
}

func testCollectionWindow(interval collect.Interval, approximation model.TimeApproximation) *model.EventInterval {
	start, end := model.MustInstant(interval.From), model.MustInstant(interval.To)
	bounds := model.BoundsClosedOpen
	return &model.EventInterval{Start: &start, End: &end, Bounds: &bounds, Precision: model.PrecisionSecond, Approximation: approximation, Basis: model.TimeBasisProxyInterval}
}

func TestNetworkInvestigationIntegrationProducesVerifiableCase(t *testing.T) {
	fixed := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	runner := &fixtureCollectionRunner{}
	output := filepath.Join(t.TempDir(), "case")
	options := investigateOptions{
		Targets:  commonTargetOptions{Repositories: []string{"acme/service"}},
		Incident: filepath.Join("..", "..", "incidents", "synthetic", "mutable-tag.yaml"),
		From:     time.Date(2026, 8, 19, 10, 0, 0, 0, time.UTC), To: time.Date(2026, 8, 19, 11, 0, 0, 0, time.UTC), Output: output, Concurrent: 2,
	}
	var stdout, stderr bytes.Buffer
	if err := runNetworkInvestigationWithRunner(context.Background(), options, &stdout, &stderr, runner, func() time.Time { return fixed }); err != nil {
		t.Fatal(err)
	}
	if err := casefile.VerifyManifest(context.Background(), output); err != nil {
		t.Fatalf("verify generated case: %v", err)
	}
	if len(runner.requests) != 1 || runner.requests[0].Purpose != livecollect.PurposeInvestigate {
		t.Fatalf("investigation requests = %#v", runner.requests)
	}
	if !strings.Contains(stdout.String(), "CONFIRMED_EXECUTED: 1") || !strings.Contains(stdout.String(), "coverage:") {
		t.Fatalf("investigation summary = %q", stdout.String())
	}
}

func TestNetworkInvestigationRejectsZeroInjectedClock(t *testing.T) {
	options := investigateOptions{
		Targets:  commonTargetOptions{Repositories: []string{"acme/service"}},
		Incident: filepath.Join("..", "..", "incidents", "synthetic", "mutable-tag.yaml"),
		From:     time.Date(2026, 8, 19, 10, 0, 0, 0, time.UTC),
		To:       time.Date(2026, 8, 19, 11, 0, 0, 0, time.UTC),
		Output:   filepath.Join(t.TempDir(), "case"),
	}
	err := runNetworkInvestigationWithRunner(context.Background(), options, &bytes.Buffer{}, &bytes.Buffer{}, &recordingNoopRunner{}, func() time.Time { return time.Time{} })
	if err == nil || !strings.Contains(err.Error(), "investigation clock: timestamp is zero") {
		t.Fatalf("error = %v, want sanitized zero-clock error", err)
	}
}

func TestOpenOrCreateArchiveRejectsZeroCreationTime(t *testing.T) {
	_, _, err := openOrCreateArchive(context.Background(), filepath.Join(t.TempDir(), "archive.db"), time.Time{})
	if err == nil || !strings.Contains(err.Error(), "archive creation time: timestamp is zero") {
		t.Fatalf("error = %v, want zero creation-time error", err)
	}
	if errors.Is(err, os.ErrNotExist) {
		t.Fatalf("creation-time validation was obscured by filesystem error: %v", err)
	}
}

func TestNetworkArchiveIntegrationCreatesAndResumes(t *testing.T) {
	fixed := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	runner := &fixtureCollectionRunner{emitCheckpoint: true}
	path := filepath.Join(t.TempDir(), "archive.db")
	options := archiveOptions{
		Targets: commonTargetOptions{Organization: "acme"},
		Store:   path, Since: 24 * time.Hour, Concurrent: 2,
	}
	for run := 0; run < 2; run++ {
		var stdout bytes.Buffer
		if err := runNetworkArchiveWithRunner(context.Background(), options, &stdout, &bytes.Buffer{}, runner, func() time.Time { return fixed }); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(stdout.String(), "coverage: complete") {
			t.Fatalf("archive summary = %q", stdout.String())
		}
	}
	if len(runner.requests) != 2 {
		t.Fatalf("requests = %d, want 2", len(runner.requests))
	}
	for _, request := range runner.requests {
		if request.Purpose != livecollect.PurposeArchive || !request.Interval.From.Equal(fixed.Add(-24*time.Hour)) || !request.Interval.To.Equal(fixed) {
			t.Fatalf("archive request = %#v", request)
		}
	}
	if runner.requests[0].ArchiveSchedule != livecollect.ArchiveScheduleInitial || len(runner.requests[0].ArchiveCheckpoints) != 0 {
		t.Fatalf("initial archive schedule = %#v", runner.requests[0])
	}
	if runner.requests[1].ArchiveSchedule != livecollect.ArchiveScheduleResume || len(runner.requests[1].ArchiveCheckpoints) != 1 {
		t.Fatalf("resumed archive schedule = %#v", runner.requests[1])
	}
	opened, err := archive.OpenReplay(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, snapshotErr := opened.Snapshot(context.Background())
	closeErr := opened.Close()
	if snapshotErr != nil || closeErr != nil {
		t.Fatalf("read archive: snapshot=%v close=%v", snapshotErr, closeErr)
	}
	if len(snapshot.Facts) == 0 || len(snapshot.Evidence) == 0 {
		t.Fatal("resumed archive lost compact evidence")
	}
}

func TestNetworkArchiveExplicitIntervalPreservesExistingCheckpoint(t *testing.T) {
	fixed := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	initialRunner := &fixtureCollectionRunner{emitCheckpoint: true}
	path := filepath.Join(t.TempDir(), "archive.db")
	initial := archiveOptions{Targets: commonTargetOptions{Organization: "acme"}, Store: path, Since: time.Hour, Concurrent: 1}
	if err := runNetworkArchiveWithRunner(context.Background(), initial, &bytes.Buffer{}, &bytes.Buffer{}, initialRunner, func() time.Time { return fixed }); err != nil {
		t.Fatal(err)
	}
	explicitFrom, explicitTo := fixed.Add(-7*24*time.Hour), fixed.Add(-6*24*time.Hour)
	explicit := archiveOptions{Targets: commonTargetOptions{Organization: "acme"}, Store: path, From: &explicitFrom, To: explicitTo, Concurrent: 1}
	runner := &recordingNoopRunner{}
	if err := runNetworkArchiveWithRunner(context.Background(), explicit, &bytes.Buffer{}, &bytes.Buffer{}, runner, func() time.Time { return fixed.Add(time.Hour) }); err != nil {
		t.Fatal(err)
	}
	request := runner.requests[0]
	if request.ArchiveSchedule != livecollect.ArchiveSchedulePreserve || len(request.ArchiveCheckpoints) != 0 || !request.Interval.From.Equal(explicitFrom) || !request.Interval.To.Equal(explicitTo) {
		t.Fatalf("explicit archive request = %#v", request)
	}
}

func TestNetworkArchiveRejectsCorruptedCheckpointBeforeCollection(t *testing.T) {
	fixed := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	initialRunner := &fixtureCollectionRunner{emitCheckpoint: true}
	path := filepath.Join(t.TempDir(), "archive.db")
	options := archiveOptions{Targets: commonTargetOptions{Organization: "acme"}, Store: path, Since: time.Hour, Concurrent: 1}
	if err := runNetworkArchiveWithRunner(context.Background(), options, &bytes.Buffer{}, &bytes.Buffer{}, initialRunner, func() time.Time { return fixed }); err != nil {
		t.Fatal(err)
	}
	database, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(context.Background(), `UPDATE archive_checkpoints SET discovery_watermark='not-a-time'`); err != nil {
		_ = database.Close()
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	resumeRunner := &fixtureCollectionRunner{}
	err = runNetworkArchiveWithRunner(context.Background(), options, &bytes.Buffer{}, &bytes.Buffer{}, resumeRunner, func() time.Time { return fixed.Add(time.Hour) })
	if err == nil || !strings.Contains(err.Error(), "read archive checkpoints") || len(resumeRunner.requests) != 0 {
		t.Fatalf("corrupt checkpoint result: err=%v requests=%d", err, len(resumeRunner.requests))
	}
}

func TestInvestigationPersistsGlobalVisibilityGapWithoutInventingRepository(t *testing.T) {
	fixed := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	output := filepath.Join(t.TempDir(), "case")
	options := investigateOptions{
		Targets:  commonTargetOptions{Organization: "acme"},
		Incident: filepath.Join("..", "..", "incidents", "synthetic", "mutable-tag.yaml"),
		From:     fixed.Add(-time.Hour), To: fixed, Output: output, Concurrent: 1,
	}
	var stdout bytes.Buffer
	if err := runNetworkInvestigationWithRunner(context.Background(), options, &stdout, &bytes.Buffer{}, globalGapRunner{}, func() time.Time { return fixed }); err != nil {
		t.Fatal(err)
	}
	if err := casefile.VerifyManifest(context.Background(), output); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(stdout.String(), "coverage: PARTIAL\nfindings: 0\n") {
		t.Fatalf("global-gap summary = %q", stdout.String())
	}
}

func TestRawLogFlagsReachCollectorAndWarnAboutSensitiveOutput(t *testing.T) {
	fixed := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	runner := &fixtureCollectionRunner{}
	investigationOutput := filepath.Join(t.TempDir(), "case")
	investigate := investigateOptions{
		Targets:  commonTargetOptions{Repositories: []string{"acme/service"}},
		Incident: filepath.Join("..", "..", "incidents", "synthetic", "mutable-tag.yaml"),
		From:     fixed.Add(-time.Hour), To: fixed, Output: investigationOutput, Concurrent: 1, RawLogs: true,
	}
	var stdout, stderr bytes.Buffer
	if err := runNetworkInvestigationWithRunner(context.Background(), investigate, &stdout, &stderr, runner, func() time.Time { return fixed }); err != nil {
		t.Fatal(err)
	}
	if len(runner.requests) != 1 || !runner.requests[0].RawRetention {
		t.Fatalf("investigation raw request=%#v", runner.requests)
	}
	if !strings.Contains(stderr.String(), "sensitive application output") {
		t.Fatalf("investigation raw warning=%q", stderr.String())
	}
	if info, err := os.Stat(filepath.Join(investigationOutput, "raw")); err != nil || !info.IsDir() {
		t.Fatalf("opted-in case raw directory: info=%v err=%v", info, err)
	}

	archiveRunner := &fixtureCollectionRunner{}
	archivePath := filepath.Join(t.TempDir(), "archive.db")
	archiveRequest := archiveOptions{Targets: commonTargetOptions{Organization: "acme"}, Store: archivePath, Since: time.Hour, Concurrent: 1, RawLogs: true}
	stdout.Reset()
	stderr.Reset()
	if err := runNetworkArchiveWithRunner(context.Background(), archiveRequest, &stdout, &stderr, archiveRunner, func() time.Time { return fixed }); err != nil {
		t.Fatal(err)
	}
	if len(archiveRunner.requests) != 1 || !archiveRunner.requests[0].RawRetention {
		t.Fatalf("archive raw request=%#v", archiveRunner.requests)
	}
	if !strings.Contains(stderr.String(), ".raw sidecar") {
		t.Fatalf("archive raw warning=%q", stderr.String())
	}
}
