package casegen

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/torjan0/cirewind/internal/analyze"
	"github.com/torjan0/cirewind/internal/casefile"
	"github.com/torjan0/cirewind/internal/demodata"
	"github.com/torjan0/cirewind/internal/incident"
)

func TestPreflightRawMaterializationBoundaries(t *testing.T) {
	t.Parallel()
	objectAtLimit := rawDescriptor{digest: strings.Repeat("a", 64), byteLength: maxCaseRawObjectBytes}
	aggregateAtLimit := []rawDescriptor{
		objectAtLimit,
		{digest: strings.Repeat("b", 64), byteLength: maxCaseRawObjectBytes},
		{digest: strings.Repeat("c", 64), byteLength: maxCaseRawObjectBytes},
		{digest: strings.Repeat("d", 64), byteLength: maxCaseRawObjectBytes},
		{digest: strings.Repeat("e", 64), byteLength: maxCaseRawObjectBytes},
	}
	if err := preflightRawMaterialization(aggregateAtLimit); err != nil {
		t.Fatalf("exact aggregate boundary was rejected: %v", err)
	}

	tooMany := make([]rawDescriptor, maxCaseRawObjectCount+1)
	for index := range tooMany {
		tooMany[index].byteLength = 0
	}
	for _, test := range []struct {
		name        string
		descriptors []rawDescriptor
	}{
		{name: "per-object overflow", descriptors: []rawDescriptor{{digest: strings.Repeat("f", 64), byteLength: maxCaseRawObjectBytes + 1}}},
		{name: "aggregate overflow", descriptors: append(append([]rawDescriptor(nil), aggregateAtLimit...), rawDescriptor{digest: strings.Repeat("0", 64), byteLength: 1})},
		{name: "object-count overflow", descriptors: tooMany},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := preflightRawMaterialization(test.descriptors); err == nil {
				t.Fatal("materialization preflight accepted an over-limit plan")
			}
		})
	}

	exactCount := tooMany[:maxCaseRawObjectCount]
	if err := preflightRawMaterialization(exactCount); err != nil {
		t.Fatalf("exact object-count boundary was rejected: %v", err)
	}
}

func TestRawCopyWriterRejectsOverlongAndRemembersViolation(t *testing.T) {
	t.Parallel()
	var destination bytes.Buffer
	writer := &rawCopyWriter{ctx: context.Background(), destination: &destination, expected: 3}
	if written, err := writer.Write([]byte("abc")); err != nil || written != 3 {
		t.Fatalf("write declared bytes = %d, %v", written, err)
	}
	if written, err := writer.Write([]byte("d")); err == nil || written != 0 {
		t.Fatalf("overlong write = %d, %v; want zero and error", written, err)
	}
	if written, err := writer.Write(nil); err == nil || written != 0 {
		t.Fatalf("sticky writer error = %d, %v; want zero and error", written, err)
	}
	if destination.String() != "abc" || writer.written != 3 {
		t.Fatalf("overlong bytes reached destination: bytes=%q count=%d", destination.String(), writer.written)
	}
}

func TestRawCopyWriterObservesCancellation(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	var destination bytes.Buffer
	writer := &rawCopyWriter{ctx: ctx, destination: &destination, expected: 2}
	if written, err := writer.Write([]byte("a")); err != nil || written != 1 {
		t.Fatalf("first write = %d, %v", written, err)
	}
	cancel()
	if written, err := writer.Write([]byte("b")); !errors.Is(err, context.Canceled) || written != 0 {
		t.Fatalf("post-cancel write = %d, %v; want context cancellation", written, err)
	}
	if destination.String() != "a" {
		t.Fatalf("bytes were written after cancellation: %q", destination.String())
	}
}

type shortRawDestination struct{}

func (shortRawDestination) Write(data []byte) (int, error) {
	if len(data) == 0 {
		return 0, nil
	}
	return len(data) - 1, nil
}

func TestRawCopyWriterRejectsShortDestinationWrite(t *testing.T) {
	t.Parallel()
	writer := &rawCopyWriter{ctx: context.Background(), destination: shortRawDestination{}, expected: 2}
	if written, err := writer.Write([]byte("ab")); !errors.Is(err, io.ErrShortWrite) || written != 1 {
		t.Fatalf("short write = %d, %v", written, err)
	}
}

type fakeCaseAborter struct {
	err error
}

func (f fakeCaseAborter) Abort() error { return f.err }

func TestAbortStagedCasePreservesCauseWithoutExposingRandomPath(t *testing.T) {
	t.Parallel()
	sentinel := errors.New("remove /private/cases/.cirewind-case-random-secret: permission denied")
	err := abortStagedCase(fakeCaseAborter{err: sentinel})
	if !errors.Is(err, sentinel) {
		t.Fatalf("cleanup error does not preserve its cause: %v", err)
	}
	if !errors.Is(err, ErrStagedCaseCleanup) {
		t.Fatalf("cleanup error does not expose its stable classification: %v", err)
	}
	if strings.Contains(err.Error(), ".cirewind-case-") || strings.Contains(err.Error(), "/private/cases") {
		t.Fatalf("cleanup error exposed the randomized staging path: %q", err)
	}
	if err := abortStagedCase(fakeCaseAborter{}); err != nil {
		t.Fatalf("successful cleanup returned an error: %v", err)
	}
}

func TestGenerateCancellationPreservesActualCleanupFailureClassification(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	parent := t.TempDir()
	output := filepath.Join(parent, "case")
	options := generationFixture(t, ctx, output)
	var staging string

	err := generate(ctx, options, generationHooks{beforeFinalize: func(_ context.Context, builder *casefile.Builder) error {
		staging = builder.StagingPath()
		moved := staging + ".moved"
		if err := os.Rename(staging, moved); err != nil {
			return fmt.Errorf("move staging fixture: %w", err)
		}
		if err := os.Mkdir(staging, 0o700); err != nil {
			return fmt.Errorf("replace staging fixture: %w", err)
		}
		cancel()
		return ctx.Err()
	}})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Generate error = %v, want context cancellation", err)
	}
	if !errors.Is(err, ErrStagedCaseCleanup) {
		t.Fatalf("Generate error = %v, want staged-cleanup classification", err)
	}
	if staging == "" {
		t.Fatal("cleanup-failure fixture did not observe private staging")
	}
	diagnostic := err.Error()
	if strings.Contains(diagnostic, filepath.Base(staging)) || strings.Contains(diagnostic, staging) || strings.Contains(diagnostic, parent) {
		t.Fatalf("cancellation/cleanup diagnostic exposed private staging: %q", diagnostic)
	}
	if !strings.Contains(diagnostic, "context canceled") || !strings.Contains(diagnostic, "staging directory removal failed") {
		t.Fatalf("cancellation/cleanup diagnostic lost its safe error categories: %q", diagnostic)
	}
	if _, statErr := os.Lstat(output); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("cancellation with cleanup failure published output: %v", statErr)
	}
}

func TestGenerateFailsClosedWhenStagedMaterialIsCorruptedBeforeFinalize(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	parent := t.TempDir()
	output := filepath.Join(parent, "case")
	options := generationFixture(t, ctx, output)
	hookCalled := false

	err := generate(ctx, options, generationHooks{beforeFinalize: func(_ context.Context, builder *casefile.Builder) error {
		hookCalled = true
		path, err := builder.Path("collection-metadata.json")
		if err != nil {
			return err
		}
		return os.WriteFile(path, []byte("{"), 0o600)
	}})
	verifiedSuccess := err == nil
	if !hookCalled {
		t.Fatal("pre-finalization failure hook was not called")
	}
	if verifiedSuccess {
		t.Fatal("corrupted staged case returned success, allowing a false verified-case message")
	}
	if !strings.Contains(err.Error(), "verify staged case") {
		t.Fatalf("Generate error = %v, want staged verification failure", err)
	}
	assertGenerationLeftNoCase(t, parent, output)
}

func TestGenerateHonorsCancellationImmediatelyBeforeFinalize(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	parent := t.TempDir()
	output := filepath.Join(parent, "case")
	options := generationFixture(t, ctx, output)

	err := generate(ctx, options, generationHooks{beforeFinalize: func(context.Context, *casefile.Builder) error {
		cancel()
		return nil
	}})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Generate error = %v, want context cancellation", err)
	}
	assertGenerationLeftNoCase(t, parent, output)
}

func TestGenerateCleansPrivateStagingWhenHookPanics(t *testing.T) {
	ctx := context.Background()
	parent := t.TempDir()
	output := filepath.Join(parent, "case")
	options := generationFixture(t, ctx, output)
	panicValue := &struct{}{}

	func() {
		defer func() {
			if recovered := recover(); recovered != panicValue {
				t.Fatalf("recovered panic = %#v, want injected sentinel", recovered)
			}
		}()
		_ = generate(ctx, options, generationHooks{beforeFinalize: func(context.Context, *casefile.Builder) error {
			panic(panicValue)
		}})
	}()
	assertGenerationLeftNoCase(t, parent, output)
}

func TestGenerateRedactsPrivateStagingPathFromPostBuilderFailure(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	parent := t.TempDir()
	output := filepath.Join(parent, "case")
	options := generationFixture(t, ctx, output)
	sentinel := errors.New("injected permission failure")
	var staging string

	err := generate(ctx, options, generationHooks{beforeFinalize: func(_ context.Context, builder *casefile.Builder) error {
		staging = builder.StagingPath()
		return fmt.Errorf("inspect generated material at %s: %w", filepath.Join(staging, "report.html"), sentinel)
	}})
	if !errors.Is(err, sentinel) {
		t.Fatalf("post-builder failure lost its cause: %v", err)
	}
	if staging == "" {
		t.Fatal("failure injection did not observe private staging")
	}
	diagnostic := err.Error()
	if strings.Contains(diagnostic, filepath.Base(staging)) || strings.Contains(diagnostic, staging) || strings.Contains(diagnostic, parent) {
		t.Fatalf("post-builder failure exposed private staging: %q", diagnostic)
	}
	if !strings.Contains(diagnostic, "materialize case in private staging") || !strings.Contains(diagnostic, "private path withheld") {
		t.Fatalf("post-builder failure lost safe operational context: %q", diagnostic)
	}
	assertGenerationLeftNoCase(t, parent, output)
}

func generationFixture(t *testing.T, ctx context.Context, output string) Options {
	t.Helper()
	bundle, err := demodata.Bundle(ctx)
	if err != nil {
		t.Fatal(err)
	}
	pack, err := incident.ValidateReader(ctx, bytes.NewReader(bundle.PackYAML))
	if err != nil {
		t.Fatal(err)
	}
	analysis, err := analyze.Derive(bundle.Snapshot, pack, bundle.AnalysisTime, analyze.ModeReplay)
	if err != nil {
		t.Fatal(err)
	}
	return Options{Output: output, Snapshot: bundle.Snapshot, Pack: pack, Case: analysis.Case}
}

func assertGenerationLeftNoCase(t *testing.T, parent, output string) {
	t.Helper()
	if _, err := os.Lstat(output); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed generation published output: %v", err)
	}
	entries, err := os.ReadDir(parent)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".cirewind-case-") {
			t.Fatalf("failed generation left staging directory %q", entry.Name())
		}
	}
}
