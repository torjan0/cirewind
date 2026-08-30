package casefile

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/torjan0/cirewind/internal/evidence"
	"github.com/torjan0/cirewind/internal/model"
	"github.com/torjan0/cirewind/internal/store"
)

func writeRequired(t *testing.T, builder *Builder) {
	t.Helper()
	for _, name := range requiredFiles {
		f, err := builder.CreateFile(name)
		if err != nil {
			t.Fatal(err)
		}
		contents := name
		if name == "collection-metadata.json" {
			contents = `{"schemaVersion":"cirewind.collection-metadata/v1alpha1"}`
		}
		if _, err := f.WriteString(contents); err != nil {
			t.Fatal(err)
		}
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestFinalizeAndVerify(t *testing.T) {
	t.Parallel()
	target := filepath.Join(t.TempDir(), "case")
	builder, err := NewBuilder(target, false)
	if err != nil {
		t.Fatal(err)
	}
	defer builder.Abort()
	writeRequired(t, builder)
	if err := builder.Finalize(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := VerifyManifest(context.Background(), target); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(target, "raw")); !os.IsNotExist(err) {
		t.Fatalf("raw directory exists by default: %v", err)
	}
	if err := os.WriteFile(filepath.Join(target, "findings.json"), []byte("tampered"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := VerifyManifest(context.Background(), target); err == nil {
		t.Fatal("tampered case verified")
	}
}

func TestFinalizeCancellationDoesNotPublishCase(t *testing.T) {
	t.Parallel()
	target := filepath.Join(t.TempDir(), "case")
	builder, err := NewBuilder(target, false)
	if err != nil {
		t.Fatal(err)
	}
	staging := builder.StagingPath()
	defer builder.Abort()
	writeRequired(t, builder)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := builder.Finalize(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Finalize error=%v, want context.Canceled", err)
	}
	if _, err := os.Lstat(target); !os.IsNotExist(err) {
		t.Fatalf("canceled finalize published target: %v", err)
	}
	if err := builder.Abort(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(staging); !os.IsNotExist(err) {
		t.Fatalf("canceled staging remains after abort: %v", err)
	}
}

func TestPublishDirectoryNoReplacePreservesConcurrentTarget(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	source := filepath.Join(root, "source")
	target := filepath.Join(root, "target")
	if err := os.Mkdir(source, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "source-marker"), []byte("source"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "target-marker"), []byte("target"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := publishDirectoryNoReplace(source, target); err == nil {
		t.Fatal("no-replace publication replaced an existing target")
	}
	if data, err := os.ReadFile(filepath.Join(target, "target-marker")); err != nil || string(data) != "target" {
		t.Fatalf("concurrent target changed: data=%q err=%v", data, err)
	}
	if data, err := os.ReadFile(filepath.Join(source, "source-marker")); err != nil || string(data) != "source" {
		t.Fatalf("failed publication consumed source: data=%q err=%v", data, err)
	}
}

func TestConcurrentBuildersNeverReplacePublishedCase(t *testing.T) {
	t.Parallel()
	target := filepath.Join(t.TempDir(), "case")
	builders := make([]*Builder, 2)
	for index := range builders {
		builder, err := NewBuilder(target, false)
		if err != nil {
			t.Fatal(err)
		}
		builders[index] = builder
		writeRequired(t, builder)
	}
	start := make(chan struct{})
	results := make(chan error, len(builders))
	for _, builder := range builders {
		go func(candidate *Builder) {
			<-start
			results <- candidate.Finalize(context.Background())
		}(builder)
	}
	close(start)
	successes := 0
	for range builders {
		if err := <-results; err == nil {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("successful concurrent publications=%d, want exactly 1", successes)
	}
	for _, builder := range builders {
		if err := builder.Abort(); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := VerifyCase(context.Background(), target); err != nil {
		t.Fatalf("published case failed verification: %v", err)
	}
}

func TestAbortRefusesReplacedStagingDirectory(t *testing.T) {
	t.Parallel()
	builder, err := NewBuilder(filepath.Join(t.TempDir(), "case"), false)
	if err != nil {
		t.Fatal(err)
	}
	staging := builder.StagingPath()
	original := staging + "-original"
	if err := os.Rename(staging, original); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(original) })
	if err := os.Mkdir(staging, 0o700); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(staging, "unrelated")
	if err := os.WriteFile(marker, []byte("preserve"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := builder.Abort(); err == nil || !strings.Contains(err.Error(), "refuse") {
		t.Fatalf("Abort error=%v, want replaced-directory refusal", err)
	}
	if data, err := os.ReadFile(marker); err != nil || string(data) != "preserve" {
		t.Fatalf("replacement staging content changed: data=%q err=%v", data, err)
	}
}

func TestFinalizeRefusesReplacedStagingDirectory(t *testing.T) {
	t.Parallel()
	builder, err := NewBuilder(filepath.Join(t.TempDir(), "case"), false)
	if err != nil {
		t.Fatal(err)
	}
	staging := builder.StagingPath()
	original := staging + "-original"
	if err := os.Rename(staging, original); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(original) })
	if err := os.Mkdir(staging, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(staging) })
	if err := builder.Finalize(context.Background()); err == nil || !strings.Contains(err.Error(), "identity changed") {
		t.Fatalf("Finalize error=%v, want staging identity rejection", err)
	}
}

func TestVerifyManifestDoesNotMutateCaseDirectory(t *testing.T) {
	t.Parallel()
	target := filepath.Join(t.TempDir(), "case")
	builder, err := NewBuilder(target, false)
	if err != nil {
		t.Fatal(err)
	}
	defer builder.Abort()
	writeRequired(t, builder)
	if err := builder.Finalize(context.Background()); err != nil {
		t.Fatal(err)
	}
	before, err := directoryEntries(target)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyManifest(context.Background(), target); err != nil {
		t.Fatal(err)
	}
	after, err := directoryEntries(target)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("manifest verification mutated case directory: before=%v after=%v", before, after)
	}
}

func directoryEntries(path string) ([]string, error) {
	entries, err := os.ReadDir(path)
	if err != nil {
		return nil, err
	}
	result := make([]string, len(entries))
	for index, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			return nil, err
		}
		result[index] = entry.Name() + ":" + info.Mode().String() + ":" + fmt.Sprint(info.Size())
	}
	return result, nil
}

func TestVerifyRejectsExtraFile(t *testing.T) {
	t.Parallel()
	target := filepath.Join(t.TempDir(), "case")
	builder, err := NewBuilder(target, false)
	if err != nil {
		t.Fatal(err)
	}
	writeRequired(t, builder)
	if err := builder.Finalize(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "extra"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := VerifyManifest(context.Background(), target); err == nil {
		t.Fatal("unmanifested extra file accepted")
	}
}

func TestVerifyRejectsSelfConsistentIncompleteCase(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "manifest.sha256"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := VerifyManifest(context.Background(), dir); err == nil || !strings.Contains(err.Error(), "required case file") {
		t.Fatalf("empty case verification error = %v", err)
	}

	if err := os.WriteFile(filepath.Join(dir, "report.html"), []byte("report"), 0o600); err != nil {
		t.Fatal(err)
	}
	manifest, err := BuildManifest(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "manifest.sha256"), manifest, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := VerifyManifest(context.Background(), dir); err == nil || !strings.Contains(err.Error(), "required case file") {
		t.Fatalf("partial case verification error = %v", err)
	}
}

func TestRawSHA256FileIsOwnerOnlyAndManifested(t *testing.T) {
	t.Parallel()
	target := filepath.Join(t.TempDir(), "case")
	builder, err := NewBuilder(target, true)
	if err != nil {
		t.Fatal(err)
	}
	defer builder.Abort()
	writeRequired(t, builder)
	digest := strings.Repeat("b", 64)
	file, err := builder.CreateRawFile(digest)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteString("raw bytes"); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := builder.RawSHA256Path("../../hostile"); err == nil {
		t.Fatal("hostile raw digest accepted")
	}
	if err := builder.Finalize(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := VerifyManifest(context.Background(), target); err != nil {
		t.Fatal(err)
	}
	manifest, err := os.ReadFile(filepath.Join(target, "manifest.sha256"))
	if err != nil || !strings.Contains(string(manifest), "raw/"+digest+".bin") {
		t.Fatalf("raw object absent from manifest: err=%v manifest=%q", err, manifest)
	}
	if runtime.GOOS != "windows" {
		directory, _ := os.Stat(filepath.Join(target, "raw"))
		retained, _ := os.Stat(filepath.Join(target, "raw", digest+".bin"))
		if directory.Mode().Perm() != 0o700 || retained.Mode().Perm() != 0o600 {
			t.Fatalf("raw permissions directory=%o file=%o", directory.Mode().Perm(), retained.Mode().Perm())
		}
	}
}

func TestRawSHA256FileDisabledByDefault(t *testing.T) {
	t.Parallel()
	builder, err := NewBuilder(filepath.Join(t.TempDir(), "case"), false)
	if err != nil {
		t.Fatal(err)
	}
	defer builder.Abort()
	if _, err := builder.CreateRawFile(strings.Repeat("c", 64)); err == nil || !strings.Contains(err.Error(), "disabled") {
		t.Fatalf("disabled raw creation error=%v", err)
	}
}

func TestNewBuilderRejectsSymlinkAncestorBeforeCreatingParents(t *testing.T) {
	t.Parallel()
	base := t.TempDir()
	redirectTarget := t.TempDir()
	link := filepath.Join(base, "redirect")
	if err := os.Symlink(redirectTarget, link); err != nil {
		t.Skipf("symlinks are unavailable: %v", err)
	}
	target := filepath.Join(link, "must-not-be-created", "case")
	if _, err := NewBuilder(target, false); err == nil {
		t.Fatal("case path with a symlink ancestor was accepted")
	}
	if _, err := os.Lstat(filepath.Join(redirectTarget, "must-not-be-created")); !os.IsNotExist(err) {
		t.Fatalf("case builder mutated the symlink target before rejection: %v", err)
	}
}

func TestTrustedRootAliasCanonicalizationKeepsDescendantLinksHostile(t *testing.T) {
	t.Parallel()
	aliasParent := t.TempDir()
	canonicalRoot := t.TempDir()
	aliasRoot := filepath.Join(aliasParent, "system-temp-alias")
	if err := os.Symlink(canonicalRoot, aliasRoot); err != nil {
		t.Skipf("symlinks are unavailable: %v", err)
	}

	safePath := filepath.Join(aliasRoot, "job", "case")
	canonicalSafe, err := canonicalizeUnderTrustedRoot(safePath, aliasRoot)
	if err != nil {
		t.Fatal(err)
	}
	resolvedRoot, err := filepath.EvalSymlinks(canonicalRoot)
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(resolvedRoot, "job", "case"); canonicalSafe != want {
		t.Fatalf("canonical safe path = %q, want %q", canonicalSafe, want)
	}
	if err := rejectLinks(filepath.Dir(canonicalSafe)); err != nil {
		t.Fatalf("trusted root alias was not removed before strict validation: %v", err)
	}

	redirectTarget := t.TempDir()
	redirect := filepath.Join(canonicalRoot, "redirect")
	if err := os.Symlink(redirectTarget, redirect); err != nil {
		t.Fatal(err)
	}
	hostilePath := filepath.Join(aliasRoot, "redirect", "must-not-be-created", "case")
	canonicalHostile, err := canonicalizeUnderTrustedRoot(hostilePath, aliasRoot)
	if err != nil {
		t.Fatal(err)
	}
	if err := rejectLinks(filepath.Dir(canonicalHostile)); err == nil {
		t.Fatal("caller-controlled link below trusted root was accepted")
	}
}

type v2RawFixture struct {
	digest string
	bytes  []byte
}

func writeV2Case(t *testing.T, rawMaterialized bool, payloads ...[]byte) string {
	t.Helper()
	target := filepath.Join(t.TempDir(), "case")
	builder, err := NewBuilderV2(target, rawMaterialized)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = builder.Abort() })

	var raws []v2RawFixture
	for _, payload := range payloads {
		sum := sha256.Sum256(payload)
		digest := hex.EncodeToString(sum[:])
		raws = append(raws, v2RawFixture{digest: digest, bytes: payload})
		file, err := builder.CreateRawFile(digest)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := file.Write(payload); err != nil {
			t.Fatal(err)
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
	}

	for _, name := range requiredFilesV2 {
		if name == "case.db" {
			continue
		}
		file, err := builder.CreateFile(name)
		if err != nil {
			t.Fatal(err)
		}
		var contents []byte
		switch name {
		case "collection-metadata.json":
			contents = v2Metadata(t, rawMaterialized)
		case "evidence.jsonl":
			contents = v2Ledger(t, raws)
		case "graph.svg":
			contents = []byte(`<svg xmlns="http://www.w3.org/2000/svg"></svg>`)
		default:
			contents = []byte(name)
		}
		if _, err := file.Write(contents); err != nil {
			t.Fatal(err)
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
	}
	databasePath, err := builder.Path("case.db")
	if err != nil {
		t.Fatal(err)
	}
	database, err := store.Create(context.Background(), databasePath, store.KindCase)
	if err != nil {
		t.Fatal(err)
	}
	caseID := "case1:" + strings.Repeat("c", 64)
	if _, err := database.DB().Exec(`INSERT INTO metadata(key,value) VALUES
		('case_raw_materialized',?),('case_id',?),('engine_version','test'),('analysis_time','2026-08-22T00:00:00Z')`,
		strconv.FormatBool(rawMaterialized), caseID); err != nil {
		_ = database.Close()
		t.Fatal(err)
	}
	if _, err := database.DB().Exec(`INSERT INTO collection_sessions(
		collection_id,mode,api_version,auth_kind,started_at,ended_at,raw_retention,scope_json,limits_json
	) VALUES(?,?,?,?,?,?,?,?,?)`, "collection:casefile", "fixture", nil, "none", "2026-08-22T00:00:00Z", "2026-08-22T00:00:00Z", 0, `{}`, `{}`); err != nil {
		_ = database.Close()
		t.Fatal(err)
	}
	if _, err := database.DB().Exec(`INSERT INTO archive_batches(
		batch_id,primary_collection_id,content_sha256,state,prepared_at,committed_at
	) VALUES(?,?,?,?,?,?)`, "batch1:"+strings.Repeat("e", 64), "collection:casefile", strings.Repeat("f", 64), "COMMITTED", "2026-08-22T00:00:00Z", "2026-08-22T00:00:00Z"); err != nil {
		_ = database.Close()
		t.Fatal(err)
	}
	if _, err := database.DB().Exec(`INSERT INTO archive_batch_collections(batch_id,collection_id) VALUES(?,?)`, "batch1:"+strings.Repeat("e", 64), "collection:casefile"); err != nil {
		_ = database.Close()
		t.Fatal(err)
	}
	if _, err := database.DB().Exec(`INSERT INTO incident_packs(
		canonical_pack_sha256,incident_id,api_version,pack_version,source_pack_sha256,canonical_json,validation_policy_version
	) VALUES(?,?,?,?,?,?,?)`, strings.Repeat("a", 64), "SYNTHETIC-CASEFILE", "cirewind.dev/v1alpha1", "2.0.0",
		strings.Repeat("b", 64), []byte(`{}`), "test"); err != nil {
		_ = database.Close()
		t.Fatal(err)
	}
	if _, err := database.DB().Exec(`INSERT INTO analysis_sessions(
		analysis_id,mode,engine_version,semantic_rule_version,canonical_pack_sha256,source_pack_sha256,policy_sha256,analyzed_at
	) VALUES(?,?,?,?,?,?,?,?)`, "analysis:"+caseID, "replay", "test", "test", strings.Repeat("a", 64),
		strings.Repeat("b", 64), strings.Repeat("d", 64), "2026-08-22T00:00:00Z"); err != nil {
		_ = database.Close()
		t.Fatal(err)
	}
	if err := database.Finalize(context.Background()); err != nil {
		_ = database.Close()
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	if err := builder.Finalize(context.Background()); err != nil {
		t.Fatal(err)
	}
	return target
}

func v2Metadata(t *testing.T, rawMaterialized bool) []byte {
	t.Helper()
	metadata := map[string]any{
		"schemaVersion":       metadataV2Schema,
		"caseContractVersion": string(ContractV1Alpha2),
		"caseKind":            "synthetic",
		"rawMaterialized":     rawMaterialized,
		"caseId":              "case1:" + strings.Repeat("c", 64),
		"mode":                "replay",
		"incidentId":          "SYNTHETIC-CASEFILE",
		"incidentPackVersion": "2.0.0",
		"canonicalPackSha256": strings.Repeat("a", 64),
		"sourcePackSha256":    strings.Repeat("b", 64),
		"engineVersion":       "test",
		"analysisTime":        "2026-08-22T00:00:00Z",
		"rawLogsRetained":     rawMaterialized,
		"coverage": map[string]any{
			"partial":                      false,
			"repositoriesRequested":        0,
			"repositoriesAccessible":       0,
			"repositoriesDenied":           0,
			"runsEnumerated":               0,
			"attemptsEnumerated":           0,
			"jobsEnumerated":               0,
			"logsRetrieved":                0,
			"logsMissing":                  0,
			"workflowDefinitionsRetrieved": 0,
			"actionDefinitionsRetrieved":   0,
		},
		"limitPolicy": "test-bounded",
	}
	data, err := json.Marshal(metadata)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func v2Ledger(t *testing.T, raws []v2RawFixture) []byte {
	t.Helper()
	envelopes := make([]evidence.Envelope, 0, len(raws))
	for index, raw := range raws {
		envelopes = append(envelopes, v2RawEnvelope(t, raw, uint64(len(raw.bytes)), index+1))
	}
	return v2LedgerEnvelopes(t, envelopes)
}

func v2LedgerEnvelopes(t *testing.T, envelopes []evidence.Envelope) []byte {
	t.Helper()
	var output strings.Builder
	for index, envelope := range envelopes {
		record := map[string]any{
			"ledgerVersion": "cirewind.ledger/v1alpha1",
			"sequence":      index + 1,
			"sessionId":     "analysis:" + strings.Repeat("d", 64),
			"recordType":    "evidence_observation",
			"payload":       envelope,
		}
		data, err := json.Marshal(record)
		if err != nil {
			t.Fatal(err)
		}
		output.Write(data)
		output.WriteByte('\n')
	}
	return []byte(output.String())
}

func v2RawEnvelope(t *testing.T, raw v2RawFixture, descriptorLength uint64, ordinal int) evidence.Envelope {
	t.Helper()
	identity := evidence.LogicalSourceIdentity{
		Kind:              evidence.SourceOtherBounded,
		CanonicalID:       fmt.Sprintf("casefile:test:raw:%s:%d", raw.digest, ordinal),
		Scope:             model.CoverageScope{},
		RequestParameters: evidence.RequestParameters{},
	}
	logicalID, err := evidence.NewLogicalSourceID(identity)
	if err != nil {
		t.Fatal(err)
	}
	retention := evidence.RetentionDescriptor{
		MediaType:              "application/octet-stream",
		ByteLength:             descriptorLength,
		RawRetained:            true,
		RetainedPayloadSHA256:  &raw.digest,
		RedactionStatus:        evidence.RedactionNotInspected,
		RedactionPolicyVersion: "raw-exact-opt-in-v1",
	}
	evidenceID, err := evidence.NewEvidenceID(logicalID, raw.digest, retention)
	if err != nil {
		t.Fatal(err)
	}
	collected := model.MustInstant(time.Date(2026, 8, 22, 0, 0, 0, 0, time.UTC))
	requestID := model.RequestID(fmt.Sprintf("request:%s:%d", raw.digest, ordinal))
	observationID, err := evidence.NewCollectionObservationID(evidenceID, "collection:casefile", requestID, collected, 1)
	if err != nil {
		t.Fatal(err)
	}
	envelope := evidence.Envelope{
		Evidence: evidence.EvidenceObject{
			SchemaVersion: evidence.EvidenceSchemaVersion,
			ID:            evidenceID,
			LogicalSource: evidence.LogicalSource{
				ID: logicalID, Kind: identity.Kind, CanonicalID: identity.CanonicalID,
				RequestParameters: identity.RequestParameters,
			},
			Source: evidence.SourceDescriptor{
				Provider: evidence.ProviderCIRewind, RequestParameters: evidence.RequestParameters{}, RequestAttempt: 1,
			},
			Scope:     model.CoverageScope{},
			EventTime: model.EventInterval{Precision: model.PrecisionUnknown, Approximation: model.ApproximationUnknown, Basis: model.TimeBasisUnknown},
			Content: evidence.ContentDescriptor{
				MediaType: "application/octet-stream", ByteLength: descriptorLength, Complete: true,
				SourceSHA256: raw.digest, RetainedPayloadSHA256: &raw.digest, RawRetained: true,
				RetainedPath: "raw/" + raw.digest + ".bin",
			},
			Extractor:  evidence.ExtractorDescriptor{Name: "casefile-fixture", Version: "1.0.0", RulesetSHA256: strings.Repeat("e", 64)},
			Redaction:  evidence.RedactionDescriptor{Status: evidence.RedactionNotInspected, PolicyVersion: "raw-exact-opt-in-v1"},
			Derivation: evidence.DerivationDescriptor{ParentEvidenceIDs: []model.EvidenceID{}},
			Errors:     []evidence.EvidenceError{},
		},
		Observation: evidence.CollectionObservation{
			ID: observationID, EvidenceID: evidenceID, CollectionSessionID: "collection:casefile",
			RequestID: requestID, RequestAttempt: 1,
			CollectionTime: model.CollectionWindow{StartedAt: collected, EndedAt: collected},
		},
	}
	if err := envelope.Validate(); err != nil {
		t.Fatal(err)
	}
	return envelope
}

func rewriteManifest(t *testing.T, dir string) {
	t.Helper()
	manifest, err := BuildManifest(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "manifest.sha256"), manifest, 0o600); err != nil {
		t.Fatal(err)
	}
}

func mutateV2CaseDatabase(t *testing.T, target, statement string, arguments ...any) {
	t.Helper()
	database, err := store.Open(context.Background(), filepath.Join(target, "case.db"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.DB().ExecContext(context.Background(), statement, arguments...); err != nil {
		_ = database.Close()
		t.Fatal(err)
	}
	if err := database.Finalize(context.Background()); err != nil {
		_ = database.Close()
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	rewriteManifest(t, target)
}

func mutateJSONObject(t *testing.T, path string, mutate func(map[string]any)) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var value map[string]any
	if err := json.Unmarshal(data, &value); err != nil {
		t.Fatal(err)
	}
	mutate(value)
	data, err = json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyCaseReportsManifestedLegacyExtrasWithoutTrustingThem(t *testing.T) {
	t.Parallel()
	target := filepath.Join(t.TempDir(), "case")
	builder, err := NewBuilder(target, false)
	if err != nil {
		t.Fatal(err)
	}
	writeRequired(t, builder)
	if err := builder.Finalize(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "graph.svg"), []byte(`<script>hostile()</script>`), 0o600); err != nil {
		t.Fatal(err)
	}
	rewriteManifest(t, target)
	result, err := VerifyCase(context.Background(), target)
	if err != nil {
		t.Fatal(err)
	}
	if result.Contract != ContractV1Alpha1 || len(result.LegacyExtras) != 1 || result.LegacyExtras[0].Path != "graph.svg" || result.LegacyExtras[0].Status != LegacyExtraStatus {
		t.Fatalf("legacy result = %+v", result)
	}
}

func TestVerifyCaseAcceptsStrictV2RawDisabledAndEnabled(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name     string
		raw      bool
		payloads [][]byte
	}{
		{name: "raw disabled"},
		{name: "raw enabled empty", raw: true},
		{name: "raw enabled multiple", raw: true, payloads: [][]byte{[]byte("one"), []byte("two")}},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			target := writeV2Case(t, test.raw, test.payloads...)
			result, err := VerifyCase(context.Background(), target)
			if err != nil {
				t.Fatal(err)
			}
			if result.Contract != ContractV1Alpha2 || len(result.LegacyExtras) != 0 {
				t.Fatalf("v2 result = %+v", result)
			}
		})
	}
}

func TestVerifyCaseRejectsV2ChangedMissingExtraAndSymlink(t *testing.T) {
	t.Parallel()
	t.Run("changed", func(t *testing.T) {
		target := writeV2Case(t, false)
		if err := os.WriteFile(filepath.Join(target, "graph.svg"), []byte("tampered"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := VerifyCase(context.Background(), target); err == nil || !strings.Contains(err.Error(), "manifest verification failed") {
			t.Fatalf("changed file error = %v", err)
		}
	})
	t.Run("missing", func(t *testing.T) {
		target := writeV2Case(t, false)
		if err := os.Remove(filepath.Join(target, "graph.svg")); err != nil {
			t.Fatal(err)
		}
		rewriteManifest(t, target)
		if _, err := VerifyCase(context.Background(), target); err == nil || !strings.Contains(err.Error(), "required v0.2") {
			t.Fatalf("missing file error = %v", err)
		}
	})
	t.Run("extra", func(t *testing.T) {
		target := writeV2Case(t, false)
		if err := os.WriteFile(filepath.Join(target, "extra.txt"), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		rewriteManifest(t, target)
		if _, err := VerifyCase(context.Background(), target); err == nil || !strings.Contains(err.Error(), "unsupported extra") {
			t.Fatalf("extra file error = %v", err)
		}
	})
	t.Run("symlink", func(t *testing.T) {
		target := writeV2Case(t, false)
		if err := os.Symlink("graph.svg", filepath.Join(target, "hostile-link")); err != nil {
			t.Skipf("symlinks are unavailable: %v", err)
		}
		if _, err := VerifyCase(context.Background(), target); err == nil || !strings.Contains(err.Error(), "symlink") {
			t.Fatalf("symlink error = %v", err)
		}
	})
}

func TestVerifyCaseRejectsV2RawPolicyViolations(t *testing.T) {
	t.Parallel()
	t.Run("raw disabled directory", func(t *testing.T) {
		target := writeV2Case(t, false)
		if err := os.Mkdir(filepath.Join(target, "raw"), 0o700); err != nil {
			t.Fatal(err)
		}
		if _, err := VerifyCase(context.Background(), target); err == nil || !strings.Contains(err.Error(), "raw-disabled") {
			t.Fatalf("raw-disabled directory error = %v", err)
		}
	})
	t.Run("unreferenced raw", func(t *testing.T) {
		target := writeV2Case(t, true)
		payload := []byte("unreferenced")
		sum := sha256.Sum256(payload)
		digest := hex.EncodeToString(sum[:])
		if err := os.WriteFile(filepath.Join(target, "raw", digest+".bin"), payload, 0o600); err != nil {
			t.Fatal(err)
		}
		rewriteManifest(t, target)
		if _, err := VerifyCase(context.Background(), target); err == nil || !strings.Contains(err.Error(), "file set differs") {
			t.Fatalf("unreferenced raw error = %v", err)
		}
	})
	t.Run("descriptor path", func(t *testing.T) {
		target := writeV2Case(t, true, []byte("raw"))
		ledgerPath := filepath.Join(target, "evidence.jsonl")
		data, err := os.ReadFile(ledgerPath)
		if err != nil {
			t.Fatal(err)
		}
		data = bytes.Replace(data, []byte(`"retained_path":"raw/`), []byte(`"retained_path":"raw/0`), 1)
		if err := os.WriteFile(ledgerPath, data, 0o600); err != nil {
			t.Fatal(err)
		}
		rewriteManifest(t, target)
		if _, err := VerifyCase(context.Background(), target); err == nil || !strings.Contains(err.Error(), "unsafe path") {
			t.Fatalf("descriptor path error = %v", err)
		}
	})
	t.Run("descriptor length", func(t *testing.T) {
		target := writeV2Case(t, true, []byte("raw"))
		ledgerPath := filepath.Join(target, "evidence.jsonl")
		sum := sha256.Sum256([]byte("raw"))
		raw := v2RawFixture{digest: hex.EncodeToString(sum[:]), bytes: []byte("raw")}
		data := v2LedgerEnvelopes(t, []evidence.Envelope{v2RawEnvelope(t, raw, 4, 1)})
		if err := os.WriteFile(ledgerPath, data, 0o600); err != nil {
			t.Fatal(err)
		}
		rewriteManifest(t, target)
		if _, err := VerifyCase(context.Background(), target); err == nil || !strings.Contains(err.Error(), "length") {
			t.Fatalf("descriptor length error = %v", err)
		}
	})
	t.Run("hash name", func(t *testing.T) {
		target := writeV2Case(t, true, []byte("raw"))
		entries, err := os.ReadDir(filepath.Join(target, "raw"))
		if err != nil || len(entries) != 1 {
			t.Fatalf("raw entries=%v err=%v", entries, err)
		}
		if err := os.WriteFile(filepath.Join(target, "raw", entries[0].Name()), []byte("changed"), 0o600); err != nil {
			t.Fatal(err)
		}
		rewriteManifest(t, target)
		if _, err := VerifyCase(context.Background(), target); err == nil || !strings.Contains(err.Error(), "hash disagrees") {
			t.Fatalf("hash/name error = %v", err)
		}
	})
	t.Run("tamper", func(t *testing.T) {
		target := writeV2Case(t, true, []byte("raw"))
		entries, _ := os.ReadDir(filepath.Join(target, "raw"))
		if err := os.WriteFile(filepath.Join(target, "raw", entries[0].Name()), []byte("tamper"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := VerifyCase(context.Background(), target); err == nil || !strings.Contains(err.Error(), "manifest verification failed") {
			t.Fatalf("raw tamper error = %v", err)
		}
	})
}

func TestVerifyCaseRejectsStrictMetadataDriftAndDatabaseMismatch(t *testing.T) {
	t.Parallel()
	t.Run("unknown metadata field", func(t *testing.T) {
		target := writeV2Case(t, false)
		metadataPath := filepath.Join(target, "collection-metadata.json")
		mutateJSONObject(t, metadataPath, func(value map[string]any) { value["unreviewed"] = true })
		rewriteManifest(t, target)
		if _, err := VerifyCase(context.Background(), target); err == nil || !strings.Contains(err.Error(), "unknown field") {
			t.Fatalf("unknown metadata field error = %v", err)
		}
	})
	t.Run("contract mismatch", func(t *testing.T) {
		target := writeV2Case(t, false)
		metadataPath := filepath.Join(target, "collection-metadata.json")
		mutateJSONObject(t, metadataPath, func(value map[string]any) { value["caseContractVersion"] = string(ContractV1Alpha1) })
		rewriteManifest(t, target)
		if _, err := VerifyCase(context.Background(), target); err == nil || !strings.Contains(err.Error(), "do not form") {
			t.Fatalf("contract mismatch error = %v", err)
		}
	})
	t.Run("database mismatch", func(t *testing.T) {
		target := writeV2Case(t, false)
		metadataPath := filepath.Join(target, "collection-metadata.json")
		mutateJSONObject(t, metadataPath, func(value map[string]any) { value["rawMaterialized"] = true })
		rewriteManifest(t, target)
		if _, err := VerifyCase(context.Background(), target); err == nil || !strings.Contains(err.Error(), "disagrees") {
			t.Fatalf("database mismatch error = %v", err)
		}
	})
	t.Run("case identifier database mismatch", func(t *testing.T) {
		target := writeV2Case(t, false)
		mutateV2CaseDatabase(t, target, `UPDATE metadata SET value=? WHERE key='case_id'`, "case1:"+strings.Repeat("f", 64))
		if _, err := VerifyCase(context.Background(), target); err == nil || !strings.Contains(err.Error(), "case_id disagrees") {
			t.Fatalf("case identifier database mismatch error = %v", err)
		}
	})
	t.Run("analysis provenance mismatch", func(t *testing.T) {
		target := writeV2Case(t, false)
		mutateV2CaseDatabase(t, target, `UPDATE analysis_sessions SET mode='investigate'`)
		if _, err := VerifyCase(context.Background(), target); err == nil || !strings.Contains(err.Error(), "analysis provenance") {
			t.Fatalf("analysis provenance mismatch error = %v", err)
		}
	})
	t.Run("incident pack provenance mismatch", func(t *testing.T) {
		target := writeV2Case(t, false)
		mutateV2CaseDatabase(t, target, `UPDATE incident_packs SET incident_id='OTHER-SYNTHETIC'`)
		if _, err := VerifyCase(context.Background(), target); err == nil || !strings.Contains(err.Error(), "incident-pack provenance") {
			t.Fatalf("incident-pack provenance mismatch error = %v", err)
		}
	})
}

func TestVerifyCaseDerivesCaseKindFromPersistedCollectionModes(t *testing.T) {
	tests := []struct {
		name     string
		kind     string
		mutateDB func(*testing.T, string)
	}{
		{name: "synthetic", kind: "synthetic", mutateDB: func(*testing.T, string) {}},
		{name: "collected archive", kind: "collected", mutateDB: func(t *testing.T, target string) {
			mutateV2CaseDatabase(t, target, `UPDATE collection_sessions SET mode='archive'`)
		}},
		{name: "collected investigate", kind: "collected", mutateDB: func(t *testing.T, target string) {
			mutateV2CaseDatabase(t, target, `UPDATE collection_sessions SET mode='investigate'`)
		}},
		{name: "mixed", kind: "mixed", mutateDB: func(t *testing.T, target string) {
			mutateV2CaseDatabase(t, target, `INSERT INTO collection_sessions(
				collection_id,mode,api_version,auth_kind,started_at,ended_at,raw_retention,scope_json,limits_json
			) VALUES('collection:casefile:collected','archive',NULL,'none','2026-08-22T00:00:00Z','2026-08-22T00:00:00Z',0,'{}','{}')`)
			mutateV2CaseDatabase(t, target, `INSERT INTO archive_batch_collections(batch_id,collection_id) VALUES(?,?)`, "batch1:"+strings.Repeat("e", 64), "collection:casefile:collected")
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			target := writeV2Case(t, false)
			test.mutateDB(t, target)
			metadataPath := filepath.Join(target, "collection-metadata.json")
			mutateJSONObject(t, metadataPath, func(value map[string]any) { value["caseKind"] = test.kind })
			rewriteManifest(t, target)
			if _, err := VerifyCase(context.Background(), target); err != nil {
				t.Fatalf("derived %s case rejected: %v", test.kind, err)
			}
		})
	}
}

func TestVerifyCaseRejectsManifestedCaseKindSpoof(t *testing.T) {
	target := writeV2Case(t, false)
	metadataPath := filepath.Join(target, "collection-metadata.json")
	mutateJSONObject(t, metadataPath, func(value map[string]any) { value["caseKind"] = "collected" })
	rewriteManifest(t, target)
	if _, err := VerifyCase(context.Background(), target); err == nil || !strings.Contains(err.Error(), "caseKind") || !strings.Contains(err.Error(), "persisted collection provenance") {
		t.Fatalf("manifested caseKind spoof error=%v", err)
	}
}

func TestVerifyCaseRejectsOrphanAndUncommittedCollectionSpoofs(t *testing.T) {
	for _, test := range []struct {
		name     string
		mutateDB func(*testing.T, string)
	}{
		{name: "orphan collection", mutateDB: func(t *testing.T, target string) {
			mutateV2CaseDatabase(t, target, `INSERT INTO collection_sessions(
				collection_id,mode,api_version,auth_kind,started_at,ended_at,raw_retention,scope_json,limits_json
			) VALUES('collection:spoof:orphan','archive',NULL,'none','2026-08-22T00:00:00Z','2026-08-22T00:00:00Z',0,'{}','{}')`)
		}},
		{name: "uncommitted collection", mutateDB: func(t *testing.T, target string) {
			mutateV2CaseDatabase(t, target, `INSERT INTO collection_sessions(
				collection_id,mode,api_version,auth_kind,started_at,ended_at,raw_retention,scope_json,limits_json
			) VALUES('collection:spoof:prepared','archive',NULL,'none','2026-08-22T00:00:00Z','2026-08-22T00:00:00Z',0,'{}','{}')`)
			mutateV2CaseDatabase(t, target, `INSERT INTO archive_batches(
				batch_id,primary_collection_id,content_sha256,state,prepared_at,committed_at
			) VALUES(?,?,?,?,?,NULL)`, "batch1:"+strings.Repeat("1", 64), "collection:spoof:prepared", strings.Repeat("2", 64), "PREPARED", "2026-08-22T00:00:00Z")
			mutateV2CaseDatabase(t, target, `INSERT INTO archive_batch_collections(batch_id,collection_id) VALUES(?,?)`, "batch1:"+strings.Repeat("1", 64), "collection:spoof:prepared")
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			target := writeV2Case(t, false)
			test.mutateDB(t, target)
			metadataPath := filepath.Join(target, "collection-metadata.json")
			mutateJSONObject(t, metadataPath, func(value map[string]any) { value["caseKind"] = "mixed" })
			rewriteManifest(t, target)
			if _, err := VerifyCase(context.Background(), target); err == nil || !strings.Contains(err.Error(), "committed collection provenance count") {
				t.Fatalf("collection provenance spoof error=%v", err)
			}
		})
	}
}

func TestDerivePersistedCaseKindTreatsUnrecognizedModeAsUnknown(t *testing.T) {
	database, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if _, err := database.Exec(`
		CREATE TABLE collection_sessions(collection_id TEXT PRIMARY KEY, mode TEXT NOT NULL);
		CREATE TABLE archive_batches(batch_id TEXT PRIMARY KEY, state TEXT NOT NULL);
		CREATE TABLE archive_batch_collections(batch_id TEXT NOT NULL, collection_id TEXT NOT NULL);
	`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT INTO collection_sessions(collection_id,mode) VALUES('collection:unknown','user-label')`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT INTO archive_batches(batch_id,state) VALUES('batch1:unknown','COMMITTED')`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT INTO archive_batch_collections(batch_id,collection_id) VALUES('batch1:unknown','collection:unknown')`); err != nil {
		t.Fatal(err)
	}
	kind, err := derivePersistedCaseKind(context.Background(), database)
	if err != nil {
		t.Fatal(err)
	}
	if kind != "unknown" {
		t.Fatalf("unrecognized persisted mode derived caseKind=%q, want unknown", kind)
	}
}

func TestVerifyV2DatabaseContractRejectsArchiveStore(t *testing.T) {
	t.Parallel()
	database, err := store.Create(context.Background(), filepath.Join(t.TempDir(), "archive.db"), store.KindArchive)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	var metadata strictMetadataV2
	if err := json.Unmarshal(v2Metadata(t, false), &metadata); err != nil {
		t.Fatal(err)
	}
	if err := verifyV2DatabaseContract(context.Background(), database, metadata); err == nil || !strings.Contains(err.Error(), "store kind") {
		t.Fatalf("archive-store error=%v, want store-kind rejection", err)
	}
}

func TestVerifyCaseRejectsDetectableV2HardLink(t *testing.T) {
	t.Parallel()
	target := writeV2Case(t, false)
	graphJSON := filepath.Join(target, "graph.json")
	graphSVG := filepath.Join(target, "graph.svg")
	if err := os.Remove(graphSVG); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(graphJSON, graphSVG); err != nil {
		t.Skipf("hard links are unavailable: %v", err)
	}
	rewriteManifest(t, target)
	if _, err := VerifyCase(context.Background(), target); err == nil || !strings.Contains(err.Error(), "hard link") {
		t.Fatalf("hard-link error = %v", err)
	}
}

func TestVerifyCaseRejectsExternalV2HardLinks(t *testing.T) {
	if runtime.GOOS == "plan9" {
		t.Skip("strict v0.2 verification is fail-closed on this platform")
	}
	for _, test := range []struct {
		name string
		raw  bool
		path func(string) string
	}{
		{name: "required file", path: func(target string) string { return filepath.Join(target, "graph.svg") }},
		{name: "manifest", path: func(target string) string { return filepath.Join(target, "manifest.sha256") }},
		{name: "raw file", raw: true, path: func(target string) string {
			entries, err := os.ReadDir(filepath.Join(target, "raw"))
			if err != nil || len(entries) != 1 {
				t.Fatalf("raw entries=%v err=%v", entries, err)
			}
			return filepath.Join(target, "raw", entries[0].Name())
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			var target string
			if test.raw {
				target = writeV2Case(t, true, []byte("raw"))
			} else {
				target = writeV2Case(t, false)
			}
			external := filepath.Join(t.TempDir(), "external-alias")
			if err := os.Link(test.path(target), external); err != nil {
				t.Skipf("hard links are unavailable: %v", err)
			}
			if _, err := VerifyCase(context.Background(), target); err == nil || !strings.Contains(err.Error(), "hard link count") {
				t.Fatalf("external hard-link error = %v", err)
			}
		})
	}
}

func TestVerifyCaseEnforcesV2MetadataSchemaSemantics(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(map[string]any)
		want   string
	}{
		{name: "case identifier", mutate: func(value map[string]any) { value["caseId"] = "case-v2-test" }, want: "canonical case1"},
		{name: "mode", mutate: func(value map[string]any) { value["mode"] = "demo" }, want: "invalid mode"},
		{name: "analysis time", mutate: func(value map[string]any) { value["analysisTime"] = "2026-08-22" }, want: "not RFC3339"},
		{name: "raw logs required", mutate: func(value map[string]any) { delete(value, "rawLogsRetained") }, want: "rawLogsRetained"},
		{name: "coverage required member", mutate: func(value map[string]any) {
			delete(value["coverage"].(map[string]any), "logsMissing")
		}, want: "omits logsMissing"},
		{name: "negative coverage", mutate: func(value map[string]any) {
			value["coverage"].(map[string]any)["jobsEnumerated"] = -1
		}, want: "jobsEnumerated is negative"},
		{name: "watch horizon", mutate: func(value map[string]any) { value["watchHorizonDays"] = 3651 }, want: "outside 0..3650"},
		{name: "duplicate warning", mutate: func(value map[string]any) { value["warnings"] = []any{"same", "same"} }, want: "duplicate value"},
		{name: "null warning", mutate: func(value map[string]any) { value["warnings"] = nil }, want: "warnings cannot be null"},
		{name: "null optional coverage", mutate: func(value map[string]any) {
			value["coverage"].(map[string]any)["incompleteEvidence"] = nil
		}, want: "coverage.incompleteEvidence cannot be null"},
		{name: "oversized engine version", mutate: func(value map[string]any) { value["engineVersion"] = strings.Repeat("x", 129) }, want: "engineVersion"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			target := writeV2Case(t, false)
			metadataPath := filepath.Join(target, "collection-metadata.json")
			mutateJSONObject(t, metadataPath, test.mutate)
			rewriteManifest(t, target)
			if _, err := VerifyCase(context.Background(), target); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("metadata error = %v, want substring %q", err, test.want)
			}
		})
	}
}

func TestBuildManifestBoundsTreeBeforeHashing(t *testing.T) {
	t.Run("unmanifested huge sparse file", func(t *testing.T) {
		target := writeV2Case(t, false)
		path := filepath.Join(target, "unmanifested-sparse")
		file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		if err := file.Truncate(int64(defaultManifestTreeLimits.maxFileBytes + 1)); err != nil {
			_ = file.Close()
			t.Skipf("sparse files are unavailable: %v", err)
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err := VerifyCase(context.Background(), target); err == nil || !strings.Contains(err.Error(), "per-file limit") {
			t.Fatalf("sparse-file error = %v", err)
		}
	})

	t.Run("entry storm", func(t *testing.T) {
		dir := t.TempDir()
		for index := 0; index < 4; index++ {
			if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("entry-%d", index)), []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		limits := manifestTreeLimits{maxEntries: 3, maxDepth: 4, maxFileBytes: 16, maxAggregateByte: 64}
		if _, err := buildManifestWithLimits(context.Background(), dir, limits); err == nil || !strings.Contains(err.Error(), "exceeds 3 entries") {
			t.Fatalf("entry-limit error = %v", err)
		}
	})

	t.Run("depth", func(t *testing.T) {
		dir := t.TempDir()
		deep := filepath.Join(dir, "one", "two")
		if err := os.MkdirAll(deep, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(deep, "file"), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		limits := manifestTreeLimits{maxEntries: 16, maxDepth: 2, maxFileBytes: 16, maxAggregateByte: 64}
		if _, err := buildManifestWithLimits(context.Background(), dir, limits); err == nil || !strings.Contains(err.Error(), "depth limit") {
			t.Fatalf("depth-limit error = %v", err)
		}
	})

	t.Run("aggregate bytes", func(t *testing.T) {
		dir := t.TempDir()
		for _, name := range []string{"one", "two"} {
			if err := os.WriteFile(filepath.Join(dir, name), []byte("123"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		limits := manifestTreeLimits{maxEntries: 4, maxDepth: 2, maxFileBytes: 4, maxAggregateByte: 5}
		if _, err := buildManifestWithLimits(context.Background(), dir, limits); err == nil || !strings.Contains(err.Error(), "aggregate byte limit") {
			t.Fatalf("aggregate-limit error = %v", err)
		}
	})

	t.Run("cancellation", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		limits := manifestTreeLimits{maxEntries: 4, maxDepth: 2, maxFileBytes: 4, maxAggregateByte: 5}
		if _, err := buildManifestWithLimits(ctx, t.TempDir(), limits); !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled traversal error = %v", err)
		}
	})
}

func TestVerifyCaseValidatesLedgerRecordsAndEvidenceEnvelopes(t *testing.T) {
	t.Run("unknown record field", func(t *testing.T) {
		target := writeV2Case(t, true, []byte("raw"))
		mutateFirstLedgerObject(t, target, func(record map[string]any) { record["unexpected"] = true })
		if _, err := VerifyCase(context.Background(), target); err == nil || !strings.Contains(err.Error(), "unknown field") {
			t.Fatalf("unknown record field error = %v", err)
		}
	})

	t.Run("unknown envelope field", func(t *testing.T) {
		target := writeV2Case(t, true, []byte("raw"))
		mutateFirstLedgerObject(t, target, func(record map[string]any) {
			payload := record["payload"].(map[string]any)
			payload["evidence"].(map[string]any)["unexpected"] = true
		})
		if _, err := VerifyCase(context.Background(), target); err == nil || !strings.Contains(err.Error(), "unknown field") {
			t.Fatalf("unknown envelope field error = %v", err)
		}
	})

	t.Run("malformed envelope", func(t *testing.T) {
		target := writeV2Case(t, true, []byte("raw"))
		mutateFirstLedgerObject(t, target, func(record map[string]any) { record["payload"] = map[string]any{} })
		if _, err := VerifyCase(context.Background(), target); err == nil || !strings.Contains(err.Error(), "validate evidence envelope") {
			t.Fatalf("malformed envelope error = %v", err)
		}
	})

	t.Run("duplicate JSON key", func(t *testing.T) {
		target := writeV2Case(t, true, []byte("raw"))
		path := filepath.Join(target, "evidence.jsonl")
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		data = bytes.Replace(data, []byte(`"sequence":1`), []byte(`"sequence":1,"sequence":1`), 1)
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		rewriteManifest(t, target)
		if _, err := VerifyCase(context.Background(), target); err == nil || !strings.Contains(err.Error(), "duplicate key") {
			t.Fatalf("duplicate JSON key error = %v", err)
		}
	})

	t.Run("duplicate observation", func(t *testing.T) {
		target := writeV2Case(t, true, []byte("raw"))
		path := filepath.Join(target, "evidence.jsonl")
		first, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var duplicate map[string]any
		if err := json.Unmarshal(bytes.TrimSpace(first), &duplicate); err != nil {
			t.Fatal(err)
		}
		duplicate["sequence"] = 2
		second, err := json.Marshal(duplicate)
		if err != nil {
			t.Fatal(err)
		}
		data := append(append([]byte(nil), first...), append(second, '\n')...)
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		rewriteManifest(t, target)
		if _, err := VerifyCase(context.Background(), target); err == nil || !strings.Contains(err.Error(), "duplicates observation") {
			t.Fatalf("duplicate observation error = %v", err)
		}
	})

	t.Run("conflicting raw descriptors", func(t *testing.T) {
		target := writeV2Case(t, true, []byte("raw"))
		sum := sha256.Sum256([]byte("raw"))
		raw := v2RawFixture{digest: hex.EncodeToString(sum[:]), bytes: []byte("raw")}
		envelopes := []evidence.Envelope{
			v2RawEnvelope(t, raw, 3, 1),
			v2RawEnvelope(t, raw, 4, 2),
		}
		if err := os.WriteFile(filepath.Join(target, "evidence.jsonl"), v2LedgerEnvelopes(t, envelopes), 0o600); err != nil {
			t.Fatal(err)
		}
		rewriteManifest(t, target)
		if _, err := VerifyCase(context.Background(), target); err == nil || !strings.Contains(err.Error(), "contradictory descriptors") {
			t.Fatalf("descriptor conflict error = %v", err)
		}
	})

	t.Run("compact case tolerates nonmaterialized large raw descriptor", func(t *testing.T) {
		target := writeV2Case(t, false)
		sum := sha256.Sum256([]byte("not-materialized"))
		raw := v2RawFixture{digest: hex.EncodeToString(sum[:]), bytes: []byte("not-materialized")}
		envelope := v2RawEnvelope(t, raw, maxRawObjectBytes+1, 1)
		if err := os.WriteFile(filepath.Join(target, "evidence.jsonl"), v2LedgerEnvelopes(t, []evidence.Envelope{envelope}), 0o600); err != nil {
			t.Fatal(err)
		}
		rewriteManifest(t, target)
		if _, err := VerifyCase(context.Background(), target); err != nil {
			t.Fatalf("compact raw descriptor rejected: %v", err)
		}
	})
}

func mutateFirstLedgerObject(t *testing.T, target string, mutate func(map[string]any)) {
	t.Helper()
	path := filepath.Join(target, "evidence.jsonl")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var record map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(data), &record); err != nil {
		t.Fatal(err)
	}
	mutate(record)
	data, err = json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	data = append(data, '\n')
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	rewriteManifest(t, target)
}
