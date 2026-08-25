package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/torjan0/cirewind/internal/analyze"
	"github.com/torjan0/cirewind/internal/archive"
	"github.com/torjan0/cirewind/internal/casefile"
	"github.com/torjan0/cirewind/internal/demodata"
	"github.com/torjan0/cirewind/internal/graph"
	"github.com/torjan0/cirewind/internal/incident"
	"github.com/torjan0/cirewind/internal/model"
	"github.com/torjan0/cirewind/internal/report"
)

func TestReplayRetainedV1CredentialBasisPreservesCaseAndOmitsOnlyVisualEdge(t *testing.T) {
	for _, test := range []struct {
		name  string
		basis model.CredentialExposureBasis
	}{
		{name: "empty", basis: ""},
		{name: "unrecognized", basis: "removed-basis-v0"},
	} {
		t.Run(test.name, func(t *testing.T) {
			for _, name := range []string{"CIREWIND_GITHUB_TOKEN", "GITHUB_TOKEN", "GH_TOKEN"} {
				t.Setenv(name, "synthetic-token-must-never-be-observed")
			}
			t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
			t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
			t.Setenv("NO_PROXY", "")

			bundle, err := demodata.Bundle(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			pack, err := incident.ValidateReader(context.Background(), bytes.NewReader(bundle.PackYAML))
			if err != nil {
				t.Fatal(err)
			}
			baseline, err := analyze.Derive(bundle.Snapshot, pack, bundle.AnalysisTime, analyze.ModeReplay)
			if err != nil {
				t.Fatal(err)
			}

			retained, exposureEvidence := retainedV1BasisSnapshot(t, bundle.Snapshot, test.basis)
			root := t.TempDir()
			archivePath := filepath.Join(root, "archive.db")
			archiveStore, err := archive.Import(context.Background(), archivePath, retained)
			if err != nil {
				t.Fatal(err)
			}
			if err := archiveStore.Close(); err != nil {
				t.Fatal(err)
			}
			before := fileSHA256(t, archivePath)
			packPath := filepath.Join(root, "incident.yaml")
			if err := os.WriteFile(packPath, bundle.PackYAML, 0o600); err != nil {
				t.Fatal(err)
			}
			output := filepath.Join(root, "case")
			var stdout, stderr bytes.Buffer
			if err := runReplay(context.Background(), []string{
				"--archive", archivePath, "--incident", packPath, "--out", output,
				"--fixed-collection-time", bundle.AnalysisTime.Format("2006-01-02T15:04:05Z07:00"),
			}, &stdout, &stderr); err != nil {
				t.Fatalf("replay retained basis %q: %v\nstderr=%s", test.basis, err, stderr.String())
			}
			if strings.Contains(stdout.String()+stderr.String(), "synthetic-token-must-never-be-observed") {
				t.Fatal("replay printed authentication material")
			}
			if got := fileSHA256(t, archivePath); got != before {
				t.Fatalf("read-only replay changed source archive hash: before=%s after=%s", before, got)
			}
			if err := casefile.VerifyManifest(context.Background(), output); err != nil {
				t.Fatal(err)
			}

			var findingsEnvelope struct {
				SchemaVersion string           `json:"schemaVersion"`
				Findings      []report.Finding `json:"findings"`
			}
			readJSONFile(t, filepath.Join(output, "findings.json"), &findingsEnvelope)
			actualCase := report.Case{Findings: findingsEnvelope.Findings}
			if len(actualCase.Findings) != len(baseline.Case.Findings) || actualCase.Counts() != baseline.Case.Counts() {
				t.Fatalf("legacy replay changed canonical findings/counts: findings=%d/%d counts=%+v/%+v", len(actualCase.Findings), len(baseline.Case.Findings), actualCase.Counts(), baseline.Case.Counts())
			}
			wantPresentationBasis := string(test.basis)
			if test.basis == "" {
				wantPresentationBasis = report.RetainedLegacyUnclassifiedBasis
			}
			var preservedRevision string
			for _, finding := range actualCase.Findings {
				for _, exposure := range finding.CredentialExposure {
					if exposure.Kind == string(model.ExposureSecretPassedToStep) && exposure.Basis == wantPresentationBasis {
						preservedRevision = finding.FindingRevisionID
					}
				}
			}
			if preservedRevision == "" {
				t.Fatalf("retained exposure basis %q was absent from canonical findings as %q", test.basis, wantPresentationBasis)
			}

			var projected graph.GraphV2
			readJSONFile(t, filepath.Join(output, "graph.json"), &projected)
			if err := projected.NormalizeAndValidate(); err != nil {
				t.Fatal(err)
			}
			if len(projected.ProjectionNotices) != 1 {
				t.Fatalf("projection notices=%#v", projected.ProjectionNotices)
			}
			notice := projected.ProjectionNotices[0]
			if notice.Code != graph.ProjectionNoticeUnclassifiableLegacyBasis || notice.Relationship != graph.EdgePassedSecretTo || notice.FindingRevisionID != preservedRevision || !reflect.DeepEqual(notice.EvidenceIDs, []string{exposureEvidence}) {
				t.Fatalf("projection notice=%#v", notice)
			}
			missing := graphEdgeDifference(baseline.Case.GraphV2.Edges, projected.Edges)
			if len(missing) != 1 || missing[0].Type != graph.EdgePassedSecretTo {
				t.Fatalf("legacy projection omitted more than the unsupported edge: %#v", missing)
			}
			if extra := graphEdgeDifference(projected.Edges, baseline.Case.GraphV2.Edges); len(extra) != 0 {
				t.Fatalf("legacy projection invented edges: %#v", extra)
			}

			for _, name := range []string{"graph.svg", "report.html"} {
				data, err := os.ReadFile(filepath.Join(output, name))
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Contains(data, []byte("visual relationship omitted")) || !bytes.Contains(data, []byte(preservedRevision)) {
					t.Fatalf("%s lacks the scoped legacy projection notice or complete finding", name)
				}
			}
		})
	}
}

func retainedV1BasisSnapshot(t *testing.T, source archive.Snapshot, basis model.CredentialExposureBasis) (archive.Snapshot, string) {
	t.Helper()
	clone := source
	clone.Facts = append([]archive.Fact(nil), source.Facts...)
	var evidenceID string
	for index := range clone.Facts {
		fact := clone.Facts[index]
		if fact.Exposure == nil || fact.Exposure.Credential == nil || fact.Exposure.Credential.Kind != model.ExposureSecretPassedToStep {
			continue
		}
		exposure := *fact.Exposure
		credential := *exposure.Credential
		credential.EvidenceIDs = append([]model.EvidenceID(nil), credential.EvidenceIDs...)
		credential.Basis = basis
		exposure.Credential = &credential
		fact.Exposure = &exposure
		fact.ID = ""
		var err error
		fact, err = archive.NormalizeRetainedV1Fact(fact)
		if err != nil {
			t.Fatal(err)
		}
		clone.Facts[index] = fact
		evidenceID = string(credential.EvidenceIDs[0])
		break
	}
	if evidenceID == "" {
		t.Fatal("synthetic fixture lacks direct secret exposure")
	}
	encoded, err := json.Marshal(clone)
	if err != nil {
		t.Fatal(err)
	}
	retained, err := archive.DecodeSnapshot(bytes.NewReader(encoded))
	if err != nil {
		t.Fatal(err)
	}
	if !archive.HasRetainedLegacyCredentialBasis(retained) {
		t.Fatal("decoded retained snapshot lacks compatibility marker")
	}
	return retained, evidenceID
}

func fileSHA256(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func graphEdgeDifference(left, right []graph.EdgeV2) []graph.EdgeV2 {
	present := make(map[string]bool, len(right))
	for _, edge := range right {
		present[edge.ID] = true
	}
	var result []graph.EdgeV2
	for _, edge := range left {
		if !present[edge.ID] {
			result = append(result, edge)
		}
	}
	return result
}
