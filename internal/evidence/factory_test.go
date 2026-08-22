package evidence

import (
	"strings"
	"testing"
	"time"

	"github.com/torjan0/cirewind/internal/model"
)

func TestNewEnvelopeHashesWithoutRetainingRaw(t *testing.T) {
	when := model.MustInstant(time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC))
	repo := model.RepositoryID(1)
	envelope, err := NewEnvelope(EnvelopeInput{
		Kind: SourceAPIJSON, CanonicalSourceID: "repos/acme/service/actions/runs/1", Provider: ProviderGitHub,
		APIVersion: "2026-03-10", EndpointTemplate: "/repos/{owner}/{repo}/actions/runs/{run_id}",
		RequestParameters: RequestParameters{"owner": "acme", "repo": "service", "run_id": "1"},
		Scope:             model.CoverageScope{RepositoryID: &repo}, MediaType: "application/json", SourceBytes: []byte(`{"id":1}`), Complete: true,
		Extractor:         ExtractorDescriptor{Name: "github-api", Version: "test", RulesetSHA256: strings.Repeat("1", 64)},
		Redaction:         RedactionDescriptor{Status: RedactionNotInspected, PolicyVersion: "discard-raw-v1"},
		CollectionSession: "collection:test", RequestID: "request:test", CollectionTime: model.CollectionWindow{StartedAt: when, EndedAt: when},
	})
	if err != nil {
		t.Fatal(err)
	}
	if envelope.Evidence.Content.RawRetained || envelope.Evidence.Content.RetainedPath != "" || envelope.Evidence.Content.SourceSHA256 == strings.Repeat("0", 64) {
		t.Fatalf("unexpected retention: %#v", envelope.Evidence.Content)
	}
}

func TestNewEnvelopeIncompleteRequiresTypedError(t *testing.T) {
	when := model.MustInstant(time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC))
	_, err := NewEnvelope(EnvelopeInput{
		Kind: SourceOtherBounded, CanonicalSourceID: "missing", Provider: ProviderCIRewind,
		Scope: model.CoverageScope{}, MediaType: "application/octet-stream", SourceBytes: []byte{}, Complete: false,
		Extractor:         ExtractorDescriptor{Name: "fixture", Version: "test", RulesetSHA256: strings.Repeat("1", 64)},
		Redaction:         RedactionDescriptor{Status: RedactionNotApplicable, PolicyVersion: "none-v1"},
		CollectionSession: "collection:test", RequestID: "request:test", CollectionTime: model.CollectionWindow{StartedAt: when, EndedAt: when},
	})
	if err == nil {
		t.Fatal("accepted incomplete evidence without error")
	}
}
