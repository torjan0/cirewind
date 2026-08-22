package livecollect

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/torjan0/cirewind/internal/archive"
	"github.com/torjan0/cirewind/internal/collect"
	"github.com/torjan0/cirewind/internal/evidence"
	"github.com/torjan0/cirewind/internal/githubapi"
	"github.com/torjan0/cirewind/internal/logparse"
	"github.com/torjan0/cirewind/internal/model"
)

type historicalExactAPI struct {
	*fakeAPI
	content         map[string][]byte
	errors          map[string]error
	hashErrors      map[string]error
	hashValues      map[string]string
	hashCalls       map[string]int
	peelResults     map[string]githubapi.GitObjectPeel
	peelErrors      map[string]error
	peelCalls       []historicalPeelCall
	attemptLogError error
	calls           []historicalContentCall
}

type historicalContentCall struct {
	repository string
	path       string
	object     githubapi.GitObjectID
}

type historicalPeelCall struct {
	repository string
	object     githubapi.GitObjectID
}

// historicalExactWithoutPeeler deliberately exposes exact content without
// promoting historicalExactAPI's peel method through the dynamic API value.
type historicalExactWithoutPeeler struct {
	API
	content ExactContentAPI
}

func (a historicalExactWithoutPeeler) GetContentAtObject(ctx context.Context, owner, repository, contentPath string, object githubapi.GitObjectID) (githubapi.ObjectResult[githubapi.Content], error) {
	return a.content.GetContentAtObject(ctx, owner, repository, contentPath, object)
}

func (a *historicalExactAPI) GetContentAtObject(_ context.Context, owner, repository, contentPath string, object githubapi.GitObjectID) (githubapi.ObjectResult[githubapi.Content], error) {
	call := historicalContentCall{repository: strings.ToLower(owner + "/" + repository), path: contentPath, object: object}
	a.calls = append(a.calls, call)
	key := call.repository + "\x00" + contentPath + "\x00" + object.Algorithm + "\x00" + object.Value
	if err := a.errors[key]; err != nil {
		return githubapi.ObjectResult[githubapi.Content]{}, err
	}
	data, ok := a.content[key]
	if !ok {
		return githubapi.ObjectResult[githubapi.Content]{}, &githubapi.Error{Class: githubapi.ErrorNotFound, Operation: "get repository content", StatusCode: 404, Message: "not found"}
	}
	return githubapi.ObjectResult[githubapi.Content]{Value: githubapi.Content{
		Type: "file", Encoding: "base64", Size: int64(len(data)), Path: contentPath,
		SHA: strings.Repeat("9", 40), Content: base64.StdEncoding.EncodeToString(data),
	}}, nil
}

func (a *historicalExactAPI) GetRepositoryHashAlgorithm(ctx context.Context, owner, repository string) (githubapi.ObjectResult[string], error) {
	slug := strings.ToLower(owner + "/" + repository)
	a.mu.Lock()
	a.hashCalls[slug]++
	a.mu.Unlock()
	if err := a.hashErrors[slug]; err != nil {
		return githubapi.ObjectResult[string]{}, err
	}
	if value := a.hashValues[slug]; value != "" {
		return githubapi.ObjectResult[string]{Value: value}, nil
	}
	return a.fakeAPI.GetRepositoryHashAlgorithm(ctx, owner, repository)
}

func (a *historicalExactAPI) PeelGitObjectToCommit(_ context.Context, owner, repository string, object githubapi.GitObjectID) (githubapi.GitObjectPeel, error) {
	call := historicalPeelCall{repository: strings.ToLower(owner + "/" + repository), object: object}
	key := call.repository + "\x00" + object.Algorithm + "\x00" + object.Value
	a.mu.Lock()
	a.peelCalls = append(a.peelCalls, call)
	configured, ok := a.peelResults[key]
	configuredErr := a.peelErrors[key]
	a.mu.Unlock()
	if ok || configuredErr != nil {
		return configured, configuredErr
	}
	length := 40
	if object.Algorithm == "sha256" {
		length = 64
	}
	commit := githubapi.GitCommitObject{
		CommitObjectID:  object,
		TreeObjectID:    githubapi.GitObjectID{Algorithm: object.Algorithm, Value: strings.Repeat("d", length)},
		ParentObjectIDs: []githubapi.GitObjectID{},
	}
	return githubapi.GitObjectPeel{
		RecordedObjectID: object,
		RecordedKind:     githubapi.GitObjectCommit,
		TagObjects:       []githubapi.GitTagObject{},
		CommitObject:     &commit,
		Responses:        []githubapi.ResponseMeta{positiveGitObjectResponse("commit", object)},
	}, nil
}

func (a *historicalExactAPI) putPeel(repository string, object githubapi.GitObjectID, result githubapi.GitObjectPeel, err error) {
	key := strings.ToLower(repository) + "\x00" + object.Algorithm + "\x00" + object.Value
	a.peelResults[key] = result
	if err != nil {
		a.peelErrors[key] = err
	}
}

func positiveGitObjectResponse(kind string, object githubapi.GitObjectID) githubapi.ResponseMeta {
	route := "/repos/{owner}/{repo}/git/commits/{commit_sha}"
	algorithmKey, objectKey := "commit_algorithm", "commit_sha"
	if kind == "tag" {
		route = "/repos/{owner}/{repo}/git/tags/{tag_sha}"
		algorithmKey, objectKey = "tag_algorithm", "tag_sha"
	}
	return githubapi.ResponseMeta{
		Method: "GET", RouteTemplate: route,
		RequestParameters: map[string]string{algorithmKey: object.Algorithm, objectKey: object.Value},
		StatusCode:        200, APIVersion: githubapi.APIVersion, MediaType: "application/json", ByteLength: 2,
		SHA256: strings.Repeat("a", 64), BodyComplete: true,
	}
}

func (a *historicalExactAPI) DownloadAttemptLogs(ctx context.Context, owner, repository string, runID int64, attempt int, writer io.Writer) (githubapi.DownloadResult, error) {
	if a.attemptLogError != nil {
		return githubapi.DownloadResult{}, a.attemptLogError
	}
	return a.fakeAPI.DownloadAttemptLogs(ctx, owner, repository, runID, attempt, writer)
}

func (a *historicalExactAPI) put(repository, contentPath, algorithm, object string, data []byte) {
	a.content[strings.ToLower(repository)+"\x00"+contentPath+"\x00"+algorithm+"\x00"+object] = data
}

func (a *historicalExactAPI) fail(repository, contentPath, algorithm, object string, err error) {
	a.errors[strings.ToLower(repository)+"\x00"+contentPath+"\x00"+algorithm+"\x00"+object] = err
}

func newHistoricalExactAPI(t *testing.T) *historicalExactAPI {
	api := &historicalExactAPI{
		fakeAPI: successfulAPI(t, false), content: make(map[string][]byte), errors: make(map[string]error),
		hashErrors: make(map[string]error), hashValues: make(map[string]string), hashCalls: make(map[string]int),
		peelResults: make(map[string]githubapi.GitObjectPeel), peelErrors: make(map[string]error),
	}
	api.put("acme/service", ".github/workflows/ci.yml", "sha1", api.attempts[10][1].HeadSHA, []byte("on: push\njobs:\n  noop:\n    runs-on: ubuntu-latest\n    steps: []\n"))
	return api
}

func historicalTarget(api *historicalExactAPI) repositoryWork {
	repository := api.repositories[0]
	return repositoryWork{repository: repository, slug: "acme/service", owner: "acme", name: "service"}
}

func historicalBundle(api *historicalExactAPI) collect.AttemptBundle {
	return collect.AttemptBundle{Attempt: 1, Run: api.attempts[10][1], Jobs: append([]githubapi.WorkflowJob(nil), api.jobs[10][1]...)}
}

func setHistoricalAttempt(api *historicalExactAPI, mutate func(*githubapi.WorkflowRun)) {
	value := api.attempts[10][1]
	mutate(&value)
	api.attempts[10][1] = value
}

func historicalEvidence(char byte) model.EvidenceID {
	return model.EvidenceID("ev1:" + strings.Repeat(string(char), 64))
}

func historicalSession() model.CollectionSessionID { return "collection:historical-test" }

func TestHistoricalResolutionUsesRecordedCalledSHAAndPreservesContradiction(t *testing.T) {
	api := newHistoricalExactAPI(t)
	calledSHA := testCalledSHA
	declaredSHA := strings.Repeat("1", 40)
	runtimeSHA := strings.Repeat("2", 40)
	setHistoricalAttempt(api, func(value *githubapi.WorkflowRun) {
		value.HeadSHA = strings.Repeat("f", 40)
		value.ReferencedWorkflows = []githubapi.ReferencedWorkflow{{Path: "acme/shared/.github/workflows/reuse.yml@v3", Ref: "v3", SHA: calledSHA}}
	})
	api.put("acme/service", ".github/workflows/ci.yml", "sha1", api.attempts[10][1].HeadSHA, []byte("on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: fixture/child@"+declaredSHA+"\n"))
	api.put("acme/shared", ".github/workflows/reuse.yml", "sha1", calledSHA, []byte("on: workflow_call\njobs:\n  build:\n    steps:\n      - uses: fixture/child@"+declaredSHA+"\n"))
	api.put("fixture/child", "action.yml", "sha1", runtimeSHA, []byte("runs:\n  using: node20\n  main: dist/index.js\n"))

	setupEvidence, attemptEvidence := historicalEvidence('1'), historicalEvidence('2')
	setup := map[int64]map[string][]setupResolution{20: {
		"fixture/child@" + declaredSHA: {{action: logparse.Action{Owner: "fixture", Repository: "child", Ref: declaredSHA, Source: logparse.GitObject{Algorithm: "sha1", Value: runtimeSHA}}, evidenceIDs: []model.EvidenceID{setupEvidence}}},
	}}
	result := repositoryResult{}
	collector := Collector{API: api}
	if err := collector.resolveHistoricalAttempt(context.Background(), historicalTarget(api), 10, historicalBundle(api), historicalSession(), fixedClock(time.Date(2026, 8, 20, 3, 0, 0, 0, time.UTC)), setup, attemptEvidence, &result); err != nil {
		t.Fatal(err)
	}

	var staticID string
	var contradiction, calledFact bool
	for _, fact := range result.facts {
		normalized, err := archive.NormalizeFact(fact)
		if err != nil {
			t.Fatalf("invalid historical fact: %v\n%+v", err, fact)
		}
		if normalized.Dependency == nil {
			continue
		}
		dependency := normalized.Dependency
		if dependency.Relation == archive.DependencyWorkflowDeclaredAction && dependency.TargetActionObjectID != nil && model.GitObjectID(*dependency.TargetActionObjectID).Value == declaredSHA {
			staticID = normalized.ID
		}
		if dependency.Relation == archive.DependencyRefResolvedTo && dependency.TargetActionObjectID != nil && model.GitObjectID(*dependency.TargetActionObjectID).Value == runtimeSHA && len(dependency.ContradictsFactIDs) == 1 {
			contradiction = true
		}
		if dependency.Basis == archive.DefinitionRuntimeAttemptMetadata && dependency.TargetCalledWorkflowObjectID != nil && model.GitObjectID(*dependency.TargetCalledWorkflowObjectID).Value == calledSHA {
			calledFact = true
		}
	}
	if staticID == "" || !contradiction || !calledFact {
		t.Fatalf("historical facts incomplete: static=%q contradiction=%v called=%v", staticID, contradiction, calledFact)
	}
	callerFetched := false
	for _, call := range api.calls {
		if call.repository == "acme/service" && call.path == ".github/workflows/ci.yml" {
			callerFetched = callerFetched || call.object.Value == api.attempts[10][1].HeadSHA
		}
		if call.repository == "acme/shared" && call.object.Value != calledSHA {
			t.Fatalf("called workflow was not fetched at GitHub-recorded SHA: %+v", call)
		}
	}
	if !callerFetched {
		t.Fatal("documented push-event caller workflow was not fetched at its event-specific candidate SHA")
	}
}

func TestHistoricalResolutionPeelsAnnotatedCalledWorkflowWithoutOverwritingRecordedObject(t *testing.T) {
	api := newHistoricalExactAPI(t)
	recordedTag := strings.Repeat("a", 40)
	peeledCommit := strings.Repeat("b", 40)
	tree := strings.Repeat("c", 40)
	setHistoricalAttempt(api, func(value *githubapi.WorkflowRun) {
		value.ReferencedWorkflows = []githubapi.ReferencedWorkflow{{Path: "acme/shared/.github/workflows/reuse.yml@v3", Ref: "refs/tags/v3", SHA: recordedTag}}
	})
	callerCommit := api.attempts[10][1].HeadSHA
	api.put("acme/service", ".github/workflows/ci.yml", "sha1", callerCommit, []byte("on: push\njobs:\n  reuse:\n    uses: acme/shared/.github/workflows/reuse.yml@v3\n"))
	api.put("acme/shared", ".github/workflows/reuse.yml", "sha1", peeledCommit, []byte("on: workflow_call\njobs:\n  noop:\n    runs-on: ubuntu-latest\n    steps: []\n"))
	recordedObject := githubapi.GitObjectID{Algorithm: "sha1", Value: recordedTag}
	commitObject := githubapi.GitObjectID{Algorithm: "sha1", Value: peeledCommit}
	api.putPeel("acme/shared", recordedObject, githubapi.GitObjectPeel{
		RecordedObjectID: recordedObject,
		RecordedKind:     githubapi.GitObjectTag,
		TagObjects: []githubapi.GitTagObject{{
			TagObjectID: recordedObject, TagName: "v3",
			Target: githubapi.GitObjectTarget{Kind: githubapi.GitObjectCommit, ObjectID: commitObject},
		}},
		CommitObject: &githubapi.GitCommitObject{
			CommitObjectID:  commitObject,
			TreeObjectID:    githubapi.GitObjectID{Algorithm: "sha1", Value: tree},
			ParentObjectIDs: []githubapi.GitObjectID{},
		},
		Responses: []githubapi.ResponseMeta{positiveGitObjectResponse("tag", recordedObject), positiveGitObjectResponse("commit", commitObject)},
	}, nil)

	attemptEvidence := historicalEvidence('d')
	result := repositoryResult{}
	if err := (Collector{API: api}).resolveHistoricalAttempt(context.Background(), historicalTarget(api), 10, historicalBundle(api), historicalSession(), fixedClock(time.Date(2026, 8, 20, 3, 0, 0, 0, time.UTC)), nil, attemptEvidence, &result); err != nil {
		t.Fatal(err)
	}
	if len(result.called) != 1 || model.GitObjectID(result.called[0].CalledObjectID).Value != recordedTag || result.called[0].DeclaredRef != "v3" || result.called[0].RecordedRef != "refs/tags/v3" {
		t.Fatalf("GitHub-recorded called object was not preserved: %+v", result.called)
	}

	var recordedFact, peeledBinding bool
	var peelEvidence model.EvidenceID
	for _, envelope := range result.evidence {
		if strings.Contains(envelope.Evidence.LogicalSource.CanonicalID, "called-workflow-object-peel") {
			peelEvidence = envelope.Evidence.ID
		}
	}
	for _, fact := range result.facts {
		if fact.Dependency == nil || fact.Dependency.TargetCalledWorkflowObjectID == nil {
			continue
		}
		object := model.GitObjectID(*fact.Dependency.TargetCalledWorkflowObjectID)
		if fact.Dependency.Basis == archive.DefinitionRuntimeAttemptMetadata && object.Value == recordedTag {
			recordedFact = fact.Dependency.AttemptExecution != nil && fact.Dependency.CallerWorkflowObjectID == nil
		}
		if fact.Dependency.Relation == archive.DependencyRefResolvedTo && object.Value == peeledCommit {
			peeledBinding = fact.Dependency.AttemptExecution != nil && fact.Dependency.CallerWorkflowObjectID != nil && containsEvidenceID(fact.EvidenceIDs, peelEvidence)
		}
	}
	if peelEvidence == "" || !recordedFact || !peeledBinding {
		t.Fatalf("annotated called-workflow evidence incomplete: peel=%q recorded=%v binding=%v", peelEvidence, recordedFact, peeledBinding)
	}
	for _, call := range api.calls {
		if call.repository != "acme/shared" {
			continue
		}
		if call.object.Value == recordedTag {
			t.Fatalf("annotated tag object was used as a content commit: %+v", call)
		}
		if call.object.Value != peeledCommit {
			t.Fatalf("called workflow content used an unexpected object: %+v", call)
		}
	}
	var projectionPreservedBoth bool
	for _, payload := range result.payloads {
		value := string(payload.Bytes)
		projectionPreservedBoth = projectionPreservedBoth || (strings.Contains(value, `"schema":"cirewind.github-called-workflow-object-peel-projection/v1"`) && strings.Contains(value, recordedTag) && strings.Contains(value, peeledCommit) && strings.Contains(value, `"complete":true`))
	}
	if !projectionPreservedBoth {
		t.Fatal("compact peel projection did not preserve recorded tag and terminal commit")
	}
}

func TestHistoricalResolutionWithholdsBindingWhenPathLiteralAndRecordedRefDisagree(t *testing.T) {
	api := newHistoricalExactAPI(t)
	commit := strings.Repeat("6", 40)
	setHistoricalAttempt(api, func(value *githubapi.WorkflowRun) {
		value.ReferencedWorkflows = []githubapi.ReferencedWorkflow{{Path: "acme/shared/.github/workflows/reuse.yml@v3", Ref: "refs/tags/v4", SHA: commit}}
	})
	api.put("acme/service", ".github/workflows/ci.yml", "sha1", api.attempts[10][1].HeadSHA, []byte("on: push\njobs:\n  reuse:\n    uses: acme/shared/.github/workflows/reuse.yml@v3\n"))
	api.put("acme/shared", ".github/workflows/reuse.yml", "sha1", commit, []byte("on: workflow_call\njobs:\n  noop:\n    runs-on: ubuntu-latest\n    steps: []\n"))
	result := repositoryResult{}
	if err := (Collector{API: api}).resolveHistoricalAttempt(context.Background(), historicalTarget(api), 10, historicalBundle(api), historicalSession(), fixedClock(time.Date(2026, 8, 20, 3, 0, 0, 0, time.UTC)), nil, historicalEvidence('f'), &result); err != nil {
		t.Fatal(err)
	}
	if len(result.called) != 1 || result.called[0].DeclaredRef != "v3" || result.called[0].RecordedRef != "refs/tags/v4" || model.GitObjectID(result.called[0].CalledObjectID).Value != commit {
		t.Fatalf("distinct ref fields or recorded object were lost: %+v", result.called)
	}
	var recorded, bound, incompatibleGap, fetchedExactDefinition bool
	for _, fact := range result.facts {
		if fact.Dependency == nil || fact.Dependency.TargetCalledWorkflowObjectID == nil {
			continue
		}
		object := model.GitObjectID(*fact.Dependency.TargetCalledWorkflowObjectID)
		recorded = recorded || (fact.Dependency.Basis == archive.DefinitionRuntimeAttemptMetadata && object.Value == commit && fact.Dependency.DeclaredRef == "v3")
		bound = bound || fact.Dependency.Relation == archive.DependencyRefResolvedTo
	}
	for _, gap := range result.gaps {
		incompatibleGap = incompatibleGap || (gap.Scope == "called_workflow_metadata" && gap.Reason == collect.GapValidation && strings.Contains(gap.Diagnostic, "incompatible"))
	}
	for _, call := range api.calls {
		fetchedExactDefinition = fetchedExactDefinition || (call.repository == "acme/shared" && call.object.Value == commit)
	}
	if !recorded || bound || !incompatibleGap || !fetchedExactDefinition {
		t.Fatalf("incompatible ref semantics: recorded=%v bound=%v gap=%v exact_definition=%v", recorded, bound, incompatibleGap, fetchedExactDefinition)
	}
}

func TestHistoricalResolutionPreservesRecordedCallWhenAdapterCannotPeel(t *testing.T) {
	api := newHistoricalExactAPI(t)
	recorded := strings.Repeat("7", 40)
	setHistoricalAttempt(api, func(value *githubapi.WorkflowRun) {
		value.ReferencedWorkflows = []githubapi.ReferencedWorkflow{{Path: "acme/shared/.github/workflows/reuse.yml@v3", Ref: "refs/tags/v3", SHA: recorded}}
	})
	wrapped := historicalExactWithoutPeeler{API: api.fakeAPI, content: api}
	result := repositoryResult{}
	if err := (Collector{API: wrapped}).resolveHistoricalAttempt(context.Background(), historicalTarget(api), 10, historicalBundle(api), historicalSession(), fixedClock(time.Date(2026, 8, 20, 3, 0, 0, 0, time.UTC)), nil, historicalEvidence('8'), &result); err != nil {
		t.Fatal(err)
	}
	if len(result.called) != 1 || model.GitObjectID(result.called[0].CalledObjectID).Value != recorded {
		t.Fatalf("recorded call was lost without peel capability: %+v", result.called)
	}
	var recordedFact, capabilityGap bool
	for _, fact := range result.facts {
		recordedFact = recordedFact || (fact.Dependency != nil && fact.Dependency.Basis == archive.DefinitionRuntimeAttemptMetadata && fact.Dependency.TargetCalledWorkflowObjectID != nil && model.GitObjectID(*fact.Dependency.TargetCalledWorkflowObjectID).Value == recorded)
	}
	for _, gap := range result.gaps {
		capabilityGap = capabilityGap || (gap.Scope == "called_workflow_definition" && gap.Reason == collect.GapValidation && strings.Contains(gap.Diagnostic, "positive"))
	}
	if !recordedFact || !capabilityGap || len(api.peelCalls) != 0 {
		t.Fatalf("missing-peeler semantics: recorded=%v gap=%v peel_calls=%d", recordedFact, capabilityGap, len(api.peelCalls))
	}
}

func TestHistoricalResolutionWithholdsCalledWorkflowContentOnPeelFailures(t *testing.T) {
	for _, test := range []struct {
		name       string
		result     func(githubapi.GitObjectID) githubapi.GitObjectPeel
		err        error
		wantReason collect.GapReason
	}{
		{
			name: "cycle returned by bounded peeler",
			result: func(recorded githubapi.GitObjectID) githubapi.GitObjectPeel {
				second := githubapi.GitObjectID{Algorithm: "sha1", Value: strings.Repeat("2", 40)}
				return githubapi.GitObjectPeel{RecordedObjectID: recorded, RecordedKind: githubapi.GitObjectTag, TagObjects: []githubapi.GitTagObject{
					{TagObjectID: recorded, TagName: "outer", Target: githubapi.GitObjectTarget{Kind: githubapi.GitObjectTag, ObjectID: second}},
					{TagObjectID: second, TagName: "inner", Target: githubapi.GitObjectTarget{Kind: githubapi.GitObjectTag, ObjectID: recorded}},
				}, Responses: []githubapi.ResponseMeta{positiveGitObjectResponse("tag", recorded), positiveGitObjectResponse("tag", second)}}
			},
			err:        errors.New("Git tag peel cycle detected"),
			wantReason: collect.GapValidation,
		},
		{
			name: "successful adapter response changes recorded identity",
			result: func(recorded githubapi.GitObjectID) githubapi.GitObjectPeel {
				other := githubapi.GitObjectID{Algorithm: "sha1", Value: strings.Repeat("3", 40)}
				commit := githubapi.GitCommitObject{CommitObjectID: other, TreeObjectID: githubapi.GitObjectID{Algorithm: "sha1", Value: strings.Repeat("4", 40)}, ParentObjectIDs: []githubapi.GitObjectID{}}
				return githubapi.GitObjectPeel{RecordedObjectID: other, RecordedKind: githubapi.GitObjectCommit, TagObjects: []githubapi.GitTagObject{}, CommitObject: &commit, Responses: []githubapi.ResponseMeta{positiveGitObjectResponse("commit", other)}}
			},
			wantReason: collect.GapMalformedResponse,
		},
		{
			name: "adapter exceeds tag depth",
			result: func(recorded githubapi.GitObjectID) githubapi.GitObjectPeel {
				tags := make([]githubapi.GitTagObject, maxHistoricalPeelTags+1)
				responses := make([]githubapi.ResponseMeta, 0, len(tags)+1)
				current := recorded
				for index := range tags {
					next := githubapi.GitObjectID{Algorithm: "sha1", Value: fmt.Sprintf("%040x", index+16)}
					kind := githubapi.GitObjectTag
					if index == len(tags)-1 {
						kind = githubapi.GitObjectCommit
					}
					tags[index] = githubapi.GitTagObject{TagObjectID: current, TagName: fmt.Sprintf("tag-%d", index), Target: githubapi.GitObjectTarget{Kind: kind, ObjectID: next}}
					responses = append(responses, positiveGitObjectResponse("tag", current))
					current = next
				}
				commit := githubapi.GitCommitObject{CommitObjectID: current, TreeObjectID: githubapi.GitObjectID{Algorithm: "sha1", Value: strings.Repeat("5", 40)}, ParentObjectIDs: []githubapi.GitObjectID{}}
				responses = append(responses, positiveGitObjectResponse("commit", current))
				return githubapi.GitObjectPeel{RecordedObjectID: recorded, RecordedKind: githubapi.GitObjectTag, TagObjects: tags, CommitObject: &commit, Responses: responses}
			},
			wantReason: collect.GapMalformedResponse,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			api := newHistoricalExactAPI(t)
			recorded := githubapi.GitObjectID{Algorithm: "sha1", Value: strings.Repeat("1", 40)}
			setHistoricalAttempt(api, func(value *githubapi.WorkflowRun) {
				value.ReferencedWorkflows = []githubapi.ReferencedWorkflow{{Path: "acme/shared/.github/workflows/reuse.yml@v3", Ref: "v3", SHA: recorded.Value}}
			})
			api.put("acme/service", ".github/workflows/ci.yml", "sha1", api.attempts[10][1].HeadSHA, []byte("on: push\njobs:\n  reuse:\n    uses: acme/shared/.github/workflows/reuse.yml@v3\n"))
			api.putPeel("acme/shared", recorded, test.result(recorded), test.err)
			result := repositoryResult{}
			if err := (Collector{API: api}).resolveHistoricalAttempt(context.Background(), historicalTarget(api), 10, historicalBundle(api), historicalSession(), fixedClock(time.Date(2026, 8, 20, 3, 0, 0, 0, time.UTC)), nil, historicalEvidence('e'), &result); err != nil {
				t.Fatal(err)
			}
			if len(result.called) != 1 || model.GitObjectID(result.called[0].CalledObjectID).Value != recorded.Value {
				t.Fatalf("recorded object was lost after peel failure: %+v", result.called)
			}
			for _, call := range api.calls {
				if call.repository == "acme/shared" {
					t.Fatalf("unvalidated peeled object was used for content retrieval: %+v", call)
				}
			}
			var gapFound, incompleteProjection bool
			for _, gap := range result.gaps {
				gapFound = gapFound || (gap.Scope == "called_workflow_definition" && gap.Reason == test.wantReason)
			}
			for _, payload := range result.payloads {
				value := string(payload.Bytes)
				incompleteProjection = incompleteProjection || (strings.Contains(value, `"schema":"cirewind.github-called-workflow-object-peel-projection/v1"`) && strings.Contains(value, `"complete":false`))
			}
			if !gapFound || !incompleteProjection {
				t.Fatalf("peel failure was not explicit: gap=%v projection=%v", gapFound, incompleteProjection)
			}
		})
	}
}

func containsEvidenceID(values []model.EvidenceID, want model.EvidenceID) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func TestHistoricalResolutionRecursesCompositeWithExactSameJobBindings(t *testing.T) {
	api := newHistoricalExactAPI(t)
	setHistoricalAttempt(api, func(value *githubapi.WorkflowRun) { value.ReferencedWorkflows = nil })
	wrapperSHA, childSHA := strings.Repeat("3", 40), strings.Repeat("4", 40)
	api.put("fixture/wrapper", "action.yml", "sha1", wrapperSHA, []byte("runs:\n  using: composite\n  steps:\n    - uses: fixture/child@v1\n"))
	api.put("fixture/child", "action.yml", "sha1", childSHA, []byte("runs:\n  using: node20\n  main: dist/index.js\n"))
	evidenceID := historicalEvidence('3')
	setup := map[int64]map[string][]setupResolution{20: {
		"fixture/wrapper@v1": {{action: logparse.Action{Owner: "fixture", Repository: "wrapper", Ref: "v1", Source: logparse.GitObject{Algorithm: "sha1", Value: wrapperSHA}}, evidenceIDs: []model.EvidenceID{evidenceID}}},
		"fixture/child@v1":   {{action: logparse.Action{Owner: "fixture", Repository: "child", Ref: "v1", Source: logparse.GitObject{Algorithm: "sha1", Value: childSHA}}, evidenceIDs: []model.EvidenceID{evidenceID}}},
	}}
	result := repositoryResult{}
	if err := (Collector{API: api}).resolveHistoricalAttempt(context.Background(), historicalTarget(api), 10, historicalBundle(api), historicalSession(), fixedClock(time.Date(2026, 8, 20, 3, 0, 0, 0, time.UTC)), setup, historicalEvidence('4'), &result); err != nil {
		t.Fatal(err)
	}
	var contains, resolved bool
	for _, fact := range result.facts {
		if fact.Dependency == nil || fact.Dependency.TargetRepository != "fixture/child" {
			continue
		}
		contains = contains || fact.Dependency.Relation == archive.DependencyActionContainsAction
		resolved = resolved || (fact.Dependency.Relation == archive.DependencyRefResolvedTo && fact.Dependency.TargetActionObjectID != nil && model.GitObjectID(*fact.Dependency.TargetActionObjectID).Value == childSHA)
	}
	if !contains || !resolved {
		t.Fatalf("composite facts missing: contains=%v resolved=%v", contains, resolved)
	}
}

func TestHistoricalResolutionLeavesLocalWorkspaceBytesUnproven(t *testing.T) {
	api := newHistoricalExactAPI(t)
	setHistoricalAttempt(api, func(value *githubapi.WorkflowRun) {
		value.ReferencedWorkflows = []githubapi.ReferencedWorkflow{{Path: "acme/shared/.github/workflows/reuse.yml@v3", Ref: "v3", SHA: testCalledSHA}}
	})
	api.put("acme/shared", ".github/workflows/reuse.yml", "sha1", testCalledSHA, []byte("on: workflow_call\njobs:\n  build:\n    steps:\n      - uses: ./.github/actions/local\n"))
	result := repositoryResult{}
	if err := (Collector{API: api}).resolveHistoricalAttempt(context.Background(), historicalTarget(api), 10, historicalBundle(api), historicalSession(), fixedClock(time.Date(2026, 8, 20, 3, 0, 0, 0, time.UTC)), nil, historicalEvidence('5'), &result); err != nil {
		t.Fatal(err)
	}
	var local bool
	for _, fact := range result.facts {
		if fact.Dependency != nil && fact.Dependency.TargetKind == archive.DependencyTargetLocalAction {
			local = true
			if fact.Dependency.TargetActionObjectID != nil {
				t.Fatal("local workspace Action was assigned repository bytes")
			}
		}
	}
	var gap bool
	for _, item := range result.gaps {
		gap = gap || strings.Contains(item.Diagnostic, "workspace bytes were not established")
	}
	if !local || !gap {
		t.Fatalf("local uncertainty missing: fact=%v gap=%v", local, gap)
	}
	for _, call := range api.calls {
		if strings.Contains(call.path, ".github/actions/local") {
			t.Fatalf("unproven local workspace path was fetched: %+v", call)
		}
	}
}

func TestHistoricalCompositeResolutionBoundsCyclesAndDepth(t *testing.T) {
	t.Run("cycle", func(t *testing.T) {
		api := newHistoricalExactAPI(t)
		setHistoricalAttempt(api, func(value *githubapi.WorkflowRun) { value.ReferencedWorkflows = nil })
		rootSHA := strings.Repeat("8", 40)
		api.put("fixture/wrapper", "actions/root/action.yml", "sha1", rootSHA, []byte("runs:\n  using: composite\n  steps:\n    - uses: $/actions/root\n"))
		setup := map[int64]map[string][]setupResolution{20: {
			"fixture/wrapper/actions/root@v1": {{action: logparse.Action{Owner: "fixture", Repository: "wrapper", Subpath: "actions/root", Ref: "v1", Source: logparse.GitObject{Algorithm: "sha1", Value: rootSHA}}, evidenceIDs: []model.EvidenceID{historicalEvidence('9')}}},
		}}
		result := repositoryResult{}
		if err := (Collector{API: api}).resolveHistoricalAttempt(context.Background(), historicalTarget(api), 10, historicalBundle(api), historicalSession(), fixedClock(time.Date(2026, 8, 20, 3, 0, 0, 0, time.UTC)), setup, historicalEvidence('a'), &result); err != nil {
			t.Fatal(err)
		}
		var cycleGap bool
		for _, gap := range result.gaps {
			cycleGap = cycleGap || strings.Contains(gap.Diagnostic, "RESOLUTION_CYCLE")
		}
		if !cycleGap || len(api.calls) > 3 {
			t.Fatalf("cycle was not bounded: gap=%v calls=%d", cycleGap, len(api.calls))
		}
	})

	t.Run("depth", func(t *testing.T) {
		api := newHistoricalExactAPI(t)
		setHistoricalAttempt(api, func(value *githubapi.WorkflowRun) { value.ReferencedWorkflows = nil })
		rootSHA := strings.Repeat("a", 40)
		for index := 0; index < historicalResolutionDepth+2; index++ {
			metadata := "runs:\n  using: composite\n  steps:\n    - uses: $/actions/" + fmt.Sprint(index+1) + "\n"
			api.put("fixture/depth", "actions/"+fmt.Sprint(index)+"/action.yml", "sha1", rootSHA, []byte(metadata))
		}
		setup := map[int64]map[string][]setupResolution{20: {
			"fixture/depth/actions/0@v1": {{action: logparse.Action{Owner: "fixture", Repository: "depth", Subpath: "actions/0", Ref: "v1", Source: logparse.GitObject{Algorithm: "sha1", Value: rootSHA}}, evidenceIDs: []model.EvidenceID{historicalEvidence('b')}}},
		}}
		result := repositoryResult{}
		if err := (Collector{API: api}).resolveHistoricalAttempt(context.Background(), historicalTarget(api), 10, historicalBundle(api), historicalSession(), fixedClock(time.Date(2026, 8, 20, 3, 0, 0, 0, time.UTC)), setup, historicalEvidence('c'), &result); err != nil {
			t.Fatal(err)
		}
		var depthGap bool
		for _, gap := range result.gaps {
			depthGap = depthGap || strings.Contains(gap.Diagnostic, "depth limit")
		}
		if !depthGap || len(api.calls) > historicalResolutionDepth*2+2 {
			t.Fatalf("depth was not bounded: gap=%v calls=%d", depthGap, len(api.calls))
		}
	})
}

func TestHistoricalResolutionContinuesAcrossDeletedAndForbiddenContent(t *testing.T) {
	api := newHistoricalExactAPI(t)
	setHistoricalAttempt(api, func(value *githubapi.WorkflowRun) {
		value.ReferencedWorkflows = []githubapi.ReferencedWorkflow{{Path: "acme/shared/.github/workflows/reuse.yml@v3", Ref: "v3", SHA: testCalledSHA}}
	})
	actionSHA := strings.Repeat("6", 40)
	api.fail("acme/shared", ".github/workflows/reuse.yml", "sha1", testCalledSHA, &githubapi.Error{Class: githubapi.ErrorNotFound, Operation: "content", StatusCode: 404, Message: "deleted"})
	api.fail("fixture/action", "action.yml", "sha1", actionSHA, &githubapi.Error{Class: githubapi.ErrorForbidden, Operation: "content", StatusCode: 403, Message: "denied"})
	api.fail("fixture/action", "action.yaml", "sha1", actionSHA, &githubapi.Error{Class: githubapi.ErrorForbidden, Operation: "content", StatusCode: 403, Message: "denied"})
	setup := map[int64]map[string][]setupResolution{20: {
		"fixture/action@v1": {{action: logparse.Action{Owner: "fixture", Repository: "action", Ref: "v1", Source: logparse.GitObject{Algorithm: "sha1", Value: actionSHA}}, evidenceIDs: []model.EvidenceID{historicalEvidence('6')}}},
	}}
	result := repositoryResult{}
	if err := (Collector{API: api}).resolveHistoricalAttempt(context.Background(), historicalTarget(api), 10, historicalBundle(api), historicalSession(), fixedClock(time.Date(2026, 8, 20, 3, 0, 0, 0, time.UTC)), setup, historicalEvidence('7'), &result); err != nil {
		t.Fatal(err)
	}
	var notFound, forbidden, calledIdentity bool
	for _, gap := range result.gaps {
		notFound = notFound || (gap.Scope == "called_workflow_definition" && gap.Reason == collect.GapNotFound)
		forbidden = forbidden || (gap.Scope == "action_definition" && gap.Reason == collect.GapForbidden)
	}
	for _, fact := range result.facts {
		calledIdentity = calledIdentity || (fact.Dependency != nil && fact.Dependency.Basis == archive.DefinitionRuntimeAttemptMetadata)
	}
	if !notFound || !forbidden || !calledIdentity {
		t.Fatalf("partial content failures not preserved: notFound=%v forbidden=%v called=%v", notFound, forbidden, calledIdentity)
	}
}

func TestCalledWorkflowHashPermissionGapDoesNotGuessObjectAlgorithm(t *testing.T) {
	api := newHistoricalExactAPI(t)
	api.hashErrors["acme/shared"] = &githubapi.Error{Class: githubapi.ErrorForbidden, Operation: "hash algorithm", StatusCode: 403, Message: "denied"}
	interval, _ := collect.NewInterval(time.Date(2026, 8, 20, 1, 0, 0, 0, time.UTC), time.Date(2026, 8, 20, 2, 0, 0, 0, time.UTC))
	result, err := (Collector{API: api, Now: fixedClock(time.Date(2026, 8, 20, 3, 0, 0, 0, time.UTC)), TempDir: t.TempDir()}).Collect(context.Background(), Request{
		Repositories: []string{"acme/service"}, Interval: interval, Purpose: PurposeInvestigate, Concurrency: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.CalledWorkflows) != 0 {
		t.Fatalf("untyped called SHA was guessed into a typed observation: %+v", result.CalledWorkflows)
	}
	var forbidden, rawSHAProjected, typedFact bool
	for _, gap := range result.Gaps {
		forbidden = forbidden || (gap.Scope == "called_workflow_definition" && gap.Reason == collect.GapForbidden)
	}
	for _, payload := range result.Batch.Payloads {
		rawSHAProjected = rawSHAProjected || strings.Contains(string(payload.Bytes), `"sha":"`+testCalledSHA+`"`)
	}
	for _, fact := range result.Batch.Facts {
		typedFact = typedFact || (fact.Dependency != nil && fact.Dependency.Basis == archive.DefinitionRuntimeAttemptMetadata && fact.Dependency.TargetCalledWorkflowObjectID != nil && model.GitObjectID(*fact.Dependency.TargetCalledWorkflowObjectID).Value == testCalledSHA)
	}
	for _, call := range api.calls {
		if call.repository == "acme/shared" {
			t.Fatalf("called workflow content was fetched without a typed object algorithm: %+v", call)
		}
	}
	if !forbidden || !rawSHAProjected || typedFact {
		t.Fatalf("hash permission semantics: forbidden=%v rawSHA=%v typedFact=%v", forbidden, rawSHAProjected, typedFact)
	}
}

func TestMissingAttemptLogsStillPreserveRecordedCalledWorkflowDefinition(t *testing.T) {
	api := newHistoricalExactAPI(t)
	api.attemptLogError = &githubapi.Error{Class: githubapi.ErrorNotFound, Operation: "attempt logs", StatusCode: 404, Message: "expired"}
	api.put("acme/shared", ".github/workflows/reuse.yml", "sha1", testCalledSHA, []byte("on: workflow_call\njobs:\n  noop:\n    runs-on: ubuntu-latest\n    steps: []\n"))
	interval, _ := collect.NewInterval(time.Date(2026, 8, 20, 1, 0, 0, 0, time.UTC), time.Date(2026, 8, 20, 2, 0, 0, 0, time.UTC))
	result, err := (Collector{API: api, Now: fixedClock(time.Date(2026, 8, 20, 3, 0, 0, 0, time.UTC)), TempDir: t.TempDir()}).Collect(context.Background(), Request{
		Repositories: []string{"acme/service"}, Interval: interval, Purpose: PurposeInvestigate, Concurrency: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	var logGap, calledFact, calledContent bool
	for _, gap := range result.Gaps {
		logGap = logGap || (gap.Scope == "attempt_log" && gap.Reason == collect.GapNotFound)
	}
	for _, fact := range result.Batch.Facts {
		calledFact = calledFact || (fact.Dependency != nil && fact.Dependency.Basis == archive.DefinitionRuntimeAttemptMetadata && fact.Dependency.TargetCalledWorkflowObjectID != nil)
	}
	for _, envelope := range result.Batch.Evidence {
		calledContent = calledContent || (envelope.Evidence.LogicalSource.Kind == "repository_content" && strings.Contains(envelope.Evidence.LogicalSource.CanonicalID, "acme/shared"))
	}
	if !logGap || !calledFact || !calledContent {
		t.Fatalf("missing-log partial collection: logGap=%v calledFact=%v calledContent=%v", logGap, calledFact, calledContent)
	}
}

func TestDecodeExactContentRejectsPathEncodingAndSizeContradictions(t *testing.T) {
	valid := []byte("runs:\n  using: node20\n")
	tests := []struct {
		name    string
		content githubapi.Content
		limit   int64
	}{
		{name: "wrong path", content: githubapi.Content{Type: "file", Path: "../action.yml", Encoding: "base64", Size: int64(len(valid)), Content: base64.StdEncoding.EncodeToString(valid)}, limit: 1024},
		{name: "symlink", content: githubapi.Content{Type: "symlink", Path: "action.yml", Encoding: "base64", Size: int64(len(valid)), Content: base64.StdEncoding.EncodeToString(valid)}, limit: 1024},
		{name: "unsupported encoding", content: githubapi.Content{Type: "file", Path: "action.yml", Encoding: "none", Size: int64(len(valid)), Content: string(valid)}, limit: 1024},
		{name: "declared mismatch", content: githubapi.Content{Type: "file", Path: "action.yml", Encoding: "base64", Size: int64(len(valid) + 1), Content: base64.StdEncoding.EncodeToString(valid)}, limit: 1024},
		{name: "size", content: githubapi.Content{Type: "file", Path: "action.yml", Encoding: "base64", Size: int64(len(valid)), Content: base64.StdEncoding.EncodeToString(valid)}, limit: 2},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := decodeExactContent(test.content, "action.yml", test.limit); err == nil {
				t.Fatal("hostile or contradictory content response was accepted")
			}
		})
	}
	if decoded, err := decodeExactContent(githubapi.Content{Type: "file", Path: "action.yml", Encoding: "base64", Size: int64(len(valid)), Content: base64.StdEncoding.EncodeToString(valid)}, "action.yml", 1024); err != nil || string(decoded) != string(valid) {
		t.Fatalf("valid exact content rejected: %q %v", decoded, err)
	}
}

func TestHistoricalResolutionCancellationDoesNotBecomeCleanCoverage(t *testing.T) {
	api := newHistoricalExactAPI(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result := repositoryResult{}
	err := (Collector{API: api}).resolveHistoricalAttempt(ctx, historicalTarget(api), 10, historicalBundle(api), historicalSession(), fixedClock(time.Date(2026, 8, 20, 3, 0, 0, 0, time.UTC)), nil, historicalEvidence('8'), &result)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation error = %v", err)
	}
}

func TestCollectPersistsExactDefinitionsInReplayableArchiveWithoutInventingCaller(t *testing.T) {
	api := newHistoricalExactAPI(t)
	api.put("fixture/action", "action.yml", "sha1", testActionSHA, []byte("runs:\n  using: node20\n  main: dist/index.js\n"))
	api.put("fixture/package", "action.yml", "sha1", testPackageSHA, []byte("runs:\n  using: node20\n  main: dist/index.js\n"))
	api.put("acme/shared", ".github/workflows/reuse.yml", "sha1", testCalledSHA, []byte("on: workflow_call\njobs:\n  noop:\n    runs-on: ubuntu-latest\n    steps: []\n"))
	interval, _ := collect.NewInterval(time.Date(2026, 8, 20, 1, 0, 0, 0, time.UTC), time.Date(2026, 8, 20, 2, 0, 0, 0, time.UTC))
	fixed := time.Date(2026, 8, 20, 3, 0, 0, 0, time.UTC)
	collector := Collector{API: api, Now: fixedClock(fixed), TempDir: t.TempDir()}
	request := Request{Repositories: []string{"acme/service"}, Interval: interval, Purpose: PurposeArchive, Concurrency: 1}
	store, err := archive.Create(context.Background(), t.TempDir()+"/archive.db", archive.Options{CreatedAt: model.MustInstant(fixed)})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	result, err := collector.CollectInto(context.Background(), request, store)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := store.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Facts) != len(result.Batch.Facts) || len(snapshot.Evidence) != len(result.Batch.Evidence) {
		t.Fatalf("archive snapshot lost historical material: batch facts/evidence=%d/%d snapshot=%d/%d", len(result.Batch.Facts), len(result.Batch.Evidence), len(snapshot.Facts), len(snapshot.Evidence))
	}
	var actionDefinitions archive.Capability
	for _, capability := range snapshot.Capabilities {
		if capability.Name == "action_definitions" {
			actionDefinitions = capability
		}
	}
	if actionDefinitions.Status != archive.CapabilityStructuredOnly || actionDefinitions.Details["parsed_count"] != "2" {
		t.Fatalf("exact Action definition capability was not reported: %+v", actionDefinitions)
	}
	var contentEvidence, callerInvented bool
	for _, envelope := range snapshot.Evidence {
		if envelope.Evidence.LogicalSource.Kind == "repository_content" {
			contentEvidence = true
			if envelope.Evidence.Content.RawRetained || envelope.Evidence.Content.RetainedPayloadSHA256 != nil {
				t.Fatalf("hostile workflow/Action YAML was retained by default: %+v", envelope.Evidence.Content)
			}
		}
	}
	for _, fact := range snapshot.Facts {
		if fact.Dependency == nil || fact.Dependency.Basis != archive.DefinitionHistoricalAtRun || fact.Dependency.CallerWorkflowObjectID == nil {
			continue
		}
		if fact.Dependency.CallerRepository == "acme/service" && fact.Dependency.CallerPath == ".github/workflows/ci.yml" {
			callerInvented = true
		}
	}
	if !contentEvidence || callerInvented {
		t.Fatalf("content evidence=%v invented caller=%v", contentEvidence, callerInvented)
	}
}

func TestCollectIntoScopesRepeatedHistoricalRequestsByRunAttempt(t *testing.T) {
	api := newHistoricalExactAPI(t)
	api.put("fixture/action", "action.yml", "sha1", testActionSHA, []byte("runs:\n  using: node20\n  main: dist/index.js\n"))
	api.put("fixture/package", "action.yml", "sha1", testPackageSHA, []byte("runs:\n  using: node20\n  main: dist/index.js\n"))
	api.put("acme/shared", ".github/workflows/reuse.yml", "sha1", testCalledSHA, []byte("on: workflow_call\njobs:\n  noop:\n    runs-on: ubuntu-latest\n    steps: []\n"))

	attemptTwo := api.attempts[10][1]
	attemptTwo.RunAttempt = 2
	api.attempts[10][2] = attemptTwo
	jobTwo := api.jobs[10][1][0]
	jobTwo.ID = 21
	jobTwo.Name = "rerun-build"
	api.jobs[10][2] = []githubapi.WorkflowJob{jobTwo}
	api.jobLogs[21] = []byte("synthetic complete job log discarded\n")
	api.attemptLogs[10][2] = makeZIP(t, map[string]string{
		"rerun-build/1_Set up job.txt": setupFixtureLog(),
	})

	interval, err := collect.NewInterval(time.Date(2026, 8, 20, 1, 0, 0, 0, time.UTC), time.Date(2026, 8, 20, 2, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	base := time.Date(2026, 8, 20, 3, 0, 0, 0, time.UTC)
	var tick int64
	clock := func() time.Time {
		value := base.Add(time.Duration(tick) * time.Nanosecond)
		tick++
		return value
	}
	store, err := archive.Create(context.Background(), t.TempDir()+"/archive.db", archive.Options{CreatedAt: model.MustInstant(base)})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	_, err = (Collector{API: api, Now: clock, TempDir: t.TempDir()}).CollectInto(context.Background(), Request{
		Repositories: []string{"acme/service"}, Interval: interval, Purpose: PurposeArchive, Concurrency: 1,
	}, store)
	if err != nil {
		t.Fatalf("persist two-attempt historical provenance: %v", err)
	}

	snapshot, err := store.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	contentRequests := make(map[model.RunAttempt]evidence.CollectionObservation)
	hashRequests := make(map[model.RunAttempt]evidence.CollectionObservation)
	for _, envelope := range snapshot.Evidence {
		if envelope.Evidence.Scope.RunAttempt == nil {
			continue
		}
		attempt := *envelope.Evidence.Scope.RunAttempt
		parameters := envelope.Evidence.Source.RequestParameters
		switch {
		case envelope.Evidence.Source.EndpointTemplate == "/repos/{owner}/{repo}/contents/{path}" &&
			parameters["owner"] == "fixture" && parameters["repo"] == "action" && parameters["path"] == "action.yml":
			contentRequests[attempt] = envelope.Observation
		case envelope.Evidence.Source.EndpointTemplate == "/repos/{owner}/{repo}/hash-algorithm" &&
			parameters["owner"] == "fixture" && parameters["repo"] == "action":
			hashRequests[attempt] = envelope.Observation
		}
	}
	assertAttemptScopedRequests := func(name string, observations map[model.RunAttempt]evidence.CollectionObservation) {
		t.Helper()
		first, firstOK := observations[1]
		second, secondOK := observations[2]
		if !firstOK || !secondOK {
			t.Fatalf("%s observations did not cover both attempts: %+v", name, observations)
		}
		if first.RequestID == second.RequestID {
			t.Fatalf("%s reused request identity across attempts: %s", name, first.RequestID)
		}
		if first.CollectionTime.StartedAt.Equal(second.CollectionTime.StartedAt.Time) {
			t.Fatalf("%s regression did not exercise distinct collection windows", name)
		}
	}
	assertAttemptScopedRequests("historical content", contentRequests)
	assertAttemptScopedRequests("target hash", hashRequests)
}

func TestSetupSourcesUseTargetRepositoryHashAlgorithm(t *testing.T) {
	tests := []struct {
		name      string
		callerAlg string
		targetAlg string
		source    string
	}{
		{name: "sha1 caller sha256 Action", callerAlg: "sha1", targetAlg: "sha256", source: strings.Repeat("a", 64)},
		{name: "sha256 caller sha1 Action", callerAlg: "sha256", targetAlg: "sha1", source: strings.Repeat("b", 40)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			api := mixedHashLifecycleAPI(t, test.source)
			api.hashValues["acme/service"] = test.callerAlg
			api.hashValues["fixture/action"] = test.targetAlg
			api.put("fixture/action", "action.yml", test.targetAlg, test.source, []byte("runs:\n  using: node20\n  main: dist/index.js\n"))
			result := collectHistoricalAPI(t, api)

			var started *model.RuntimeActionObservation
			var hashEvidence model.EvidenceID
			for _, envelope := range result.Batch.Evidence {
				if envelope.Evidence.Source.EndpointTemplate == "/repos/{owner}/{repo}/hash-algorithm" &&
					envelope.Evidence.Source.RequestParameters["owner"] == "fixture" && envelope.Evidence.Source.RequestParameters["repo"] == "action" {
					hashEvidence = envelope.Evidence.ID
				}
			}
			for _, fact := range result.Batch.Facts {
				if fact.Kind != archive.FactActionOccurrence || fact.ActionOccurrence.Observation.ActionRepository != "fixture/action" {
					continue
				}
				observation := fact.ActionOccurrence.Observation
				if observation.SourceObjectID == nil {
					t.Fatalf("verified Action occurrence omitted its source object: %+v", observation)
				}
				object := model.GitObjectID(*observation.SourceObjectID)
				if string(object.Algorithm) != test.targetAlg || object.Value != test.source {
					t.Fatalf("source used caller or width-derived algorithm: %+v", object)
				}
				if observation.Kind == model.ObservationLifecycleStarted {
					copy := observation
					started = &copy
				}
			}
			if started == nil || hashEvidence == "" || !containsEvidence(started.SourceEvidenceIDs, hashEvidence) {
				t.Fatalf("lifecycle did not retain target hash evidence: started=%v hash=%s", started != nil, hashEvidence)
			}
			api.mu.Lock()
			calls := api.hashCalls["fixture/action"]
			api.mu.Unlock()
			if calls != 1 {
				t.Fatalf("target hash endpoint calls = %d, want one cached request", calls)
			}
			for _, call := range api.calls {
				if call.repository == "fixture/action" && (call.object.Algorithm != test.targetAlg || call.object.Value != test.source) {
					t.Fatalf("exact content request used an unverified object: %+v", call)
				}
			}
		})
	}
}

func TestDeniedTargetHashLookupWithholdsMutableExecutionIdentity(t *testing.T) {
	source := strings.Repeat("d", 40)
	api := mixedHashLifecycleAPI(t, source)
	api.hashErrors["fixture/action"] = &githubapi.Error{Class: githubapi.ErrorForbidden, Operation: "hash algorithm", StatusCode: 403, Message: "denied"}
	result := collectHistoricalAPI(t, api)

	for _, fact := range result.Batch.Facts {
		if fact.Kind == archive.FactActionOccurrence && fact.ActionOccurrence.Observation.ActionRepository == "fixture/action" {
			t.Fatalf("unverified mutable Action produced a source or execution claim: %+v", fact.ActionOccurrence.Observation)
		}
	}
	var forbidden, lifecycleGap, rawSourceProjected bool
	for _, gap := range result.Gaps {
		forbidden = forbidden || (gap.Scope == "action_definition" && gap.Reason == collect.GapForbidden)
		lifecycleGap = lifecycleGap || gap.Scope == "action_step_resolution"
	}
	for _, payload := range result.Batch.Payloads {
		rawSourceProjected = rawSourceProjected || strings.Contains(string(payload.Bytes), `"source_hex_untyped":"`+source+`"`)
	}
	api.mu.Lock()
	calls := api.hashCalls["fixture/action"]
	api.mu.Unlock()
	if !forbidden || !lifecycleGap || !rawSourceProjected || calls != 1 {
		t.Fatalf("denied lookup semantics: forbidden=%v lifecycleGap=%v rawSource=%v calls=%d", forbidden, lifecycleGap, rawSourceProjected, calls)
	}
}

func TestDeniedTargetHashLookupPreservesIndependentImmutableDigest(t *testing.T) {
	source := strings.Repeat("e", 40)
	digest := strings.Repeat("f", 64)
	api := newHistoricalExactAPI(t)
	setHistoricalAttempt(api, func(value *githubapi.WorkflowRun) { value.ReferencedWorkflows = nil })
	api.hashErrors["fixture/package"] = &githubapi.Error{Class: githubapi.ErrorForbidden, Operation: "hash algorithm", StatusCode: 403, Message: "denied"}
	job := api.jobs[10][1][0]
	job.Steps = append(job.Steps, actionAPIStep(2, "Run fixture/package@v2", "success"))
	api.jobs[10][1] = []githubapi.WorkflowJob{job}
	setup := "2026-08-20T01:10:03Z Download immutable action package 'fixture/package@v2'\n" +
		"2026-08-20T01:10:03Z Version: 2.0.0\n" +
		"2026-08-20T01:10:03Z Source commit SHA: " + source + "\n" +
		"2026-08-20T01:10:03Z Digest: sha256:" + digest + "\n"
	api.attemptLogs[10][1] = makeZIP(t, map[string]string{
		"build/1_Set up job.txt":            setup,
		"build/2_Run fixturepackage@v2.txt": repositoryActionFrame("fixture/package@v2"),
	})
	result := collectHistoricalAPI(t, api)
	for _, fact := range result.Batch.Facts {
		if fact.Kind != archive.FactActionOccurrence || fact.ActionOccurrence.Observation.Kind != model.ObservationLifecycleStarted {
			continue
		}
		observation := fact.ActionOccurrence.Observation
		if observation.ActionRepository == "fixture/package" && observation.SourceObjectID == nil && observation.PackageDigest != nil && observation.PackageDigest.Value == digest {
			return
		}
	}
	t.Fatal("verified immutable digest was lost or coupled to an unverified source algorithm")
}

func mixedHashLifecycleAPI(t *testing.T, source string) *historicalExactAPI {
	t.Helper()
	api := newHistoricalExactAPI(t)
	setHistoricalAttempt(api, func(value *githubapi.WorkflowRun) { value.ReferencedWorkflows = nil })
	job := api.jobs[10][1][0]
	job.Steps = append(job.Steps, actionAPIStep(2, "Run fixture/action@v1", "success"))
	api.jobs[10][1] = []githubapi.WorkflowJob{job}
	setup := "2026-08-20T01:10:03Z Download action repository 'fixture/action@v1' (SHA:" + source + ")\n"
	api.attemptLogs[10][1] = makeZIP(t, map[string]string{
		"build/1_Set up job.txt":           setup,
		"build/2_Run fixtureaction@v1.txt": repositoryActionFrame("fixture/action@v1"),
	})
	return api
}

func collectHistoricalAPI(t *testing.T, api API) Result {
	t.Helper()
	interval, err := collect.NewInterval(time.Date(2026, 8, 20, 1, 0, 0, 0, time.UTC), time.Date(2026, 8, 20, 2, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	result, err := (Collector{API: api, Now: fixedClock(time.Date(2026, 8, 20, 3, 0, 0, 0, time.UTC)), TempDir: t.TempDir()}).Collect(context.Background(), Request{
		Repositories: []string{"acme/service"}, Interval: interval, Purpose: PurposeInvestigate, Concurrency: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	return result
}
