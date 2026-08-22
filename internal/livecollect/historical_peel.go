package livecollect

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/torjan0/cirewind/internal/collect"
	"github.com/torjan0/cirewind/internal/evidence"
	"github.com/torjan0/cirewind/internal/githubapi"
	"github.com/torjan0/cirewind/internal/model"
)

const (
	maxHistoricalPeelTags      = 8
	maxHistoricalPeelParents   = 16_384
	maxHistoricalPeelResponses = 128
)

type gitObjectProjection struct {
	Algorithm string `json:"algorithm"`
	Value     string `json:"value"`
}

type gitTagPeelProjection struct {
	TagObject  gitObjectProjection `json:"tag_object"`
	TagName    string              `json:"tag_name"`
	TargetKind string              `json:"target_kind"`
	Target     gitObjectProjection `json:"target"`
}

type gitCommitPeelProjection struct {
	CommitObject gitObjectProjection `json:"commit_object"`
	TreeObject   gitObjectProjection `json:"tree_object"`
	ParentCount  int                 `json:"parent_count"`
}

type calledWorkflowPeelProjection struct {
	Schema                 string                   `json:"schema"`
	Repository             string                   `json:"repository"`
	RecordedObject         gitObjectProjection      `json:"recorded_object"`
	ReturnedRecordedObject gitObjectProjection      `json:"returned_recorded_object"`
	RecordedKind           string                   `json:"recorded_kind,omitempty"`
	TagObjects             []gitTagPeelProjection   `json:"tag_objects"`
	TagObjectsLimited      bool                     `json:"tag_objects_limited"`
	CommitObject           *gitCommitPeelProjection `json:"commit_object,omitempty"`
	Complete               bool                     `json:"complete"`
	Responses              []responseProjection     `json:"responses"`
	ResponsesLimited       bool                     `json:"responses_limited"`
}

// peelCalledWorkflowObject retains a compact projection of every API response
// involved in the bounded peel. Failure records a material gap and returns
// ok=false; only a fully validated terminal commit can be used for exact
// content retrieval or reusable-workflow reference binding.
func (h *historicalAttempt) peelCalledWorkflowObject(ctx context.Context, slug model.RepositorySlug, recorded model.GitObjectID) (model.GitObjectID, model.EvidenceID, bool, error) {
	owner, repository := splitSlug(slug)
	started := model.MustInstant(h.now().UTC())
	result, peelErr := h.peeler.PeelGitObjectToCommit(ctx, owner, repository, githubapi.GitObjectID{Algorithm: string(recorded.Algorithm), Value: recorded.Value})
	ended := model.MustInstant(h.now().UTC())
	validationErr := error(nil)
	var terminal model.GitObjectID
	if peelErr == nil {
		terminal, validationErr = validateCalledWorkflowPeel(recorded, result)
	}
	complete := peelErr == nil && validationErr == nil
	projection := projectCalledWorkflowPeel(slug, recorded, result, complete)
	payload, envelope, envelopeErr := compactEnvelopeAt(
		h.sessionID,
		scopedRequestID("called-workflow-object-peel", h.scope, string(slug), string(recorded.Algorithm), recorded.Value),
		"normalized:github:called-workflow-object-peel:"+safeKey(string(slug)+"\x00"+string(recorded.Algorithm)+"\x00"+recorded.Value),
		evidence.SourceAPIJSON,
		githubapi.APIVersion,
		"/repos/{owner}/{repo}/git/{object_type}/{object_sha}",
		evidence.RequestParameters{"owner": owner, "repo": repository, "recorded_algorithm": string(recorded.Algorithm), "recorded_object": recorded.Value, "operation": "bounded-tag-peel"},
		h.scope,
		h.event,
		projection,
		started,
		ended,
	)
	if envelopeErr != nil {
		return model.GitObjectID{}, "", false, fmt.Errorf("construct called-workflow Git object peel evidence: %w", envelopeErr)
	}
	h.result.payloads = append(h.result.payloads, payload)
	h.result.evidence = append(h.result.evidence, envelope)

	if peelErr != nil {
		if errors.Is(peelErr, context.Canceled) || errors.Is(peelErr, context.DeadlineExceeded) {
			return model.GitObjectID{}, envelope.Evidence.ID, false, peelErr
		}
		gap := collect.GapFromError("called_workflow_definition", h.target.repository.ID, h.runID, h.bundle.Attempt, peelErr)
		if gap.Reason == collect.GapUnknown {
			gap.Reason = collect.GapValidation
			gap.Diagnostic = "GitHub-recorded called-workflow object could not be positively peeled to a commit"
		}
		gap.Responses = append([]githubapi.ResponseMeta(nil), result.Responses...)
		if err := appendGap(h.result, gap); err != nil {
			return model.GitObjectID{}, envelope.Evidence.ID, false, err
		}
		return model.GitObjectID{}, envelope.Evidence.ID, false, nil
	}
	if validationErr != nil {
		if err := appendGap(h.result, collect.Gap{Reason: collect.GapMalformedResponse, Scope: "called_workflow_definition", RepositoryID: h.target.repository.ID, RunID: h.runID, Attempt: h.bundle.Attempt, Material: true, Diagnostic: "called-workflow object peel response was internally inconsistent", Responses: append([]githubapi.ResponseMeta(nil), result.Responses...)}); err != nil {
			return model.GitObjectID{}, envelope.Evidence.ID, false, err
		}
		return model.GitObjectID{}, envelope.Evidence.ID, false, nil
	}
	return terminal, envelope.Evidence.ID, true, nil
}

func validateCalledWorkflowPeel(recorded model.GitObjectID, result githubapi.GitObjectPeel) (model.GitObjectID, error) {
	want := githubapi.GitObjectID{Algorithm: string(recorded.Algorithm), Value: recorded.Value}
	if result.RecordedObjectID != want {
		return model.GitObjectID{}, errors.New("peel changed the recorded object identity")
	}
	if result.RecordedKind != githubapi.GitObjectCommit && result.RecordedKind != githubapi.GitObjectTag {
		return model.GitObjectID{}, errors.New("peel did not positively type the recorded object")
	}
	if result.CommitObject == nil {
		return model.GitObjectID{}, errors.New("peel omitted a terminal commit object")
	}
	if len(result.TagObjects) > maxHistoricalPeelTags || len(result.CommitObject.ParentObjectIDs) > maxHistoricalPeelParents || len(result.Responses) > maxHistoricalPeelResponses {
		return model.GitObjectID{}, errors.New("peel exceeded the compiled object limits")
	}
	if result.RecordedKind == githubapi.GitObjectCommit {
		if len(result.TagObjects) != 0 || result.CommitObject.CommitObjectID != want {
			return model.GitObjectID{}, errors.New("commit peel disagreed with the recorded object")
		}
	} else {
		if len(result.TagObjects) == 0 || result.TagObjects[0].TagObjectID != want {
			return model.GitObjectID{}, errors.New("tag peel did not begin at the recorded object")
		}
		expected := want
		visited := make(map[githubapi.GitObjectID]struct{}, len(result.TagObjects))
		for index, tag := range result.TagObjects {
			if tag.TagObjectID != expected {
				return model.GitObjectID{}, errors.New("tag peel chain was discontinuous")
			}
			if _, exists := visited[tag.TagObjectID]; exists {
				return model.GitObjectID{}, errors.New("tag peel chain contained a cycle")
			}
			visited[tag.TagObjectID] = struct{}{}
			if tag.TagName == "" || len(tag.TagName) > 4<<10 || strings.ContainsRune(tag.TagName, 0) || tag.Target.ObjectID.Algorithm != want.Algorithm {
				return model.GitObjectID{}, errors.New("tag peel contained invalid tag metadata")
			}
			if _, err := validateProjectedGitObject(want.Algorithm, tag.TagObjectID); err != nil {
				return model.GitObjectID{}, err
			}
			if _, err := validateProjectedGitObject(want.Algorithm, tag.Target.ObjectID); err != nil {
				return model.GitObjectID{}, err
			}
			switch tag.Target.Kind {
			case githubapi.GitObjectTag:
				if index == len(result.TagObjects)-1 {
					return model.GitObjectID{}, errors.New("tag peel ended before a commit")
				}
				expected = tag.Target.ObjectID
			case githubapi.GitObjectCommit:
				if index != len(result.TagObjects)-1 || tag.Target.ObjectID != result.CommitObject.CommitObjectID {
					return model.GitObjectID{}, errors.New("tag peel terminal commit disagreed with the tag target")
				}
			default:
				return model.GitObjectID{}, errors.New("tag peel ended at a non-commit object")
			}
		}
	}
	commit, err := validateProjectedGitObject(want.Algorithm, result.CommitObject.CommitObjectID)
	if err != nil {
		return model.GitObjectID{}, err
	}
	if _, err := validateProjectedGitObject(want.Algorithm, result.CommitObject.TreeObjectID); err != nil {
		return model.GitObjectID{}, err
	}
	for _, parent := range result.CommitObject.ParentObjectIDs {
		if _, err := validateProjectedGitObject(want.Algorithm, parent); err != nil {
			return model.GitObjectID{}, err
		}
	}
	if !hasPositiveCommitResponse(result.Responses, result.CommitObject.CommitObjectID) {
		return model.GitObjectID{}, errors.New("peel lacked a complete successful commit-object response")
	}
	for _, tag := range result.TagObjects {
		if !hasPositiveTagResponse(result.Responses, tag.TagObjectID) {
			return model.GitObjectID{}, errors.New("peel lacked a complete successful tag-object response")
		}
	}
	return commit, nil
}

func validateProjectedGitObject(algorithm string, object githubapi.GitObjectID) (model.GitObjectID, error) {
	if object.Algorithm != algorithm {
		return model.GitObjectID{}, errors.New("peel crossed repository object algorithms")
	}
	return model.NewGitObjectID(model.HashAlgorithm(object.Algorithm), object.Value)
}

func hasPositiveCommitResponse(responses []githubapi.ResponseMeta, object githubapi.GitObjectID) bool {
	return hasPositiveObjectResponse(responses, "/repos/{owner}/{repo}/git/commits/{commit_sha}", "commit_algorithm", "commit_sha", object)
}

func hasPositiveTagResponse(responses []githubapi.ResponseMeta, object githubapi.GitObjectID) bool {
	return hasPositiveObjectResponse(responses, "/repos/{owner}/{repo}/git/tags/{tag_sha}", "tag_algorithm", "tag_sha", object)
}

func hasPositiveObjectResponse(responses []githubapi.ResponseMeta, route, algorithmKey, objectKey string, object githubapi.GitObjectID) bool {
	for _, response := range responses {
		if response.RouteTemplate == route && response.StatusCode >= 200 && response.StatusCode < 300 && response.BodyComplete &&
			response.RequestParameters[algorithmKey] == object.Algorithm && response.RequestParameters[objectKey] == object.Value &&
			len(response.SHA256) == 64 && safeHex(response.SHA256, 64) == response.SHA256 {
			return true
		}
	}
	return false
}

func projectCalledWorkflowPeel(slug model.RepositorySlug, recorded model.GitObjectID, result githubapi.GitObjectPeel, complete bool) calledWorkflowPeelProjection {
	tags := result.TagObjects
	tagsLimited := len(tags) > maxHistoricalPeelTags+1
	if tagsLimited {
		tags = tags[:maxHistoricalPeelTags+1]
	}
	responses := result.Responses
	responsesLimited := len(responses) > maxHistoricalPeelResponses
	if responsesLimited {
		responses = responses[:maxHistoricalPeelResponses]
	}
	projection := calledWorkflowPeelProjection{
		Schema: "cirewind.github-called-workflow-object-peel-projection/v1", Repository: string(slug),
		RecordedObject: projectModelGitObject(recorded), ReturnedRecordedObject: projectGitObject(result.RecordedObjectID), RecordedKind: safeMachine(string(result.RecordedKind), 32),
		TagObjects: []gitTagPeelProjection{}, TagObjectsLimited: tagsLimited, Complete: complete,
		Responses: projectResponses(responses), ResponsesLimited: responsesLimited,
	}
	for _, tag := range tags {
		projection.TagObjects = append(projection.TagObjects, gitTagPeelProjection{
			TagObject: projectGitObject(tag.TagObjectID), TagName: safeField(tag.TagName, 4<<10),
			TargetKind: safeMachine(string(tag.Target.Kind), 32), Target: projectGitObject(tag.Target.ObjectID),
		})
	}
	if result.CommitObject != nil {
		projection.CommitObject = &gitCommitPeelProjection{
			CommitObject: projectGitObject(result.CommitObject.CommitObjectID), TreeObject: projectGitObject(result.CommitObject.TreeObjectID),
			ParentCount: len(result.CommitObject.ParentObjectIDs),
		}
	}
	return projection
}

func projectGitObject(object githubapi.GitObjectID) gitObjectProjection {
	return gitObjectProjection{Algorithm: safeMachine(object.Algorithm, 32), Value: safeHex(object.Value, 64)}
}

func projectModelGitObject(object model.GitObjectID) gitObjectProjection {
	return gitObjectProjection{Algorithm: safeMachine(string(object.Algorithm), 32), Value: safeHex(object.Value, 64)}
}
