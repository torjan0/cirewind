package livecollect

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"path"
	"strings"

	"github.com/torjan0/cirewind/internal/collect"
	"github.com/torjan0/cirewind/internal/evidence"
	"github.com/torjan0/cirewind/internal/githubapi"
	"github.com/torjan0/cirewind/internal/model"
	"github.com/torjan0/cirewind/internal/resolve"
	"github.com/torjan0/cirewind/internal/workflow"
)

const historicalContentLimit = int64(4 << 20)

// ExactContentAPI is an optional, read-only boundary. Live collection uses it
// only with an algorithm-qualified full Git object ID obtained independently
// of workflow head_sha. githubapi.Client satisfies this interface.
type ExactContentAPI interface {
	GetContentAtObject(context.Context, string, string, string, githubapi.GitObjectID) (githubapi.ObjectResult[githubapi.Content], error)
}

var _ ExactContentAPI = (*githubapi.Client)(nil)

// GitObjectPeelAPI is an optional, read-only object-typing boundary. Referenced
// workflow metadata can contain an annotated-tag object ID rather than a
// commit ID. Exact workflow bytes are fetched only after this operation has
// positively typed the terminal object as a commit. The originally recorded
// object remains a distinct attempt-scoped identity.
type GitObjectPeelAPI interface {
	PeelGitObjectToCommit(context.Context, string, string, githubapi.GitObjectID) (githubapi.GitObjectPeel, error)
}

var _ GitObjectPeelAPI = (*githubapi.Client)(nil)

type historicalContentSource struct {
	api       ExactContentAPI
	sessionID model.CollectionSessionID
	scope     model.CoverageScope
	event     model.EventInterval
	now       Clock
	result    *repositoryResult
	cache     map[string]historicalContentCache
}

type historicalContentCache struct {
	content resolve.Content
	err     error
}

func newHistoricalContentSource(api ExactContentAPI, sessionID model.CollectionSessionID, scope model.CoverageScope, event model.EventInterval, now Clock, result *repositoryResult) *historicalContentSource {
	return &historicalContentSource{api: api, sessionID: sessionID, scope: scope, event: event, now: now, result: result, cache: make(map[string]historicalContentCache)}
}

func (s *historicalContentSource) Fetch(ctx context.Context, key resolve.DefinitionKey) (resolve.Content, error) {
	if err := ctx.Err(); err != nil {
		return resolve.Content{}, err
	}
	cacheKey := historicalContentCacheKey(key)
	if cached, ok := s.cache[cacheKey]; ok {
		return cached.content, cached.err
	}
	content, err := s.fetch(ctx, key)
	s.cache[cacheKey] = historicalContentCache{content: content, err: err}
	return content, err
}

func (s *historicalContentSource) fetch(ctx context.Context, key resolve.DefinitionKey) (resolve.Content, error) {
	if s.api == nil || s.result == nil || s.now == nil {
		return resolve.Content{}, errors.New("historical content source is not configured")
	}
	object, err := model.NewGitObjectID(model.HashAlgorithm(key.Commit.Algorithm), strings.ToLower(key.Commit.Value))
	if err != nil {
		return s.fail(key, collect.GapValidation, "exact historical content request had an invalid typed Git object", err)
	}
	normalizedPath, err := workflow.NormalizeRepositoryPath(key.Path)
	if err != nil || normalizedPath == "" || path.Clean(normalizedPath) != normalizedPath {
		return s.fail(key, collect.GapValidation, "exact historical content request had an unsafe repository path", err)
	}
	started := model.MustInstant(s.now().UTC())
	response, requestErr := s.api.GetContentAtObject(ctx, key.Repository.Owner, key.Repository.Name, normalizedPath, githubapi.GitObjectID{Algorithm: string(object.Algorithm), Value: object.Value})
	ended := model.MustInstant(s.now().UTC())
	if requestErr != nil {
		// action.yml/action.yaml probing deliberately treats one missing name as
		// normal when the other exists. Let the resolver decide when absence is
		// material instead of persisting a false gap here.
		if githubapi.IsClass(requestErr, githubapi.ErrorNotFound) {
			return resolve.Content{}, errors.Join(resolve.ErrContentNotFound, requestErr)
		}
		gap := collect.GapFromError(historicalContentScope(normalizedPath), coverageRepository(s.scope), coverageRun(s.scope), coverageAttempt(s.scope), requestErr)
		gap.Diagnostic = "exact historical repository content was unavailable"
		if appendErr := appendGap(s.result, gap); appendErr != nil {
			return resolve.Content{}, appendErr
		}
		return resolve.Content{}, requestErr
	}
	decoded, decodeErr := decodeExactContent(response.Value, normalizedPath, historicalContentLimit)
	if decodeErr != nil {
		reason := collect.GapMalformedResponse
		if errors.Is(decodeErr, errHistoricalContentSize) {
			reason = collect.GapSizeLimit
		}
		return s.fail(key, reason, decodeErr.Error(), decodeErr)
	}
	requestAttempt := uint32(len(response.Responses))
	if requestAttempt == 0 {
		requestAttempt = 1
	}
	var status *int
	if len(response.Responses) > 0 && response.Responses[len(response.Responses)-1].StatusCode != 0 {
		value := response.Responses[len(response.Responses)-1].StatusCode
		status = &value
	}
	parameters := evidence.RequestParameters{
		"owner": key.Repository.Owner, "repo": key.Repository.Name, "path": normalizedPath,
		"ref_algorithm": string(object.Algorithm), "ref": object.Value,
	}
	envelope, envelopeErr := evidence.NewEnvelope(evidence.EnvelopeInput{
		Kind: evidence.SourceRepositoryContent, CanonicalSourceID: "github:repository-content:" + strings.ToLower(key.Repository.Owner) + "/" + strings.ToLower(key.Repository.Name) + ":" + string(object.Algorithm) + ":" + object.Value + ":" + normalizedPath,
		Provider: evidence.ProviderGitHub, APIVersion: githubapi.APIVersion,
		EndpointTemplate: "/repos/{owner}/{repo}/contents/{path}", RequestParameters: parameters,
		RequestAttempt: requestAttempt, HTTPStatus: status, Scope: s.scope, EventTime: s.event,
		MediaType: "application/yaml", SourceBytes: decoded, Complete: true,
		Extractor: evidence.ExtractorDescriptor{Name: "livecollect", Version: ExtractorVersion, RulesetSHA256: extractorRulesetSHA256},
		Redaction: evidence.RedactionDescriptor{Status: evidence.RedactionNotInspected, PolicyVersion: defaultRedactionPolicy},
		Errors:    []evidence.EvidenceError{}, CollectionSession: s.sessionID,
		RequestID:      collectionRequestID(s.sessionID, scopedRequestID("historical-content", s.scope, strings.ToLower(key.Repository.Owner), strings.ToLower(key.Repository.Name), normalizedPath, string(object.Algorithm), object.Value)),
		CollectionTime: model.CollectionWindow{StartedAt: started, EndedAt: ended},
	})
	if envelopeErr != nil {
		return resolve.Content{}, fmt.Errorf("construct exact historical content evidence: %w", envelopeErr)
	}
	s.result.evidence = append(s.result.evidence, envelope)
	return resolve.Content{Bytes: decoded, EvidenceID: string(envelope.Evidence.ID)}, nil
}

var errHistoricalContentSize = errors.New("historical content size limit exceeded")

func decodeExactContent(content githubapi.Content, requestedPath string, limit int64) ([]byte, error) {
	if content.Type != "file" {
		return nil, errors.New("historical content response was not a regular file")
	}
	if content.Path != "" && content.Path != requestedPath {
		return nil, errors.New("historical content response path disagreed with the exact request")
	}
	if content.Encoding != "base64" {
		return nil, errors.New("historical content response used an unsupported encoding")
	}
	if content.Size < 0 || content.Size > limit || int64(len(content.Content)) > ((limit+2)/3)*4+(1<<16) {
		return nil, errHistoricalContentSize
	}
	decoder := base64.NewDecoder(base64.StdEncoding, strings.NewReader(content.Content))
	decoded, err := io.ReadAll(io.LimitReader(decoder, limit+1))
	if err != nil {
		return nil, errors.New("historical content response contained invalid base64")
	}
	if int64(len(decoded)) > limit {
		return nil, errHistoricalContentSize
	}
	if int64(len(decoded)) != content.Size {
		return nil, errors.New("historical content response byte length disagreed with its declared size")
	}
	return decoded, nil
}

func (s *historicalContentSource) fail(key resolve.DefinitionKey, reason collect.GapReason, diagnostic string, cause error) (resolve.Content, error) {
	gap := collect.Gap{Reason: reason, Scope: historicalContentScope(key.Path), RepositoryID: coverageRepository(s.scope), RunID: coverageRun(s.scope), Attempt: coverageAttempt(s.scope), Material: true, Diagnostic: diagnostic}
	if err := appendGap(s.result, gap); err != nil {
		return resolve.Content{}, err
	}
	if cause == nil {
		cause = errors.New(diagnostic)
	}
	return resolve.Content{}, cause
}

func historicalContentScope(contentPath string) string {
	if strings.HasPrefix(contentPath, ".github/workflows/") {
		return "called_workflow_definition"
	}
	return "action_definition"
}

func historicalContentCacheKey(key resolve.DefinitionKey) string {
	return strings.ToLower(key.Repository.Owner) + "/" + strings.ToLower(key.Repository.Name) + "\x00" + key.Path + "\x00" + key.Commit.Algorithm + "\x00" + strings.ToLower(key.Commit.Value)
}

func coverageRepository(scope model.CoverageScope) int64 {
	if scope.RepositoryID == nil {
		return 0
	}
	return int64(*scope.RepositoryID)
}

func coverageRun(scope model.CoverageScope) int64 {
	if scope.RunID == nil {
		return 0
	}
	return int64(*scope.RunID)
}

func coverageAttempt(scope model.CoverageScope) int {
	if scope.RunAttempt == nil {
		return 0
	}
	return int(*scope.RunAttempt)
}
