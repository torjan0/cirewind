package githubapi

import (
	"context"
	"encoding/hex"
	"net/url"
	"strings"
)

const maxGitTagNameBytes = 4 << 10

// GetGitTag gets one annotated Git tag object by its complete,
// algorithm-qualified object ID. It does not peel the tag or reinterpret a
// missing tag object as a commit.
func (c *Client) GetGitTag(ctx context.Context, owner, repository string, tagObject GitObjectID) (ObjectResult[GitTagObject], error) {
	ownerPart, repositoryPart, err := repositoryParts(owner, repository)
	if err != nil {
		return ObjectResult[GitTagObject]{}, err
	}
	if !validFullGitObjectID(tagObject) {
		return ObjectResult[GitTagObject]{}, invalidArgument("get Git tag", "tag object ID must be a supported algorithm-qualified full lowercase object ID")
	}

	operation := "get Git tag"
	response, getErr := c.get(ctx, requestSpec{
		routeTemplate: "/repos/{owner}/{repo}/git/tags/{tag_sha}",
		path:          "/repos/" + ownerPart + "/" + repositoryPart + "/git/tags/" + url.PathEscape(tagObject.Value),
		parameters: map[string]string{
			"owner": owner, "repo": repository,
			"tag_algorithm": tagObject.Algorithm, "tag_sha": tagObject.Value,
		},
		operation: operation,
	})
	result := ObjectResult[GitTagObject]{Responses: response.attempts}
	if getErr != nil {
		return result, getErr
	}

	var document struct {
		NodeID string `json:"node_id"`
		Tag    string `json:"tag"`
		SHA    string `json:"sha"`
		Object struct {
			Type string `json:"type"`
			SHA  string `json:"sha"`
		} `json:"object"`
	}
	if err := decodeJSON(response, &document, operation); err != nil {
		return result, err
	}
	if document.Tag == "" || len(document.Tag) > maxGitTagNameBytes || strings.ContainsRune(document.Tag, 0) {
		return result, malformedError(operation, response, "Git tag response omitted a bounded tag name")
	}

	returnedTag := GitObjectID{Algorithm: tagObject.Algorithm, Value: document.SHA}
	if !validFullGitObjectID(returnedTag) {
		return result, malformedError(operation, response, "Git tag response contained an invalid tag object ID")
	}
	if returnedTag != tagObject {
		return result, malformedError(operation, response, "Git tag response object ID did not match the requested tag object")
	}

	targetKind := GitObjectKind(document.Object.Type)
	if !targetKind.Valid() {
		return result, malformedError(operation, response, "Git tag response contained an unsupported target object type")
	}
	targetID := GitObjectID{Algorithm: tagObject.Algorithm, Value: document.Object.SHA}
	if !validFullGitObjectID(targetID) {
		return result, malformedError(operation, response, "Git tag response contained an invalid target object ID")
	}

	result.Value = GitTagObject{
		TagObjectID: returnedTag,
		NodeID:      document.NodeID,
		TagName:     document.Tag,
		Target:      GitObjectTarget{Kind: targetKind, ObjectID: targetID},
	}
	return result, nil
}

func validFullGitObjectID(object GitObjectID) bool {
	wantLength := 0
	switch object.Algorithm {
	case "sha1":
		wantLength = 40
	case "sha256":
		wantLength = 64
	default:
		return false
	}
	if len(object.Value) != wantLength || object.Value != strings.ToLower(object.Value) {
		return false
	}
	_, err := hex.DecodeString(object.Value)
	return err == nil
}
