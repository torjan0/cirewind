package githubapi

import (
	"context"
	"net/url"
)

const maxGitCommitParents = 16_384

// GetGitCommit positively types one complete Git object ID as a commit. A
// not-found response is not reinterpreted as another object kind.
func (c *Client) GetGitCommit(ctx context.Context, owner, repository string, commitObject GitObjectID) (ObjectResult[GitCommitObject], error) {
	ownerPart, repositoryPart, err := repositoryParts(owner, repository)
	if err != nil {
		return ObjectResult[GitCommitObject]{}, err
	}
	if !validFullGitObjectID(commitObject) {
		return ObjectResult[GitCommitObject]{}, invalidArgument("get Git commit", "commit object ID must be a supported algorithm-qualified full lowercase object ID")
	}
	operation := "get Git commit"
	response, getErr := c.get(ctx, requestSpec{
		routeTemplate: "/repos/{owner}/{repo}/git/commits/{commit_sha}",
		path:          "/repos/" + ownerPart + "/" + repositoryPart + "/git/commits/" + url.PathEscape(commitObject.Value),
		parameters: map[string]string{
			"owner": owner, "repo": repository,
			"commit_algorithm": commitObject.Algorithm, "commit_sha": commitObject.Value,
		},
		operation: operation,
	})
	result := ObjectResult[GitCommitObject]{Responses: response.attempts}
	if getErr != nil {
		return result, getErr
	}
	var document struct {
		SHA    string `json:"sha"`
		NodeID string `json:"node_id"`
		Tree   struct {
			SHA string `json:"sha"`
		} `json:"tree"`
		Parents []struct {
			SHA string `json:"sha"`
		} `json:"parents"`
	}
	if err := decodeJSON(response, &document, operation); err != nil {
		return result, err
	}
	returned := GitObjectID{Algorithm: commitObject.Algorithm, Value: document.SHA}
	if !validFullGitObjectID(returned) || returned != commitObject {
		return result, malformedError(operation, response, "Git commit response object ID was invalid or did not match the request")
	}
	tree := GitObjectID{Algorithm: commitObject.Algorithm, Value: document.Tree.SHA}
	if !validFullGitObjectID(tree) {
		return result, malformedError(operation, response, "Git commit response contained an invalid tree object ID")
	}
	if len(document.Parents) > maxGitCommitParents {
		return result, malformedError(operation, response, "Git commit response exceeded the parent limit")
	}
	parents := make([]GitObjectID, len(document.Parents))
	for index, parent := range document.Parents {
		parents[index] = GitObjectID{Algorithm: commitObject.Algorithm, Value: parent.SHA}
		if !validFullGitObjectID(parents[index]) {
			return result, malformedError(operation, response, "Git commit response contained an invalid parent object ID")
		}
	}
	result.Value = GitCommitObject{CommitObjectID: returned, NodeID: document.NodeID, TreeObjectID: tree, ParentObjectIDs: parents}
	return result, nil
}
