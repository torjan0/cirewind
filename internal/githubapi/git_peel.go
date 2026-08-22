package githubapi

import (
	"context"
	"errors"
	"fmt"
)

const maxGitTagPeelDepth = 8

// PeelGitObjectToCommit positively types recorded as either an annotated tag
// object or a commit, follows at most eight evidence-backed tag hops, and
// positively validates the terminal commit. The recorded object is never
// overwritten by the peeled commit.
func (c *Client) PeelGitObjectToCommit(ctx context.Context, owner, repository string, recorded GitObjectID) (GitObjectPeel, error) {
	result := GitObjectPeel{RecordedObjectID: recorded, TagObjects: []GitTagObject{}, Responses: []ResponseMeta{}}
	if !validFullGitObjectID(recorded) {
		return result, invalidArgument("peel Git object", "recorded object ID must be a supported algorithm-qualified full lowercase object ID")
	}

	firstTag, tagErr := c.GetGitTag(ctx, owner, repository, recorded)
	result.Responses = append(result.Responses, firstTag.Responses...)
	if tagErr == nil {
		result.RecordedKind = GitObjectTag
		result.TagObjects = append(result.TagObjects, firstTag.Value)
		return c.peelKnownTagTarget(ctx, owner, repository, result, firstTag.Value.Target)
	}
	if !IsClass(tagErr, ErrorNotFound) {
		return result, fmt.Errorf("type recorded Git object as tag: %w", tagErr)
	}

	commit, commitErr := c.GetGitCommit(ctx, owner, repository, recorded)
	result.Responses = append(result.Responses, commit.Responses...)
	if commitErr != nil {
		return result, fmt.Errorf("positively type recorded Git object as commit after tag miss: %w", commitErr)
	}
	result.RecordedKind = GitObjectCommit
	result.CommitObject = &commit.Value
	return result, nil
}

func (c *Client) peelKnownTagTarget(ctx context.Context, owner, repository string, result GitObjectPeel, target GitObjectTarget) (GitObjectPeel, error) {
	visited := map[GitObjectID]bool{result.RecordedObjectID: true}
	for depth := 1; depth <= maxGitTagPeelDepth; depth++ {
		if err := ctx.Err(); err != nil {
			return result, err
		}
		switch target.Kind {
		case GitObjectCommit:
			commit, err := c.GetGitCommit(ctx, owner, repository, target.ObjectID)
			result.Responses = append(result.Responses, commit.Responses...)
			if err != nil {
				return result, fmt.Errorf("positively type peeled Git commit: %w", err)
			}
			result.CommitObject = &commit.Value
			return result, nil
		case GitObjectTag:
			if visited[target.ObjectID] {
				return result, errors.New("Git tag peel cycle detected")
			}
			visited[target.ObjectID] = true
			tag, err := c.GetGitTag(ctx, owner, repository, target.ObjectID)
			result.Responses = append(result.Responses, tag.Responses...)
			if err != nil {
				return result, fmt.Errorf("read nested Git tag object: %w", err)
			}
			result.TagObjects = append(result.TagObjects, tag.Value)
			target = tag.Value.Target
		case GitObjectTree, GitObjectBlob:
			return result, fmt.Errorf("Git tag peel ended at unsupported %s object", target.Kind)
		default:
			return result, errors.New("Git tag peel encountered an invalid target kind")
		}
	}
	return result, errors.New("Git tag peel exceeded the maximum depth")
}
