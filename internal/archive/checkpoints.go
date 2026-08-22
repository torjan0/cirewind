package archive

import (
	"context"
	"errors"
	"fmt"
)

// Checkpoints reads only the bounded incremental scheduler state. Archive
// polling does not need to materialize every retained evidence payload merely
// to decide which parent runs must be revisited.
func (a *Archive) Checkpoints(ctx context.Context) ([]Checkpoint, error) {
	if a == nil || a.store == nil {
		return nil, errors.New("archive is not open")
	}
	var checkpoints, parents int64
	if err := a.store.DB().QueryRowContext(ctx, `SELECT count(*) FROM archive_checkpoints`).Scan(&checkpoints); err != nil {
		return nil, fmt.Errorf("inspect archive checkpoint count: %w", err)
	}
	if err := a.store.DB().QueryRowContext(ctx, `SELECT count(*) FROM watched_parents`).Scan(&parents); err != nil {
		return nil, fmt.Errorf("inspect watched-parent count: %w", err)
	}
	if checkpoints < 0 || checkpoints > maxSnapshotEvidence || parents < 0 || parents > maxSnapshotEvidence {
		return nil, errors.New("persisted incremental scheduler state exceeds the compiled count limit")
	}
	var missingCollections, orphanParents int64
	if err := a.store.DB().QueryRowContext(ctx, `
		SELECT count(*) FROM archive_checkpoints cp
		LEFT JOIN collection_sessions cs ON cs.collection_id=cp.last_successful_collection_id
		WHERE cs.collection_id IS NULL`).Scan(&missingCollections); err != nil {
		return nil, fmt.Errorf("inspect checkpoint collection references: %w", err)
	}
	if err := a.store.DB().QueryRowContext(ctx, `
		SELECT count(*) FROM watched_parents wp
		LEFT JOIN archive_checkpoints cp ON cp.repository_id=wp.repository_id
		WHERE cp.repository_id IS NULL`).Scan(&orphanParents); err != nil {
		return nil, fmt.Errorf("inspect watched-parent references: %w", err)
	}
	if missingCollections != 0 || orphanParents != 0 {
		return nil, errors.New("persisted incremental scheduler state has broken references")
	}
	result, err := readCheckpoints(ctx, a.store.DB())
	if err != nil {
		return nil, fmt.Errorf("read archive checkpoints: %w", err)
	}
	for index := range result {
		if err := result[index].Validate(); err != nil {
			return nil, fmt.Errorf("validate archive checkpoint %d: %w", index, err)
		}
		if index > 0 && result[index-1].RepositoryID >= result[index].RepositoryID {
			return nil, errors.New("persisted archive checkpoints are not unique and sorted")
		}
		if result[index].WatchedParents != nil {
			parents := make([]WatchedParent, len(result[index].WatchedParents))
			copy(parents, result[index].WatchedParents)
			result[index].WatchedParents = parents
		}
	}
	return result, nil
}
