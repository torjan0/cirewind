package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

var createSchemaObject = regexp.MustCompile(`(?m)^CREATE[[:space:]]+(TABLE|INDEX)[[:space:]]+([A-Za-z0-9_]+)[[:space:]]`)

const maxSchemaDDLBytes = 1 << 20

// validateSchema rejects substituted tables, views, triggers, virtual tables,
// and unrecognized objects before an imported database reaches replay queries.
// The normalized DDL comes from the compiled migration, not the archive.
func (s *Store) validateSchema(ctx context.Context) error {
	expected, err := compiledSchemaDDL()
	if err != nil {
		return err
	}
	var objectCount, maximumDDLBytes int64
	if err := s.db.QueryRowContext(ctx, `
		SELECT count(*),coalesce(max(length(sql)),0) FROM sqlite_schema
		WHERE name NOT LIKE 'sqlite_%'`).Scan(&objectCount, &maximumDDLBytes); err != nil {
		return fmt.Errorf("inspect SQLite schema budget: %w", err)
	}
	if objectCount != int64(len(expected)) {
		return fmt.Errorf("archive schema object count %d differs from required count %d", objectCount, len(expected))
	}
	if maximumDDLBytes < 0 || maximumDDLBytes > maxSchemaDDLBytes {
		return fmt.Errorf("archive schema definition exceeds the compiled %d-byte limit", maxSchemaDDLBytes)
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT type,name,sql FROM sqlite_schema
		WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name`)
	if err != nil {
		return fmt.Errorf("inspect SQLite schema: %w", err)
	}
	defer rows.Close()
	seen := make(map[string]struct{}, len(expected))
	for rows.Next() {
		var objectType, name string
		var ddl sql.NullString
		if err := rows.Scan(&objectType, &name, &ddl); err != nil {
			return fmt.Errorf("read SQLite schema object: %w", err)
		}
		key := objectType + ":" + name
		want, ok := expected[key]
		if !ok {
			return fmt.Errorf("archive schema contains unsupported %s %q", bounded(objectType, 32), bounded(name, 256))
		}
		if !ddl.Valid || normalizeDDL(ddl.String) != want {
			return fmt.Errorf("archive schema definition differs for %s %q", objectType, bounded(name, 256))
		}
		seen[key] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate SQLite schema: %w", err)
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("close SQLite schema rows: %w", err)
	}
	missing := make([]string, 0)
	for key := range expected {
		if _, ok := seen[key]; !ok {
			missing = append(missing, key)
		}
	}
	if len(missing) != 0 {
		sort.Strings(missing)
		return fmt.Errorf("archive schema is missing required object %q", missing[0])
	}
	return nil
}

func compiledSchemaDDL() (map[string]string, error) {
	result := make(map[string]string)
	for _, statement := range strings.Split(schemaV1, ";") {
		match := createSchemaObject.FindStringSubmatchIndex(statement)
		if match == nil {
			continue
		}
		objectType := strings.ToLower(statement[match[2]:match[3]])
		name := statement[match[4]:match[5]]
		ddl := strings.TrimSpace(statement[match[0]:])
		key := objectType + ":" + name
		if _, duplicate := result[key]; duplicate {
			return nil, fmt.Errorf("compiled schema repeats %s", key)
		}
		result[key] = normalizeDDL(ddl)
	}
	if len(result) == 0 {
		return nil, errors.New("compiled SQLite schema has no objects")
	}
	return result, nil
}

func normalizeDDL(value string) string {
	return strings.Join(strings.Fields(value), " ")
}
