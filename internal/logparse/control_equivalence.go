package logparse

import "context"

// EqualRunnerControlText reports whether two GitHub-provided log views contain
// exactly the same timestamped runner payload records in the same order.
// GitHub's root whole-job and nested per-step archive views have been observed
// to render the same runner records with slightly different view timestamps,
// so timestamps are validated but deliberately excluded from equality.
//
// Callers must first bind both archive entries to the same API job and role.
// This function does not establish identity and must never be used to merge
// two entries of the same structural layout.
func EqualRunnerControlText(ctx context.Context, left, right []byte) (bool, error) {
	leftRecords, leftOK, err := runnerControlText(ctx, left)
	if err != nil || !leftOK {
		return false, err
	}
	rightRecords, rightOK, err := runnerControlText(ctx, right)
	if err != nil || !rightOK || len(leftRecords) != len(rightRecords) {
		return false, err
	}
	return equalControlPrefix(leftRecords, rightRecords), nil
}

// RunnerControlTextIsPrefix reports whether prefix contains exactly the first
// timestamped runner payload records in body. It is used only for the bounded
// current GitHub archive duplication where a consolidated lifecycle frame is
// the complete first repository-Action details group and the nested step view
// may also contain later main/post output. The suffix is not declared equal or
// parsed as part of the selected lifecycle frame.
func RunnerControlTextIsPrefix(ctx context.Context, prefix, body []byte) (bool, error) {
	prefixRecords, prefixOK, err := runnerControlText(ctx, prefix)
	if err != nil || !prefixOK {
		return false, err
	}
	bodyRecords, bodyOK, err := runnerControlText(ctx, body)
	if err != nil || !bodyOK || len(prefixRecords) > len(bodyRecords) {
		return false, err
	}
	return equalControlPrefix(prefixRecords, bodyRecords), nil
}

func runnerControlText(ctx context.Context, body []byte) ([]string, bool, error) {
	if len(body) == 0 || len(body) > MaxConsolidatedJobBytes {
		return nil, false, nil
	}
	lines, diagnostic, err := scanConsolidatedLines(ctx, body)
	if err != nil || diagnostic != nil || len(lines) == 0 {
		return nil, false, err
	}
	result := make([]string, len(lines))
	for index, line := range lines {
		if line.when == nil {
			return nil, false, nil
		}
		result[index] = line.text
	}
	return result, true, nil
}

func equalControlPrefix(prefix, body []string) bool {
	for index := range prefix {
		if prefix[index] != body[index] {
			return false
		}
	}
	return true
}
