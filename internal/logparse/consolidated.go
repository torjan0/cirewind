package logparse

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

// ConsolidatedGrammarVersion names the bounded whole-job grammar observed in
// current GitHub.com attempt-log archives. Its setup download block follows
// the exact grammar used by the pinned GitHub-maintained
// audit-actions-workflow-runs parser; its job and step boundaries are stricter.
const ConsolidatedGrammarVersion = "github-attempt-log-consolidated/v1alpha1"

// MaxConsolidatedJobBytes is an independent in-memory framing ceiling below
// the ZIP entry ceiling. Larger whole-job logs remain retained source evidence
// (when requested) but are not parsed as runner-control evidence.
const MaxConsolidatedJobBytes = 64 << 20

type ConsolidatedStep struct {
	Number int
	Name   string
	// ExpectedAction is populated only from an exact historical workflow step
	// that the collector already bound to this API job and step number/name.
	ExpectedAction  string
	HistoricalBound bool
	Status          string
	Conclusion      string
	StartedAt       *time.Time
	CompletedAt     *time.Time
}

type ConsolidatedFrame struct {
	Role          EntryRole
	APIStepNumber int
	LineStart     int
	LineEnd       int
	Bytes         []byte
	// AdjacentRun preserves at most the one complete Run group immediately
	// following a top-level Action details group. It is not execution evidence
	// by itself: the collector may consume it only after exact composite
	// metadata proves that the parent's first unconditional operation is the
	// same repository Action. This narrow prefix is the only part of a
	// composite step that precedes application-controlled Action output.
	AdjacentRun *ConsolidatedRunGroup
}

type ConsolidatedRunGroup struct {
	LineStart     int
	LineEnd       int
	Bytes         []byte
	EvidenceBytes []byte
	MarkerLine    int
	MarkerDisplay string
	MarkerID      string
}

type ConsolidatedDiagnostic struct {
	Code          string
	Line          int
	APIStepNumber int
	Error         string
}

type ConsolidatedResult struct {
	Setup       *ConsolidatedFrame
	ActionSteps []ConsolidatedFrame
	Diagnostics []ConsolidatedDiagnostic
	Complete    bool
}

type consolidatedLine struct {
	number int
	start  int
	end    int
	when   *time.Time
	text   string
}

var (
	consolidatedVersion                  = regexp.MustCompile(`^Version: [A-Za-z0-9._-]{1,256}$`)
	consolidatedSource                   = regexp.MustCompile(`^Source commit SHA: [0-9A-Fa-f]{40}(?:[0-9A-Fa-f]{24})?$`)
	consolidatedDigest                   = regexp.MustCompile(`^Digest: sha256:[0-9A-Fa-f]{64}$`)
	consolidatedReusableWorkflowByRef    = regexp.MustCompile(`^Uses: ([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/\.github/workflows/[A-Za-z0-9_./-]+\.(?:yml|yaml))@(refs/(?:heads|tags)/[^[:space:]()]+) \(([0-9a-f]{40}|[0-9a-f]{64})\)$`)
	consolidatedReusableWorkflowByObject = regexp.MustCompile(`^Uses: ([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/\.github/workflows/[A-Za-z0-9_./-]+\.(?:yml|yaml))@([0-9a-f]{40}|[0-9a-f]{64})$`)
	consolidatedReusableInput            = regexp.MustCompile(`^  ([A-Za-z0-9_.-]{1,256}):(?: .*)?$`)
	consolidatedCompositeMarkerID        = regexp.MustCompile(`^__[A-Za-z0-9_.-]+$`)
)

// FrameConsolidatedJob recognizes only a structurally complete root whole-job
// stream after the collector has already bound its archive entry to one API
// job. It never treats later workflow output as setup evidence. For Action
// steps it emits only the first runner group in the exact API step interval;
// this ensures a shell step's own group wins over any forged group printed by
// the shell later.
func FrameConsolidatedJob(ctx context.Context, body []byte, jobName string, steps []ConsolidatedStep) (ConsolidatedResult, error) {
	result := ConsolidatedResult{}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	if len(body) == 0 || len(body) > MaxConsolidatedJobBytes {
		result.Diagnostics = append(result.Diagnostics, ConsolidatedDiagnostic{Code: "CONSOLIDATED_SIZE_LIMIT", Error: "whole-job log is empty or exceeds the framing ceiling"})
		return result, nil
	}
	if !safeCorrelationText(jobName) {
		result.Diagnostics = append(result.Diagnostics, ConsolidatedDiagnostic{Code: "AMBIGUOUS_JOB_IDENTITY", Error: "API job name is empty or contains structural control data"})
		return result, nil
	}
	lines, diagnostic, err := scanConsolidatedLines(ctx, body)
	if err != nil {
		return result, err
	}
	if diagnostic != nil {
		result.Diagnostics = append(result.Diagnostics, *diagnostic)
		return result, nil
	}
	if len(lines) == 0 || !validConsolidatedRunnerVersion(lines[0].text) {
		result.Diagnostics = append(result.Diagnostics, ConsolidatedDiagnostic{Code: "UNSUPPORTED_CONSOLIDATED_GRAMMAR", Line: 1, Error: "whole-job log does not begin with the pinned runner-version record"})
		return result, nil
	}

	boundary, boundaryDiagnostic := consolidatedSetupBoundary(lines, jobName)
	if boundaryDiagnostic != nil {
		result.Diagnostics = append(result.Diagnostics, *boundaryDiagnostic)
		return result, nil
	}
	if diagnostic := validateConsolidatedSetupTime(lines[:boundary+1]); diagnostic != nil {
		result.Diagnostics = append(result.Diagnostics, *diagnostic)
		return result, nil
	}
	if diagnostic := validateConsolidatedPermissions(lines[:boundary+1]); diagnostic != nil {
		result.Diagnostics = append(result.Diagnostics, *diagnostic)
		return result, nil
	}
	if diagnostic := validateConsolidatedDownloads(lines[:boundary+1]); diagnostic != nil {
		result.Diagnostics = append(result.Diagnostics, *diagnostic)
		return result, nil
	}

	result.Setup = &ConsolidatedFrame{
		Role: RoleSetup, LineStart: 1, LineEnd: lines[boundary].number,
		Bytes: append([]byte(nil), body[:lines[boundary].end]...),
	}
	frames, diagnostics := frameConsolidatedActionSteps(lines, boundary, body, steps)
	result.ActionSteps = frames
	result.Diagnostics = append(result.Diagnostics, diagnostics...)
	result.Complete = true
	return result, nil
}

func validConsolidatedRunnerVersion(value string) bool {
	const prefix = "Current runner version: '"
	if !strings.HasPrefix(value, prefix) || !strings.HasSuffix(value, "'") {
		return false
	}
	version := strings.TrimSuffix(strings.TrimPrefix(value, prefix), "'")
	if len(version) == 0 || len(version) > 256 {
		return false
	}
	for _, char := range version {
		if (char < 'a' || char > 'z') && (char < 'A' || char > 'Z') && (char < '0' || char > '9') && char != '.' && char != '-' && char != '_' && char != '+' {
			return false
		}
	}
	return true
}

func scanConsolidatedLines(ctx context.Context, body []byte) ([]consolidatedLine, *ConsolidatedDiagnostic, error) {
	lines := make([]consolidatedLine, 0, bytes.Count(body, []byte{'\n'})+1)
	for start, number := 0, 1; start < len(body); number++ {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		relativeEnd := bytes.IndexByte(body[start:], '\n')
		end := len(body)
		contentEnd := end
		if relativeEnd >= 0 {
			contentEnd = start + relativeEnd
			end = contentEnd + 1
		}
		if contentEnd-start > MaxLogLineBytes {
			return nil, &ConsolidatedDiagnostic{Code: "CONSOLIDATED_LINE_LIMIT", Line: number, Error: "whole-job record exceeds the line ceiling"}, nil
		}
		content := body[start:contentEnd]
		if len(content) > 0 && content[len(content)-1] == '\r' {
			content = content[:len(content)-1]
		}
		if !utf8.Valid(content) {
			return nil, &ConsolidatedDiagnostic{Code: "UNSUPPORTED_CONSOLIDATED_GRAMMAR", Line: number, Error: "whole-job record is not valid UTF-8"}, nil
		}
		lineText := string(content)
		if number == 1 {
			lineText = strings.TrimPrefix(lineText, "\uFEFF")
		}
		when, text := splitTimestamp(lineText)
		lines = append(lines, consolidatedLine{number: number, start: start, end: end, when: when, text: text})
		start = end
	}
	return lines, nil, nil
}

func validateConsolidatedSetupTime(lines []consolidatedLine) *ConsolidatedDiagnostic {
	previous := time.Time{}
	for _, line := range lines {
		if line.when == nil {
			return &ConsolidatedDiagnostic{Code: "UNSUPPORTED_CONSOLIDATED_GRAMMAR", Line: line.number, Error: "runner-owned setup record is not timestamped"}
		}
		if !previous.IsZero() && line.when.Before(previous) {
			return &ConsolidatedDiagnostic{Code: "NON_MONOTONIC_CONSOLIDATED_TIME", Line: line.number, Error: "runner-owned setup timestamps moved backwards"}
		}
		previous = *line.when
	}
	return nil
}

func consolidatedSetupBoundary(lines []consolidatedLine, jobName string) (int, *ConsolidatedDiagnostic) {
	const prefix = "Complete job name: "
	boundary := -1
	for index, line := range lines {
		if strings.HasPrefix(line.text, "##[group]Run ") {
			if boundary < 0 {
				return 0, &ConsolidatedDiagnostic{Code: "MISSING_SETUP_BOUNDARY", Line: line.number, Error: "normal step group occurred before an exact complete-job-name record"}
			}
			break
		}
		if strings.HasPrefix(line.text, "Complete job name:") {
			if boundary >= 0 {
				return 0, &ConsolidatedDiagnostic{Code: "AMBIGUOUS_SETUP_BOUNDARY", Line: line.number, Error: "multiple complete-job-name records precede trusted framing"}
			}
			if line.text != prefix+jobName {
				return 0, &ConsolidatedDiagnostic{Code: "AMBIGUOUS_JOB_IDENTITY", Line: line.number, Error: "complete-job-name record does not exactly match the bound API job"}
			}
			boundary = index
		}
	}
	if boundary < 0 {
		return 0, &ConsolidatedDiagnostic{Code: "MISSING_SETUP_BOUNDARY", Error: "whole-job log has no exact complete-job-name record"}
	}
	return boundary, nil
}

func validateConsolidatedPermissions(lines []consolidatedLine) *ConsolidatedDiagnostic {
	groups := 0
	for index := 0; index < len(lines); index++ {
		if lines[index].text != "##[group]GITHUB_TOKEN Permissions" {
			continue
		}
		groups++
		if groups > 1 {
			return &ConsolidatedDiagnostic{Code: "AMBIGUOUS_PERMISSION_GROUP", Line: lines[index].number, Error: "multiple token-permission groups occurred in setup"}
		}
		closed := false
		for index++; index < len(lines); index++ {
			text := strings.TrimSpace(lines[index].text)
			if text == "##[endgroup]" {
				closed = true
				break
			}
			if permissionPattern.FindStringSubmatch(text) == nil {
				return &ConsolidatedDiagnostic{Code: "UNSUPPORTED_PERMISSION_GROUP", Line: lines[index].number, Error: "token-permission record is outside the pinned grammar"}
			}
		}
		if !closed {
			return &ConsolidatedDiagnostic{Code: "TRUNCATED_PERMISSION_GROUP", Line: lines[len(lines)-1].number, Error: "token-permission group has no closing runner record"}
		}
	}
	return nil
}

func validateConsolidatedDownloads(lines []consolidatedLine) *ConsolidatedDiagnostic {
	const sentinel = "Getting action download info"
	boundary := len(lines) - 1
	downloadBoundary := boundary
	usesIndex := -1
	for index := 0; index < boundary; index++ {
		if strings.HasPrefix(lines[index].text, "Uses: ") {
			if usesIndex >= 0 {
				return &ConsolidatedDiagnostic{Code: "AMBIGUOUS_REUSABLE_WORKFLOW_IDENTITY", Line: lines[index].number, Error: "multiple called-workflow setup identities occurred before setup completion"}
			}
			usesIndex = index
		}
		if lines[index].text == "##[group] Inputs" && usesIndex < 0 {
			return &ConsolidatedDiagnostic{Code: "AMBIGUOUS_REUSABLE_WORKFLOW_INPUTS", Line: lines[index].number, Error: "called-workflow inputs occurred without a preceding exact setup identity"}
		}
	}
	if usesIndex >= 0 {
		if diagnostic := validateConsolidatedReusableTail(lines, usesIndex, boundary); diagnostic != nil {
			return diagnostic
		}
		downloadBoundary = usesIndex
	}
	firstSentinel := -1
	for index := 0; index < downloadBoundary; index++ {
		if lines[index].text == sentinel {
			firstSentinel = index
			break
		}
		if downloadPattern.MatchString(lines[index].text) || immutablePattern.MatchString(lines[index].text) {
			return &ConsolidatedDiagnostic{Code: "AMBIGUOUS_DOWNLOAD_BLOCK", Line: lines[index].number, Error: "Action record occurred before the runner download sentinel"}
		}
	}
	if firstSentinel < 0 {
		return nil
	}

	// Current GitHub-hosted runners may emit another exact sentinel while
	// preparing a recursively discovered composite dependency. Each sentinel
	// therefore opens one bounded block and must be followed by at least one
	// complete mutable or immutable Action record before the next sentinel or
	// setup boundary. No other runner or application record is admitted.
	for index := firstSentinel; index < downloadBoundary; {
		if lines[index].text != sentinel {
			return &ConsolidatedDiagnostic{Code: "UNSUPPORTED_DOWNLOAD_BLOCK", Line: lines[index].number, Error: "record between Action-download blocks is outside the pinned grammar"}
		}
		blockSentinel := lines[index]
		index++
		actions := 0
		for index < downloadBoundary && lines[index].text != sentinel {
			line := lines[index]
			switch {
			case strings.HasPrefix(line.text, "Download action repository '"):
				match := downloadPattern.FindStringSubmatch(line.text)
				if match == nil {
					return &ConsolidatedDiagnostic{Code: "MALFORMED_ACTION_RESOLUTION", Line: line.number, Error: "mutable Action record is outside the pinned grammar"}
				}
				if _, err := parseResolvedAction(match[1], match[2], ""); err != nil {
					return &ConsolidatedDiagnostic{Code: "MALFORMED_ACTION_RESOLUTION", Line: line.number, Error: err.Error()}
				}
				actions++
				index++
			case strings.HasPrefix(line.text, "##[group]Download immutable action package '"):
				next, diagnostic := validateConsolidatedImmutable(lines, index, boundary)
				if diagnostic != nil {
					return diagnostic
				}
				actions++
				index = next
			default:
				return &ConsolidatedDiagnostic{Code: "UNSUPPORTED_DOWNLOAD_BLOCK", Line: line.number, Error: "record inside the Action-download block is outside the pinned grammar"}
			}
		}
		if actions == 0 {
			// A single empty block immediately before setup completion is the
			// observed no-repository-Action shape. Repeated/earlier empty blocks
			// are ambiguous and cannot delimit recursive preparation.
			if firstSentinel == index-1 && index == downloadBoundary {
				return nil
			}
			return &ConsolidatedDiagnostic{Code: "MISSING_ACTION_RESOLUTION", Line: blockSentinel.number, Error: "Action-download sentinel was not followed by an Action record"}
		}
	}
	return nil
}

func validConsolidatedReusableWorkflow(value string) bool {
	match := consolidatedReusableWorkflowByRef.FindStringSubmatch(value)
	if match != nil {
		if !validConsolidatedWorkflowPath(match[1]) {
			return false
		}
		ref := match[2]
		if len(ref) > 1024 || strings.Contains(ref, "..") || strings.Contains(ref, "@{") || strings.ContainsAny(ref, "~^:?*[\\\x00\r\n") || strings.HasSuffix(ref, "/") || strings.HasSuffix(ref, ".") {
			return false
		}
		return validateOID("", match[3]) == nil
	}
	match = consolidatedReusableWorkflowByObject.FindStringSubmatch(value)
	if match == nil || !validConsolidatedWorkflowPath(match[1]) {
		return false
	}
	return validateOID("", match[2]) == nil
}

func validConsolidatedWorkflowPath(value string) bool {
	segments := strings.Split(value, "/")
	if len(segments) < 5 || segments[2] != ".github" || segments[3] != "workflows" {
		return false
	}
	for _, segment := range segments {
		if segment == "" || segment == "." || segment == ".." {
			return false
		}
	}
	return true
}

func validateConsolidatedReusableTail(lines []consolidatedLine, usesIndex, boundary int) *ConsolidatedDiagnostic {
	if !validConsolidatedReusableWorkflow(lines[usesIndex].text) {
		return &ConsolidatedDiagnostic{Code: "MALFORMED_REUSABLE_WORKFLOW_IDENTITY", Line: lines[usesIndex].number, Error: "called-workflow setup identity is outside the pinned grammar"}
	}
	if usesIndex+1 == boundary {
		return nil
	}
	if lines[usesIndex+1].text != "##[group] Inputs" {
		return &ConsolidatedDiagnostic{Code: "UNSUPPORTED_REUSABLE_WORKFLOW_TAIL", Line: lines[usesIndex+1].number, Error: "record after called-workflow identity is outside the pinned setup grammar"}
	}
	if usesIndex+4 > boundary || lines[boundary-1].text != "##[endgroup]" {
		return &ConsolidatedDiagnostic{Code: "TRUNCATED_REUSABLE_WORKFLOW_INPUTS", Line: lines[usesIndex+1].number, Error: "called-workflow inputs group is empty or lacks an exact closing runner record"}
	}
	for index := usesIndex + 2; index < boundary-1; index++ {
		if !consolidatedReusableInput.MatchString(lines[index].text) || strings.ContainsRune(lines[index].text, '\x1b') || hasStructuralControl(lines[index].text) {
			return &ConsolidatedDiagnostic{Code: "UNSUPPORTED_REUSABLE_WORKFLOW_INPUTS", Line: lines[index].number, Error: "called-workflow input record is outside the pinned bounded grammar"}
		}
	}
	return nil
}

func validateConsolidatedImmutable(lines []consolidatedLine, start, boundary int) (int, *ConsolidatedDiagnostic) {
	match := immutablePattern.FindStringSubmatch(lines[start].text)
	if match == nil {
		return 0, &ConsolidatedDiagnostic{Code: "MALFORMED_IMMUTABLE_PACKAGE_GROUP", Line: lines[start].number, Error: "immutable Action announcement is malformed"}
	}
	if _, err := parseDeclaredAction(match[1]); err != nil {
		return 0, &ConsolidatedDiagnostic{Code: "MALFORMED_IMMUTABLE_PACKAGE_GROUP", Line: lines[start].number, Error: err.Error()}
	}
	seenVersion, seenSource, seenDigest := false, false, false
	for index := start + 1; index < boundary && index <= start+4; index++ {
		text := lines[index].text
		if text == "##[endgroup]" {
			if !seenVersion || !seenSource || !seenDigest {
				return 0, &ConsolidatedDiagnostic{Code: "INCOMPLETE_IMMUTABLE_PACKAGE_GROUP", Line: lines[index].number, Error: "immutable Action group omitted version, source SHA, or digest"}
			}
			return index + 1, nil
		}
		switch {
		case consolidatedVersion.MatchString(text) && !seenVersion:
			seenVersion = true
		case consolidatedSource.MatchString(text) && !seenSource:
			seenSource = true
		case consolidatedDigest.MatchString(text) && !seenDigest:
			seenDigest = true
		default:
			return 0, &ConsolidatedDiagnostic{Code: "MALFORMED_IMMUTABLE_PACKAGE_GROUP", Line: lines[index].number, Error: "immutable Action field is duplicated or outside the pinned grammar"}
		}
	}
	return 0, &ConsolidatedDiagnostic{Code: "INCOMPLETE_IMMUTABLE_PACKAGE_GROUP", Line: lines[start].number, Error: "immutable Action group has no exact closing runner record"}
}

func frameConsolidatedActionSteps(lines []consolidatedLine, boundary int, body []byte, steps []ConsolidatedStep) ([]ConsolidatedFrame, []ConsolidatedDiagnostic) {
	ordered := append([]ConsolidatedStep(nil), steps...)
	sort.SliceStable(ordered, func(i, j int) bool {
		if ordered[i].StartedAt == nil || ordered[i].StartedAt.IsZero() {
			return false
		}
		if ordered[j].StartedAt == nil || ordered[j].StartedAt.IsZero() {
			return true
		}
		if !ordered[i].StartedAt.Equal(*ordered[j].StartedAt) {
			return ordered[i].StartedAt.Before(*ordered[j].StartedAt)
		}
		return ordered[i].Number < ordered[j].Number
	})
	numberCount := make(map[int]int, len(ordered))
	startCount := make(map[int64]int, len(ordered))
	for _, step := range ordered {
		numberCount[step.Number]++
		if step.StartedAt != nil && !step.StartedAt.IsZero() {
			startCount[step.StartedAt.UTC().UnixNano()]++
		}
	}

	frames := make([]ConsolidatedFrame, 0)
	diagnostics := make([]ConsolidatedDiagnostic, 0)
	groupLines := make([]int, 0)
	previousGroupTime := time.Time{}
	for index := boundary + 1; index < len(lines); index++ {
		if strings.HasPrefix(lines[index].text, "##[group]") {
			if lines[index].when == nil {
				return frames, []ConsolidatedDiagnostic{{Code: "UNSUPPORTED_ACTION_FRAME", Line: lines[index].number, Error: "runner group is not timestamped"}}
			}
			if !previousGroupTime.IsZero() && lines[index].when.Before(previousGroupTime) {
				return frames, []ConsolidatedDiagnostic{{Code: "NON_MONOTONIC_ACTION_FRAME_TIME", Line: lines[index].number, Error: "runner-group timestamps moved backwards"}}
			}
			previousGroupTime = *lines[index].when
			groupLines = append(groupLines, index)
		}
	}
	for _, step := range ordered {
		expected := ""
		if step.HistoricalBound {
			expected = step.ExpectedAction
		} else if strings.HasPrefix(step.Name, "Run ") {
			expected = strings.TrimPrefix(step.Name, "Run ")
		}
		if expected == "" {
			continue
		}
		if _, err := parseDeclaredAction(expected); err != nil {
			continue
		}
		if strings.EqualFold(step.Conclusion, "skipped") || strings.EqualFold(step.Conclusion, "cancelled") || strings.EqualFold(step.Conclusion, "canceled") {
			continue
		}
		if step.Number <= 0 || numberCount[step.Number] != 1 {
			diagnostics = append(diagnostics, ConsolidatedDiagnostic{Code: "AMBIGUOUS_API_STEP", APIStepNumber: step.Number, Error: "API step number is missing or non-unique"})
			continue
		}
		if step.HistoricalBound {
			frame, diagnostic := frameHistoricallyBoundAction(lines, boundary, body, groupLines, step, expected)
			if diagnostic != nil {
				diagnostics = append(diagnostics, *diagnostic)
				continue
			}
			frames = append(frames, frame)
			continue
		}
		if step.StartedAt == nil || step.StartedAt.IsZero() {
			diagnostics = append(diagnostics, ConsolidatedDiagnostic{Code: "MISSING_API_STEP_START", APIStepNumber: step.Number, Error: "default-named Action step has no exact API start"})
			continue
		}
		start := step.StartedAt.UTC()
		if startCount[start.UnixNano()] != 1 {
			diagnostics = append(diagnostics, ConsolidatedDiagnostic{Code: "AMBIGUOUS_API_STEP_INTERVAL", APIStepNumber: step.Number, Error: "multiple API steps share the same start boundary"})
			continue
		}
		var nextStart *time.Time
		for _, candidate := range ordered {
			if candidate.StartedAt == nil || !candidate.StartedAt.After(start) {
				continue
			}
			candidateStart := candidate.StartedAt.UTC()
			if nextStart == nil || candidateStart.Before(*nextStart) {
				copy := candidateStart
				nextStart = &copy
			}
		}

		position := sort.Search(len(groupLines), func(index int) bool {
			return !lines[groupLines[index]].when.Before(start)
		})
		if position == len(groupLines) {
			continue
		}
		groupStart := groupLines[position]
		when := lines[groupStart].when
		if nextStart != nil && !when.Before(*nextStart) {
			continue
		}
		if step.CompletedAt != nil && !step.CompletedAt.IsZero() && !when.Before(step.CompletedAt.UTC().Add(time.Second)) {
			diagnostics = append(diagnostics, ConsolidatedDiagnostic{Code: "ACTION_FRAME_OUTSIDE_API_STEP", Line: lines[groupStart].number, APIStepNumber: step.Number, Error: "first runner group occurred after the API step completion bound"})
			continue
		}
		groupEnd := -1
		for index := groupStart + 1; index < len(lines); index++ {
			if lines[index].when == nil {
				diagnostics = append(diagnostics, ConsolidatedDiagnostic{Code: "UNSUPPORTED_ACTION_FRAME", Line: lines[index].number, APIStepNumber: step.Number, Error: "Action frame record is not timestamped"})
				break
			}
			if nextStart != nil && !lines[index].when.Before(*nextStart) {
				break
			}
			if lines[index].text == "##[endgroup]" {
				groupEnd = index
				break
			}
		}
		if groupEnd < 0 {
			diagnostics = append(diagnostics, ConsolidatedDiagnostic{Code: "TRUNCATED_ACTION_FRAME", Line: lines[groupStart].number, APIStepNumber: step.Number, Error: "first runner group in API step has no closing record"})
			continue
		}
		frame := ConsolidatedFrame{
			Role: RoleActionStep, APIStepNumber: step.Number,
			LineStart: lines[groupStart].number, LineEnd: lines[groupEnd].number,
			Bytes: append([]byte(nil), body[lines[groupStart].start:lines[groupEnd].end]...),
		}
		deadline := nextStart
		if step.CompletedAt != nil && !step.CompletedAt.IsZero() {
			completedBound := step.CompletedAt.UTC().Add(time.Second)
			if deadline == nil || completedBound.Before(*deadline) {
				deadline = &completedBound
			}
		}
		frame.AdjacentRun = frameAdjacentRunGroup(lines, body, groupEnd, deadline)
		frames = append(frames, frame)
	}
	sort.Slice(frames, func(i, j int) bool { return frames[i].APIStepNumber < frames[j].APIStepNumber })
	return frames, diagnostics
}

// frameHistoricallyBoundAction handles current API timestamps that are rounded
// to seconds and can collapse an Action step and Complete-job step onto the
// same boundary. Identity comes from the exact historical job/ordinal/name/uses
// binding; time is only a conservative containment check. The Action details
// group must be the first runner group in that API interval.
func frameHistoricallyBoundAction(lines []consolidatedLine, boundary int, body []byte, groupLines []int, step ConsolidatedStep, expected string) (ConsolidatedFrame, *ConsolidatedDiagnostic) {
	diagnostic := func(code string, line int, message string) (ConsolidatedFrame, *ConsolidatedDiagnostic) {
		return ConsolidatedFrame{}, &ConsolidatedDiagnostic{Code: code, Line: line, APIStepNumber: step.Number, Error: message}
	}
	if step.StartedAt == nil || step.StartedAt.IsZero() {
		return diagnostic("MISSING_API_STEP_START", 0, "historically bound Action step has no API start")
	}
	start := step.StartedAt.UTC()
	end := start.Add(time.Second)
	if step.CompletedAt != nil && !step.CompletedAt.IsZero() {
		completed := step.CompletedAt.UTC()
		if completed.Before(start) {
			return diagnostic("INVALID_API_STEP_INTERVAL", 0, "historically bound Action step completion precedes its start")
		}
		end = completed.Add(time.Second)
	}
	groupStart := -1
	for _, index := range groupLines {
		if index <= boundary || lines[index].when == nil || lines[index].when.Before(start) || !lines[index].when.Before(end) {
			continue
		}
		groupStart = index
		break
	}
	if groupStart < 0 {
		return diagnostic("MISSING_ACTION_FRAME", 0, "historically bound Action step interval contained no runner group")
	}
	match := runPattern.FindStringSubmatch(lines[groupStart].text)
	if match == nil || !sameActionDeclaration(expected, match[1]) {
		return diagnostic("AMBIGUOUS_ACTION_FRAME", lines[groupStart].number, "first runner group in the historically bound API step interval did not equal the exact historical uses declaration")
	}
	groupEnd := -1
	for index := groupStart + 1; index < len(lines); index++ {
		if lines[index].when == nil || !lines[index].when.Before(end) {
			break
		}
		if lines[index].text == "##[endgroup]" {
			groupEnd = index
			break
		}
	}
	if groupEnd < 0 {
		return diagnostic("TRUNCATED_ACTION_FRAME", lines[groupStart].number, "historically bound Action details group has no closing runner record inside the API step interval")
	}
	frame := ConsolidatedFrame{
		Role: RoleActionStep, APIStepNumber: step.Number, LineStart: lines[groupStart].number, LineEnd: lines[groupEnd].number,
		Bytes: append([]byte(nil), body[lines[groupStart].start:lines[groupEnd].end]...),
	}
	frame.AdjacentRun = frameAdjacentRunGroup(lines, body, groupEnd, &end)
	return frame, nil
}

// frameAdjacentRunGroup returns only a complete, timestamped Run group whose
// opening record is the very next log record after the parent details group.
// The routine deliberately does not scan forward: once any Action-controlled
// output can occur, a later group-looking string is spoofable. Exact composite
// metadata and setup resolution are separate mandatory joins in the collector.
func frameAdjacentRunGroup(lines []consolidatedLine, body []byte, parentEnd int, deadline *time.Time) *ConsolidatedRunGroup {
	start := parentEnd + 1
	if start < 0 || start >= len(lines) || lines[start].when == nil {
		return nil
	}
	if deadline != nil && !lines[start].when.Before(*deadline) {
		return nil
	}
	sourceStart := start
	markerLine, markerDisplay, markerID := 0, "", ""
	if display, id, ok := parseConsolidatedCompositeMarker(lines[start].text); ok {
		markerLine, markerDisplay, markerID = lines[start].number, display, id
		start++
		if start >= len(lines) || lines[start].when == nil || lines[start].when.Before(*lines[start-1].when) || (deadline != nil && !lines[start].when.Before(*deadline)) {
			return nil
		}
	}
	match := runPattern.FindStringSubmatch(lines[start].text)
	if match == nil {
		return nil
	}
	if _, err := parseDeclaredAction(match[1]); err != nil {
		return nil
	}
	previous := *lines[start].when
	for index := start + 1; index < len(lines); index++ {
		line := lines[index]
		if line.when == nil || line.when.Before(previous) || (deadline != nil && !line.when.Before(*deadline)) {
			return nil
		}
		previous = *line.when
		if strings.HasPrefix(line.text, "##[group]") {
			return nil
		}
		if line.text != "##[endgroup]" {
			continue
		}
		return &ConsolidatedRunGroup{
			LineStart:     lines[start].number,
			LineEnd:       line.number,
			Bytes:         append([]byte(nil), body[lines[start].start:line.end]...),
			EvidenceBytes: append([]byte(nil), body[lines[sourceStart].start:line.end]...),
			MarkerLine:    markerLine,
			MarkerDisplay: markerDisplay,
			MarkerID:      markerID,
		}
	}
	return nil
}

func parseConsolidatedCompositeMarker(text string) (string, string, bool) {
	// This exact control record is emitted by CompositeActionHandler in the
	// pinned actions/runner commit 258d6c857db3519913f7deb6004b60172f8043ae.
	// The marker precedes condition evaluation, so callers must still require a
	// following complete Run group and independently prove an unconditional
	// child from exact historical Action metadata.
	const prefix = "##[start-action display="
	if !strings.HasPrefix(text, prefix) || !strings.HasSuffix(text, "]") || len(text) > 4096 {
		return "", "", false
	}
	body := strings.TrimSuffix(strings.TrimPrefix(text, prefix), "]")
	separator := strings.LastIndex(body, ";id=")
	if separator <= 0 || separator+4 >= len(body) {
		return "", "", false
	}
	display, id := body[:separator], body[separator+4:]
	if len(display) > 1024 || !utf8.ValidString(display) || strings.ContainsAny(display, ";\x00\r\n\x1b") || len(id) < 3 || len(id) > 1024 || !consolidatedCompositeMarkerID.MatchString(id) || strings.Contains(id, "..") {
		return "", "", false
	}
	return display, id, true
}

func safeCorrelationText(value string) bool {
	if value == "" || !utf8.ValidString(value) {
		return false
	}
	for _, char := range value {
		if char < 0x20 || char == 0x7f {
			return false
		}
	}
	return true
}

var errInvalidConsolidatedFrame = errors.New("invalid consolidated frame")

func validateConsolidatedFrame(frame ConsolidatedFrame) error {
	if frame.Role != RoleSetup && frame.Role != RoleActionStep {
		return errInvalidConsolidatedFrame
	}
	if frame.LineStart <= 0 || frame.LineEnd < frame.LineStart || len(frame.Bytes) == 0 {
		return fmt.Errorf("%w: invalid span", errInvalidConsolidatedFrame)
	}
	if frame.Role == RoleActionStep && frame.APIStepNumber <= 0 {
		return fmt.Errorf("%w: missing API step", errInvalidConsolidatedFrame)
	}
	if frame.AdjacentRun != nil {
		adjacent := frame.AdjacentRun
		startsAdjacent := adjacent.LineStart == frame.LineEnd+1 && adjacent.MarkerLine == 0
		startsAfterMarker := adjacent.MarkerLine == frame.LineEnd+1 && adjacent.LineStart == adjacent.MarkerLine+1 && adjacent.MarkerDisplay != "" && adjacent.MarkerID != ""
		if frame.Role != RoleActionStep || (!startsAdjacent && !startsAfterMarker) || adjacent.LineEnd < adjacent.LineStart || len(adjacent.Bytes) == 0 || len(adjacent.EvidenceBytes) < len(adjacent.Bytes) {
			return fmt.Errorf("%w: invalid adjacent Run group", errInvalidConsolidatedFrame)
		}
	}
	return nil
}
