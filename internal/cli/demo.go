package cli

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"path/filepath"

	"github.com/torjan0/cirewind/internal/analyze"
	"github.com/torjan0/cirewind/internal/archive"
	"github.com/torjan0/cirewind/internal/demodata"
	"github.com/torjan0/cirewind/internal/incident"
	"github.com/torjan0/cirewind/internal/model"
	"github.com/torjan0/cirewind/internal/report"
)

func runDemo(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	options, err := parseDemo(args, stderr)
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	bundle, err := demodata.Bundle(ctx)
	if err != nil {
		return fmt.Errorf("load embedded demo bundle: %w", err)
	}
	pack, err := incident.ValidateReader(ctx, bytes.NewReader(bundle.PackYAML))
	if err != nil {
		return fmt.Errorf("validate embedded demo incident pack: %w", err)
	}
	caseValue, err := deriveAndGenerateCase(ctx, casePipelineRequest{
		Snapshot: bundle.Snapshot, Pack: pack, AnalysisTime: bundle.AnalysisTime,
		Mode: analyze.ModeReplay, Output: options.Output,
		BeforeGenerate: func(snapshot archive.Snapshot, caseValue report.Case) error {
			return bundle.Oracle.Validate(snapshot, caseValue)
		},
	})
	if err != nil {
		return fmt.Errorf("generate synthetic demo: %w", err)
	}
	// The production case generator verifies the complete staged contract with
	// the production verifier before its atomic publish. Do not start a second,
	// cancellation-sensitive verification after publication: cancellation must
	// never report failure while leaving a newly published case behind.
	printDemoSummary(stdout, caseValue, options.Output)
	return nil
}

func printDemoSummary(writer io.Writer, caseValue report.Case, output string) {
	fmt.Fprintln(writer, "SYNTHETIC DEMO — PARTIAL COVERAGE")
	fmt.Fprintf(writer, "findings: %d\n", len(caseValue.Findings))
	counts := make(map[model.FindingState]int)
	for _, finding := range caseValue.Findings {
		counts[model.FindingState(finding.State)]++
	}
	for _, state := range model.FindingStates() {
		if count := counts[state]; count != 0 {
			fmt.Fprintf(writer, "%s: %d\n", state, count)
		}
	}
	clean := filepath.Clean(output)
	fmt.Fprintln(writer, "manifest: verified")
	fmt.Fprintln(writer, "network requests: 0")
	fmt.Fprintf(writer, "case: %s\n", sanitizeDiagnostic(clean))
	fmt.Fprintf(writer, "report: %s\n", sanitizeDiagnostic(filepath.Join(clean, "report.html")))
}
