package samplesite

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/torjan0/cirewind/internal/casefile"
	"github.com/torjan0/cirewind/internal/demodata"
	"github.com/torjan0/cirewind/internal/model"
	"github.com/torjan0/cirewind/internal/report"
)

const (
	maxFindingsBytes = 32 << 20
	maxMetadataBytes = 4 << 20
	requiredCaseKind = "synthetic"
	requiredContract = "cirewind.case/v1alpha2"
)

// CaseSummary is the typed summary the site renders. Every count is derived
// from validated case output and checked against the embedded demo oracle;
// the site never keeps an independent handwritten total.
type CaseSummary struct {
	Files          []string
	Counts         map[model.FindingState]int
	Total          int
	Exposures      map[demodata.ExposureMetric]int
	CaseKind       string
	ManifestSHA256 string
}

// LoadVerifiedCase verifies a raw-disabled v0.2 synthetic case with the
// production verifier, strictly decodes its findings and metadata, derives the
// finding and relationship counts, and requires them to equal the oracle.
func LoadVerifiedCase(ctx context.Context, dir string, oracle demodata.Oracle) (CaseSummary, error) {
	if err := ctx.Err(); err != nil {
		return CaseSummary{}, err
	}
	if _, err := casefile.VerifyCase(ctx, dir); err != nil {
		return CaseSummary{}, fmt.Errorf("verify case manifest: %w", err)
	}
	names, err := listRegularFiles(ctx, dir)
	if err != nil {
		return CaseSummary{}, err
	}
	expected := append([]string(nil), oracle.FinalFiles...)
	sort.Strings(expected)
	if strings.Join(names, "\n") != strings.Join(expected, "\n") {
		return CaseSummary{}, fmt.Errorf("case file set %v differs from the fixed raw-disabled contract %v", names, expected)
	}
	if _, err := os.Lstat(filepath.Join(dir, "raw")); err == nil {
		return CaseSummary{}, errors.New("case contains a raw directory")
	}
	caseKind, err := loadSyntheticMetadata(filepath.Join(dir, "collection-metadata.json"))
	if err != nil {
		return CaseSummary{}, err
	}
	findings, err := loadFindings(filepath.Join(dir, "findings.json"))
	if err != nil {
		return CaseSummary{}, err
	}
	counts := make(map[model.FindingState]int, len(model.FindingStates()))
	for _, state := range model.FindingStates() {
		counts[state] = 0
	}
	exposures := map[demodata.ExposureMetric]int{
		demodata.ExposureWriteTokenJob:       0,
		demodata.ExposureNamedSecretFlow:     0,
		demodata.ExposureOIDCMintingJob:      0,
		demodata.ExposureSelfHostedRunnerJob: 0,
		demodata.ExposureDeploymentAfter:     0,
	}
	for _, finding := range findings {
		state := model.FindingState(finding.State)
		if !state.Valid() {
			return CaseSummary{}, fmt.Errorf("findings.json contains non-canonical state %q", finding.State)
		}
		if !model.ProvenanceLevel(finding.Provenance).Valid() {
			return CaseSummary{}, fmt.Errorf("findings.json contains non-canonical provenance %q", finding.Provenance)
		}
		counts[state]++
		writeCapable := false
		for _, exposure := range finding.CredentialExposure {
			switch exposure.Kind {
			case string(model.ExposureGitHubTokenPermission):
				if strings.HasSuffix(exposure.Capability, ":write") && !strings.HasPrefix(exposure.Capability, "id-token:") {
					writeCapable = true
				}
			case string(model.ExposureSecretPassedToStep):
				exposures[demodata.ExposureNamedSecretFlow]++
			case string(model.ExposureOIDCMintingCapability):
				exposures[demodata.ExposureOIDCMintingJob]++
			}
		}
		if writeCapable {
			exposures[demodata.ExposureWriteTokenJob]++
		}
		for _, exposure := range finding.ResourceExposure {
			switch exposure.Kind {
			case "SELF_HOSTED_RUNNER":
				exposures[demodata.ExposureSelfHostedRunnerJob]++
			case string(model.ResourceDeployment):
				if exposure.Basis == string(model.CorrelationObservedAfter) {
					exposures[demodata.ExposureDeploymentAfter]++
				}
			}
		}
	}
	for _, state := range model.FindingStates() {
		if counts[state] != oracle.FindingCounts[state] {
			return CaseSummary{}, fmt.Errorf("finding state %s count %d differs from the demo oracle %d", state, counts[state], oracle.FindingCounts[state])
		}
	}
	for metric, count := range exposures {
		if count != oracle.ExposureCounts[metric] {
			return CaseSummary{}, fmt.Errorf("relationship %s count %d differs from the demo oracle %d", metric, count, oracle.ExposureCounts[metric])
		}
	}
	if len(findings) != len(oracle.Findings) {
		return CaseSummary{}, fmt.Errorf("findings.json has %d findings, oracle expects %d", len(findings), len(oracle.Findings))
	}
	manifest, err := readBoundedRegular(filepath.Join(dir, "manifest.sha256"), maxManifestBytes)
	if err != nil {
		return CaseSummary{}, err
	}
	sum := sha256.Sum256(manifest)
	return CaseSummary{
		Files:          expected,
		Counts:         counts,
		Total:          len(findings),
		Exposures:      exposures,
		CaseKind:       caseKind,
		ManifestSHA256: hex.EncodeToString(sum[:]),
	}, nil
}

func loadFindings(path string) ([]report.Finding, error) {
	data, err := readBoundedRegular(path, maxFindingsBytes)
	if err != nil {
		return nil, fmt.Errorf("read findings.json: %w", err)
	}
	var document struct {
		SchemaVersion string           `json:"schemaVersion"`
		Findings      []report.Finding `json:"findings"`
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&document); err != nil {
		return nil, fmt.Errorf("decode findings.json: %w", err)
	}
	if document.SchemaVersion != report.FindingsSchema {
		return nil, fmt.Errorf("findings.json schema %q is not %q", document.SchemaVersion, report.FindingsSchema)
	}
	if len(document.Findings) == 0 {
		return nil, errors.New("findings.json contains no finding")
	}
	return document.Findings, nil
}

func loadSyntheticMetadata(path string) (string, error) {
	data, err := readBoundedRegular(path, maxMetadataBytes)
	if err != nil {
		return "", fmt.Errorf("read collection-metadata.json: %w", err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return "", fmt.Errorf("decode collection-metadata.json: %w", err)
	}
	var caseKind, contract string
	var rawMaterialized bool
	for key, target := range map[string]any{"caseKind": &caseKind, "caseContractVersion": &contract, "rawMaterialized": &rawMaterialized} {
		raw, ok := fields[key]
		if !ok {
			return "", fmt.Errorf("collection-metadata.json omits %s", key)
		}
		if err := json.Unmarshal(raw, target); err != nil {
			return "", fmt.Errorf("collection-metadata.json field %s: %w", key, err)
		}
	}
	if contract != requiredContract {
		return "", fmt.Errorf("case contract %q is not %q", contract, requiredContract)
	}
	if caseKind != requiredCaseKind {
		return "", fmt.Errorf("case kind %q is not %q; the public sample accepts only synthetic cases", caseKind, requiredCaseKind)
	}
	if rawMaterialized {
		return "", errors.New("case declares materialized raw evidence")
	}
	return caseKind, nil
}
