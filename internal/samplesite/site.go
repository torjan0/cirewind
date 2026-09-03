package samplesite

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/torjan0/cirewind/internal/demodata"
	"github.com/torjan0/cirewind/internal/model"
)

const (
	// Schema identifies the generator layout; it does not version the case.
	Schema           = "cirewind.sample-site/v1alpha1"
	provenanceSchema = "cirewind.sample-site-provenance/v1alpha1"
)

var goVersionPattern = regexp.MustCompile(`^go[1-9][0-9]*(\.[0-9]+){0,2}$`)

// Options are the trusted build inputs. None of them is derived from case
// content, and no case field controls an output path.
type Options struct {
	CaseDir      string
	Output       string
	Version      string
	SourceCommit string
	GoVersion    string
	// Priors are earlier version trees or tombstones, each locked to the
	// SHA-256 of its recorded site manifest and copied verbatim from Dir.
	Priors []PriorTree
}

// Result summarizes a built or verified site.
type Result struct {
	SiteDir            string
	Version            string
	CaseManifestSHA256 string
	ArchiveSHA256      string
	SiteManifestSHA256 string
	Total              int
}

// ProvenanceCount is one canonical state count in fixed state order.
type ProvenanceCount struct {
	State string `json:"state"`
	Count int    `json:"count"`
}

// Provenance is the deterministic record published beside the versioned tree.
// It deliberately contains no wall-clock time, run ID, or deployment URL.
type Provenance struct {
	SchemaVersion      string            `json:"schemaVersion"`
	SiteVersion        string            `json:"siteVersion"`
	GeneratorSchema    string            `json:"generatorSchema"`
	SourceCommit       string            `json:"sourceCommit"`
	GoVersion          string            `json:"goVersion"`
	DemoBundleID       string            `json:"demoBundleId"`
	DemoFixtureVersion string            `json:"demoFixtureVersion"`
	CaseKind           string            `json:"caseKind"`
	CaseManifestSHA256 string            `json:"caseManifestSha256"`
	ArchiveName        string            `json:"archiveName"`
	ArchiveSHA256      string            `json:"archiveSha256"`
	ArchiveByteLength  int               `json:"archiveByteLength"`
	FindingTotal       int               `json:"findingTotal"`
	FindingCounts      []ProvenanceCount `json:"findingCounts"`
	Regeneration       string            `json:"regeneration"`
}

func (p Provenance) validate(version string) error {
	if p.SchemaVersion != provenanceSchema || p.GeneratorSchema != Schema || p.SiteVersion != version || p.CaseKind != requiredCaseKind ||
		p.DemoBundleID != demodata.BundleID || p.DemoFixtureVersion != demodata.FixtureVersion || !hexToken(p.SourceCommit, 40) ||
		!goVersionPattern.MatchString(p.GoVersion) || !hexToken(p.CaseManifestSHA256, 64) || !hexToken(p.ArchiveSHA256, 64) ||
		p.ArchiveByteLength <= 0 || p.ArchiveName != ArchiveName(version) || p.FindingTotal <= 0 || p.Regeneration != regenerationCommand(version) {
		return errors.New("provenance record is not the reviewed shape for this version")
	}
	if len(p.FindingCounts) != len(model.FindingStates()) {
		return errors.New("provenance omits a canonical state count")
	}
	total := 0
	for index, row := range p.FindingCounts {
		if row.State != string(model.FindingStates()[index]) || row.Count < 0 {
			return errors.New("provenance counts are not in canonical state order")
		}
		total += row.Count
	}
	if total != p.FindingTotal {
		return errors.New("provenance finding total does not equal the sum of its counts")
	}
	return nil
}

func regenerationCommand(version string) string {
	return "make sample-site SITE_VERSION=" + version + " SITE_OUT=DIR"
}

// Build stages the complete versioned site from one verified synthetic case,
// audits the staged tree, and publishes it atomically to a new directory.
func Build(ctx context.Context, options Options) (Result, error) {
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	if err := ValidateVersion(options.Version); err != nil {
		return Result{}, err
	}
	if !hexToken(options.SourceCommit, 40) {
		return Result{}, errors.New("source commit must be a full lowercase hexadecimal object ID")
	}
	if !goVersionPattern.MatchString(options.GoVersion) {
		return Result{}, errors.New("go version must look like go1.25.13")
	}
	if err := validatePriors(options.Version, options.Priors); err != nil {
		return Result{}, err
	}
	if options.Output == "" || filepath.Clean(options.Output) != options.Output {
		return Result{}, errors.New("output path must be a nonempty clean path")
	}
	if _, err := os.Lstat(options.Output); err == nil {
		return Result{}, errors.New("output path already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return Result{}, err
	}
	parent := filepath.Dir(options.Output)
	parentInfo, err := os.Lstat(parent)
	if err != nil || !parentInfo.IsDir() || parentInfo.Mode()&os.ModeSymlink != 0 {
		return Result{}, errors.New("output parent must be an existing real directory")
	}
	bundle, err := demodata.Bundle(ctx)
	if err != nil {
		return Result{}, fmt.Errorf("load embedded demo oracle: %w", err)
	}
	summary, err := LoadVerifiedCase(ctx, options.CaseDir, bundle.Oracle)
	if err != nil {
		return Result{}, fmt.Errorf("load verified case: %w", err)
	}

	staging, err := os.MkdirTemp(parent, ".cirewind-site-")
	if err != nil {
		return Result{}, fmt.Errorf("create private staging directory: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = os.RemoveAll(staging)
		}
	}()
	versionDir := filepath.Join(staging, "v"+options.Version)
	for _, directory := range []string{versionDir, filepath.Join(versionDir, sampleCaseDir), filepath.Join(versionDir, downloadsDir)} {
		if err := os.Mkdir(directory, 0o755); err != nil {
			return Result{}, err
		}
	}
	caseContents := make(map[string][]byte, len(summary.Files))
	for _, name := range summary.Files {
		data, err := readBoundedRegular(filepath.Join(options.CaseDir, filepath.FromSlash(name)), budgetFor(name))
		if err != nil {
			return Result{}, fmt.Errorf("read case file %s: %w", name, err)
		}
		caseContents[name] = data
		if err := writeSiteFile(filepath.Join(versionDir, sampleCaseDir, name), data); err != nil {
			return Result{}, err
		}
	}
	for _, name := range []string{"graph.svg", "findings.json", "summary.md"} {
		if err := writeSiteFile(filepath.Join(versionDir, name), caseContents[name]); err != nil {
			return Result{}, err
		}
	}
	svgInfo, err := AuditSVG(caseContents["graph.svg"])
	if err != nil {
		return Result{}, fmt.Errorf("audit case SVG: %w", err)
	}
	archive, err := BuildDeterministicTarGz(ctx, options.CaseDir, "cirewind-synthetic-case-v"+options.Version, summary.Files)
	if err != nil {
		return Result{}, fmt.Errorf("build deterministic archive: %w", err)
	}
	archiveName := ArchiveName(options.Version)
	archiveSum := sha256.Sum256(archive)
	archiveDigest := hex.EncodeToString(archiveSum[:])
	if err := writeSiteFile(filepath.Join(versionDir, downloadsDir, archiveName), archive); err != nil {
		return Result{}, err
	}
	if err := writeSiteFile(filepath.Join(versionDir, downloadsDir, sumsName), []byte(archiveDigest+"  "+archiveName+"\n")); err != nil {
		return Result{}, err
	}
	counts := make([]CountRow, 0, len(model.FindingStates()))
	provenanceCounts := make([]ProvenanceCount, 0, len(model.FindingStates()))
	for _, state := range model.FindingStates() {
		counts = append(counts, CountRow{State: state, Count: summary.Counts[state]})
		provenanceCounts = append(provenanceCounts, ProvenanceCount{State: string(state), Count: summary.Counts[state]})
	}
	provenance := Provenance{
		SchemaVersion:      provenanceSchema,
		SiteVersion:        options.Version,
		GeneratorSchema:    Schema,
		SourceCommit:       options.SourceCommit,
		GoVersion:          options.GoVersion,
		DemoBundleID:       bundle.ID,
		DemoFixtureVersion: bundle.FixtureVersion,
		CaseKind:           summary.CaseKind,
		CaseManifestSHA256: summary.ManifestSHA256,
		ArchiveName:        archiveName,
		ArchiveSHA256:      archiveDigest,
		ArchiveByteLength:  len(archive),
		FindingTotal:       summary.Total,
		FindingCounts:      provenanceCounts,
		Regeneration:       regenerationCommand(options.Version),
	}
	provenanceBytes, err := json.MarshalIndent(provenance, "", "  ")
	if err != nil {
		return Result{}, err
	}
	if err := writeSiteFile(filepath.Join(versionDir, provenanceName), append(provenanceBytes, '\n')); err != nil {
		return Result{}, err
	}
	landing, err := RenderLanding(PageData{
		Version:            options.Version,
		VersionPath:        "v" + options.Version,
		Counts:             counts,
		Total:              summary.Total,
		WriteTokenJobs:     summary.Exposures[demodata.ExposureWriteTokenJob],
		NamedSecretFlows:   summary.Exposures[demodata.ExposureNamedSecretFlow],
		OIDCJobs:           summary.Exposures[demodata.ExposureOIDCMintingJob],
		SelfHostedJobs:     summary.Exposures[demodata.ExposureSelfHostedRunnerJob],
		DeploymentsAfter:   summary.Exposures[demodata.ExposureDeploymentAfter],
		ArchiveName:        archiveName,
		ArchiveSHA256:      archiveDigest,
		CaseManifestSHA256: summary.ManifestSHA256,
		SourceCommit:       options.SourceCommit,
		GoVersion:          options.GoVersion,
		DemoBundleID:       bundle.ID,
		FixtureVersion:     bundle.FixtureVersion,
		SVGWidth:           svgInfo.Width,
		SVGHeight:          svgInfo.Height,
	})
	if err != nil {
		return Result{}, fmt.Errorf("render landing page: %w", err)
	}
	if err := writeSiteFile(filepath.Join(versionDir, versionedIndexTop), landing); err != nil {
		return Result{}, err
	}
	siteManifest, err := BuildTreeManifest(ctx, versionDir, siteManifestName)
	if err != nil {
		return Result{}, fmt.Errorf("build site manifest: %w", err)
	}
	if err := writeSiteFile(filepath.Join(versionDir, siteManifestName), siteManifest); err != nil {
		return Result{}, err
	}
	root, err := RenderRoot(options.Version)
	if err != nil {
		return Result{}, err
	}
	if err := writeSiteFile(filepath.Join(staging, rootIndexName), root); err != nil {
		return Result{}, err
	}
	for _, prior := range options.Priors {
		if err := stagePriorTree(ctx, staging, prior); err != nil {
			return Result{}, err
		}
	}
	if _, err := AuditTree(ctx, staging, options.Version, summary.Files, options.Priors); err != nil {
		return Result{}, fmt.Errorf("audit staged site: %w", err)
	}
	if err := os.Chmod(staging, 0o755); err != nil {
		return Result{}, err
	}
	if err := os.Rename(staging, options.Output); err != nil {
		return Result{}, fmt.Errorf("publish site: %w", err)
	}
	committed = true
	manifestSum := sha256.Sum256(siteManifest)
	return Result{
		SiteDir:            options.Output,
		Version:            options.Version,
		CaseManifestSHA256: summary.ManifestSHA256,
		ArchiveSHA256:      archiveDigest,
		SiteManifestSHA256: hex.EncodeToString(manifestSum[:]),
		Total:              summary.Total,
	}, nil
}

// stagePriorTree verifies a locally supplied prior version tree against its
// hash-locked manifest and copies exactly the covered files into staging.
func stagePriorTree(ctx context.Context, staging string, prior PriorTree) error {
	if prior.Dir == "" {
		return fmt.Errorf("prior version %s has no local source directory", prior.Version)
	}
	files, err := lockedManifestFiles(prior.Dir, prior)
	if err != nil {
		return err
	}
	if err := VerifyTreeManifest(ctx, prior.Dir, siteManifestName); err != nil {
		return fmt.Errorf("prior version %s: %w", prior.Version, err)
	}
	target := filepath.Join(staging, "v"+prior.Version)
	if err := os.Mkdir(target, 0o755); err != nil {
		return err
	}
	for _, name := range append(files, siteManifestName) {
		if err := ctx.Err(); err != nil {
			return err
		}
		data, err := readBoundedRegular(filepath.Join(prior.Dir, filepath.FromSlash(name)), budgetFor(name))
		if err != nil {
			return fmt.Errorf("prior version %s file %s: %w", prior.Version, name, err)
		}
		destination := filepath.Join(target, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
			return err
		}
		if err := writeSiteFile(destination, data); err != nil {
			return err
		}
	}
	return nil
}

// Verify re-audits a published site tree for one version, including its case
// manifest, site manifest, checksums, provenance, allowlists, and any
// hash-locked prior version trees.
func Verify(ctx context.Context, siteDir, version string, priors []PriorTree) (Result, error) {
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	bundle, err := demodata.Bundle(ctx)
	if err != nil {
		return Result{}, err
	}
	provenance, err := AuditTree(ctx, siteDir, version, bundle.Oracle.FinalFiles, priors)
	if err != nil {
		return Result{}, err
	}
	if _, err := LoadVerifiedCase(ctx, filepath.Join(siteDir, filepath.FromSlash("v"+version+"/"+sampleCaseDir)), bundle.Oracle); err != nil {
		return Result{}, fmt.Errorf("published sample case: %w", err)
	}
	manifest, err := readBoundedRegular(filepath.Join(siteDir, filepath.FromSlash("v"+version+"/"+siteManifestName)), maxManifestBytes)
	if err != nil {
		return Result{}, err
	}
	manifestSum := sha256.Sum256(manifest)
	return Result{
		SiteDir:            siteDir,
		Version:            version,
		CaseManifestSHA256: provenance.CaseManifestSHA256,
		ArchiveSHA256:      provenance.ArchiveSHA256,
		SiteManifestSHA256: hex.EncodeToString(manifestSum[:]),
		Total:              provenance.FindingTotal,
	}, nil
}

func writeSiteFile(path string, data []byte) error {
	if strings.ContainsAny(path, "\x00") {
		return errors.New("invalid output path")
	}
	handle, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return fmt.Errorf("create %s: %w", filepath.Base(path), err)
	}
	if _, err := handle.Write(data); err != nil {
		_ = handle.Close()
		return fmt.Errorf("write %s: %w", filepath.Base(path), err)
	}
	if err := handle.Close(); err != nil {
		return err
	}
	return os.Chmod(path, 0o644)
}
