// Command samplesite builds and verifies the deterministic synthetic sample
// site from one verified demo case. It is a maintainer build tool, separate
// from the shipped cirewind CLI, and performs no network request and no child
// process.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/torjan0/cirewind/internal/samplesite"
)

const usage = `Usage:
  samplesite build --case DIR --out DIR --version SEMVER --source-commit COMMIT --go-version GOVERSION [--prior SEMVER@SHA256@DIR]...
  samplesite verify --site DIR --version SEMVER [--prior SEMVER@SHA256]...
  samplesite readme --case DIR --out-dir DIR --version SEMVER [--final] [--check]

build stages the complete versioned site tree from a verified raw-disabled
synthetic case, audits it, and publishes it atomically to a new directory.
verify re-audits a published tree: exact file allowlist, no links or
executable bits, size budgets, credential and host-path rejection, inert SVG,
exact content security policy, fixed external links, case manifest, versioned
site manifest, download checksum, and provenance binding.

The version is canonical SemVer without a v prefix; the source commit is the
exact reviewed revision the site is generated from; the Go version is the
toolchain that built the demo. All three are recorded in provenance.json.

Each --prior names an earlier version tree or tombstone that is published
verbatim beside the current version. SHA256 locks the SHA-256 of that tree's
recorded site-manifest.sha256; build copies the tree from the local DIR after
verifying the lock and every covered file, and verify re-checks the same lock.
Prior trees are never fetched from the deployed site.

readme renders the staged README candidate, the README preview viewport of
graph.svg, a byte-identical graph copy, and the explicit slot inventory into
an existing directory (normally site/generated). --check regenerates in memory
and fails on any byte of drift instead of writing. --final drops the
staged-candidate banner and names the file README.md; it is reserved for the
release-candidate materialization step and must not reach the default branch
before activation.
`

type priorFlag struct {
	withDir bool
	values  []samplesite.PriorTree
}

func (p *priorFlag) String() string { return fmt.Sprintf("%d prior trees", len(p.values)) }

func (p *priorFlag) Set(value string) error {
	parts := strings.SplitN(value, "@", 3)
	if p.withDir {
		if len(parts) != 3 || parts[2] == "" {
			return errors.New("--prior must be SEMVER@SHA256@DIR")
		}
	} else if len(parts) != 2 {
		return errors.New("--prior must be SEMVER@SHA256")
	}
	prior := samplesite.PriorTree{Version: parts[0], SiteManifestSHA256: parts[1]}
	if p.withDir {
		prior.Dir = parts[2]
	}
	p.values = append(p.values, prior)
	return nil
}

type commandResult struct {
	SchemaVersion      string `json:"schemaVersion"`
	Operation          string `json:"operation"`
	SiteDir            string `json:"siteDir"`
	SiteVersion        string `json:"siteVersion"`
	FindingTotal       int    `json:"findingTotal"`
	CaseManifestSHA256 string `json:"caseManifestSha256"`
	ArchiveSHA256      string `json:"archiveSha256"`
	SiteManifestSHA256 string `json:"siteManifestSha256"`
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Stdout, os.Stderr))
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	var result samplesite.Result
	var err error
	switch args[0] {
	case "build":
		result, err = runBuild(ctx, args[1:], stderr)
	case "verify":
		result, err = runVerify(ctx, args[1:], stderr)
	case "readme":
		return runReadme(ctx, args[1:], stdout, stderr)
	case "help", "-h", "--help":
		fmt.Fprint(stdout, usage)
		return 0
	default:
		fmt.Fprintf(stderr, "unknown command %q\n%s", args[0], usage)
		return 2
	}
	if err != nil {
		var usageErr usageError
		if errors.As(err, &usageErr) {
			fmt.Fprintf(stderr, "%v\n%s", err, usage)
			return 2
		}
		fmt.Fprintf(stderr, "samplesite %s: %v\n", args[0], err)
		return 1
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(commandResult{
		SchemaVersion:      "cirewind.samplesite-result/v1alpha1",
		Operation:          args[0],
		SiteDir:            result.SiteDir,
		SiteVersion:        result.Version,
		FindingTotal:       result.Total,
		CaseManifestSHA256: result.CaseManifestSHA256,
		ArchiveSHA256:      result.ArchiveSHA256,
		SiteManifestSHA256: result.SiteManifestSHA256,
	}); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	return 0
}

type usageError struct{ message string }

func (u usageError) Error() string { return u.message }

type readmeResult struct {
	SchemaVersion string            `json:"schemaVersion"`
	Operation     string            `json:"operation"`
	Directory     string            `json:"directory"`
	SiteVersion   string            `json:"siteVersion"`
	Candidate     bool              `json:"candidate"`
	Checked       bool              `json:"checked"`
	Digests       map[string]string `json:"digests"`
}

func runReadme(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("readme", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var caseDir, outDir, version string
	var final, check bool
	flags.StringVar(&caseDir, "case", "", "verified raw-disabled synthetic case directory")
	flags.StringVar(&outDir, "out-dir", "", "existing directory that receives the generated files")
	flags.StringVar(&version, "version", "", "site version, canonical SemVer without v")
	flags.BoolVar(&final, "final", false, "render README.md without the staged-candidate banner (release-candidate materialization only)")
	flags.BoolVar(&check, "check", false, "compare regenerated bytes with the directory instead of writing")
	if err := flags.Parse(args); err != nil {
		fmt.Fprintf(stderr, "%v\n%s", err, usage)
		return 2
	}
	if flags.NArg() != 0 || caseDir == "" || outDir == "" || version == "" {
		fmt.Fprintf(stderr, "readme requires --case, --out-dir, and --version\n%s", usage)
		return 2
	}
	candidate, err := samplesite.BuildReadmeCandidate(ctx, caseDir, samplesite.ReadmeSlots{Version: version, Final: final})
	if err != nil {
		fmt.Fprintf(stderr, "samplesite readme: %v\n", err)
		return 1
	}
	if check {
		err = candidate.Compare(outDir)
	} else {
		err = candidate.Write(outDir)
	}
	if err != nil {
		fmt.Fprintf(stderr, "samplesite readme: %v\n", err)
		return 1
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(readmeResult{
		SchemaVersion: "cirewind.samplesite-readme-result/v1alpha1",
		Operation:     "readme",
		Directory:     outDir,
		SiteVersion:   version,
		Candidate:     !final,
		Checked:       check,
		Digests:       candidate.Digests(),
	}); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	return 0
}

func runBuild(ctx context.Context, args []string, stderr io.Writer) (samplesite.Result, error) {
	flags := flag.NewFlagSet("build", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var options samplesite.Options
	flags.StringVar(&options.CaseDir, "case", "", "verified raw-disabled synthetic case directory")
	flags.StringVar(&options.Output, "out", "", "new site output directory (must not exist)")
	flags.StringVar(&options.Version, "version", "", "site version, canonical SemVer without v")
	flags.StringVar(&options.SourceCommit, "source-commit", "", "exact source revision (40 lowercase hexadecimal characters)")
	flags.StringVar(&options.GoVersion, "go-version", "", "Go toolchain version that built the demo, for example go1.25.13")
	priors := &priorFlag{withDir: true}
	flags.Var(priors, "prior", "hash-locked prior version tree as SEMVER@SHA256@DIR (repeatable)")
	if err := flags.Parse(args); err != nil {
		return samplesite.Result{}, usageError{err.Error()}
	}
	if flags.NArg() != 0 || options.CaseDir == "" || options.Output == "" || options.Version == "" || options.SourceCommit == "" || options.GoVersion == "" {
		return samplesite.Result{}, usageError{"build requires --case, --out, --version, --source-commit, and --go-version"}
	}
	options.Priors = priors.values
	return samplesite.Build(ctx, options)
}

func runVerify(ctx context.Context, args []string, stderr io.Writer) (samplesite.Result, error) {
	flags := flag.NewFlagSet("verify", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var siteDir, version string
	flags.StringVar(&siteDir, "site", "", "published site directory")
	flags.StringVar(&version, "version", "", "site version, canonical SemVer without v")
	priors := &priorFlag{}
	flags.Var(priors, "prior", "hash-locked prior version tree as SEMVER@SHA256 (repeatable)")
	if err := flags.Parse(args); err != nil {
		return samplesite.Result{}, usageError{err.Error()}
	}
	if flags.NArg() != 0 || siteDir == "" || version == "" {
		return samplesite.Result{}, usageError{"verify requires --site and --version"}
	}
	return samplesite.Verify(ctx, siteDir, version, priors.values)
}
