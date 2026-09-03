// releasetool is source-controlled maintainer tooling for deterministic release
// candidates. It never publishes, signs, or authenticates an artifact.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/torjan0/cirewind/internal/releaseartifact"
)

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintf(os.Stderr, "cirewind releasetool: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return errors.New("expected build-date, ldflags, package, finalize, verify, compare, or formula")
	}
	switch args[0] {
	case "build-date", "ldflags":
		metadata, err := parseMetadataFlags(args[0], args[1:], stderr)
		if err != nil {
			return err
		}
		if args[0] == "build-date" {
			fmt.Fprintln(stdout, metadata.BuildDate)
		} else {
			fmt.Fprintln(stdout, releaseartifact.LDFlags(metadata))
		}
		return nil
	case "package":
		return runPackage(args[1:], stderr)
	case "finalize":
		return runFinalize(args[1:], stderr)
	case "verify":
		return runVerify(args[1:], stdout, stderr)
	case "compare":
		return runCompare(args[1:], stdout, stderr)
	case "formula":
		return runFormula(args[1:], stdout, stderr)
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func runFormula(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("formula", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var directory, out, downloadBase string
	fs.StringVar(&directory, "dist", "", "verified release distribution directory")
	fs.StringVar(&out, "out", "", "new formula file to write (cirewind.rb)")
	fs.StringVar(&downloadBase, "download-base", "", "fixture-only absolute directory URL that serves the subjects locally; omit for the upstream release location")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if directory == "" || out == "" || fs.NArg() != 0 {
		return errors.New("formula requires --dist and --out, optionally --download-base")
	}
	formula, err := releaseartifact.RenderFormulaFromDistribution(directory, releaseartifact.FormulaOptions{DownloadBase: downloadBase})
	if err != nil {
		return err
	}
	if err := writeExclusive(out, formula); err != nil {
		return err
	}
	// Formula files are read by Homebrew's audit and style tooling, which
	// rejects private modes; the file carries no secret.
	if err := os.Chmod(out, 0o644); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "Homebrew evaluation-lane formula rendered from verified release subjects: %s\n", out)
	return nil
}

type metadataFlags struct {
	version   string
	commit    string
	goVersion string
	epoch     int64
}

func addMetadataFlags(fs *flag.FlagSet, values *metadataFlags) {
	fs.StringVar(&values.version, "version", "", "canonical SemVer without v prefix")
	fs.StringVar(&values.commit, "commit", "", "full lowercase Git object ID")
	fs.StringVar(&values.goVersion, "go-version", "", "exact Go toolchain version")
	fs.Int64Var(&values.epoch, "source-date-epoch", 0, "release source timestamp as Unix seconds")
}

func (values metadataFlags) metadata() (releaseartifact.BuildMetadata, error) {
	return releaseartifact.NewBuildMetadata(values.version, values.commit, values.goVersion, values.epoch)
}

func parseMetadataFlags(name string, args []string, stderr io.Writer) (releaseartifact.BuildMetadata, error) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	var values metadataFlags
	addMetadataFlags(fs, &values)
	if err := fs.Parse(args); err != nil {
		return releaseartifact.BuildMetadata{}, err
	}
	if fs.NArg() != 0 {
		return releaseartifact.BuildMetadata{}, fmt.Errorf("%s accepts flags only", name)
	}
	return values.metadata()
}

func runPackage(args []string, stderr io.Writer) error {
	fs := flag.NewFlagSet("package", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var values metadataFlags
	addMetadataFlags(fs, &values)
	var root, binary, output, targetValue, descriptorPath string
	fs.StringVar(&root, "root", "", "repository root")
	fs.StringVar(&binary, "binary", "", "exact target binary")
	fs.StringVar(&output, "out", "", "new release output directory")
	fs.StringVar(&targetValue, "target", "", "GOOS/GOARCH")
	fs.StringVar(&descriptorPath, "descriptor", "", "new descriptor JSON path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || root == "" || binary == "" || output == "" || targetValue == "" || descriptorPath == "" {
		return errors.New("package requires --root, --binary, --out, --target, and --descriptor")
	}
	metadata, err := values.metadata()
	if err != nil {
		return err
	}
	target, err := releaseartifact.ParseTarget(targetValue)
	if err != nil {
		return err
	}
	descriptor, err := releaseartifact.PackageTarget(releaseartifact.PackageOptions{
		Root: root, BinaryPath: binary, OutputDir: output, Target: target, Build: metadata,
	})
	if err != nil {
		return err
	}
	encoded, err := json.MarshalIndent(descriptor, "", "  ")
	if err != nil {
		return err
	}
	return writeExclusive(descriptorPath, append(encoded, '\n'))
}

func runFinalize(args []string, stderr io.Writer) error {
	fs := flag.NewFlagSet("finalize", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var output string
	fs.StringVar(&output, "out", "", "release output directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if output == "" || fs.NArg() == 0 {
		return errors.New("finalize requires --out and descriptor paths")
	}
	descriptors := make([]releaseartifact.ArtifactDescriptor, 0, fs.NArg())
	for _, path := range fs.Args() {
		file, err := os.Open(path)
		if err != nil {
			return fmt.Errorf("open descriptor %q: %w", path, err)
		}
		decoder := json.NewDecoder(io.LimitReader(file, 1<<20))
		decoder.DisallowUnknownFields()
		var descriptor releaseartifact.ArtifactDescriptor
		decodeErr := decoder.Decode(&descriptor)
		var extra any
		eofErr := decoder.Decode(&extra)
		closeErr := file.Close()
		if decodeErr != nil {
			return errors.Join(fmt.Errorf("decode descriptor %q: %w", path, decodeErr), closeErr)
		}
		if !errors.Is(eofErr, io.EOF) {
			if eofErr == nil {
				eofErr = errors.New("multiple JSON values are not allowed")
			}
			return errors.Join(fmt.Errorf("decode descriptor %q: %w", path, eofErr), closeErr)
		}
		if closeErr != nil {
			return fmt.Errorf("close descriptor %q: %w", path, closeErr)
		}
		descriptors = append(descriptors, descriptor)
	}
	return releaseartifact.FinalizeDistribution(output, descriptors)
}

func runVerify(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var directory string
	fs.StringVar(&directory, "dist", "", "release distribution directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if directory == "" || fs.NArg() != 0 {
		return errors.New("verify requires only --dist")
	}
	if err := releaseartifact.VerifyDistribution(directory); err != nil {
		return err
	}
	fmt.Fprintln(stdout, "release candidate checksums, archives, build graphs, licenses, and SBOMs verified (publisher authenticity not verified)")
	return nil
}

func runCompare(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("compare", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var first, second string
	fs.StringVar(&first, "first", "", "first release distribution")
	fs.StringVar(&second, "second", "", "second release distribution")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if first == "" || second == "" || fs.NArg() != 0 {
		return errors.New("compare requires only --first and --second")
	}
	if err := releaseartifact.CompareDistributions(first, second); err != nil {
		return err
	}
	fmt.Fprintln(stdout, "release distributions are byte-for-byte reproducible")
	return nil
}

func writeExclusive(path string, contents []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	written, writeErr := io.Copy(file, bytes.NewReader(contents))
	if writeErr == nil && written != int64(len(contents)) {
		writeErr = errors.New("short write")
	}
	closeErr := file.Close()
	return errors.Join(writeErr, closeErr)
}
