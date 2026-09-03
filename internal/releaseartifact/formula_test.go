package releaseartifact

import (
	"strings"
	"testing"
)

func syntheticMetadata(t *testing.T) DistributionMetadata {
	t.Helper()
	build, err := NewBuildMetadata("0.2.0", strings.Repeat("a", 40), "go1.25.13", 1_700_000_000)
	if err != nil {
		t.Fatal(err)
	}
	metadata := DistributionMetadata{FormatVersion: FormatVersion, Build: build}
	for index, target := range supportedTargets {
		base := "cirewind_0.2.0_" + target.OS + "_" + target.Arch
		metadata.Artifacts = append(metadata.Artifacts, ArtifactDescriptor{
			FormatVersion: FormatVersion,
			Target:        target,
			TopDirectory:  base,
			Archive:       FileRecord{Name: base + target.ArchiveExtension(), SHA256: strings.Repeat(string(rune('0'+index)), 64), Bytes: 1000 + int64(index)},
			Binary:        FileRecord{Name: target.BinaryName(), SHA256: strings.Repeat("b", 64), Bytes: 500},
			SBOM:          FileRecord{Name: base + ".spdx.json", SHA256: strings.Repeat("c", 64), Bytes: 400},
			Build:         build,
			ReviewedPacks: []ReviewedPack{},
		})
	}
	return metadata
}

func TestRenderFormulaBindsEveryUnixSubject(t *testing.T) {
	formula, err := RenderFormula(syntheticMetadata(t), FormulaOptions{})
	if err != nil {
		t.Fatal(err)
	}
	text := string(formula)
	for _, required := range []string{
		"class Cirewind < Formula",
		`homepage "https://github.com/torjan0/cirewind"`,
		`license "Apache-2.0"`,
		`url "https://github.com/torjan0/cirewind/releases/download/v0.2.0/cirewind_0.2.0_darwin_arm64.tar.gz"`,
		`url "https://github.com/torjan0/cirewind/releases/download/v0.2.0/cirewind_0.2.0_darwin_amd64.tar.gz"`,
		`url "https://github.com/torjan0/cirewind/releases/download/v0.2.0/cirewind_0.2.0_linux_arm64.tar.gz"`,
		`url "https://github.com/torjan0/cirewind/releases/download/v0.2.0/cirewind_0.2.0_linux_amd64.tar.gz"`,
		"evaluation lane",
		"not an attestation",
		`system bin/"cirewind", "demo", "--out", testpath/"demo"`,
		`system bin/"cirewind", "verify", testpath/"demo"`,
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("formula lacks %q:\n%s", required, text)
		}
	}
	for _, forbidden := range []string{"windows", "version \"", "{{", "postinstall", "curl", "FIXTURE"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("formula contains %q", forbidden)
		}
	}
	if strings.Count(text, "sha256 \"") != 4 || strings.Count(text, "url \"") != 4 {
		t.Fatalf("formula must carry exactly four url and sha256 pairs:\n%s", text)
	}
	again, err := RenderFormula(syntheticMetadata(t), FormulaOptions{})
	if err != nil || string(again) != text {
		t.Fatal("formula rendering is not deterministic")
	}
	fixture, err := RenderFormula(syntheticMetadata(t), FormulaOptions{DownloadBase: "http://127.0.0.1:8080/torjan0/cirewind/releases/download/v0.2.0/"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(fixture), "# FIXTURE FORMULA") || !strings.Contains(string(fixture), `url "http://127.0.0.1:8080/torjan0/cirewind/releases/download/v0.2.0/cirewind_0.2.0_linux_amd64.tar.gz"`) {
		t.Fatalf("fixture formula is not labeled or mapped:\n%s", fixture)
	}
}

func TestRenderFormulaRejectsMissingDuplicateAndWrongPlatformSubjects(t *testing.T) {
	cases := map[string]func(m *DistributionMetadata){
		"missing linux arm64": func(m *DistributionMetadata) {
			kept := m.Artifacts[:0]
			for _, artifact := range m.Artifacts {
				if artifact.Target != (Target{OS: "linux", Arch: "arm64"}) {
					kept = append(kept, artifact)
				}
			}
			m.Artifacts = kept
		},
		"duplicate darwin arm64": func(m *DistributionMetadata) {
			m.Artifacts = append(m.Artifacts, m.Artifacts[1])
		},
		"wrong archive name": func(m *DistributionMetadata) {
			m.Artifacts[2].Archive.Name = "cirewind_0.2.0_linux_amd64.zip"
		},
		"foreign platform": func(m *DistributionMetadata) {
			m.Artifacts[2].Target = Target{OS: "freebsd", Arch: "amd64"}
			m.Artifacts[2].Archive.Name = "cirewind_0.2.0_freebsd_amd64.tar.gz"
		},
		"uppercase digest": func(m *DistributionMetadata) {
			m.Artifacts[0].Archive.SHA256 = strings.ToUpper(strings.Repeat("a", 64))
		},
		"version drift": func(m *DistributionMetadata) {
			m.Artifacts[3].Build.Version = "0.2.1"
		},
		"format version": func(m *DistributionMetadata) {
			m.FormatVersion = FormatVersion + 1
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			metadata := syntheticMetadata(t)
			mutate(&metadata)
			if _, err := RenderFormula(metadata, FormulaOptions{}); err == nil {
				t.Fatal("unsound subjects rendered a formula")
			}
		})
	}
	if _, err := RenderFormula(syntheticMetadata(t), FormulaOptions{DownloadBase: "ftp://example.invalid/"}); err == nil {
		t.Fatal("non-HTTP download base accepted")
	}
	if _, err := RenderFormula(syntheticMetadata(t), FormulaOptions{DownloadBase: "https://example.invalid/no-trailing-slash"}); err == nil {
		t.Fatal("download base without a trailing slash accepted")
	}
}
