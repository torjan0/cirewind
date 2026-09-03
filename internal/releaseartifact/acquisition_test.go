package releaseartifact

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

func syntheticSubjects(metadata DistributionMetadata) []FileRecord {
	subjects := []FileRecord{{Name: "SHA256SUMS", SHA256: strings.Repeat("d", 64), Bytes: 700}, {Name: "release-metadata.json", SHA256: strings.Repeat("e", 64), Bytes: 900}}
	for _, artifact := range metadata.Artifacts {
		subjects = append(subjects, artifact.Archive, artifact.SBOM)
	}
	return subjects
}

func syntheticInput() AcquisitionInput {
	return AcquisitionInput{
		IntendedVersion: "0.2.0", SourceCommit: strings.Repeat("a", 40), ExpectedDefaultTip: strings.Repeat("f", 40), SourceDateEpoch: 1_700_000_000,
		HostOS: "linux", HostArch: "amd64",
		Formula: FileRecord{Name: "cirewind.rb", SHA256: strings.Repeat("1", 64), Bytes: 1200},
		Readme:  FileRecord{Name: "README.md", SHA256: strings.Repeat("2", 64), Bytes: 3400},
		Suites: []SuiteResult{
			{Name: "vet", Status: "pass", Command: "make vet", DurationMs: 1200},
			{Name: "browser-audit", Status: "skipped", Command: "make browser-audit", DurationMs: 0, Reason: "no sandboxed Chromium on this host"},
			{Name: "test", Status: "pass", Command: "make test", DurationMs: 90000},
		},
	}
}

func compileAcquisitionSchema(t *testing.T) *jsonschema.Schema {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "schema", "rc-acquisition-record-v1alpha1.json"))
	if err != nil {
		t.Fatal(err)
	}
	compiler := jsonschema.NewCompiler()
	compiler.DefaultDraft(jsonschema.Draft2020)
	document, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	if err := compiler.AddResource("rc-acquisition-record-v1alpha1.json", document); err != nil {
		t.Fatal(err)
	}
	schema, err := compiler.Compile("rc-acquisition-record-v1alpha1.json")
	if err != nil {
		t.Fatal(err)
	}
	return schema
}

func TestBuildAcquisitionRecordIsBoundedDeterministicAndSchemaValid(t *testing.T) {
	metadata := syntheticMetadata(t)
	record, err := BuildAcquisitionRecord(metadata, syntheticInput(), syntheticSubjects(metadata))
	if err != nil {
		t.Fatal(err)
	}
	if record.Qualification.Complete {
		t.Fatal("a skipped suite must keep the freeze incomplete")
	}
	if len(record.ReleaseSubjects) != 2+2*len(metadata.Artifacts) || len(record.Binaries) != len(metadata.Artifacts) {
		t.Fatalf("subjects=%d binaries=%d", len(record.ReleaseSubjects), len(record.Binaries))
	}
	for index := 1; index < len(record.ReleaseSubjects); index++ {
		if record.ReleaseSubjects[index-1].Name >= record.ReleaseSubjects[index].Name {
			t.Fatal("release subjects are not sorted")
		}
	}
	if record.Qualification.Suites[0].Name != "browser-audit" || record.Qualification.Suites[2].Name != "vet" {
		t.Fatalf("suites are not sorted: %+v", record.Qualification.Suites)
	}
	if record.ImmutableArtifact != nil || record.Publication != AcquisitionPublicationStatement || record.BuildCommand != "sh scripts/build-release.sh 0.2.0 "+strings.Repeat("a", 40)+" 1700000000 OUTPUT_DIR" {
		t.Fatalf("record identity fields are wrong: %+v", record)
	}
	first, err := EncodeAcquisitionRecord(record)
	if err != nil {
		t.Fatal(err)
	}
	again, _ := BuildAcquisitionRecord(metadata, syntheticInput(), syntheticSubjects(metadata))
	second, _ := EncodeAcquisitionRecord(again)
	if !bytes.Equal(first, second) {
		t.Fatal("two records from identical inputs differ")
	}
	var decoded any
	if err := json.Unmarshal(first, &decoded); err != nil {
		t.Fatal(err)
	}
	if err := compileAcquisitionSchema(t).Validate(decoded); err != nil {
		t.Fatalf("record does not satisfy its schema: %v", err)
	}
	complete := syntheticInput()
	complete.Suites = complete.Suites[:1]
	full, err := BuildAcquisitionRecord(metadata, complete, syntheticSubjects(metadata))
	if err != nil || !full.Qualification.Complete {
		t.Fatalf("all-pass suites must complete the freeze: %v %+v", err, full.Qualification)
	}
}

func TestBuildAcquisitionRecordRejectsDisagreements(t *testing.T) {
	metadata := syntheticMetadata(t)
	cases := map[string]func(input *AcquisitionInput, subjects *[]FileRecord){
		"v-prefixed version":     func(i *AcquisitionInput, _ *[]FileRecord) { i.IntendedVersion = "v0.2.0" },
		"pre-release version":    func(i *AcquisitionInput, _ *[]FileRecord) { i.IntendedVersion = "0.2.0-rc.1" },
		"other version":          func(i *AcquisitionInput, _ *[]FileRecord) { i.IntendedVersion = "0.3.0" },
		"other commit":           func(i *AcquisitionInput, _ *[]FileRecord) { i.SourceCommit = strings.Repeat("b", 40) },
		"short tip":              func(i *AcquisitionInput, _ *[]FileRecord) { i.ExpectedDefaultTip = "abc" },
		"other epoch":            func(i *AcquisitionInput, _ *[]FileRecord) { i.SourceDateEpoch = 1 },
		"bad host":               func(i *AcquisitionInput, _ *[]FileRecord) { i.HostOS = "Linux/x" },
		"bad formula digest":     func(i *AcquisitionInput, _ *[]FileRecord) { i.Formula.SHA256 = "zz" },
		"duplicate suite":        func(i *AcquisitionInput, _ *[]FileRecord) { i.Suites = append(i.Suites, i.Suites[0]) },
		"skip without reason":    func(i *AcquisitionInput, _ *[]FileRecord) { i.Suites[1].Reason = "" },
		"unknown status":         func(i *AcquisitionInput, _ *[]FileRecord) { i.Suites[0].Status = "ok" },
		"angle bracket reason":   func(i *AcquisitionInput, _ *[]FileRecord) { i.Suites[1].Reason = "<skipped>" },
		"missing archive":        func(_ *AcquisitionInput, s *[]FileRecord) { *s = (*s)[:len(*s)-2] },
		"drifted archive digest": func(_ *AcquisitionInput, s *[]FileRecord) { (*s)[2].SHA256 = strings.Repeat("9", 64) },
		"duplicate subject":      func(_ *AcquisitionInput, s *[]FileRecord) { *s = append(*s, (*s)[0]) },
	}
	for name, mutate := range cases {
		input := syntheticInput()
		subjects := syntheticSubjects(metadata)
		mutate(&input, &subjects)
		if _, err := BuildAcquisitionRecord(metadata, input, subjects); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	drifted := syntheticMetadata(t)
	drifted.Build.Trimpath = false
	if _, err := BuildAcquisitionRecord(drifted, syntheticInput(), syntheticSubjects(drifted)); err == nil {
		t.Error("non-reproducible build controls were accepted")
	}
}

func TestParseSuiteLedger(t *testing.T) {
	suites, err := ParseSuiteLedger([]byte("test\tpass\t1200\tmake test\t\n\nrace\tskipped\t0\tmake race\tno time\n"))
	if err != nil || len(suites) != 2 || suites[1].Reason != "no time" || suites[0].DurationMs != 1200 {
		t.Fatalf("ledger parse: %v %+v", err, suites)
	}
	for name, ledger := range map[string]string{"four fields": "a\tpass\t1\tcmd\n", "negative duration": "a\tpass\t-1\tcmd\t\n", "text duration": "a\tpass\tx\tcmd\t\n"} {
		if _, err := ParseSuiteLedger([]byte(ledger)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
