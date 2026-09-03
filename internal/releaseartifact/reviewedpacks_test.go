package releaseartifact

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type registryFixture struct {
	root    string
	records []map[string]any
}

func newRegistryFixture(t *testing.T) *registryFixture {
	t.Helper()
	return &registryFixture{root: t.TempDir()}
}

func (f *registryFixture) writePack(t *testing.T, relative, content string) string {
	t.Helper()
	path := filepath.Join(f.root, filepath.FromSlash(relative))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return digestHex([]byte(content))
}

func (f *registryFixture) add(record map[string]any) {
	f.records = append(f.records, record)
}

func (f *registryFixture) write(t *testing.T) {
	t.Helper()
	data, err := json.Marshal(map[string]any{"schemaVersion": "cirewind.review-registry/v1alpha1", "records": f.records})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(f.root, ReviewRegistryName), append(data, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
}

func reviewedRecord(id, version, recordID, hash string) map[string]any {
	return map[string]any{
		"recordId": recordID, "incidentId": id, "packVersion": version, "status": "reviewed",
		"candidateCommit": strings.Repeat("c", 40), "promotionContentCommit": strings.Repeat("d", 40),
		"reviewedPath":       "incidents/reviewed/" + id + "/" + version + ".yaml",
		"originalPackSha256": hash, "canonicalPackSha256": strings.Repeat("e", 64),
		"candidateManifestSha256": strings.Repeat("f", 64), "reviewRecordManifestSha256": strings.Repeat("a", 64),
		"approvalIds": []string{"approval-maintainer-1", "approval-outside-1"}, "reviewPolicyProfile": "standard-v0.2",
		"reviewPolicySha256": strings.Repeat("b", 64), "recordedAt": "2026-09-01T00:00:00Z",
	}
}

func TestLoadReviewedPacksBundlesOnlyLatestReviewedRecords(t *testing.T) {
	fixture := newRegistryFixture(t)
	reviewedHash := fixture.writePack(t, "incidents/reviewed/synthetic-a/1.0.0.yaml", "incident: synthetic-a\n")
	fixture.writePack(t, "incidents/reviewed/synthetic-b/1.0.0.yaml", "incident: synthetic-b withdrawn\n")
	fixture.writePack(t, "incidents/reviewed/synthetic-c/1.0.0.yaml", "incident: synthetic-c superseded\n")
	supersedingHash := fixture.writePack(t, "incidents/reviewed/synthetic-c/1.1.0.yaml", "incident: synthetic-c newer\n")
	fixture.writePack(t, "incidents/candidates/synthetic-d/1.0.0.yaml", "incident: synthetic-d candidate\n")
	fixture.add(map[string]any{"recordId": "r0", "incidentId": "synthetic-d", "packVersion": "1.0.0", "status": "candidate", "candidateCommit": strings.Repeat("1", 40), "approvalIds": []string{}, "recordedAt": "2026-08-01T00:00:00Z"})
	fixture.add(reviewedRecord("synthetic-a", "1.0.0", "r1", reviewedHash))
	fixture.add(reviewedRecord("synthetic-b", "1.0.0", "r2", digestHex([]byte("incident: synthetic-b withdrawn\n"))))
	withdrawn := reviewedRecord("synthetic-b", "1.0.0", "r3", digestHex([]byte("incident: synthetic-b withdrawn\n")))
	withdrawn["status"] = "withdrawn"
	withdrawn["previousRecordId"] = "r2"
	withdrawn["withdrawalReason"] = "synthetic withdrawal"
	fixture.add(withdrawn)
	fixture.add(reviewedRecord("synthetic-c", "1.0.0", "r4", digestHex([]byte("incident: synthetic-c superseded\n"))))
	superseded := reviewedRecord("synthetic-c", "1.0.0", "r5", digestHex([]byte("incident: synthetic-c superseded\n")))
	superseded["status"] = "superseded"
	superseded["supersededByPackVersion"] = "1.1.0"
	fixture.add(superseded)
	newer := reviewedRecord("synthetic-c", "1.1.0", "r6", supersedingHash)
	newer["supersedesPackVersion"] = "1.0.0"
	fixture.add(newer)
	fixture.write(t)

	packs, err := LoadReviewedPacks(fixture.root)
	if err != nil {
		t.Fatalf("load reviewed packs: %v", err)
	}
	if len(packs) != 2 || packs[0].IncidentID != "synthetic-a" || packs[1].IncidentID != "synthetic-c" || packs[1].PackVersion != "1.1.0" {
		t.Fatalf("packs=%+v", packs)
	}
	if packs[0].Path != "incidents/reviewed/synthetic-a/1.0.0.yaml" || packs[0].RecordID != "r1" || len(packs[0].ApprovalIDs) != 2 {
		t.Fatalf("pack=%+v", packs[0])
	}
	reviewed, files, err := reviewedArchiveFiles(fixture.root)
	if err != nil {
		t.Fatal(err)
	}
	if len(reviewed) != 2 || len(files) != 3 || files[0].Name != ReviewedIndexName {
		t.Fatalf("files=%v", files)
	}
	for _, file := range files {
		if strings.HasPrefix(file.Name, "incidents/candidates/") {
			t.Fatalf("candidate copy entered release files: %s", file.Name)
		}
	}
	index, err := EncodeReviewedIndex(reviewed)
	if err != nil {
		t.Fatal(err)
	}
	var decoded ReviewedIndex
	if err := json.Unmarshal(index, &decoded); err != nil || decoded.SchemaVersion != "cirewind.reviewed-pack-index/v1alpha1" || len(decoded.Packs) != 2 {
		t.Fatalf("index=%s err=%v", index, err)
	}

	archive := map[string][]byte{"top/" + ReviewedIndexName: index}
	for _, file := range files[1:] {
		archive["top/"+file.Name] = file.Data
	}
	archive["top/incidents/synthetic/mutable-tag.yaml"] = []byte("synthetic\n")
	accounted, err := verifyReviewedEntries(archive, "top/", reviewed)
	if err != nil || len(accounted) != 3 {
		t.Fatalf("verify reviewed entries: accounted=%v err=%v", accounted, err)
	}
	archive["top/incidents/candidates/synthetic-d/1.0.0.yaml"] = []byte("candidate\n")
	if _, err := verifyReviewedEntries(archive, "top/", reviewed); err == nil {
		t.Fatal("candidate copy inside the archive was accepted")
	}
	delete(archive, "top/incidents/candidates/synthetic-d/1.0.0.yaml")
	archive["top/review-packets/x/review.json"] = []byte("{}")
	if _, err := verifyReviewedEntries(archive, "top/", reviewed); err == nil {
		t.Fatal("review packet inside the archive was accepted")
	}
	delete(archive, "top/review-packets/x/review.json")
	archive["top/incidents/reviewed/synthetic-z/9.9.9.yaml"] = []byte("unlisted\n")
	if _, err := verifyReviewedEntries(archive, "top/", reviewed); err == nil {
		t.Fatal("unlisted reviewed pack inside the archive was accepted")
	}
	delete(archive, "top/incidents/reviewed/synthetic-z/9.9.9.yaml")
	archive["top/incidents/reviewed/synthetic-a/1.0.0.yaml"] = []byte("tampered\n")
	if _, err := verifyReviewedEntries(archive, "top/", reviewed); err == nil {
		t.Fatal("tampered reviewed pack inside the archive was accepted")
	}
	if _, err := verifyReviewedEntries(map[string][]byte{}, "top/", nil); err == nil {
		t.Fatal("archive without the reviewed index was accepted")
	}
}

func TestLoadReviewedPacksRejectsUnsoundRecords(t *testing.T) {
	cases := map[string]func(t *testing.T, fixture *registryFixture){
		"hash mismatch": func(t *testing.T, fixture *registryFixture) {
			fixture.writePack(t, "incidents/reviewed/synthetic-a/1.0.0.yaml", "incident: a\n")
			fixture.add(reviewedRecord("synthetic-a", "1.0.0", "r1", strings.Repeat("0", 64)))
		},
		"missing file": func(t *testing.T, fixture *registryFixture) {
			fixture.add(reviewedRecord("synthetic-a", "1.0.0", "r1", digestHex([]byte("incident: a\n"))))
		},
		"path outside reviewed tree": func(t *testing.T, fixture *registryFixture) {
			hash := fixture.writePack(t, "incidents/reviewed/synthetic-a/1.0.0.yaml", "incident: a\n")
			record := reviewedRecord("synthetic-a", "1.0.0", "r1", hash)
			record["reviewedPath"] = "incidents/candidates/synthetic-a/1.0.0.yaml"
			fixture.add(record)
		},
		"unsafe identifier": func(t *testing.T, fixture *registryFixture) {
			hash := fixture.writePack(t, "incidents/reviewed/synthetic-a/1.0.0.yaml", "incident: a\n")
			record := reviewedRecord("../synthetic-a", "1.0.0", "r1", hash)
			fixture.add(record)
		},
		"no approvals": func(t *testing.T, fixture *registryFixture) {
			hash := fixture.writePack(t, "incidents/reviewed/synthetic-a/1.0.0.yaml", "incident: a\n")
			record := reviewedRecord("synthetic-a", "1.0.0", "r1", hash)
			record["approvalIds"] = []string{}
			fixture.add(record)
		},
		"short promotion commit": func(t *testing.T, fixture *registryFixture) {
			hash := fixture.writePack(t, "incidents/reviewed/synthetic-a/1.0.0.yaml", "incident: a\n")
			record := reviewedRecord("synthetic-a", "1.0.0", "r1", hash)
			record["promotionContentCommit"] = "abc123"
			fixture.add(record)
		},
		"unknown field": func(t *testing.T, fixture *registryFixture) {
			hash := fixture.writePack(t, "incidents/reviewed/synthetic-a/1.0.0.yaml", "incident: a\n")
			record := reviewedRecord("synthetic-a", "1.0.0", "r1", hash)
			record["releaseReady"] = true
			fixture.add(record)
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			fixture := newRegistryFixture(t)
			mutate(t, fixture)
			fixture.write(t)
			if _, err := LoadReviewedPacks(fixture.root); err == nil {
				t.Fatal("unsound registry record was bundled")
			}
		})
	}
	t.Run("symlinked reviewed pack", func(t *testing.T) {
		fixture := newRegistryFixture(t)
		hash := fixture.writePack(t, "elsewhere.yaml", "incident: a\n")
		if err := os.MkdirAll(filepath.Join(fixture.root, "incidents", "reviewed", "synthetic-a"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Join(fixture.root, "elsewhere.yaml"), filepath.Join(fixture.root, "incidents", "reviewed", "synthetic-a", "1.0.0.yaml")); err != nil {
			t.Skip("symbolic links are unavailable")
		}
		fixture.add(reviewedRecord("synthetic-a", "1.0.0", "r1", hash))
		fixture.write(t)
		if _, err := LoadReviewedPacks(fixture.root); err == nil {
			t.Fatal("symlinked reviewed pack was bundled")
		}
	})
	t.Run("registry absent", func(t *testing.T) {
		if _, err := LoadReviewedPacks(t.TempDir()); err == nil {
			t.Fatal("release without a review registry was accepted")
		}
	})
	t.Run("repository registry is empty and valid", func(t *testing.T) {
		packs, err := LoadReviewedPacks(filepath.Join("..", ".."))
		if err != nil || len(packs) != 0 {
			t.Fatalf("repository registry packs=%v err=%v", packs, err)
		}
	})
}
