package releaseartifact

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Reviewed-pack release contract. Only packs whose latest append-only registry
// record is "reviewed" enter a release, by exact bytes bound to the registry's
// recorded original-pack hash, together with an index that carries the
// registry and approval identifiers. Candidate copies, review packets, and
// superseded or withdrawn versions never enter release output. The packager
// does not judge review quality: the governance validation in
// internal/packreview and the CI review contract remain the authority for
// whether a registry record is legitimate.
const (
	ReviewRegistryName   = "review-registry.json"
	reviewRegistrySchema = "cirewind.review-registry/v1alpha1"
	ReviewedIndexName    = "incidents/reviewed/index.json"
	reviewedIndexSchema  = "cirewind.reviewed-pack-index/v1alpha1"
	maxRegistryBytes     = 4 << 20
	maxReviewedPackBytes = 1 << 20
	maxReviewedPacks     = 256
	candidatePackPrefix  = "incidents/candidates/"
	reviewPacketPrefix   = "review-packets/"
	reviewedPackPrefix   = "incidents/reviewed/"
	syntheticPackPath    = "incidents/synthetic/mutable-tag.yaml"
)

var (
	packIdentifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	commitPattern         = regexp.MustCompile(`^[0-9a-f]{40}$`)
	sha256Pattern         = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// ReviewedPack is one registry-marked reviewed incident pack bundled by exact
// bytes with the registry and approval identifiers that reviewed it.
type ReviewedPack struct {
	RecordID               string   `json:"recordId"`
	IncidentID             string   `json:"incidentId"`
	PackVersion            string   `json:"packVersion"`
	Path                   string   `json:"path"`
	OriginalPackSHA256     string   `json:"originalPackSha256"`
	CanonicalPackSHA256    string   `json:"canonicalPackSha256"`
	PromotionContentCommit string   `json:"promotionContentCommit"`
	ApprovalIDs            []string `json:"approvalIds"`
	ReviewPolicyProfile    string   `json:"reviewPolicyProfile"`
}

// ReviewedIndex is the archive-bundled index of reviewed packs. An empty list
// is a positive statement that the release bundles no reviewed real pack.
type ReviewedIndex struct {
	SchemaVersion string         `json:"schemaVersion"`
	Packs         []ReviewedPack `json:"packs"`
}

// reviewRegistry mirrors the packreview registry shape strictly so the release
// tool does not depend on the governance package; unknown fields are rejected.
type reviewRegistry struct {
	SchemaVersion string                 `json:"schemaVersion"`
	Records       []reviewRegistryRecord `json:"records"`
}

type reviewRegistryRecord struct {
	RecordID                   string   `json:"recordId"`
	IncidentID                 string   `json:"incidentId"`
	PackVersion                string   `json:"packVersion"`
	Status                     string   `json:"status"`
	PreviousRecordID           string   `json:"previousRecordId,omitempty"`
	CandidateCommit            string   `json:"candidateCommit,omitempty"`
	PromotionContentCommit     string   `json:"promotionContentCommit,omitempty"`
	ReviewedPath               string   `json:"reviewedPath,omitempty"`
	OriginalPackSHA256         string   `json:"originalPackSha256,omitempty"`
	CanonicalPackSHA256        string   `json:"canonicalPackSha256,omitempty"`
	CandidateManifestSHA256    string   `json:"candidateManifestSha256,omitempty"`
	ReviewRecordManifestSHA256 string   `json:"reviewRecordManifestSha256,omitempty"`
	ApprovalIDs                []string `json:"approvalIds"`
	ReviewPolicyProfile        string   `json:"reviewPolicyProfile,omitempty"`
	ReviewPolicySHA256         string   `json:"reviewPolicySha256,omitempty"`
	RecordedAt                 string   `json:"recordedAt"`
	SupersedesPackVersion      string   `json:"supersedesPackVersion,omitempty"`
	SupersededByPackVersion    string   `json:"supersededByPackVersion,omitempty"`
	WithdrawalReason           string   `json:"withdrawalReason,omitempty"`
}

// LoadReviewedPacks reads the repository's review registry and returns every
// pack whose latest record is reviewed, after binding the retained reviewed
// file bytes to the recorded original-pack hash. The registry must exist: a
// release without governance data is not a valid release input.
func LoadReviewedPacks(root string) ([]ReviewedPack, error) {
	raw, err := readBoundedRegular(filepath.Join(root, ReviewRegistryName), maxRegistryBytes)
	if err != nil {
		return nil, fmt.Errorf("read review registry: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var registry reviewRegistry
	if err := decoder.Decode(&registry); err != nil {
		return nil, fmt.Errorf("decode review registry: %w", err)
	}
	if err := requireJSONEOF(decoder); err != nil {
		return nil, fmt.Errorf("decode review registry: %w", err)
	}
	if registry.SchemaVersion != reviewRegistrySchema {
		return nil, fmt.Errorf("review registry schema %q is not %q", registry.SchemaVersion, reviewRegistrySchema)
	}
	latest := make(map[string]reviewRegistryRecord)
	order := make([]string, 0)
	for _, record := range registry.Records {
		if !packIdentifierPattern.MatchString(record.IncidentID) || !packIdentifierPattern.MatchString(record.PackVersion) {
			return nil, fmt.Errorf("review registry record %q carries an unsafe incident or version identifier", record.RecordID)
		}
		key := record.IncidentID + "/" + record.PackVersion
		if _, seen := latest[key]; !seen {
			order = append(order, key)
		}
		latest[key] = record
	}
	packs := make([]ReviewedPack, 0)
	for _, key := range order {
		record := latest[key]
		if record.Status != "reviewed" {
			continue
		}
		pack, err := reviewedPackFromRecord(root, record)
		if err != nil {
			return nil, err
		}
		packs = append(packs, pack)
	}
	if len(packs) > maxReviewedPacks {
		return nil, fmt.Errorf("release bundles at most %d reviewed packs", maxReviewedPacks)
	}
	sort.Slice(packs, func(i, j int) bool {
		if packs[i].IncidentID != packs[j].IncidentID {
			return packs[i].IncidentID < packs[j].IncidentID
		}
		return packs[i].PackVersion < packs[j].PackVersion
	})
	return packs, nil
}

func reviewedPackFromRecord(root string, record reviewRegistryRecord) (ReviewedPack, error) {
	label := record.IncidentID + "/" + record.PackVersion
	wantPath := reviewedPackPrefix + record.IncidentID + "/" + record.PackVersion + ".yaml"
	switch {
	case record.RecordID == "":
		return ReviewedPack{}, fmt.Errorf("reviewed pack %s has no record identifier", label)
	case record.ReviewedPath != wantPath:
		return ReviewedPack{}, fmt.Errorf("reviewed pack %s path %q is not the fixed reviewed location %q", label, record.ReviewedPath, wantPath)
	case !commitPattern.MatchString(record.PromotionContentCommit):
		return ReviewedPack{}, fmt.Errorf("reviewed pack %s lacks a full promotion content commit", label)
	case !sha256Pattern.MatchString(record.OriginalPackSHA256) || !sha256Pattern.MatchString(record.CanonicalPackSHA256):
		return ReviewedPack{}, fmt.Errorf("reviewed pack %s lacks lowercase SHA-256 pack hashes", label)
	case len(record.ApprovalIDs) == 0:
		return ReviewedPack{}, fmt.Errorf("reviewed pack %s carries no approval identifiers", label)
	case record.ReviewPolicyProfile == "":
		return ReviewedPack{}, fmt.Errorf("reviewed pack %s carries no review policy profile", label)
	}
	for _, approval := range record.ApprovalIDs {
		if strings.TrimSpace(approval) == "" || len(approval) > 256 {
			return ReviewedPack{}, fmt.Errorf("reviewed pack %s carries an empty or oversized approval identifier", label)
		}
	}
	path := filepath.Join(root, filepath.FromSlash(wantPath))
	info, err := os.Lstat(path)
	if err != nil {
		return ReviewedPack{}, fmt.Errorf("reviewed pack %s: %w", label, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return ReviewedPack{}, fmt.Errorf("reviewed pack %s is not a regular file", label)
	}
	data, err := readBoundedRegular(path, maxReviewedPackBytes)
	if err != nil {
		return ReviewedPack{}, fmt.Errorf("reviewed pack %s: %w", label, err)
	}
	if digestHex(data) != record.OriginalPackSHA256 {
		return ReviewedPack{}, fmt.Errorf("reviewed pack %s bytes do not match the registry's original pack hash", label)
	}
	return ReviewedPack{
		RecordID:               record.RecordID,
		IncidentID:             record.IncidentID,
		PackVersion:            record.PackVersion,
		Path:                   wantPath,
		OriginalPackSHA256:     record.OriginalPackSHA256,
		CanonicalPackSHA256:    record.CanonicalPackSHA256,
		PromotionContentCommit: record.PromotionContentCommit,
		ApprovalIDs:            append([]string(nil), record.ApprovalIDs...),
		ReviewPolicyProfile:    record.ReviewPolicyProfile,
	}, nil
}

// EncodeReviewedIndex renders the deterministic archive index.
func EncodeReviewedIndex(packs []ReviewedPack) ([]byte, error) {
	if packs == nil {
		packs = []ReviewedPack{}
	}
	data, err := json.MarshalIndent(ReviewedIndex{SchemaVersion: reviewedIndexSchema, Packs: packs}, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

// reviewedArchiveFiles returns the reviewed packs and the archive files that
// carry them: each pack at its fixed path plus the index.
func reviewedArchiveFiles(root string) ([]ReviewedPack, []ArchiveFile, error) {
	packs, err := LoadReviewedPacks(root)
	if err != nil {
		return nil, nil, err
	}
	index, err := EncodeReviewedIndex(packs)
	if err != nil {
		return nil, nil, err
	}
	files := []ArchiveFile{{Name: ReviewedIndexName, Data: index, Mode: 0o644}}
	for _, pack := range packs {
		data, err := readBoundedRegular(filepath.Join(root, filepath.FromSlash(pack.Path)), maxReviewedPackBytes)
		if err != nil {
			return nil, nil, err
		}
		files = append(files, ArchiveFile{Name: pack.Path, Data: data, Mode: 0o644})
	}
	return packs, files, nil
}

// verifyReviewedEntries checks the reviewed index and every listed pack inside
// an extracted archive, rejects any candidate, review-packet, or unlisted
// incident material, and returns the archive entry names it accounts for.
func verifyReviewedEntries(files map[string][]byte, prefix string, packs []ReviewedPack) (map[string]bool, error) {
	accounted := make(map[string]bool, len(packs)+1)
	wantIndex, err := EncodeReviewedIndex(packs)
	if err != nil {
		return nil, err
	}
	index, ok := files[prefix+ReviewedIndexName]
	if !ok {
		return nil, errors.New("archive omits the reviewed-pack index")
	}
	if !bytes.Equal(index, wantIndex) {
		return nil, errors.New("archived reviewed-pack index differs from the descriptor")
	}
	accounted[prefix+ReviewedIndexName] = true
	listed := make(map[string]bool, len(packs))
	for _, pack := range packs {
		wantPath := reviewedPackPrefix + pack.IncidentID + "/" + pack.PackVersion + ".yaml"
		if pack.Path != wantPath || !sha256Pattern.MatchString(pack.OriginalPackSHA256) {
			return nil, fmt.Errorf("descriptor reviewed pack %s/%s is malformed", pack.IncidentID, pack.PackVersion)
		}
		data, ok := files[prefix+pack.Path]
		if !ok {
			return nil, fmt.Errorf("archive omits reviewed pack %q", pack.Path)
		}
		if digestHex(data) != pack.OriginalPackSHA256 {
			return nil, fmt.Errorf("archived reviewed pack %q does not match its registry hash", pack.Path)
		}
		accounted[prefix+pack.Path] = true
		listed[prefix+pack.Path] = true
	}
	for name := range files {
		relative := strings.TrimPrefix(name, prefix)
		switch {
		case strings.HasPrefix(relative, candidatePackPrefix), strings.HasPrefix(relative, reviewPacketPrefix):
			return nil, fmt.Errorf("archive contains unreviewed governance material %q", relative)
		case strings.HasPrefix(relative, "incidents/") && relative != syntheticPackPath && relative != ReviewedIndexName && !listed[name]:
			return nil, fmt.Errorf("archive contains unlisted incident material %q", relative)
		}
	}
	return accounted, nil
}
