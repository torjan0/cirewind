package packextract

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Trivy2026Tags identifies the derivation of the original trivy-action tag
// inventory from the repository's current tag listing.
const (
	Trivy2026TagsExtractor        = "trivy-2026-action-tag-inventory"
	Trivy2026TagsExtractorVersion = "1"
	trivy2026FirstSafeTag         = "0.35.0"
	maxListingRefs                = 10000
)

var (
	versionTagPattern = regexp.MustCompile(`^refs/tags/v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`)
	plainVersion      = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`)
)

// TagInventory is the reproducible derivation of the pre-incident tag names
// of aquasecurity/trivy-action. The maintainer advisory states that the
// original tags (0.0.1 to 0.34.2) were deleted, that new tags with a v prefix
// were published pointing to the original commits, and that three named tags
// were not restored. The derivation strips the prefix from every current
// v-prefixed tag below the first safe release and adds the named unrestored
// tags, which the caller supplies verbatim from the advisory.
type TagInventory struct {
	SchemaVersion    string          `json:"schemaVersion"`
	Extractor        string          `json:"extractor"`
	ExtractorVersion string          `json:"extractorVersion"`
	InputSHA256      string          `json:"inputSha256"`
	InputByteLength  int             `json:"inputByteLength"`
	FirstSafeTag     string          `json:"firstSafeTag"`
	Restored         []RestoredTag   `json:"restored"`
	Unrestored       []string        `json:"unrestored"`
	Skipped          []string        `json:"skipped"`
	OriginalTags     []string        `json:"originalTags"`
	Counts           InventoryCounts `json:"counts"`
	OutputSHA256     string          `json:"outputSha256"`
}

// RestoredTag pairs a current v-prefixed ref with the original name it stands
// in for and the object it currently points at.
type RestoredTag struct {
	Ref          string `json:"ref"`
	OriginalName string `json:"originalName"`
	ObjectType   string `json:"objectType"`
	ObjectSHA    string `json:"objectSha"`
}

// InventoryCounts summarizes the derivation so a count mismatch against the
// advisory's own tally is visible at a glance.
type InventoryCounts struct {
	ListingRefs int `json:"listingRefs"`
	Restored    int `json:"restored"`
	Unrestored  int `json:"unrestored"`
	Skipped     int `json:"skipped"`
	Original    int `json:"original"`
}

// DeriveTrivy2026TagInventory derives the original tag names from the JSON
// array returned by GET /repos/aquasecurity/trivy-action/git/matching-refs/tags/
// and the unrestored names the advisory states.
func DeriveTrivy2026TagInventory(listing []byte, unrestored []string) (*TagInventory, error) {
	if len(listing) > maxInputBytes {
		return nil, fmt.Errorf("listing is %d bytes, more than the %d allowed", len(listing), maxInputBytes)
	}
	var refs []struct {
		Ref    string `json:"ref"`
		Object struct {
			Type string `json:"type"`
			SHA  string `json:"sha"`
		} `json:"object"`
	}
	if err := json.Unmarshal(listing, &refs); err != nil {
		return nil, fmt.Errorf("listing is not a JSON array of refs: %w", err)
	}
	if len(refs) > maxListingRefs {
		return nil, fmt.Errorf("listing has %d refs, more than the %d allowed", len(refs), maxListingRefs)
	}
	firstSafe, _ := parseVersion(trivy2026FirstSafeTag)
	sum := sha256.Sum256(listing)
	result := &TagInventory{
		SchemaVersion: ExtractionSchema, Extractor: Trivy2026TagsExtractor, ExtractorVersion: Trivy2026TagsExtractorVersion,
		InputSHA256: hex.EncodeToString(sum[:]), InputByteLength: len(listing), FirstSafeTag: trivy2026FirstSafeTag,
		Restored: []RestoredTag{}, Unrestored: []string{}, Skipped: []string{}, OriginalTags: []string{},
	}
	seen := make(map[string]string)
	for _, ref := range refs {
		if ref.Ref == "" {
			return nil, fmt.Errorf("listing entry lacks a ref")
		}
		if _, dup := seen[ref.Ref]; dup {
			return nil, fmt.Errorf("listing repeats ref %s", ref.Ref)
		}
		seen[ref.Ref] = ref.Object.SHA
		match := versionTagPattern.FindStringSubmatch(ref.Ref)
		if match == nil {
			result.Skipped = append(result.Skipped, ref.Ref)
			continue
		}
		version, _ := parseVersion(match[1] + "." + match[2] + "." + match[3])
		if !version.less(firstSafe) {
			result.Skipped = append(result.Skipped, ref.Ref)
			continue
		}
		if !regexp.MustCompile(`^[0-9a-f]{40}$`).MatchString(ref.Object.SHA) || (ref.Object.Type != "commit" && ref.Object.Type != "tag") {
			return nil, fmt.Errorf("ref %s has a malformed object", ref.Ref)
		}
		result.Restored = append(result.Restored, RestoredTag{Ref: ref.Ref, OriginalName: version.String(), ObjectType: ref.Object.Type, ObjectSHA: ref.Object.SHA})
	}
	original := make(map[string]struct{})
	for _, tag := range result.Restored {
		original[tag.OriginalName] = struct{}{}
	}
	for _, name := range unrestored {
		version, ok := parseVersion(name)
		if !ok {
			return nil, fmt.Errorf("unrestored tag %q is not a plain MAJOR.MINOR.PATCH version", name)
		}
		if !version.less(firstSafe) {
			return nil, fmt.Errorf("unrestored tag %q is not below the first safe tag %s", name, trivy2026FirstSafeTag)
		}
		if _, dup := original[name]; dup {
			return nil, fmt.Errorf("unrestored tag %q is already present in the listing", name)
		}
		original[name] = struct{}{}
		result.Unrestored = append(result.Unrestored, name)
	}
	for name := range original {
		result.OriginalTags = append(result.OriginalTags, name)
	}
	sort.Slice(result.Restored, func(i, j int) bool {
		return versionLess(result.Restored[i].OriginalName, result.Restored[j].OriginalName)
	})
	sort.Slice(result.Unrestored, func(i, j int) bool { return versionLess(result.Unrestored[i], result.Unrestored[j]) })
	sort.Slice(result.OriginalTags, func(i, j int) bool { return versionLess(result.OriginalTags[i], result.OriginalTags[j]) })
	sort.Strings(result.Skipped)
	result.Counts = InventoryCounts{ListingRefs: len(refs), Restored: len(result.Restored), Unrestored: len(result.Unrestored), Skipped: len(result.Skipped), Original: len(result.OriginalTags)}
	if err := seal(result); err != nil {
		return nil, err
	}
	return result, nil
}

type version struct{ major, minor, patch uint64 }

func parseVersion(text string) (version, bool) {
	match := plainVersion.FindStringSubmatch(text)
	if match == nil {
		return version{}, false
	}
	parts := make([]uint64, 3)
	for index := range parts {
		value, err := strconv.ParseUint(match[index+1], 10, 32)
		if err != nil {
			return version{}, false
		}
		parts[index] = value
	}
	return version{parts[0], parts[1], parts[2]}, true
}

func (v version) less(other version) bool {
	if v.major != other.major {
		return v.major < other.major
	}
	if v.minor != other.minor {
		return v.minor < other.minor
	}
	return v.patch < other.patch
}

func (v version) String() string {
	return strings.Join([]string{strconv.FormatUint(v.major, 10), strconv.FormatUint(v.minor, 10), strconv.FormatUint(v.patch, 10)}, ".")
}

func versionLess(a, b string) bool {
	left, _ := parseVersion(a)
	right, _ := parseVersion(b)
	return left.less(right)
}
