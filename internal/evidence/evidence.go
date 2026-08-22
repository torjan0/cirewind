package evidence

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"path"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/torjan0/cirewind/internal/model"
)

const EvidenceSchemaVersion = "cirewind.evidence/v1alpha1"

type SourceKind string

const (
	SourceWorkflowRunAttemptLog SourceKind = "workflow_run_attempt_log"
	SourceJobLog                SourceKind = "job_log"
	SourceAPIJSON               SourceKind = "api_json"
	SourceRepositoryContent     SourceKind = "repository_content"
	SourceDerivedRecord         SourceKind = "derived_record"
	SourceOtherBounded          SourceKind = "other_bounded_kind"
)

func (k SourceKind) Valid() bool {
	switch k {
	case SourceWorkflowRunAttemptLog, SourceJobLog, SourceAPIJSON, SourceRepositoryContent, SourceDerivedRecord, SourceOtherBounded:
		return true
	default:
		return false
	}
}

func (k *SourceKind) UnmarshalJSON(data []byte) error {
	var value string
	if err := json.Unmarshal(data, &value); err != nil {
		return fmt.Errorf("decode source kind: %w", err)
	}
	if !SourceKind(value).Valid() {
		return fmt.Errorf("unknown source kind %q", value)
	}
	*k = SourceKind(value)
	return nil
}

type Provider string

const (
	ProviderGitHub   Provider = "github.com"
	ProviderCIRewind Provider = "cirewind"
)

func (p Provider) Valid() bool { return p == ProviderGitHub || p == ProviderCIRewind }

type RedactionStatus string

const (
	RedactionNotApplicable       RedactionStatus = "not_applicable"
	RedactionNotInspected        RedactionStatus = "not_inspected"
	RedactionStructuredAllowlist RedactionStatus = "structured_allowlist"
	RedactionRedacted            RedactionStatus = "redacted"
)

func (s RedactionStatus) Valid() bool {
	return s == RedactionNotApplicable || s == RedactionNotInspected || s == RedactionStructuredAllowlist || s == RedactionRedacted
}

type ErrorPhase string

const (
	ErrorCollect ErrorPhase = "collect"
	ErrorDecode  ErrorPhase = "decode"
	ErrorExtract ErrorPhase = "extract"
	ErrorDerive  ErrorPhase = "derive"
)

func (p ErrorPhase) Valid() bool {
	return p == ErrorCollect || p == ErrorDecode || p == ErrorExtract || p == ErrorDerive
}

type RequestParameters map[string]string

func (p RequestParameters) Validate() error {
	if p == nil {
		return errors.New("request parameters must be an explicit object")
	}
	if len(p) > 64 {
		return errors.New("too many recorded request parameters")
	}
	for key, value := range p {
		if key == "" || len(key) > 128 || !utf8.ValidString(key) || sensitiveName(key) {
			return fmt.Errorf("request parameter %q is not allowlist-safe", key)
		}
		if len(value) > 4096 || !utf8.ValidString(value) || hasControl(value) || looksSensitive(value) {
			return fmt.Errorf("request parameter %q has an unsafe value", key)
		}
	}
	return nil
}

type LogicalSourceIdentity struct {
	Kind              SourceKind          `json:"kind"`
	CanonicalID       string              `json:"canonical_id"`
	Scope             model.CoverageScope `json:"scope"`
	RequestParameters RequestParameters   `json:"request_parameters"`
}

func (i LogicalSourceIdentity) Validate() error {
	if !i.Kind.Valid() {
		return fmt.Errorf("invalid source kind %q", i.Kind)
	}
	if i.CanonicalID == "" || len(i.CanonicalID) > 4096 || !utf8.ValidString(i.CanonicalID) || hasControl(i.CanonicalID) || looksSensitive(i.CanonicalID) {
		return errors.New("logical source canonical ID is unsafe")
	}
	if err := i.Scope.Validate(); err != nil {
		return err
	}
	return i.RequestParameters.Validate()
}

type LogicalSource struct {
	ID                model.LogicalSourceID `json:"id"`
	Kind              SourceKind            `json:"kind"`
	CanonicalID       string                `json:"canonical_id"`
	RequestParameters RequestParameters     `json:"request_parameters"`
}

func (s LogicalSource) Identity(scope model.CoverageScope) LogicalSourceIdentity {
	return LogicalSourceIdentity{
		Kind:              s.Kind,
		CanonicalID:       s.CanonicalID,
		Scope:             scope,
		RequestParameters: s.RequestParameters,
	}
}

func (s LogicalSource) Validate(scope model.CoverageScope) error {
	if err := s.ID.Validate(); err != nil {
		return err
	}
	identity := s.Identity(scope)
	if err := identity.Validate(); err != nil {
		return err
	}
	expected, err := NewLogicalSourceID(identity)
	if err != nil {
		return err
	}
	if expected != s.ID {
		return errors.New("logical source ID does not match its canonical identity")
	}
	return nil
}

type SourceDescriptor struct {
	Provider          Provider          `json:"provider"`
	APIVersion        string            `json:"api_version,omitempty"`
	EndpointTemplate  string            `json:"endpoint_template,omitempty"`
	SourceURL         string            `json:"source_url,omitempty"`
	RequestParameters RequestParameters `json:"request_parameters"`
	RequestAttempt    uint32            `json:"request_attempt"`
	HTTPStatus        *int              `json:"http_status,omitempty"`
}

func (s SourceDescriptor) Validate() error {
	if !s.Provider.Valid() {
		return fmt.Errorf("invalid source provider %q", s.Provider)
	}
	if s.RequestAttempt == 0 {
		return errors.New("request attempt must be positive")
	}
	if len(s.APIVersion) > 128 || len(s.EndpointTemplate) > 2048 || !utf8.ValidString(s.APIVersion+s.EndpointTemplate) || looksSensitive(s.EndpointTemplate) {
		return errors.New("source API descriptor is unsafe")
	}
	if s.SourceURL != "" {
		parsed, err := url.Parse(s.SourceURL)
		if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
			return errors.New("source URL must be a query-free HTTPS identifier without user information")
		}
	}
	if s.HTTPStatus != nil && (*s.HTTPStatus < 100 || *s.HTTPStatus > 599) {
		return errors.New("HTTP status is outside the valid range")
	}
	return s.RequestParameters.Validate()
}

type ContentDescriptor struct {
	MediaType             string  `json:"media_type"`
	ByteLength            uint64  `json:"byte_length"`
	DeclaredByteLength    *uint64 `json:"declared_byte_length,omitempty"`
	Complete              bool    `json:"complete"`
	SourceSHA256          string  `json:"source_sha256"`
	RetainedPayloadSHA256 *string `json:"retained_payload_sha256,omitempty"`
	RawRetained           bool    `json:"raw_retained"`
	RetainedPath          string  `json:"retained_path,omitempty"`
}

func (c ContentDescriptor) Validate() error {
	if c.MediaType == "" || len(c.MediaType) > 256 || !utf8.ValidString(c.MediaType) {
		return errors.New("content media type is invalid")
	}
	if err := validateSHA256(c.SourceSHA256, "source SHA-256"); err != nil {
		return err
	}
	if c.RetainedPayloadSHA256 != nil {
		if err := validateSHA256(*c.RetainedPayloadSHA256, "retained payload SHA-256"); err != nil {
			return err
		}
	}
	if c.RawRetained {
		if c.RetainedPayloadSHA256 == nil || !safeRelativePath(c.RetainedPath) {
			return errors.New("raw-retained content requires a retained hash and safe relative path")
		}
	} else if c.RetainedPath != "" {
		return errors.New("discarded raw content cannot have a retained path")
	}
	return nil
}

type ExtractorDescriptor struct {
	Name          string `json:"name"`
	Version       string `json:"version"`
	RulesetSHA256 string `json:"ruleset_sha256"`
}

func (e ExtractorDescriptor) Validate() error {
	if e.Name == "" || len(e.Name) > 128 || e.Version == "" || len(e.Version) > 128 || !utf8.ValidString(e.Name+e.Version) {
		return errors.New("extractor name or version is invalid")
	}
	return validateSHA256(e.RulesetSHA256, "extractor ruleset SHA-256")
}

type RedactionDescriptor struct {
	Status        RedactionStatus `json:"status"`
	PolicyVersion string          `json:"policy_version"`
}

func (r RedactionDescriptor) Validate() error {
	if !r.Status.Valid() {
		return fmt.Errorf("invalid redaction status %q", r.Status)
	}
	if r.PolicyVersion == "" || len(r.PolicyVersion) > 128 || !utf8.ValidString(r.PolicyVersion) {
		return errors.New("redaction policy version is invalid")
	}
	return nil
}

// RetentionDescriptor is the exact identity-bearing representation descriptor.
type RetentionDescriptor struct {
	MediaType              string          `json:"media_type"`
	ByteLength             uint64          `json:"byte_length"`
	RawRetained            bool            `json:"raw_retained"`
	RetainedPayloadSHA256  *string         `json:"retained_payload_sha256"`
	RedactionStatus        RedactionStatus `json:"redaction_status"`
	RedactionPolicyVersion string          `json:"redaction_policy_version"`
}

func (r RetentionDescriptor) Validate() error {
	content := ContentDescriptor{
		MediaType:             r.MediaType,
		ByteLength:            r.ByteLength,
		Complete:              true,
		SourceSHA256:          strings.Repeat("0", 64),
		RetainedPayloadSHA256: r.RetainedPayloadSHA256,
		RawRetained:           r.RawRetained,
	}
	if r.RawRetained {
		content.RetainedPath = "raw/identity-placeholder"
	}
	if err := content.Validate(); err != nil {
		return err
	}
	return (RedactionDescriptor{Status: r.RedactionStatus, PolicyVersion: r.RedactionPolicyVersion}).Validate()
}

type DerivationDescriptor struct {
	Kind              string             `json:"kind,omitempty"`
	ParentEvidenceIDs []model.EvidenceID `json:"parent_evidence_ids"`
	RuleID            string             `json:"rule_id,omitempty"`
	RuleVersion       string             `json:"rule_version,omitempty"`
	ParametersSHA256  *string            `json:"parameters_sha256,omitempty"`
}

func (d DerivationDescriptor) Validate() error {
	if d.ParentEvidenceIDs == nil {
		return errors.New("derivation parent evidence IDs must be an explicit array")
	}
	if d.Kind == "" {
		if len(d.ParentEvidenceIDs) != 0 || d.RuleID != "" || d.RuleVersion != "" || d.ParametersSHA256 != nil {
			return errors.New("non-derived evidence cannot have derivation fields")
		}
		return nil
	}
	if d.RuleID == "" || d.RuleVersion == "" || len(d.ParentEvidenceIDs) == 0 {
		return errors.New("derived evidence requires parents and a versioned rule")
	}
	if err := validateSortedEvidenceIDs(d.ParentEvidenceIDs); err != nil {
		return err
	}
	if d.ParametersSHA256 != nil {
		return validateSHA256(*d.ParametersSHA256, "derivation parameters SHA-256")
	}
	return nil
}

type EvidenceError struct {
	Phase             ErrorPhase `json:"phase"`
	Code              string     `json:"code"`
	HTTPStatus        *int       `json:"http_status,omitempty"`
	Retryable         bool       `json:"retryable"`
	PermissionRelated *bool      `json:"permission_related,omitempty"`
	SanitizedMessage  string     `json:"sanitized_message,omitempty"`
	RawMessageSHA256  *string    `json:"raw_message_sha256,omitempty"`
}

func (e EvidenceError) Validate() error {
	if !e.Phase.Valid() || e.Code == "" || len(e.Code) > 128 || !utf8.ValidString(e.Code) {
		return errors.New("evidence error phase or code is invalid")
	}
	if e.HTTPStatus != nil && (*e.HTTPStatus < 100 || *e.HTTPStatus > 599) {
		return errors.New("evidence error HTTP status is invalid")
	}
	if len(e.SanitizedMessage) > 2048 || !utf8.ValidString(e.SanitizedMessage) || hasControl(e.SanitizedMessage) || looksSensitive(e.SanitizedMessage) {
		return errors.New("evidence error message is not safely sanitized")
	}
	if e.RawMessageSHA256 != nil {
		return validateSHA256(*e.RawMessageSHA256, "raw error-message SHA-256")
	}
	return nil
}

type EvidenceObject struct {
	SchemaVersion string               `json:"schema_version"`
	ID            model.EvidenceID     `json:"evidence_id"`
	LogicalSource LogicalSource        `json:"logical_source"`
	Source        SourceDescriptor     `json:"source"`
	Scope         model.CoverageScope  `json:"scope"`
	EventTime     model.EventInterval  `json:"event_time"`
	Content       ContentDescriptor    `json:"content"`
	Extractor     ExtractorDescriptor  `json:"extractor"`
	Redaction     RedactionDescriptor  `json:"redaction"`
	Derivation    DerivationDescriptor `json:"derivation"`
	Errors        []EvidenceError      `json:"errors"`
}

func (e EvidenceObject) Validate() error {
	if e.SchemaVersion != EvidenceSchemaVersion {
		return fmt.Errorf("unsupported evidence schema %q", e.SchemaVersion)
	}
	if err := e.ID.Validate(); err != nil {
		return err
	}
	if err := e.LogicalSource.Validate(e.Scope); err != nil {
		return err
	}
	if err := e.Source.Validate(); err != nil {
		return err
	}
	if err := e.Scope.Validate(); err != nil {
		return err
	}
	if err := e.EventTime.Validate(); err != nil {
		return err
	}
	if err := e.Content.Validate(); err != nil {
		return err
	}
	if err := e.Extractor.Validate(); err != nil {
		return err
	}
	if err := e.Redaction.Validate(); err != nil {
		return err
	}
	if err := e.Derivation.Validate(); err != nil {
		return err
	}
	if e.Derivation.Kind != "" {
		if e.Source.Provider != ProviderCIRewind || e.LogicalSource.Kind != SourceDerivedRecord {
			return errors.New("derived evidence must use the CIRewind provider and derived-record source kind")
		}
		expectedSource, err := NewDerivedLogicalSource(e.Scope, e.Derivation, e.Content.SourceSHA256)
		if err != nil {
			return err
		}
		if expectedSource.ID != e.LogicalSource.ID || expectedSource.CanonicalID != e.LogicalSource.CanonicalID {
			return errors.New("derived logical source does not match its parent/rule/payload identity")
		}
	} else if e.LogicalSource.Kind == SourceDerivedRecord {
		return errors.New("derived-record source requires derivation metadata")
	}
	if e.Errors == nil {
		return errors.New("evidence errors must be an explicit array")
	}
	for _, evidenceError := range e.Errors {
		if err := evidenceError.Validate(); err != nil {
			return err
		}
	}
	if !e.Content.Complete && len(e.Errors) == 0 {
		return errors.New("incomplete evidence requires a typed error")
	}
	retention := RetentionDescriptor{
		MediaType:              e.Content.MediaType,
		ByteLength:             e.Content.ByteLength,
		RawRetained:            e.Content.RawRetained,
		RetainedPayloadSHA256:  e.Content.RetainedPayloadSHA256,
		RedactionStatus:        e.Redaction.Status,
		RedactionPolicyVersion: e.Redaction.PolicyVersion,
	}
	expectedID, err := NewEvidenceID(e.LogicalSource.ID, e.Content.SourceSHA256, retention)
	if err != nil {
		return err
	}
	if expectedID != e.ID {
		return errors.New("evidence ID does not match content and retention identity")
	}
	for _, parentID := range e.Derivation.ParentEvidenceIDs {
		if parentID == e.ID {
			return errors.New("evidence object cannot derive from itself")
		}
	}
	return nil
}

type CollectionObservation struct {
	ID                  model.CollectionObservationID `json:"observation_id"`
	EvidenceID          model.EvidenceID              `json:"evidence_id"`
	CollectionSessionID model.CollectionSessionID     `json:"collection_session_id"`
	RequestID           model.RequestID               `json:"request_id"`
	RequestAttempt      uint32                        `json:"request_attempt"`
	CollectionTime      model.CollectionWindow        `json:"collection_time"`
}

func (o CollectionObservation) Validate() error {
	if err := o.ID.Validate(); err != nil {
		return err
	}
	if err := o.EvidenceID.Validate(); err != nil {
		return err
	}
	if err := o.CollectionSessionID.Validate(); err != nil {
		return err
	}
	if err := o.RequestID.Validate(); err != nil {
		return err
	}
	if o.RequestAttempt == 0 {
		return errors.New("collection request attempt must be positive")
	}
	if err := o.CollectionTime.Validate(); err != nil {
		return err
	}
	expectedID, err := NewCollectionObservationID(o.EvidenceID, o.CollectionSessionID, o.RequestID, o.CollectionTime.EndedAt, o.RequestAttempt)
	if err != nil {
		return err
	}
	if expectedID != o.ID {
		return errors.New("collection observation ID does not match its canonical identity")
	}
	return nil
}

type Envelope struct {
	Evidence    EvidenceObject        `json:"evidence"`
	Observation CollectionObservation `json:"observation"`
}

func (e Envelope) Validate() error {
	if err := e.Evidence.Validate(); err != nil {
		return err
	}
	if err := e.Observation.Validate(); err != nil {
		return err
	}
	if e.Evidence.ID != e.Observation.EvidenceID {
		return errors.New("collection observation references a different evidence object")
	}
	return nil
}

func validateSHA256(value, label string) error {
	if len(value) != 64 || value != strings.ToLower(value) {
		return fmt.Errorf("%s must be 64 lowercase hexadecimal characters", label)
	}
	if _, err := hex.DecodeString(value); err != nil {
		return fmt.Errorf("%s is not hexadecimal: %w", label, err)
	}
	return nil
}

func validateSortedEvidenceIDs(ids []model.EvidenceID) error {
	for index, id := range ids {
		if err := id.Validate(); err != nil {
			return err
		}
		if index > 0 && ids[index-1] >= id {
			return errors.New("evidence IDs must be strictly sorted and unique")
		}
	}
	return nil
}

func sortEvidenceIDs(ids []model.EvidenceID) []model.EvidenceID {
	result := append([]model.EvidenceID(nil), ids...)
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	if len(result) == 0 {
		return result
	}
	write := 1
	for read := 1; read < len(result); read++ {
		if result[read] == result[write-1] {
			continue
		}
		result[write] = result[read]
		write++
	}
	return result[:write]
}

func safeRelativePath(value string) bool {
	return value != "" && !strings.Contains(value, `\`) && !strings.HasPrefix(value, "/") && path.Clean(value) == value && value != "." && !strings.HasPrefix(value, "../")
}

func sensitiveName(value string) bool {
	lower := strings.ToLower(value)
	for _, fragment := range []string{"authorization", "cookie", "token", "secret", "password", "signature", "credential", "jwt", "x-amz"} {
		if strings.Contains(lower, fragment) {
			return true
		}
	}
	return false
}

func looksSensitive(value string) bool {
	lower := strings.ToLower(value)
	for _, fragment := range []string{"authorization:", "bearer ", "token=", "access_token", "x-amz-signature", "x-goog-signature", "sig="} {
		if strings.Contains(lower, fragment) {
			return true
		}
	}
	return false
}

func hasControl(value string) bool {
	for _, char := range value {
		if char < 0x20 || char == 0x7f {
			return true
		}
	}
	return false
}
