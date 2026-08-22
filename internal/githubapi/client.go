package githubapi

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	defaultJSONLimit = int64(64 << 20)
	hardJSONLimit    = int64(256 << 20)
	maxAPIRedirects  = 3
)

type RetryPolicy struct {
	MaxAttempts       int
	BaseDelay         time.Duration
	MaxDelay          time.Duration
	SecondaryMinDelay time.Duration
}

type Limits struct {
	JSONResponseBytes int64
	MaxPages          int
	AttemptLogBytes   int64
	JobLogBytes       int64
}

type Option func(*clientConfig) error

type clientConfig struct {
	httpClient        *http.Client
	userAgent         string
	retry             RetryPolicy
	limits            Limits
	now               func() time.Time
	sleep             func(context.Context, time.Duration) error
	jitter            func(time.Duration) time.Duration
	redirectValidator func(context.Context, *url.URL) error
}

func defaultClientConfig() clientConfig {
	return clientConfig{
		httpClient: &http.Client{Timeout: 2 * time.Minute},
		userAgent:  "CIRewind/dev",
		retry: RetryPolicy{
			MaxAttempts:       3,
			BaseDelay:         time.Second,
			MaxDelay:          5 * time.Minute,
			SecondaryMinDelay: time.Minute,
		},
		limits: Limits{
			JSONResponseBytes: defaultJSONLimit,
			MaxPages:          10_000,
			AttemptLogBytes:   512 << 20,
			JobLogBytes:       256 << 20,
		},
		now:               time.Now,
		sleep:             contextSleep,
		jitter:            cryptoJitter,
		redirectValidator: defaultRedirectValidator,
	}
}

func WithHTTPClient(client *http.Client) Option {
	return func(cfg *clientConfig) error {
		if client == nil {
			return errors.New("github HTTP client is nil")
		}
		cfg.httpClient = client
		return nil
	}
}

func WithUserAgent(value string) Option {
	return func(cfg *clientConfig) error {
		value = strings.TrimSpace(value)
		if value == "" || strings.ContainsAny(value, "\r\n") {
			return errors.New("github user agent is empty or contains a newline")
		}
		cfg.userAgent = value
		return nil
	}
}

func WithRetryPolicy(policy RetryPolicy) Option {
	return func(cfg *clientConfig) error {
		if policy.MaxAttempts < 1 || policy.MaxAttempts > 10 {
			return errors.New("retry attempts must be between 1 and 10")
		}
		if policy.BaseDelay < 0 || policy.MaxDelay < 0 || policy.SecondaryMinDelay < 0 {
			return errors.New("retry delays cannot be negative")
		}
		cfg.retry = policy
		return nil
	}
}

func WithLimits(limits Limits) Option {
	return func(cfg *clientConfig) error {
		if limits.JSONResponseBytes <= 0 || limits.JSONResponseBytes > hardJSONLimit {
			return fmt.Errorf("JSON response limit must be in 1..%d", hardJSONLimit)
		}
		if limits.MaxPages <= 0 || limits.MaxPages > 1_000_000 {
			return errors.New("maximum page count must be in 1..1000000")
		}
		if limits.AttemptLogBytes <= 0 || limits.AttemptLogBytes > 2<<30 {
			return errors.New("attempt log limit must be in 1..2GiB")
		}
		if limits.JobLogBytes <= 0 || limits.JobLogBytes > 1<<30 {
			return errors.New("job log limit must be in 1..1GiB")
		}
		cfg.limits = limits
		return nil
	}
}

// Client contains no general-purpose exported request method. Callers can only
// invoke the typed, read-only GitHub routes implemented by this package.
type Client struct {
	base              *url.URL
	httpClient        *http.Client
	storageHTTPClient *http.Client
	tokens            TokenSource
	userAgent         string
	retry             RetryPolicy
	limits            Limits
	now               func() time.Time
	sleep             func(context.Context, time.Duration) error
	jitter            func(time.Duration) time.Duration
	validateRedirect  func(context.Context, *url.URL) error
}

func New(tokens TokenSource, options ...Option) (*Client, error) {
	base, err := url.Parse(APIBaseURL)
	if err != nil {
		return nil, err
	}
	return newClient(base, tokens, false, options...)
}

func newClient(base *url.URL, tokens TokenSource, allowTestEndpoint bool, options ...Option) (*Client, error) {
	if base == nil || base.Scheme == "" || base.Host == "" {
		return nil, errors.New("GitHub API endpoint is invalid")
	}
	if !allowTestEndpoint && (base.Scheme != "https" || !strings.EqualFold(base.Hostname(), "api.github.com") || base.Port() != "") {
		return nil, &Error{Class: ErrorUnsupportedTarget, Operation: "configure", Message: "v0.1 supports only https://api.github.com"}
	}
	if tokens == nil {
		tokens = NoToken()
	}
	cfg := defaultClientConfig()
	for _, option := range options {
		if option == nil {
			continue
		}
		if err := option(&cfg); err != nil {
			return nil, err
		}
	}
	apiClient := cloneNoRedirectClient(cfg.httpClient, true)
	storageClient := cloneNoRedirectClient(cfg.httpClient, false)
	return &Client{
		base:              cloneURL(base),
		httpClient:        apiClient,
		storageHTTPClient: storageClient,
		tokens:            tokens,
		userAgent:         cfg.userAgent,
		retry:             cfg.retry,
		limits:            cfg.limits,
		now:               cfg.now,
		sleep:             cfg.sleep,
		jitter:            cfg.jitter,
		validateRedirect:  cfg.redirectValidator,
	}, nil
}

func cloneNoRedirectClient(source *http.Client, keepJar bool) *http.Client {
	clone := *source
	clone.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	if !keepJar {
		clone.Jar = nil
	}
	return &clone
}

func cloneURL(source *url.URL) *url.URL {
	clone := *source
	return &clone
}

type requestSpec struct {
	routeTemplate string
	path          string
	query         url.Values
	parameters    map[string]string
	accept        string
	maxBytes      int64
	ifNoneMatch   string
	absoluteURL   *url.URL
	operation     string
}

type rawResponse struct {
	body     []byte
	meta     ResponseMeta
	attempts []ResponseMeta
	next     *url.URL
	redirect *url.URL
}

func (c *Client) get(ctx context.Context, spec requestSpec) (rawResponse, error) {
	if err := ctx.Err(); err != nil {
		return rawResponse{}, &Error{Class: ErrorCancelled, Operation: spec.operation, Message: "request cancelled", Cause: err}
	}
	if spec.accept == "" {
		spec.accept = DefaultAccept
	}
	if spec.maxBytes <= 0 {
		spec.maxBytes = c.limits.JSONResponseBytes
	}
	if spec.maxBytes > hardJSONLimit && spec.accept == DefaultAccept {
		return rawResponse{}, &Error{Class: ErrorInvalidRequest, Operation: spec.operation, Message: "response budget exceeds JSON hard ceiling"}
	}
	target, err := c.requestURL(spec)
	if err != nil {
		return rawResponse{}, err
	}

	var attempts []ResponseMeta
	seenRedirects := map[string]struct{}{target.String(): {}}
	redirects := 0
	for attempt := 1; attempt <= c.retry.MaxAttempts; attempt++ {
		token, tokenErr := c.tokens.Token(ctx)
		if tokenErr != nil {
			return rawResponse{}, &Error{Class: ErrorUnauthorized, Operation: spec.operation, Message: "authentication source failed"}
		}
		for {
			response, requestErr := c.getOnce(ctx, target, spec, token)
			attempts = append(attempts, response.meta)
			response.attempts = append([]ResponseMeta(nil), attempts...)
			if requestErr == nil && response.redirect != nil {
				redirects++
				key := response.redirect.String()
				_, repeated := seenRedirects[key]
				if redirects > maxAPIRedirects || repeated {
					response.meta.ErrorClass = ErrorUnsafeRedirect
					attempts[len(attempts)-1].ErrorClass = ErrorUnsafeRedirect
					response.attempts = append([]ResponseMeta(nil), attempts...)
					return response, &Error{Class: ErrorUnsafeRedirect, Operation: spec.operation, StatusCode: response.meta.StatusCode, Message: "GitHub API redirect chain was cyclic or exceeded its bound", Responses: response.attempts}
				}
				seenRedirects[key] = struct{}{}
				target = response.redirect
				continue
			}
			if requestErr == nil {
				return response, nil
			}

			var apiErr *Error
			if !errors.As(requestErr, &apiErr) {
				return response, requestErr
			}
			apiErr.Responses = append([]ResponseMeta(nil), attempts...)
			if !apiErr.Retryable || attempt == c.retry.MaxAttempts {
				apiErr.Retryable = false
				if attempt == c.retry.MaxAttempts && attempt > 1 {
					apiErr.Message = appendDiagnostic(apiErr.Message, "retry budget exhausted")
				}
				return response, apiErr
			}

			delay := c.retryDelay(attempt, response.meta, apiErr.Class)
			if err := c.sleep(ctx, delay); err != nil {
				return response, &Error{Class: ErrorCancelled, Operation: spec.operation, Message: "retry cancelled", Responses: attempts, Cause: err}
			}
			break
		}
	}
	return rawResponse{}, &Error{
		Class:     ErrorRetryBudget,
		Operation: spec.operation,
		Message:   "request retry loop exhausted without a terminal result",
		Responses: attempts,
	}
}

func (c *Client) getOnce(ctx context.Context, target *url.URL, spec requestSpec, token string) (rawResponse, error) {
	started := c.now().UTC()
	meta := ResponseMeta{
		Method:            http.MethodGet,
		RouteTemplate:     spec.routeTemplate,
		RequestParameters: sanitizedParameters(spec.parameters),
		APIVersion:        APIVersion,
		StartedAt:         started,
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		meta.CompletedAt = c.now().UTC()
		meta.ErrorClass = ErrorInvalidRequest
		return rawResponse{meta: meta}, &Error{Class: ErrorInvalidRequest, Operation: spec.operation, Message: "could not create request"}
	}
	req.Header.Set("Accept", spec.accept)
	req.Header.Set("X-GitHub-Api-Version", APIVersion)
	req.Header.Set("User-Agent", c.userAgent)
	if spec.ifNoneMatch != "" {
		req.Header.Set("If-None-Match", spec.ifNoneMatch)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		meta.CompletedAt = c.now().UTC()
		if ctx.Err() != nil {
			meta.ErrorClass = ErrorCancelled
			return rawResponse{meta: meta}, &Error{Class: ErrorCancelled, Operation: spec.operation, Message: "request cancelled", Cause: ctx.Err()}
		}
		meta.ErrorClass = ErrorTransient
		return rawResponse{meta: meta}, &Error{Class: ErrorTransient, Operation: spec.operation, Message: "network request failed", Retryable: true}
	}
	defer resp.Body.Close()

	body, complete, readErr := readBounded(resp.Body, spec.maxBytes)
	meta = responseMetadata(meta, resp, body, complete, c.now().UTC())
	if readErr != nil {
		class := ErrorTransient
		message := "response body could not be read completely"
		retryable := true
		var sizeErr *Error
		if errors.As(readErr, &sizeErr) && sizeErr.Class == ErrorSizeLimit {
			class = ErrorSizeLimit
			message = "response exceeded configured byte limit"
			retryable = false
		}
		meta.ErrorClass = class
		return rawResponse{body: body, meta: meta}, &Error{Class: class, Operation: spec.operation, StatusCode: resp.StatusCode, Message: message, Retryable: retryable}
	}
	result := rawResponse{body: body, meta: meta}
	if isAPIRedirect(resp.StatusCode) {
		redirect, redirectErr := c.validateAPIRedirect(resp.Header.Get("Location"))
		if redirectErr != nil {
			result.meta.ErrorClass = ErrorUnsafeRedirect
			return result, &Error{Class: ErrorUnsafeRedirect, Operation: spec.operation, StatusCode: resp.StatusCode, Message: "GitHub API redirect left the configured origin or was malformed"}
		}
		result.redirect = redirect
		return result, nil
	}
	if link := strings.Join(resp.Header.Values("Link"), ","); link != "" {
		next, parseErr := c.nextLink(link)
		if parseErr != nil {
			result.meta.ErrorClass = ErrorPagination
			return result, &Error{Class: ErrorPagination, Operation: spec.operation, StatusCode: resp.StatusCode, Message: parseErr.Error()}
		}
		result.next = next
	}
	if resp.StatusCode == http.StatusNotModified {
		return result, nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		class, retryable := classifyHTTP(resp, body)
		result.meta.ErrorClass = class
		return result, &Error{
			Class:      class,
			Operation:  spec.operation,
			StatusCode: resp.StatusCode,
			Message:    sanitizeResponseMessage(body, token),
			Retryable:  retryable,
		}
	}
	return result, nil
}

func isAPIRedirect(status int) bool {
	return status == http.StatusMovedPermanently || status == http.StatusFound || status == http.StatusTemporaryRedirect || status == http.StatusPermanentRedirect
}

func (c *Client) validateAPIRedirect(value string) (*url.URL, error) {
	redirect, err := url.Parse(strings.TrimSpace(value))
	if err != nil || !redirect.IsAbs() {
		return nil, errors.New("API redirect is not an absolute URL")
	}
	if err := c.validateAPIURL(redirect); err != nil {
		return nil, err
	}
	return redirect, nil
}

func (c *Client) requestURL(spec requestSpec) (*url.URL, error) {
	if spec.absoluteURL != nil {
		if err := c.validateAPIURL(spec.absoluteURL); err != nil {
			return nil, err
		}
		return cloneURL(spec.absoluteURL), nil
	}
	if spec.path == "" || !strings.HasPrefix(spec.path, "/") {
		return nil, &Error{Class: ErrorInvalidRequest, Operation: spec.operation, Message: "compiled route path is invalid"}
	}
	target := cloneURL(c.base)
	escapedPath := strings.TrimSuffix(target.EscapedPath(), "/") + spec.path
	decodedPath, err := url.PathUnescape(escapedPath)
	if err != nil {
		return nil, &Error{Class: ErrorInvalidRequest, Operation: spec.operation, Message: "compiled route path has invalid escaping"}
	}
	target.Path = decodedPath
	target.RawPath = escapedPath
	target.RawQuery = spec.query.Encode()
	return target, nil
}

func (c *Client) validateAPIURL(candidate *url.URL) error {
	if candidate == nil || candidate.User != nil || candidate.Fragment != "" ||
		!strings.EqualFold(candidate.Scheme, c.base.Scheme) || !strings.EqualFold(candidate.Host, c.base.Host) {
		return &Error{Class: ErrorPagination, Operation: "paginate", Message: "next link left the configured GitHub API origin"}
	}
	basePath := strings.TrimSuffix(c.base.EscapedPath(), "/")
	if basePath != "" && !strings.HasPrefix(candidate.EscapedPath(), basePath+"/") {
		return &Error{Class: ErrorPagination, Operation: "paginate", Message: "next link left the configured API path"}
	}
	if err := safePaginationQuery(candidate); err != nil {
		return &Error{Class: ErrorPagination, Operation: "paginate", Message: err.Error()}
	}
	return nil
}

func readBounded(reader io.Reader, limit int64) ([]byte, bool, error) {
	if limit <= 0 {
		return nil, false, errors.New("invalid byte limit")
	}
	body, err := io.ReadAll(io.LimitReader(reader, limit+1))
	if err != nil {
		return body, false, err
	}
	if int64(len(body)) > limit {
		return body[:limit], false, &Error{Class: ErrorSizeLimit}
	}
	return body, true, nil
}

func responseMetadata(meta ResponseMeta, response *http.Response, body []byte, complete bool, completed time.Time) ResponseMeta {
	meta.StatusCode = response.StatusCode
	meta.RequestID = sanitizeDiagnostic(response.Header.Get("X-GitHub-Request-Id"))
	meta.ResponseAPIVersion = sanitizeDiagnostic(response.Header.Get("X-GitHub-Api-Version"))
	if meta.ResponseAPIVersion == "" {
		meta.ResponseAPIVersion = sanitizeDiagnostic(response.Header.Get("X-GitHub-Api-Version-Selected"))
	}
	meta.MediaType = sanitizeDiagnostic(response.Header.Get("Content-Type"))
	meta.ByteLength = int64(len(body))
	meta.BodyComplete = complete
	if complete {
		hash := sha256.Sum256(body)
		meta.SHA256 = hex.EncodeToString(hash[:])
	}
	meta.ETag = sanitizeDiagnostic(response.Header.Get("ETag"))
	meta.RateLimit = parseInt64Header(response.Header.Get("X-RateLimit-Limit"))
	meta.RateRemaining = parseInt64Header(response.Header.Get("X-RateLimit-Remaining"))
	meta.RateUsed = parseInt64Header(response.Header.Get("X-RateLimit-Used"))
	meta.RateReset = parseInt64Header(response.Header.Get("X-RateLimit-Reset"))
	meta.RateResource = sanitizeDiagnostic(response.Header.Get("X-RateLimit-Resource"))
	meta.RetryAfterSeconds = parseRetryAfter(response.Header.Get("Retry-After"), completed)
	meta.CompletedAt = completed
	return meta
}

func parseInt64Header(value string) int64 {
	result, _ := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
	return result
}

func parseRetryAfter(value string, now time.Time) int64 {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0
	}
	if seconds, err := strconv.ParseInt(value, 10, 64); err == nil {
		if seconds > 0 {
			return seconds
		}
		return 0
	}
	when, err := http.ParseTime(value)
	if err != nil || !when.After(now) {
		return 0
	}
	seconds := int64(when.Sub(now) / time.Second)
	if now.Add(time.Duration(seconds) * time.Second).Before(when) {
		seconds++
	}
	return seconds
}

func classifyHTTP(response *http.Response, body []byte) (ErrorClass, bool) {
	switch response.StatusCode {
	case http.StatusUnauthorized:
		return ErrorUnauthorized, false
	case http.StatusForbidden:
		lower := strings.ToLower(string(body))
		if response.Header.Get("Retry-After") != "" || strings.Contains(lower, "secondary rate limit") || strings.Contains(lower, "abuse detection") {
			return ErrorSecondaryLimit, true
		}
		if response.Header.Get("X-RateLimit-Remaining") == "0" {
			return ErrorRateLimited, true
		}
		return ErrorForbidden, false
	case http.StatusNotFound:
		return ErrorNotFound, false
	case http.StatusGone:
		return ErrorAPIVersion, false
	case http.StatusUnprocessableEntity:
		return ErrorValidation, false
	case http.StatusTooManyRequests:
		return ErrorRateLimited, true
	default:
		if response.StatusCode >= 500 && response.StatusCode <= 599 {
			return ErrorTransient, true
		}
		return ErrorMalformedResponse, false
	}
}

func sanitizeResponseMessage(body []byte, secrets ...string) string {
	message := strings.TrimSpace(string(body))
	for _, secret := range secrets {
		if secret != "" {
			message = strings.ReplaceAll(message, secret, "[REDACTED]")
		}
	}
	if message == "" {
		return "GitHub returned an error"
	}
	return sanitizeDiagnostic(message)
}

func sanitizedParameters(parameters map[string]string) map[string]string {
	if len(parameters) == 0 {
		return nil
	}
	result := make(map[string]string, len(parameters))
	for key, value := range parameters {
		result[sanitizeDiagnostic(key)] = sanitizeDiagnostic(value)
	}
	return result
}

func appendDiagnostic(left, right string) string {
	if left == "" {
		return right
	}
	return left + "; " + right
}

func (c *Client) retryDelay(attempt int, meta ResponseMeta, class ErrorClass) time.Duration {
	if meta.RetryAfterSeconds > 0 {
		return minDuration(time.Duration(meta.RetryAfterSeconds)*time.Second, c.retry.MaxDelay)
	}
	if class == ErrorRateLimited && meta.RateReset > 0 {
		reset := time.Unix(meta.RateReset, 0)
		if delay := reset.Sub(c.now()); delay > 0 {
			return minDuration(delay, c.retry.MaxDelay)
		}
	}
	delay := c.retry.BaseDelay
	for i := 1; i < attempt; i++ {
		if delay >= c.retry.MaxDelay/2 {
			delay = c.retry.MaxDelay
			break
		}
		delay *= 2
	}
	if class == ErrorSecondaryLimit && delay < c.retry.SecondaryMinDelay {
		delay = c.retry.SecondaryMinDelay
	}
	delay = minDuration(delay, c.retry.MaxDelay)
	if c.jitter != nil {
		delay = minDuration(delay+c.jitter(delay), c.retry.MaxDelay)
	}
	return delay
}

func minDuration(a, b time.Duration) time.Duration {
	if b <= 0 || a < b {
		return a
	}
	return b
}

func contextSleep(ctx context.Context, duration time.Duration) error {
	if duration <= 0 {
		return nil
	}
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func cryptoJitter(base time.Duration) time.Duration {
	if base <= 0 {
		return 0
	}
	maximum := uint64(base / 4)
	if maximum == 0 {
		return 0
	}
	var bytes [8]byte
	if _, err := rand.Read(bytes[:]); err != nil {
		return 0
	}
	value := uint64(0)
	for _, one := range bytes {
		value = value<<8 | uint64(one)
	}
	return time.Duration(value % maximum)
}

func defaultRedirectValidator(ctx context.Context, target *url.URL) error {
	if target == nil || !strings.EqualFold(target.Scheme, "https") || target.Hostname() == "" || target.User != nil || target.Fragment != "" {
		return &Error{Class: ErrorUnsafeRedirect, Operation: "download logs", Message: "log redirect is not a plain HTTPS URL"}
	}
	if port := target.Port(); port != "" && port != "443" {
		return &Error{Class: ErrorUnsafeRedirect, Operation: "download logs", Message: "log redirect uses a non-HTTPS port"}
	}
	host := strings.ToLower(strings.TrimSuffix(target.Hostname(), "."))
	allowed := false
	for _, suffix := range []string{".actions.githubusercontent.com", ".blob.core.windows.net"} {
		if strings.HasSuffix(host, suffix) && len(host) > len(suffix) {
			allowed = true
			break
		}
	}
	if !allowed {
		return &Error{Class: ErrorUnsafeRedirect, Operation: "download logs", Message: "log redirect host is outside the validated allowlist"}
	}
	addresses, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil || len(addresses) == 0 {
		return &Error{Class: ErrorUnsafeRedirect, Operation: "download logs", Message: "log redirect host could not be safely resolved"}
	}
	for _, address := range addresses {
		if !isPublicIP(address.IP) {
			return &Error{Class: ErrorUnsafeRedirect, Operation: "download logs", Message: "log redirect resolved to a non-public address"}
		}
	}
	return nil
}

func isPublicIP(ip net.IP) bool {
	if ip == nil || ip.IsUnspecified() || ip.IsLoopback() || ip.IsMulticast() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsPrivate() {
		return false
	}
	return true
}
