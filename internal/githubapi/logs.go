package githubapi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
)

func (c *Client) DownloadAttemptLogs(ctx context.Context, owner, repository string, runID int64, attempt int, destination io.Writer) (DownloadResult, error) {
	ownerPart, repositoryPart, err := repositoryParts(owner, repository)
	if err != nil {
		return DownloadResult{}, err
	}
	if runID <= 0 || attempt <= 0 {
		return DownloadResult{}, invalidArgument("download attempt logs", "run ID and attempt must be positive")
	}
	spec := requestSpec{
		routeTemplate: "/repos/{owner}/{repo}/actions/runs/{run_id}/attempts/{attempt_number}/logs",
		path: "/repos/" + ownerPart + "/" + repositoryPart + "/actions/runs/" + strconv.FormatInt(runID, 10) +
			"/attempts/" + strconv.Itoa(attempt) + "/logs",
		parameters: map[string]string{
			"owner": owner, "repo": repository, "run_id": strconv.FormatInt(runID, 10), "attempt_number": strconv.Itoa(attempt),
		},
		operation: "download attempt logs",
	}
	return c.downloadLogs(ctx, spec, "application/zip", c.limits.AttemptLogBytes, destination)
}

func (c *Client) DownloadJobLogs(ctx context.Context, owner, repository string, jobID int64, destination io.Writer) (DownloadResult, error) {
	ownerPart, repositoryPart, err := repositoryParts(owner, repository)
	if err != nil {
		return DownloadResult{}, err
	}
	if jobID <= 0 {
		return DownloadResult{}, invalidArgument("download job logs", "job ID must be positive")
	}
	spec := requestSpec{
		routeTemplate: "/repos/{owner}/{repo}/actions/jobs/{job_id}/logs",
		path:          "/repos/" + ownerPart + "/" + repositoryPart + "/actions/jobs/" + strconv.FormatInt(jobID, 10) + "/logs",
		parameters: map[string]string{
			"owner": owner, "repo": repository, "job_id": strconv.FormatInt(jobID, 10),
		},
		operation: "download job logs",
	}
	return c.downloadLogs(ctx, spec, "text/plain", c.limits.JobLogBytes, destination)
}

func (c *Client) downloadLogs(ctx context.Context, spec requestSpec, accept string, limit int64, destination io.Writer) (DownloadResult, error) {
	if destination == nil {
		return DownloadResult{}, invalidArgument(spec.operation, "download destination is nil")
	}
	result := DownloadResult{LogicalSourceRoute: spec.routeTemplate}
	for acquisition := 0; acquisition < 2; acquisition++ {
		location, responses, err := c.acquireLogRedirect(ctx, spec)
		result.APIResponses = append(result.APIResponses, responses...)
		if err != nil {
			return result, err
		}
		storage, renew, err := c.fetchLogObject(ctx, location, spec.operation, accept, limit, destination)
		result.StorageResponses = append(result.StorageResponses, storage.meta)
		if err == nil {
			result.MediaType = storage.meta.MediaType
			result.ByteLength = storage.meta.ByteLength
			result.SHA256 = storage.meta.SHA256
			result.RenewedRedirect = acquisition > 0
			return result, nil
		}
		if !renew || acquisition == 1 {
			return result, err
		}
		result.RenewedRedirect = true
	}
	return result, &Error{
		Class:     ErrorRetryBudget,
		Operation: spec.operation,
		Message:   "log acquisition loop exhausted without a terminal result",
		Responses: append(append([]ResponseMeta(nil), result.APIResponses...), result.StorageResponses...),
		Retryable: false,
	}
}

func (c *Client) acquireLogRedirect(ctx context.Context, spec requestSpec) (*url.URL, []ResponseMeta, error) {
	target, err := c.requestURL(spec)
	if err != nil {
		return nil, nil, err
	}
	var attempts []ResponseMeta
	seenAPITargets := map[string]struct{}{target.String(): {}}
	apiRedirects := 0

retryAttempt:
	for attempt := 1; attempt <= c.retry.MaxAttempts; attempt++ {
		token, tokenErr := c.tokens.Token(ctx)
		if tokenErr != nil {
			return nil, attempts, &Error{Class: ErrorUnauthorized, Operation: spec.operation, Message: "authentication source failed", Responses: attempts}
		}
		for {
			started := c.now().UTC()
			meta := ResponseMeta{
				Method: http.MethodGet, RouteTemplate: spec.routeTemplate, RequestParameters: sanitizedParameters(spec.parameters),
				APIVersion: APIVersion, StartedAt: started,
			}
			req, requestErr := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
			if requestErr != nil {
				meta.CompletedAt = c.now().UTC()
				meta.ErrorClass = ErrorInvalidRequest
				attempts = append(attempts, meta)
				return nil, attempts, &Error{Class: ErrorInvalidRequest, Operation: spec.operation, Message: "could not create log request", Responses: attempts}
			}
			req.Header.Set("Accept", DefaultAccept)
			req.Header.Set("X-GitHub-Api-Version", APIVersion)
			req.Header.Set("User-Agent", c.userAgent)
			if token != "" {
				req.Header.Set("Authorization", "Bearer "+token)
			}
			resp, requestErr := c.httpClient.Do(req)
			if requestErr != nil {
				meta.CompletedAt = c.now().UTC()
				if ctx.Err() != nil {
					meta.ErrorClass = ErrorCancelled
					attempts = append(attempts, meta)
					return nil, attempts, &Error{Class: ErrorCancelled, Operation: spec.operation, Message: "log redirect request cancelled", Responses: attempts, Cause: ctx.Err()}
				}
				meta.ErrorClass = ErrorTransient
				attempts = append(attempts, meta)
				if attempt == c.retry.MaxAttempts {
					return nil, attempts, &Error{Class: ErrorTransient, Operation: spec.operation, Message: "log redirect request failed; retry budget exhausted", Responses: attempts}
				}
				if err := c.sleep(ctx, c.retryDelay(attempt, meta, ErrorTransient)); err != nil {
					return nil, attempts, &Error{Class: ErrorCancelled, Operation: spec.operation, Message: "log redirect retry cancelled", Responses: attempts, Cause: err}
				}
				continue retryAttempt
			}
			body, complete, bodyErr := readBounded(resp.Body, 64<<10)
			resp.Body.Close()
			meta = responseMetadata(meta, resp, body, complete, c.now().UTC())
			if bodyErr != nil {
				class := ErrorTransient
				message := "redirect response could not be read completely"
				var sizeErr *Error
				if errors.As(bodyErr, &sizeErr) && sizeErr.Class == ErrorSizeLimit {
					class = ErrorSizeLimit
					message = "redirect response exceeded its byte limit"
				}
				meta.ErrorClass = class
				attempts = append(attempts, meta)
				if class == ErrorTransient && attempt < c.retry.MaxAttempts {
					if err := c.sleep(ctx, c.retryDelay(attempt, meta, class)); err != nil {
						return nil, attempts, &Error{Class: ErrorCancelled, Operation: spec.operation, Message: "log redirect retry cancelled", Responses: attempts, Cause: err}
					}
					continue retryAttempt
				}
				return nil, attempts, &Error{Class: class, Operation: spec.operation, StatusCode: resp.StatusCode, Message: message, Responses: attempts}
			}
			attempts = append(attempts, meta)
			if resp.StatusCode == http.StatusMovedPermanently || resp.StatusCode == http.StatusTemporaryRedirect || resp.StatusCode == http.StatusPermanentRedirect {
				location, locationErr := c.validateAPIRedirect(resp.Header.Get("Location"))
				if locationErr != nil {
					attempts[len(attempts)-1].ErrorClass = ErrorUnsafeRedirect
					return nil, attempts, &Error{Class: ErrorUnsafeRedirect, Operation: spec.operation, StatusCode: resp.StatusCode, Message: "GitHub log API relocation left the configured origin or was malformed", Responses: attempts}
				}
				apiRedirects++
				key := location.String()
				_, repeated := seenAPITargets[key]
				if apiRedirects > maxAPIRedirects || repeated {
					attempts[len(attempts)-1].ErrorClass = ErrorUnsafeRedirect
					return nil, attempts, &Error{Class: ErrorUnsafeRedirect, Operation: spec.operation, StatusCode: resp.StatusCode, Message: "GitHub log API relocation chain was cyclic or exceeded its bound", Responses: attempts}
				}
				seenAPITargets[key] = struct{}{}
				target = location
				continue
			}
			if resp.StatusCode == http.StatusFound {
				locationText := resp.Header.Get("Location")
				location, parseErr := url.Parse(locationText)
				if parseErr != nil || !location.IsAbs() {
					attempts[len(attempts)-1].ErrorClass = ErrorUnsafeRedirect
					return nil, attempts, &Error{Class: ErrorUnsafeRedirect, Operation: spec.operation, StatusCode: resp.StatusCode, Message: "GitHub returned an invalid log redirect", Responses: attempts}
				}
				if err := c.validateRedirect(ctx, location); err != nil {
					attempts[len(attempts)-1].ErrorClass = ErrorUnsafeRedirect
					return nil, attempts, &Error{Class: ErrorUnsafeRedirect, Operation: spec.operation, StatusCode: resp.StatusCode, Message: "GitHub returned a log redirect outside policy", Responses: attempts}
				}
				return location, attempts, nil
			}
			class, retryable := classifyHTTP(resp, body)
			if resp.StatusCode == http.StatusGone && meta.ResponseAPIVersion == APIVersion {
				// GitHub.com uses endpoint-specific 410 responses when retained
				// workflow/job log content is no longer available and confirms the
				// requested API version in X-GitHub-Api-Version-Selected. A 410
				// without that confirmation remains an API-version failure.
				class, retryable = ErrorRetentionOrDeletion, false
			}
			attempts[len(attempts)-1].ErrorClass = class
			if !retryable || attempt == c.retry.MaxAttempts {
				message := sanitizeResponseMessage(body, token)
				if retryable && attempt == c.retry.MaxAttempts {
					message = appendDiagnostic(message, "retry budget exhausted")
				}
				return nil, attempts, &Error{Class: class, Operation: spec.operation, StatusCode: resp.StatusCode, Message: message, Responses: attempts}
			}
			if err := c.sleep(ctx, c.retryDelay(attempt, meta, class)); err != nil {
				return nil, attempts, &Error{Class: ErrorCancelled, Operation: spec.operation, Message: "log redirect retry cancelled", Responses: attempts, Cause: err}
			}
			continue retryAttempt
		}
	}
	return nil, attempts, &Error{
		Class:     ErrorRetryBudget,
		Operation: spec.operation,
		Message:   "log redirect retry loop exhausted without a terminal result",
		Responses: attempts,
	}
}

type storageFetch struct {
	meta ResponseMeta
}

func (c *Client) fetchLogObject(ctx context.Context, location *url.URL, operation, accept string, limit int64, destination io.Writer) (storageFetch, bool, error) {
	started := c.now().UTC()
	meta := ResponseMeta{
		Method: http.MethodGet, RouteTemplate: "temporary-log-object", RequestParameters: nil,
		StartedAt: started,
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, location.String(), nil)
	if err != nil {
		meta.CompletedAt = c.now().UTC()
		meta.ErrorClass = ErrorUnsafeRedirect
		return storageFetch{meta: meta}, false, &Error{Class: ErrorUnsafeRedirect, Operation: operation, Message: "could not create temporary log request", Responses: []ResponseMeta{meta}}
	}
	req.Header.Set("Accept", accept)
	req.Header.Set("User-Agent", c.userAgent)
	// Authorization and Cookie are deliberately never set on this request.
	resp, err := c.storageHTTPClient.Do(req)
	if err != nil {
		meta.CompletedAt = c.now().UTC()
		if ctx.Err() != nil {
			meta.ErrorClass = ErrorCancelled
			return storageFetch{meta: meta}, false, &Error{Class: ErrorCancelled, Operation: operation, Message: "temporary log request cancelled", Responses: []ResponseMeta{meta}, Cause: ctx.Err()}
		}
		meta.ErrorClass = ErrorTransient
		return storageFetch{meta: meta}, true, &Error{Class: ErrorTransient, Operation: operation, Message: "temporary log request failed", Responses: []ResponseMeta{meta}}
	}
	defer resp.Body.Close()
	meta.StatusCode = resp.StatusCode
	meta.MediaType = sanitizeDiagnostic(resp.Header.Get("Content-Type"))
	meta.StartedAt = started
	meta.CompletedAt = c.now().UTC()
	if resp.StatusCode >= 300 && resp.StatusCode <= 399 {
		meta.ErrorClass = ErrorUnsafeRedirect
		return storageFetch{meta: meta}, false, &Error{Class: ErrorUnsafeRedirect, Operation: operation, StatusCode: resp.StatusCode, Message: "temporary log host attempted another redirect", Responses: []ResponseMeta{meta}}
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, complete, _ := readBounded(resp.Body, 64<<10)
		meta = responseMetadata(meta, resp, body, complete, c.now().UTC())
		renew := resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusGone || resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500
		class := ErrorTransient
		if renew {
			class = ErrorRedirectExpired
		}
		meta.ErrorClass = class
		return storageFetch{meta: meta}, renew, &Error{Class: class, Operation: operation, StatusCode: resp.StatusCode, Message: "temporary log object was unavailable", Responses: []ResponseMeta{meta}}
	}

	hash := sha256.New()
	written, complete, copyErr := copyBounded(io.MultiWriter(destination, hash), resp.Body, limit)
	meta.ByteLength = written
	meta.BodyComplete = complete
	meta.CompletedAt = c.now().UTC()
	if complete {
		meta.SHA256 = hex.EncodeToString(hash.Sum(nil))
	}
	if copyErr != nil {
		var sizeErr *Error
		if errors.As(copyErr, &sizeErr) && sizeErr.Class == ErrorSizeLimit {
			meta.ErrorClass = ErrorSizeLimit
			return storageFetch{meta: meta}, false, &Error{Class: ErrorSizeLimit, Operation: operation, StatusCode: resp.StatusCode, Message: "log object exceeded configured byte limit", Responses: []ResponseMeta{meta}}
		}
		var writeErr *destinationWriteError
		if errors.As(copyErr, &writeErr) {
			meta.ErrorClass = ErrorLocalIO
			return storageFetch{meta: meta}, false, &Error{Class: ErrorLocalIO, Operation: operation, StatusCode: resp.StatusCode, Message: "could not stream log object to local storage", Responses: []ResponseMeta{meta}}
		}
		meta.ErrorClass = ErrorTransient
		return storageFetch{meta: meta}, false, &Error{Class: ErrorTransient, Operation: operation, StatusCode: resp.StatusCode, Message: "temporary log object ended before it could be read completely", Responses: []ResponseMeta{meta}}
	}
	return storageFetch{meta: meta}, false, nil
}

func copyBounded(destination io.Writer, source io.Reader, limit int64) (int64, bool, error) {
	if limit <= 0 {
		return 0, false, &Error{Class: ErrorSizeLimit, Message: "invalid log byte limit"}
	}
	buffer := make([]byte, 64<<10)
	var written int64
	for {
		remaining := limit - written
		readSize := len(buffer)
		if remaining < int64(readSize) {
			readSize = int(remaining) + 1
		}
		count, readErr := source.Read(buffer[:readSize])
		if count > 0 {
			if int64(count) > remaining {
				if remaining > 0 {
					stored, writeErr := destination.Write(buffer[:remaining])
					written += int64(stored)
					if writeErr != nil {
						return written, false, &destinationWriteError{cause: writeErr}
					}
					if int64(stored) != remaining {
						return written, false, &destinationWriteError{cause: io.ErrShortWrite}
					}
				}
				return written, false, &Error{Class: ErrorSizeLimit, Message: "log byte limit exceeded"}
			}
			stored, writeErr := destination.Write(buffer[:count])
			written += int64(stored)
			if writeErr != nil {
				return written, false, &destinationWriteError{cause: writeErr}
			}
			if stored != count {
				return written, false, &destinationWriteError{cause: io.ErrShortWrite}
			}
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				return written, true, nil
			}
			return written, false, readErr
		}
		if count == 0 {
			return written, false, errors.New("log reader made no progress")
		}
	}
}

type destinationWriteError struct {
	cause error
}

func (e *destinationWriteError) Error() string { return "log destination write failed" }
func (e *destinationWriteError) Unwrap() error { return e.cause }
