package cloud

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// Code is a stable Azaleva Cloud error code (the problem's "code" member).
type Code string

// The error codes of API v1. New codes may be added within v1; treat an unknown code by its
// HTTP status and Retryable.
const (
	CodeInvalidRequest         Code = "invalid_request"
	CodeInvalidPolicy          Code = "invalid_policy"
	CodeInvalidTemplatePackage Code = "invalid_template_package"
	CodeUnauthenticated        Code = "unauthenticated"
	CodeForbidden              Code = "forbidden"
	CodeScopeMissing           Code = "scope_missing"
	CodeReauthRequired         Code = "reauth_required"
	CodeNotFound               Code = "not_found"
	CodeBusy                   Code = "busy"
	CodeConflict               Code = "conflict"
	CodeCapacityExhausted      Code = "capacity_exhausted"
	CodeNodeUnavailable        Code = "node_unavailable"
	CodeNotAvailableOnNode     Code = "not_available_on_node"
	CodeTemplateNotReady       Code = "template_not_ready"
	CodeGone                   Code = "gone"
	CodePreconditionFailed     Code = "precondition_failed"
	CodeIdempotencyMismatch    Code = "idempotency_mismatch"
	CodeQuotaExceeded          Code = "quota_exceeded"
	CodeRateLimited            Code = "rate_limited"
	CodeInternal               Code = "internal"
	CodeNotImplemented         Code = "not_implemented"
	CodeUnavailable            Code = "unavailable"

	// The machine-service transport (see the Azaleva Cloud documentation). All but service_absent and
	// machine_unavailable are answered only by the transport endpoint.
	CodeServiceAbsent      Code = "service_absent"      // 404: the consumer's machine does not declare the service
	CodeMachineUnavailable Code = "machine_unavailable" // 409: the machine is not ready; the transport never starts it
	CodeAppNotListening    Code = "app_not_listening"   // 502: no connection to the service, and no byte of the request reached it (retryable)
	CodeAppTimeout         Code = "app_timeout"         // 504: no response headers in time; never replayed
	CodeConnectionLost     Code = "connection_lost"     // 502: the request may have reached the application, or the transport cannot tell; never replayed
	CodeThrottled          Code = "throttled"           // 429: a transport concurrency ceiling (retryable)
	CodeTicketExpired      Code = "ticket_expired"      // 401: mint a new ticket and send again (nothing was sent)
)

// CodeStatus maps every v1 code to its HTTP status.
var CodeStatus = map[Code]int{
	CodeInvalidRequest: 400, CodeInvalidPolicy: 400, CodeInvalidTemplatePackage: 400,
	CodeUnauthenticated: 401,
	CodeForbidden:       403, CodeScopeMissing: 403, CodeReauthRequired: 403,
	CodeNotFound: 404,
	CodeBusy:     409, CodeConflict: 409, CodeCapacityExhausted: 409, CodeNodeUnavailable: 409,
	CodeNotAvailableOnNode: 409, CodeTemplateNotReady: 409,
	CodeGone:                410,
	CodePreconditionFailed:  412,
	CodeIdempotencyMismatch: 422, CodeQuotaExceeded: 422,
	CodeRateLimited:    429,
	CodeInternal:       500,
	CodeNotImplemented: 501,
	CodeUnavailable:    503,

	CodeServiceAbsent: 404, CodeMachineUnavailable: 409, CodeAppNotListening: 502, CodeAppTimeout: 504,
	CodeConnectionLost: 502, CodeThrottled: 429, CodeTicketExpired: 401,
}

// FieldError points at one invalid part of a request.
type FieldError struct {
	Field   string `json:"field"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

// QuotaViolation names the quota a request would exceed.
type QuotaViolation struct {
	Name      string `json:"name"`
	Scope     string `json:"scope,omitempty"`
	Limit     int64  `json:"limit"`
	Used      int64  `json:"used"`
	Requested int64  `json:"requested,omitempty"`
}

// Error is an RFC 9457 problem returned by Azaleva Cloud. An answer that is not a problem
// document (from a proxy or load balancer in between, for example) becomes an Error with an
// empty Type, its Code derived from the HTTP status alone: 401 unauthenticated, 403 forbidden,
// 404 not_found, 409 conflict, 410 gone, 412 precondition_failed, 429 rate_limited
// (retryable), 408, 502, 503 and 504 unavailable (retryable), other 5xx internal (retryable),
// any other status invalid_request. Check Type before trusting such a code as Azaleva Cloud's
// answer about a resource (a proxy's 404 for a wrong base URL is not_found too).
type Error struct {
	Type       string          `json:"type"`
	Title      string          `json:"title"`
	Status     int             `json:"status"`
	Detail     string          `json:"detail,omitempty"`
	Instance   string          `json:"instance,omitempty"`
	Code       Code            `json:"code"`
	Retryable  bool            `json:"retryable"`
	RetryAfter int             `json:"retry_after,omitempty"`
	RequestID  string          `json:"request_id,omitempty"`
	Errors     []FieldError    `json:"errors,omitempty"`
	Quota      *QuotaViolation `json:"quota,omitempty"`
	Scope      string          `json:"scope,omitempty"`
}

func (e *Error) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "azaleva cloud: %d %s", e.Status, e.Code)
	if e.Detail != "" {
		b.WriteString(": " + e.Detail)
	} else if e.Title != "" {
		b.WriteString(": " + e.Title)
	}
	for _, f := range e.Errors {
		fmt.Fprintf(&b, "; %s: %s", f.Field, f.Code)
	}
	return b.String()
}

// RetryDelay is the server's retry_after hint (0 when none).
func (e *Error) RetryDelay() time.Duration { return time.Duration(e.RetryAfter) * time.Second }

// ProblemType is the "type" URI of a code.
func ProblemType(c Code) string { return "urn:agent-cloud:problem:" + string(c) }

// AsError returns err as an *Error when it is (or wraps) one.
func AsError(err error) (*Error, bool) {
	var e *Error
	ok := errors.As(err, &e)
	return e, ok
}

// IsCode reports whether err is an Azaleva Cloud problem with code c.
func IsCode(err error, c Code) bool {
	e, ok := AsError(err)
	return ok && e.Code == c
}

// IsRetryable reports whether err is a problem the server marked retryable.
func IsRetryable(err error) bool {
	e, ok := AsError(err)
	return ok && e.Retryable
}
