// Package cloud is the Go SDK of the Azaleva Cloud API.
//
// A Client talks to one Azaleva Cloud installation with one credential: a consumer API key
// (ack_…). Every mutating call carries an Idempotency-Key (generated when the caller gives
// none) that is reused across retries; only errors the server marks retryable (and transport errors of keyed or safe
// requests) are retried, with exponential backoff, full jitter and the server's retry_after.
//
// The package cloudtest provides an in-memory implementation of the same API for tests, and
// the package contract holds the contract suite every implementation must pass.
package cloud

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Version is the version of the API document this SDK implements (its info.version), sent in
// the User-Agent. The module's own version is its tag (vX.Y.Z).
const Version = "1.0.0-alpha.1"

// DefaultResponseHeaderTimeout bounds the wait for a response's headers on the client New
// creates by default: above the longest wait the API holds a request for (a synchronous exec,
// up to 300 s), so a server or proxy that never answers fails the call instead of hanging it.
// There is no overall timeout: output, events and terminals stream for as long as they last.
// Give each call a context deadline for anything tighter.
const DefaultResponseHeaderTimeout = 330 * time.Second

// defaultHTTPClient is the HTTP client of a Client created without WithHTTPClient.
func defaultHTTPClient() *http.Client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.ResponseHeaderTimeout = DefaultResponseHeaderTimeout
	return &http.Client{Transport: tr}
}

// RetryPolicy controls automatic retries.
type RetryPolicy struct {
	// MaxAttempts is the total number of attempts (1 disables retries). Default 4.
	MaxAttempts int
	// BaseDelay is the first backoff step. Default 200 ms.
	BaseDelay time.Duration
	// MaxDelay caps one wait. Default 10 s.
	MaxDelay time.Duration
}

// Option configures a Client.
type Option func(*Client)

// WithHTTPClient sets the HTTP client (for example one with a client certificate for mTLS). It
// replaces the default client, whose transport waits at most DefaultResponseHeaderTimeout for
// response headers; set your own bounds on hc (avoid http.Client.Timeout, which also cuts
// streams).
func WithHTTPClient(hc *http.Client) Option { return func(c *Client) { c.hc, c.defaultHC = hc, false } }

// WithRetry sets the retry policy.
func WithRetry(p RetryPolicy) Option { return func(c *Client) { c.retry = p } }

// WithUserAgent prefixes the User-Agent header.
func WithUserAgent(ua string) Option { return func(c *Client) { c.ua = ua + " " + c.ua } }

// WithIdempotencyKeyFunc replaces the generator of idempotency keys.
func WithIdempotencyKeyFunc(f func() string) Option { return func(c *Client) { c.newKey = f } }

// Client is an Azaleva Cloud API client. It is safe for concurrent use.
type Client struct {
	base  string // ends in /v1, no trailing slash
	token string
	hc    *http.Client
	// defaultHC: hc is the client New made (defaultHTTPClient), not the caller's.
	defaultHC bool
	retry     RetryPolicy
	ua        string
	newKey    func() string

	Projects  *ProjectsService
	Jobs      *JobsService
	Sandboxes *SandboxesService
	Machines  *MachinesService
	Addresses *AddressesService
	Presets   *PresetsService
	Templates *TemplatesService
	Profiles  *ProfilesService
	Events    *EventsService
	Usage     *UsageService
}

// New returns a client for the installation at baseURL ("https://cloud.example" or
// "https://cloud.example/v1") authenticating with token (an ack_ API key; empty for
// unauthenticated calls). Without
// WithHTTPClient it uses an HTTP client of its own (not http.DefaultClient) whose transport
// waits at most DefaultResponseHeaderTimeout for response headers.
func New(baseURL, token string, opts ...Option) (*Client, error) {
	u, err := url.Parse(strings.TrimRight(baseURL, "/"))
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("cloud: invalid base URL %q", baseURL)
	}
	if !strings.HasSuffix(u.Path, "/v1") {
		u.Path += "/v1"
	}
	c := &Client{
		base:      u.String(),
		token:     token,
		hc:        defaultHTTPClient(),
		defaultHC: true,
		retry:     RetryPolicy{MaxAttempts: 4, BaseDelay: 200 * time.Millisecond, MaxDelay: 10 * time.Second},
		ua:        "azaleva-cloud-go/" + Version,
		newKey:    NewIdempotencyKey,
	}
	for _, o := range opts {
		o(c)
	}
	if c.retry.MaxAttempts < 1 {
		c.retry.MaxAttempts = 1
	}
	c.Projects = &ProjectsService{c}
	c.Jobs = &JobsService{c}
	c.Sandboxes = &SandboxesService{instanceOps{c, "sandboxes"}}
	c.Machines = &MachinesService{instanceOps{c, "machines"}}
	c.Addresses = &AddressesService{c}
	c.Presets = &PresetsService{c}
	c.Templates = &TemplatesService{c}
	c.Profiles = &ProfilesService{c}
	c.Events = &EventsService{c}
	c.Usage = &UsageService{c}
	return c, nil
}

// WithToken returns a copy of the client that uses another credential.
func (c *Client) WithToken(token string) *Client {
	cp, _ := New(c.base, token, WithHTTPClient(c.hc), WithRetry(c.retry), WithIdempotencyKeyFunc(c.newKey))
	cp.ua, cp.defaultHC = c.ua, c.defaultHC
	return cp
}

// WithRetry returns a copy of the client with another retry policy.
func (c *Client) WithRetry(p RetryPolicy) *Client {
	cp := c.WithToken(c.token)
	cp.retry = p
	if cp.retry.MaxAttempts < 1 {
		cp.retry.MaxAttempts = 1
	}
	return cp
}

// NewIdempotencyKey returns a random 128-bit key.
func NewIdempotencyKey() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return "idk_" + hex.EncodeToString(b)
}

// ResponseMeta describes the HTTP response of a call (see WithResponse).
type ResponseMeta struct {
	StatusCode     int
	ETag           string
	Replayed       bool
	IdempotencyKey string
	Header         http.Header
}

// CallOption adjusts one call.
type CallOption func(*callConfig)

type callConfig struct {
	idemKey string
	ifMatch string
	meta    *ResponseMeta
	header  http.Header
	purge   bool // Templates.Delete: WithPurge
}

// WithIdempotencyKey sets the Idempotency-Key of a mutating call (by default a random key is
// generated per call and reused across its retries).
func WithIdempotencyKey(key string) CallOption { return func(c *callConfig) { c.idemKey = key } }

// IfMatch makes a write conditional on the resource's version (412 precondition_failed otherwise).
func IfMatch(version int64) CallOption {
	return func(c *callConfig) { c.ifMatch = strconv.Quote(strconv.FormatInt(version, 10)) }
}

// WithResponse records the response's status, ETag and replay flag into m.
func WithResponse(m *ResponseMeta) CallOption { return func(c *callConfig) { c.meta = m } }

// WithHeader adds a request header.
func WithHeader(k, v string) CallOption {
	return func(c *callConfig) {
		if c.header == nil {
			c.header = http.Header{}
		}
		c.header.Add(k, v)
	}
}

type request struct {
	method   string
	path     string // below /v1, starting with /
	query    url.Values
	body     []byte
	ctype    string
	accept   string
	stream   bool // return the body unread on success
	noRetry  bool
	attempts int
	// mint: a POST that mints a secret shown once and changes nothing else (a transport
	// ticket). It carries no Idempotency-Key (the answer is never kept for replay) and is safe
	// to send again: a lost answer only leaves an unused ticket behind.
	mint bool
}

func (c *Client) newRequest(method, path string, query url.Values, in any) (*request, error) {
	r := &request{method: method, path: path, query: query, accept: "application/json"}
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return nil, fmt.Errorf("cloud: encode request: %w", err)
		}
		r.body, r.ctype = b, "application/json"
	}
	return r, nil
}

// call performs a JSON request and decodes a JSON response into out (when non-nil).
func (c *Client) call(ctx context.Context, method, path string, query url.Values, in, out any, opts ...CallOption) error {
	r, err := c.newRequest(method, path, query, in)
	if err != nil {
		return err
	}
	return c.callRequest(ctx, r, out, opts...)
}

// callRequest performs r and decodes a JSON response into out (when non-nil).
func (c *Client) callRequest(ctx context.Context, r *request, out any, opts ...CallOption) error {
	method, path := r.method, r.path
	resp, err := c.do(ctx, r, opts...)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if out == nil || resp.StatusCode == http.StatusNoContent {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("cloud: decode %s %s: %w", method, path, err)
	}
	return nil
}

func isMutating(method string) bool {
	return method == http.MethodPost || method == http.MethodDelete || method == http.MethodPut || method == http.MethodPatch
}

// do sends r with retries. On success the caller owns resp.Body.
func (c *Client) do(ctx context.Context, r *request, opts ...CallOption) (*http.Response, error) {
	var cfg callConfig
	for _, o := range opts {
		o(&cfg)
	}
	if cfg.idemKey == "" && (r.method == http.MethodPost || r.method == http.MethodDelete) && !r.mint {
		cfg.idemKey = c.newKey()
	}
	// Transport errors are retried only when a replay is safe: GET, a keyed request, or a mint.
	safeToReplay := !isMutating(r.method) || cfg.idemKey != "" || r.mint
	attempts := c.retry.MaxAttempts
	if r.noRetry {
		attempts = 1
	}
	var lastErr error
	for attempt := 1; ; attempt++ {
		resp, err := c.send(ctx, r, &cfg)
		var wait time.Duration
		switch {
		case err != nil:
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			lastErr = err
			if !safeToReplay {
				return nil, err
			}
		case resp.StatusCode >= 400:
			perr := decodeProblem(resp)
			lastErr = perr
			if !perr.Retryable {
				return nil, perr
			}
			wait = perr.RetryDelay()
		default:
			if cfg.meta != nil {
				*cfg.meta = ResponseMeta{
					StatusCode: resp.StatusCode, ETag: resp.Header.Get("ETag"),
					Replayed:       resp.Header.Get("Idempotent-Replayed") == "true",
					IdempotencyKey: cfg.idemKey, Header: resp.Header,
				}
			}
			return resp, nil
		}
		if attempt >= attempts {
			return nil, lastErr
		}
		if d := c.backoff(attempt); d > wait {
			wait = d
		}
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return nil, ctx.Err()
		case <-t.C:
		}
	}
}

func (c *Client) backoff(attempt int) time.Duration {
	d := c.retry.BaseDelay << (attempt - 1)
	if d <= 0 || d > c.retry.MaxDelay {
		d = c.retry.MaxDelay
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(d)+1))
	if err != nil {
		return d
	}
	return time.Duration(n.Int64()) // full jitter
}

func (c *Client) send(ctx context.Context, r *request, cfg *callConfig) (*http.Response, error) {
	u := c.base + r.path
	if len(r.query) > 0 {
		u += "?" + r.query.Encode()
	}
	var body io.Reader
	if r.body != nil {
		body = bytes.NewReader(r.body)
	}
	req, err := http.NewRequestWithContext(ctx, r.method, u, body)
	if err != nil {
		return nil, err
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	req.Header.Set("User-Agent", c.ua)
	if r.accept != "" {
		req.Header.Set("Accept", r.accept)
	}
	if r.ctype != "" {
		req.Header.Set("Content-Type", r.ctype)
	}
	if cfg.idemKey != "" {
		req.Header.Set("Idempotency-Key", cfg.idemKey)
	}
	if cfg.ifMatch != "" {
		req.Header.Set("If-Match", cfg.ifMatch)
	}
	for k, vs := range cfg.header {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	return c.hc.Do(req)
}

func decodeProblem(resp *http.Response) *Error {
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var e Error
	if err := json.Unmarshal(b, &e); err != nil || e.Code == "" {
		// Not a problem document (a proxy in between, for example): classify by status. Type
		// stays empty, which tells such an error from one Azaleva Cloud answered.
		e = Error{Status: resp.StatusCode, Title: http.StatusText(resp.StatusCode), Detail: strings.TrimSpace(string(b))}
		e.Code, e.Retryable = statusCode(resp.StatusCode)
	}
	if e.Status == 0 {
		e.Status = resp.StatusCode
	}
	if e.RetryAfter == 0 {
		if s, err := strconv.Atoi(resp.Header.Get("Retry-After")); err == nil {
			e.RetryAfter = s
		}
	}
	return &e
}

// statusCode classifies an answer that is not a problem document by its HTTP status alone.
func statusCode(status int) (Code, bool) {
	switch status {
	case 401:
		return CodeUnauthenticated, false
	case 403:
		return CodeForbidden, false
	case 404:
		return CodeNotFound, false
	case 408:
		return CodeUnavailable, true
	case 409:
		return CodeConflict, false
	case 410:
		return CodeGone, false
	case 412:
		return CodePreconditionFailed, false
	case 429:
		return CodeRateLimited, true
	case 502, 503, 504:
		return CodeUnavailable, true
	}
	if status >= 500 {
		return CodeInternal, true
	}
	return CodeInvalidRequest, false
}

// pathEscape escapes one path segment.
func pathEscape(s string) string { return url.PathEscape(s) }

// errMissing is returned for an empty required ID.
var errMissing = errors.New("cloud: empty ID")

func p(segments ...string) (string, error) {
	var b strings.Builder
	for i, s := range segments {
		if i%2 == 1 { // odd positions are IDs
			if s == "" {
				return "", errMissing
			}
			s = pathEscape(s)
		}
		b.WriteString("/" + s)
	}
	return b.String(), nil
}
