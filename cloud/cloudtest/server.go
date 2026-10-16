// Package cloudtest is an in-memory implementation of the Azaleva Cloud API for tests:
// projects, jobs, sandboxes, machines, execs, files, terminals, network, templates, events,
// webhooks and usage, with a mock driver instead of real machines. It passes the same contract
// suite (package contract) as the real server, so a consumer's unit tests can run against it
// without real machines.
//
// What the consumer API cannot do itself (consumers, their keys, pools, nodes) is set up with
// plain Go methods on the Server: see CreateConsumer, CreateKey and the other setup methods.
//
// The mock driver's commands (echo, cat, sleep, …), file rules, failure markers, seed content
// and test hooks are documented in docs/MOCK-DRIVER.md; the service transport's fakes and hooks
// in the Azaleva Cloud documentation.
package cloudtest

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/azaleva/azaleva-cloud-go/cloud"
)

// Options configure a Server.
type Options struct {
	// Nodes overrides the default fleet (pool "default": node-1, node-2; pool "spare": node-3).
	Nodes []NodeSpec
	// Logf, when set, receives one line per request.
	Logf func(format string, args ...any)
	// Profiles are added to the default profiles (job-small, job-large, machine-small,
	// machine-large), replacing one of the same name; zero MaxConcurrentExecs and
	// MaxTerminals take the defaults.
	Profiles []cloud.Profile

	// Transport overrides the machine-service transport's limits (zero fields: the defaults of
	// cloud.DefaultTransportLimits). The fake enforces the connect and header timeouts and the
	// concurrency ceilings.
	Transport cloud.TransportLimits
	// Services, when set, makes the fake application behind every declared service (default
	// EchoHandler); returning nil makes the service not listen.
	Services func(machine string, svc cloud.ServiceDeclaration) http.Handler
	// Companion, when set, makes every machine's fake agent-companion (see HandleCompanion).
	Companion func(machine string) http.Handler
	// BuiltinServices declares services on built-in templates by name (as an installation's
	// template definitions do), e.g. {"computer-base": {{Name: "web", Port: 8080, Protocol: "http"}}}.
	BuiltinServices map[string][]cloud.ServiceDeclaration
	// TemplateDeleteGrace is how long a deleted template version can be restored (default 7
	// days, Azaleva Cloud's default; negative: none).
	TemplateDeleteGrace time.Duration
}

// NodeSpec describes a fake node.
type NodeSpec struct {
	ID        string
	Pool      string
	MemoryMiB int
	JobSlots  int
	IPv6Block string // a /64 prefix such as "2001:db8:1::"
}

// Route is one operation the server implements, with its authorization.
type Route struct {
	Method string
	Path   string // as in the OpenAPI document, below /v1
	Scope  string // the API key scope it needs, or "any"
}

// Server is a running fake.
type Server struct {
	URL string
	// TransportURL is the fake's transport endpoint (the tickets' transport_url): another
	// listener, as the real transport endpoint is another host than the API.
	TransportURL string

	opts   Options
	http   *httptest.Server
	edge   *httptest.Server
	mux    *http.ServeMux
	routes []Route

	mu     sync.Mutex
	offset time.Duration // added to the real clock by Advance
	st     *state
	closed chan struct{}
	wg     sync.WaitGroup
}

// NewServer starts a fake on a local port. Call Close when done.
func NewServer(opts Options) *Server {
	s := &Server{opts: opts, mux: http.NewServeMux(), closed: make(chan struct{})}
	s.st = newState(s)
	s.registerRoutes()
	s.http = httptest.NewServer(s)
	s.URL = s.http.URL
	s.startTransport()
	return s
}

// Start starts a fake and closes it when the test ends. With CLOUDTEST_LOG set, every request
// is logged to the test.
func Start(tb testing.TB, opts ...Options) *Server {
	var o Options
	if len(opts) > 0 {
		o = opts[0]
	}
	if o.Logf == nil && os.Getenv("CLOUDTEST_LOG") != "" {
		o.Logf = tb.Logf
	}
	s := NewServer(o)
	tb.Cleanup(s.Close)
	return s
}

// Close stops the server and its background work.
func (s *Server) Close() {
	select {
	case <-s.closed:
		return
	default:
	}
	close(s.closed)
	s.mu.Lock()
	s.st.closeAll()
	s.mu.Unlock()
	s.http.CloseClientConnections()
	s.http.Close()
	s.closeTransport()
	s.wg.Wait()
}

// Routes lists every implemented operation with its scope.
func (s *Server) Routes() []Route { return append([]Route(nil), s.routes...) }

// Now is the server's clock (real time plus everything Advance added).
func (s *Server) Now() time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.now()
}

func (s *Server) now() time.Time { return time.Now().UTC().Add(s.offset) }

// Advance moves the server's clock forward and runs what is due: TTL and lease expiry, terminal
// timeouts, closing usage hours, event and output retention, reference reports' age.
func (s *Server) Advance(d time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.offset += d
	s.st.sweep()
}

// Client returns an SDK client with token.
func (s *Server) Client(token string) *cloud.Client {
	c, _ := cloud.New(s.URL, token)
	return c
}

// ---- HTTP plumbing ----

type ctx struct {
	s   *Server
	w   http.ResponseWriter
	r   *http.Request
	st  *state
	csm *consumer // the caller
	key *apiKey
	ip  string

	// Streaming handlers release the server lock while they wait.
	unlock, lock func()
}

type handler func(c *ctx)

func (s *Server) route(method, path, scope string, h handler) {
	s.routes = append(s.routes, Route{Method: method, Path: path, Scope: scope})
	s.mux.HandleFunc(method+" /v1"+path, func(w http.ResponseWriter, r *http.Request) {
		c := &ctx{s: s, w: w, r: r, st: s.st, ip: r.RemoteAddr}
		if i := strings.LastIndex(c.ip, ":"); i > 0 {
			c.ip = c.ip[:i]
		}
		s.serveRoute(c, method, scope, h)
	})
}

// ServeHTTP implements http.Handler.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if s.opts.Logf != nil {
		s.opts.Logf("cloudtest: %s %s", r.Method, r.URL.RequestURI())
	}
	if _, pattern := s.mux.Handler(r); pattern == "" {
		writeProblem(w, r, perr(404, cloud.CodeNotFound, "no such operation"))
		return
	}
	s.mux.ServeHTTP(w, r)
}

func (s *Server) serveRoute(c *ctx, method, scope string, h handler) {
	s.mu.Lock()
	locked := true
	unlock := func() {
		if locked {
			locked = false
			s.mu.Unlock()
		}
	}
	defer unlock()
	s.st.sweep()
	if err := s.authenticate(c, scope); err != nil {
		writeProblem(c.w, c.r, err)
		return
	}
	// Handlers that wait (streams, long polls, synchronous execs) release the lock meanwhile
	// and must hold it again when they return.
	c.unlock, c.lock = unlock, func() { s.mu.Lock(); locked = true }
	key := c.r.Header.Get("Idempotency-Key")
	// A file archive (POST …/archive) only reads: its key is ignored and nothing is kept.
	archive := method == http.MethodPost && strings.HasSuffix(c.r.URL.Path, "/archive")
	if key != "" && !archive && (method == http.MethodPost || method == http.MethodDelete) {
		s.serveIdempotent(c, key, h)
		return
	}
	safe(c, h)
}

func safe(c *ctx, h handler) {
	defer func() {
		if v := recover(); v != nil {
			if pe, ok := v.(*problemError); ok {
				writeProblem(c.w, c.r, pe)
				return
			}
			panic(v)
		}
	}()
	h(c)
}

// ---- problems ----

// problemError is the panic value handlers use to answer with a problem.
type problemError = cloud.Error

var retryableCodes = map[cloud.Code]bool{
	cloud.CodeBusy: true, cloud.CodeCapacityExhausted: true, cloud.CodeNodeUnavailable: true,
	cloud.CodeRateLimited: true, cloud.CodeInternal: true, cloud.CodeUnavailable: true,
	cloud.CodeAppNotListening: true, cloud.CodeThrottled: true, cloud.CodeTicketExpired: true,
}

func perr(status int, code cloud.Code, detail string) *problemError {
	return &problemError{Type: cloud.ProblemType(code), Title: strings.ReplaceAll(string(code), "_", " "),
		Status: status, Code: code, Detail: detail, Retryable: retryableCodes[code]}
}

func fail(status int, code cloud.Code, format string, args ...any) {
	panic(perr(status, code, fmt.Sprintf(format, args...)))
}

func notFound(what string) { fail(404, cloud.CodeNotFound, "%s not found", what) }

func invalid(field, code, format string, args ...any) {
	e := perr(400, cloud.CodeInvalidRequest, fmt.Sprintf(format, args...))
	e.Errors = []cloud.FieldError{{Field: field, Code: code, Message: e.Detail}}
	panic(e)
}

func writeProblem(w http.ResponseWriter, r *http.Request, err error) {
	var pe *problemError
	if !errors.As(err, &pe) {
		pe = perr(500, cloud.CodeInternal, err.Error())
	}
	e := *pe
	e.Instance = r.URL.Path
	if e.RetryAfter > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(e.RetryAfter))
	}
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(e.Status)
	_ = json.NewEncoder(w).Encode(e)
}

// ---- request and response helpers ----

func (c *ctx) decode(v any) {
	b, err := io.ReadAll(io.LimitReader(c.r.Body, 64<<20))
	if err != nil {
		fail(400, cloud.CodeInvalidRequest, "read body: %v", err)
	}
	if len(bytes.TrimSpace(b)) == 0 {
		b = []byte("{}")
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		fail(400, cloud.CodeInvalidRequest, "invalid JSON body: %v", err)
	}
}

func (c *ctx) json(status int, v any) {
	if ver, ok := versionOf(v); ok {
		c.w.Header().Set("ETag", strconv.Quote(strconv.FormatInt(ver, 10)))
	}
	c.w.Header().Set("Content-Type", "application/json")
	c.w.WriteHeader(status)
	_ = json.NewEncoder(c.w).Encode(v)
}

func (c *ctx) noContent() { c.w.WriteHeader(http.StatusNoContent) }

func versionOf(v any) (int64, bool) {
	switch x := v.(type) {
	case *cloud.Project:
		return x.Version, true
	case *cloud.Job:
		return x.Version, true
	case *cloud.Sandbox:
		return x.Version, true
	case *cloud.Machine:
		return x.Version, true
	case *cloud.ProjectQuotas:
		return x.Version, true
	case *cloud.MachineEgress:
		return x.Version, true
	case *cloud.MachineInbound:
		return x.Version, true
	case *cloud.Preset:
		return int64(x.Version), true
	}
	return 0, false
}

// checkIfMatch enforces If-Match against the current version.
func (c *ctx) checkIfMatch(current int64) {
	h := c.r.Header.Get("If-Match")
	if h == "" || h == "*" {
		return
	}
	want := strconv.Quote(strconv.FormatInt(current, 10))
	for _, part := range strings.Split(h, ",") {
		if strings.TrimSpace(part) == want {
			return
		}
	}
	fail(412, cloud.CodePreconditionFailed, "If-Match %s does not match the current version %s", h, want)
}

func (c *ctx) query(name string) string { return c.r.URL.Query().Get(name) }

func (c *ctx) queryInt(name string, def, min, max int) int {
	v := c.query(name)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < min || n > max {
		invalid(name, "invalid", "%s must be an integer between %d and %d", name, min, max)
	}
	return n
}

func (c *ctx) queryBool(name string) bool {
	switch c.query(name) {
	case "", "false", "0":
		return false
	case "true", "1":
		return true
	}
	invalid(name, "invalid", "%s must be true or false", name)
	return false
}

func (c *ctx) labelFilter() map[string]string {
	out := map[string]string{}
	for _, l := range c.r.URL.Query()["label"] {
		k, v, ok := strings.Cut(l, "=")
		if !ok || k == "" {
			invalid("label", "invalid", "label filters are key=value")
		}
		out[k] = v
	}
	return out
}

func labelsMatch(have cloud.Labels, want map[string]string) bool {
	for k, v := range want {
		if have[k] != v {
			return false
		}
	}
	return true
}

func stateMatch(state string, want []string) bool {
	if len(want) == 0 {
		return true
	}
	for _, w := range want {
		if w == state {
			return true
		}
	}
	return false
}

// paginate returns one page of items (already in their stable order).
func paginate[T any](c *ctx, items []T) cloud.Page[T] {
	limit := c.queryInt("limit", 50, 1, 200)
	start := 0
	if cur := c.query("cursor"); cur != "" {
		b, err := base64.RawURLEncoding.DecodeString(cur)
		n, err2 := strconv.Atoi(strings.TrimPrefix(string(b), "o:"))
		if err != nil || err2 != nil || n < 0 || n > len(items) {
			invalid("cursor", "invalid", "invalid cursor")
		}
		start = n
	}
	end := start + limit
	if end > len(items) {
		end = len(items)
	}
	page := cloud.Page[T]{Data: append([]T{}, items[start:end]...)}
	if end < len(items) {
		cur := base64.RawURLEncoding.EncodeToString([]byte("o:" + strconv.Itoa(end)))
		page.NextCursor = &cur
	}
	return page
}

// ---- idempotency ----

// secretRE matches the secrets the server mints (ack_ keys and ctk_ transport tickets with
// their secret part, whsec_ secrets); IDs alone do not match.
var secretRE = regexp.MustCompile(`(?:ack|ctk)_[0-9a-f]{8,}_[0-9a-f]{16,}|whsec_[0-9a-f]{16,}`)

type idemEntry struct {
	hash     string
	done     bool
	status   int
	header   http.Header
	body     []byte
	storedAt time.Time
}

func (s *Server) serveIdempotent(c *ctx, key string, h handler) {
	if len(key) > 200 {
		writeProblem(c.w, c.r, perr(400, cloud.CodeInvalidRequest, "Idempotency-Key is longer than 200 characters"))
		return
	}
	body, err := io.ReadAll(io.LimitReader(c.r.Body, 300<<20))
	if err != nil {
		writeProblem(c.w, c.r, perr(400, cloud.CodeInvalidRequest, "read body"))
		return
	}
	c.r.Body = io.NopCloser(bytes.NewReader(body))
	sum := sha256.Sum256([]byte(c.r.Method + " " + c.r.URL.RequestURI() + "\n" + string(body)))
	hash := hex.EncodeToString(sum[:])
	scope := c.principal() + "\x00" + key
	if e, ok := s.st.idem[scope]; ok {
		switch {
		case e.hash != hash:
			writeProblem(c.w, c.r, perr(422, cloud.CodeIdempotencyMismatch, "this Idempotency-Key was used with a different request"))
		case !e.done:
			p := perr(409, cloud.CodeConflict, "a request with this Idempotency-Key is still in progress")
			p.Retryable = true
			p.RetryAfter = 1
			writeProblem(c.w, c.r, p)
		default:
			for k, v := range e.header {
				c.w.Header()[k] = v
			}
			c.w.Header().Set("Idempotent-Replayed", "true")
			c.w.WriteHeader(e.status)
			_, _ = c.w.Write(e.body)
		}
		return
	}
	e := &idemEntry{hash: hash, storedAt: s.now()}
	s.st.idem[scope] = e
	rec := httptest.NewRecorder()
	orig := c.w
	c.w = rec
	safe(c, h)
	c.w = orig
	res := rec.Result()
	resBody := rec.Body.Bytes()
	keep := res.StatusCode < 400
	if !keep && strings.HasPrefix(res.Header.Get("Content-Type"), "application/problem+json") {
		var pe cloud.Error
		if json.Unmarshal(resBody, &pe) == nil && !pe.Retryable && res.StatusCode < 500 {
			keep = true
		}
	}
	if keep && res.StatusCode < 400 && secretRE.Match(resBody) {
		// As Azaleva Cloud: an answer that carries a secret shown once is never kept; a retry
		// with the key gets 409 conflict (not retryable) and mints nothing.
		p := perr(409, cloud.CodeConflict, "a request with this Idempotency-Key already completed; its answer carried a secret that is "+
			"shown once and not kept, so it cannot be replayed (revoke or rotate it and create a new one if it was lost)")
		b, _ := json.Marshal(p)
		h := http.Header{}
		h.Set("Content-Type", "application/problem+json")
		e.done, e.status, e.header, e.body = true, 409, h, b
	} else if keep {
		e.done, e.status, e.header, e.body = true, res.StatusCode, res.Header.Clone(), resBody
	} else {
		delete(s.st.idem, scope)
	}
	for k, v := range res.Header {
		orig.Header()[k] = v
	}
	orig.WriteHeader(res.StatusCode)
	_, _ = orig.Write(resBody)
}

func (c *ctx) principal() string {
	switch {
	case c.csm != nil:
		return "c:" + c.csm.id
	default:
		return "anon:" + c.ip
	}
}

// ---- auth ----

func (s *Server) authenticate(c *ctx, scope string) error {
	h := c.r.Header.Get("Authorization")
	token, ok := strings.CutPrefix(h, "Bearer ")
	if !ok || token == "" {
		return perr(401, cloud.CodeUnauthenticated, "missing bearer credential")
	}
	if !strings.HasPrefix(token, "ack_") {
		return perr(401, cloud.CodeUnauthenticated, "this operation takes a consumer API key")
	}
	now := s.now()
	k := s.st.keys[hashToken(token)]
	if k == nil || k.revokedAt != nil || (k.expiresAt != nil && now.After(*k.expiresAt)) {
		return perr(401, cloud.CodeUnauthenticated, "unknown, expired or revoked API key")
	}
	cs := s.st.consumers[k.consumer]
	if cs == nil || cs.state != "active" {
		return perr(401, cloud.CodeUnauthenticated, "the consumer is disabled")
	}
	t := now
	k.lastUsedAt = &t
	c.csm, c.key = cs, k
	if scope != "any" && !k.hasScope(scope) {
		e := perr(403, cloud.CodeScopeMissing, "the API key lacks the scope "+scope)
		e.Scope = scope
		return e
	}
	return nil
}

func hashToken(t string) string {
	sum := sha256.Sum256([]byte("cloudtest-pepper\x00" + t))
	return hex.EncodeToString(sum[:])
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
