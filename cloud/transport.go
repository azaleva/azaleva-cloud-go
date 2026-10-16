package cloud

// The machine-service transport (see the Azaleva Cloud documentation): HTTP requests and WebSocket
// upgrades to a service inside a machine, under policy app (a service the machine's template
// declares) or policy companion (the machine's agent-companion, with the credential the node
// injects). The control API mints short-lived tickets; the bytes go to the transport endpoint
// (ServiceTicket.TransportURL) with the ticket in Cloud-Ticket, never through the JSON API.
//
// ServiceTransport is an http.RoundTripper bound to one (machine, service): plug it into an
// httputil.ReverseProxy (WebSocket upgrades included) or an http.Client. It mints and renews
// tickets itself and never retries a request, with one exception that is safe by contract: a
// request refused with ticket_expired (nothing reached the machine) is sent once more with a
// new ticket when its body can be replayed. It never adds an Idempotency-Key.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

// TransportVersion is the transport protocol version this SDK speaks
// (Capabilities.ServiceTransport.Versions).
const TransportVersion = "1"

// Transport headers.
const (
	// HeaderTicket carries the ticket on every transport request.
	HeaderTicket = "Cloud-Ticket"
	// HeaderTransportError marks an answer of the transport itself (its value is the problem's
	// code); an answer without it comes from the application.
	HeaderTransportError = "Cloud-Transport-Error"
	// HeaderTransportRequest is the transport's ID of a request (in logs on both sides).
	HeaderTransportRequest = "Cloud-Transport-Request"
	// The public origin the consumer validated. The application receives exactly these three
	// headers (set by the node; any the caller sent itself are dropped), never X-Forwarded-* or
	// Forwarded, and always Host localhost:<port>.
	HeaderForwardedHost  = "Cloud-Forwarded-Host"
	HeaderForwardedProto = "Cloud-Forwarded-Proto"
	HeaderForwardedFor   = "Cloud-Forwarded-For"
)

// Service policies.
const (
	PolicyApp       = "app"
	PolicyCompanion = "companion"
)

// CompanionService is the service name of policy companion in tickets.
const CompanionService = "companion"

// Capabilities is what an installation offers.
type Capabilities struct {
	API              string                      `json:"api"`
	Release          string                      `json:"release,omitempty"`
	ServiceTransport *ServiceTransportCapability `json:"service_transport"`
}

// ServiceTransportCapability describes the transport of an installation.
type ServiceTransportCapability struct {
	Versions []string        `json:"versions"`
	Policies []string        `json:"policies"`
	Limits   TransportLimits `json:"limits"`
}

// Supports reports whether the installation offers the transport version this SDK speaks and
// the policy.
func (c *ServiceTransportCapability) Supports(policy string) bool {
	if c == nil {
		return false
	}
	v, p := false, false
	for _, x := range c.Versions {
		v = v || x == TransportVersion
	}
	for _, x := range c.Policies {
		p = p || x == policy
	}
	return v && p
}

// TransportLimits are the transport's bounds at an installation.
type TransportLimits struct {
	TicketTTLSecondsMax            int   `json:"ticket_ttl_seconds_max"`
	ConnectTimeoutSeconds          int   `json:"connect_timeout_seconds"`
	HeaderTimeoutSeconds           int   `json:"header_timeout_seconds"`
	IdleTimeoutSeconds             int   `json:"idle_timeout_seconds"`
	MaxConnectionSeconds           int   `json:"max_connection_seconds"`
	MaxRequestHeaderBytes          int   `json:"max_request_header_bytes"`
	MaxRequestHeaderFields         int   `json:"max_request_header_fields"`
	MaxTargetBytes                 int   `json:"max_target_bytes"`
	MaxResponseHeaderBytes         int   `json:"max_response_header_bytes"`
	MaxRequestBodyBytes            int64 `json:"max_request_body_bytes"`
	ConnectionsPerMachine          int   `json:"connections_per_machine"`
	CompanionConnectionsPerMachine int   `json:"companion_connections_per_machine"`
	ConnectionsPerConsumer         int   `json:"connections_per_consumer"`
	CloseBoundSeconds              int   `json:"close_bound_seconds"`
}

// DefaultTransportLimits are the documented defaults (see the Azaleva Cloud documentation).
var DefaultTransportLimits = TransportLimits{
	TicketTTLSecondsMax: 900, ConnectTimeoutSeconds: 5, HeaderTimeoutSeconds: 120, IdleTimeoutSeconds: 900,
	MaxConnectionSeconds: 86400, MaxRequestHeaderBytes: 64 << 10, MaxRequestHeaderFields: 100,
	MaxTargetBytes: 8 << 10, MaxResponseHeaderBytes: 64 << 10,
	MaxRequestBodyBytes: 1 << 30, ConnectionsPerMachine: 256, CompanionConnectionsPerMachine: 64,
	ConnectionsPerConsumer: 2048, CloseBoundSeconds: 10,
}

// ServiceDeclaration is one service of a machine template: a fixed guest port and protocol.
type ServiceDeclaration struct {
	Name        string `json:"name"`
	Port        int    `json:"port"`
	Protocol    string `json:"protocol"`
	Description string `json:"description,omitempty"`
}

// ReservedServicePorts are the machines' own infrastructure ports, never a declared service:
// agent-companion, its metrics, the gateway relay and envd, and 8642 (an application's internal
// API port that must never be exposed, refused whatever a template says).
var ReservedServicePorts = []int{8000, 8642, 9090, 47801, 49982, 49983}

// MaxServicesPerTemplate bounds a template's declared services.
const MaxServicesPerTemplate = 16

var serviceNameRE = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)

// ValidServiceName reports whether name is a valid service name (CompanionService is
// reserved).
func ValidServiceName(name string) bool {
	return serviceNameRE.MatchString(name) && name != CompanionService
}

// ValidateServiceDeclarations checks a template's services as Azaleva Cloud does on upload; the
// field errors are those of 400 invalid_template_package (field services[i].…, codes invalid,
// duplicate, reserved_port, too_many).
func ValidateServiceDeclarations(svcs []ServiceDeclaration) []FieldError {
	var errs []FieldError
	add := func(field, code, msg string) { errs = append(errs, FieldError{Field: field, Code: code, Message: msg}) }
	if len(svcs) > MaxServicesPerTemplate {
		add("services", "too_many", fmt.Sprintf("at most %d services", MaxServicesPerTemplate))
	}
	names, ports := map[string]bool{}, map[int]bool{}
	for i, s := range svcs {
		f := fmt.Sprintf("services[%d]", i)
		switch {
		case !ValidServiceName(s.Name):
			add(f+".name", "invalid", "a service name matches [a-z][a-z0-9-]{0,31} and is not \"companion\"")
		case names[s.Name]:
			add(f+".name", "duplicate", "service "+s.Name+" is declared twice")
		}
		names[s.Name] = true
		switch {
		case s.Port < 1024 || s.Port > 65535:
			add(f+".port", "invalid", "a service port is 1024-65535")
		case contains(ReservedServicePorts, s.Port):
			add(f+".port", "reserved_port", fmt.Sprintf("port %d belongs to the machine's infrastructure", s.Port))
		case ports[s.Port]:
			add(f+".port", "duplicate", fmt.Sprintf("port %d is declared twice", s.Port))
		}
		ports[s.Port] = true
		if s.Protocol != "http" {
			add(f+".protocol", "invalid", "protocol is http")
		}
		if len(s.Description) > 200 {
			add(f+".description", "too_long", "at most 200 characters")
		}
	}
	return errs
}

func contains[T comparable](xs []T, x T) bool {
	for _, y := range xs {
		if y == x {
			return true
		}
	}
	return false
}

// ServiceReadiness is whether the node reaches a service's guest port.
type ServiceReadiness struct {
	State     string     `json:"state"` // listening, not_listening, unknown
	CheckedAt *time.Time `json:"checked_at,omitempty"`
}

// MachineService is a declared service of a machine.
type MachineService struct {
	Name        string           `json:"name"`
	Port        int              `json:"port"`
	Protocol    string           `json:"protocol"`
	Description string           `json:"description,omitempty"`
	Policy      string           `json:"policy"`
	Readiness   ServiceReadiness `json:"readiness"`
}

// ServiceTicketCreate asks for a policy-app ticket.
type ServiceTicketCreate struct {
	TTLSeconds int    `json:"ttl_seconds,omitempty"`
	Actor      string `json:"actor,omitempty"`
}

// CompanionTicketCreate asks for a policy-companion ticket.
type CompanionTicketCreate struct {
	Context    string `json:"context"`
	TTLSeconds int    `json:"ttl_seconds,omitempty"`
	Actor      string `json:"actor,omitempty"`
}

// ServiceTicket authorises transport requests to one (machine, service) until ExpiresAt.
// Ticket is a secret: send it only as Cloud-Ticket to TransportURL, never log it.
type ServiceTicket struct {
	ID           string    `json:"id"`
	Ticket       string    `json:"ticket"`
	Policy       string    `json:"policy"`
	Machine      string    `json:"machine"`
	Service      string    `json:"service"`
	Context      string    `json:"context,omitempty"`
	Actor        string    `json:"actor,omitempty"`
	TransportURL string    `json:"transport_url"`
	ExpiresAt    time.Time `json:"expires_at"`
	CreatedAt    time.Time `json:"created_at"`
}

// MachineCompanion is a machine's agent-companion as installed and running.
type MachineCompanion struct {
	State         string            `json:"state"`    // ready, starting, unavailable, absent
	Fallback      string            `json:"fallback"` // none, envd
	Version       string            `json:"version,omitempty"`
	PinnedVersion string            `json:"pinned_version,omitempty"`
	Tooling       map[string]string `json:"tooling,omitempty"`
	Activity      *struct {
		Connections int `json:"connections"`
		Terminals   int `json:"terminals"`
		Processes   int `json:"processes"`
		Notebooks   int `json:"notebooks"`
	} `json:"activity,omitempty"`
	CheckedAt *time.Time `json:"checked_at,omitempty"`
}

// Capabilities returns what the installation offers. An installation from before the
// capability endpoint answers 404 not_found: Capabilities then returns an empty value (no
// service transport) and no error.
func (c *Client) Capabilities(ctx context.Context) (*Capabilities, error) {
	var out Capabilities
	err := c.call(ctx, http.MethodGet, "/capabilities", nil, nil, &out)
	if IsCode(err, CodeNotFound) {
		return &Capabilities{API: "v1"}, nil
	}
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// ListServices returns the machine's declared services with their readiness (scope
// machines:services). It never starts or wakes the machine.
func (s *MachinesService) ListServices(ctx context.Context, machine string) ([]MachineService, error) {
	path, err := p("machines", machine, "services")
	if err != nil {
		return nil, err
	}
	var out struct {
		Data []MachineService `json:"data"`
	}
	return out.Data, s.c.call(ctx, http.MethodGet, path, nil, nil, &out)
}

// CreateServiceTicket mints a policy-app ticket for one declared service (scope
// machines:services). It is sent without an Idempotency-Key (a ticket is a secret shown once)
// and retried like a read. Most callers use ServiceTransport, which mints and renews tickets.
func (s *MachinesService) CreateServiceTicket(ctx context.Context, machine, service string, in ServiceTicketCreate, opts ...CallOption) (*ServiceTicket, error) {
	if service == "" {
		return nil, errMissing
	}
	path, err := p("machines", machine, "services", service, "tickets")
	if err != nil {
		return nil, err
	}
	return s.mintTicket(ctx, path, in, opts)
}

// Companion returns the machine's agent-companion (scope machines:companion).
func (s *MachinesService) Companion(ctx context.Context, machine string) (*MachineCompanion, error) {
	path, err := p("machines", machine, "companion")
	if err != nil {
		return nil, err
	}
	var out MachineCompanion
	return &out, s.c.call(ctx, http.MethodGet, path, nil, nil, &out)
}

// CreateCompanionTicket mints a policy-companion ticket (scope machines:companion), as
// CreateServiceTicket. Most callers use CompanionTransport.
func (s *MachinesService) CreateCompanionTicket(ctx context.Context, machine string, in CompanionTicketCreate, opts ...CallOption) (*ServiceTicket, error) {
	path, err := p("machines", machine, "companion", "tickets")
	if err != nil {
		return nil, err
	}
	return s.mintTicket(ctx, path, in, opts)
}

func (s *MachinesService) mintTicket(ctx context.Context, path string, in any, opts []CallOption) (*ServiceTicket, error) {
	r, err := s.c.newRequest(http.MethodPost, path, nil, in)
	if err != nil {
		return nil, err
	}
	r.mint = true
	var out ServiceTicket
	return &out, s.c.callRequest(ctx, r, &out, opts...)
}

// Forwarded is the public origin of a request as the consumer validated it (the browser's
// host, scheme and address). The application receives it as Cloud-Forwarded-Host,
// Cloud-Forwarded-Proto and Cloud-Forwarded-For, set by the node; its Host is always
// localhost:<port> and it gets no X-Forwarded-* or Forwarded (the sandbox runtime's proxy
// accepts no other Host and strips those). Recipes configure the application's public origin
// (absolute URLs, allowed origins) or read the Cloud-Forwarded-* headers. Azaleva Cloud never
// takes these values from anything else.
type Forwarded struct {
	Host  string   // host[:port] the browser addressed
	Proto string   // http or https
	For   []string // client IP addresses, nearest last
}

type forwardedKey struct{}

// WithForwarded attaches the public origin to a request's context; ServiceTransport sends it
// as Cloud-Forwarded-*. Use it from httputil.ReverseProxy's Rewrite:
//
//	pr.Out = pr.Out.WithContext(cloud.WithForwarded(pr.Out.Context(), cloud.Forwarded{...}))
func WithForwarded(ctx context.Context, f Forwarded) context.Context {
	return context.WithValue(ctx, forwardedKey{}, f)
}

var hostRE = regexp.MustCompile(`^(\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)*)(:[0-9]{1,5})?$`)

// Validate checks f as the transport does (400 invalid_request, fields Cloud-Forwarded-*).
func (f Forwarded) Validate() error {
	var errs []FieldError
	if f.Host != "" && (len(f.Host) > 255 || !hostRE.MatchString(f.Host)) {
		errs = append(errs, FieldError{Field: HeaderForwardedHost, Code: "invalid", Message: "a host name or IP literal with an optional port"})
	}
	if f.Proto != "" && f.Proto != "http" && f.Proto != "https" {
		errs = append(errs, FieldError{Field: HeaderForwardedProto, Code: "invalid", Message: "http or https"})
	}
	if len(f.For) > 8 {
		errs = append(errs, FieldError{Field: HeaderForwardedFor, Code: "too_long", Message: "at most 8 addresses"})
	}
	for _, a := range f.For {
		if net.ParseIP(strings.TrimSpace(a)) == nil {
			errs = append(errs, FieldError{Field: HeaderForwardedFor, Code: "invalid", Message: "IP addresses only"})
			break
		}
	}
	if len(errs) == 0 {
		return nil
	}
	return &Error{Type: ProblemType(CodeInvalidRequest), Title: "invalid request", Status: 400, Code: CodeInvalidRequest,
		Detail: "invalid forwarded origin", Errors: errs}
}

// ParseForwarded reads the Cloud-Forwarded-* headers of a transport request (the transport
// endpoint's side; cloudtest uses it).
func ParseForwarded(h http.Header) Forwarded {
	f := Forwarded{Host: h.Get(HeaderForwardedHost), Proto: h.Get(HeaderForwardedProto)}
	if v := h.Get(HeaderForwardedFor); v != "" {
		for _, a := range strings.Split(v, ",") {
			f.For = append(f.For, strings.TrimSpace(a))
		}
	}
	return f
}

// CheckServiceRequest checks a transport request's method and target as the transport does:
// CONNECT and TRACE are refused; the path must be absolute (origin form) without dot segments
// (also percent-encoded), backslashes (also %5c) or control characters (also encoded); the
// query without raw control characters. The path and query are otherwise forwarded byte for byte
// (an encoded slash stays encoded). The error is a 400 invalid_request problem.
func CheckServiceRequest(method, escapedPath, rawQuery string) error {
	bad := func(field, code, msg string) error {
		return &Error{Type: ProblemType(CodeInvalidRequest), Title: "invalid request", Status: 400, Code: CodeInvalidRequest,
			Detail: msg, Errors: []FieldError{{Field: field, Code: code, Message: msg}}}
	}
	switch method {
	case http.MethodConnect, http.MethodTrace:
		return bad("method", "not_allowed", "method "+method+" is not forwarded")
	}
	if !strings.HasPrefix(escapedPath, "/") {
		return bad("path", "invalid", "the target is a path starting with / (never an absolute URL)")
	}
	if len(escapedPath)+len(rawQuery) > 8<<10 {
		return bad("path", "too_long", "path and query are at most 8 KiB")
	}
	if hasControl(escapedPath, true) {
		return bad("path", "invalid", "control characters (raw or percent-encoded) are refused in the path")
	}
	if hasControl(rawQuery, false) {
		return bad("query", "invalid", "raw control characters are refused in the query")
	}
	lower := strings.ToLower(escapedPath)
	if strings.Contains(lower, `\`) || strings.Contains(lower, "%5c") {
		return bad("path", "invalid", "backslashes (raw or %5c) are refused")
	}
	for _, seg := range strings.Split(escapedPath[1:], "/") {
		d := strings.ReplaceAll(strings.ToLower(seg), "%2e", ".")
		if d == "." || d == ".." {
			return bad("path", "traversal", "dot segments (raw or percent-encoded) are refused")
		}
	}
	return nil
}

func hasControl(s string, encoded bool) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x20 || c == 0x7f || c == '#' {
			return true
		}
		if encoded && c == '%' && i+2 < len(s) {
			h := strings.ToLower(s[i+1 : i+3])
			if (h[0] == '0' || h[0] == '1') && isHex(h[1]) || h == "7f" {
				return true
			}
		}
	}
	return false
}

func isHex(c byte) bool { return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' }

// cloudCredentialRE matches the shape of Azaleva Cloud's credentials (an API key, an
// installation's own tokens, a transport ticket: <prefix>_<hex id>_<hex secret>) as a whole token, so an
// application's own token (a JWT or base64url value that happens to contain "ack_") is not
// mistaken for one.
var cloudCredentialRE = regexp.MustCompile(`(?:^|[^A-Za-z0-9_-])(?:ack|aco|ctk)_[0-9a-f]{8,}_[0-9a-f]{16,}(?:$|[^A-Za-z0-9_-])`)

// HasCloudCredential reports whether a header carries an Azaleva Cloud credential (an API key,
// another Cloud token or a ticket) in Authorization or Proxy-Authorization. The transport refuses
// such requests (400 invalid_request, field Authorization): a Cloud credential never reaches a
// machine.
func HasCloudCredential(h http.Header) bool {
	for _, k := range []string{"Authorization", "Proxy-Authorization"} {
		for _, v := range h.Values(k) {
			if cloudCredentialRE.MatchString(v) {
				return true
			}
		}
	}
	return false
}

// ServiceTransportOptions configure Machines.ServiceTransport and Machines.CompanionTransport.
type ServiceTransportOptions struct {
	// Actor is kept with each ticket for the audit (opaque).
	Actor string
	// TicketTTL is the lifetime asked for each ticket (default 5 minutes, at most the
	// installation's ticket_ttl_seconds_max).
	TicketTTL time.Duration
	// Base sends the requests to the transport endpoint. Default: a clone of the Client's
	// *http.Transport (or http.DefaultTransport) with DisableCompression, so bodies and
	// Content-Encoding reach the caller unchanged. A custom Base must not decompress, follow
	// redirects or retry.
	Base http.RoundTripper
}

// ServiceTransport is an http.RoundTripper to one service of one machine. It is safe for
// concurrent use. The request's URL contributes only its path and query (its scheme and host
// are ignored: the destination is the ticket's); every Cloud-* header of the request is
// dropped; the public origin comes from WithForwarded. Answers of the transport itself are
// returned as *Error (codes service_absent, machine_unavailable, app_not_listening,
// app_timeout, connection_lost, throttled, …), the application's answers as responses,
// redirects included (never followed). A 101 response's Body is the upgraded connection
// (io.ReadWriteCloser), as net/http's Transport returns it.
type ServiceTransport struct {
	ms      *MachinesService
	machine string
	service string // "" for policy companion
	context string
	opts    ServiceTransportOptions
	base    http.RoundTripper

	mu  sync.Mutex
	tk  *ServiceTicket
	tku *url.URL
	at  time.Time // when tk was minted (local clock)
}

// ServiceTransport returns a transport to a declared service of a machine (policy app, scope
// machines:services). Tickets are minted on first use.
func (s *MachinesService) ServiceTransport(machine, service string, opts *ServiceTransportOptions) *ServiceTransport {
	return s.newTransport(machine, service, "", opts)
}

// CompanionTransport returns a transport to the machine's agent-companion (policy companion,
// scope machines:companion) for one caller context (see CompanionTicketCreate).
func (s *MachinesService) CompanionTransport(machine, callerContext string, opts *ServiceTransportOptions) *ServiceTransport {
	return s.newTransport(machine, "", callerContext, opts)
}

func (s *MachinesService) newTransport(machine, service, callerContext string, opts *ServiceTransportOptions) *ServiceTransport {
	t := &ServiceTransport{ms: s, machine: machine, service: service, context: callerContext}
	if opts != nil {
		t.opts = *opts
	}
	t.base = t.opts.Base
	if t.base == nil {
		var tr *http.Transport
		// The SDK's default client bounds response headers for the API; the transport endpoint
		// has its own header timeout, so a service request does not inherit that bound.
		if ht, ok := s.c.hc.Transport.(*http.Transport); ok && !s.c.defaultHC {
			tr = ht.Clone()
		} else {
			tr = http.DefaultTransport.(*http.Transport).Clone()
		}
		tr.DisableCompression = true
		t.base = tr
	}
	return t
}

// Ticket returns the current ticket, minting one when there is none or it is close to its
// expiry (within a third of its lifetime, at most a minute).
func (t *ServiceTransport) Ticket(ctx context.Context) (*ServiceTicket, error) {
	tk, _, err := t.ticket(ctx, nil)
	return tk, err
}

func (t *ServiceTransport) ticket(ctx context.Context, stale *ServiceTicket) (*ServiceTicket, *url.URL, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.tk != nil && t.tk != stale {
		life := t.tk.ExpiresAt.Sub(t.tk.CreatedAt)
		margin := life / 3
		if margin > time.Minute {
			margin = time.Minute
		}
		if time.Now().Before(t.at.Add(life - margin)) {
			return t.tk, t.tku, nil
		}
	}
	ttl := int(t.opts.TicketTTL / time.Second)
	var tk *ServiceTicket
	var err error
	if t.service != "" {
		tk, err = t.ms.CreateServiceTicket(ctx, t.machine, t.service, ServiceTicketCreate{TTLSeconds: ttl, Actor: t.opts.Actor})
	} else {
		tk, err = t.ms.CreateCompanionTicket(ctx, t.machine, CompanionTicketCreate{Context: t.context, TTLSeconds: ttl, Actor: t.opts.Actor})
	}
	if err != nil {
		return nil, nil, err
	}
	u, err := url.Parse(strings.TrimRight(tk.TransportURL, "/"))
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.RawQuery != "" {
		return nil, nil, fmt.Errorf("cloud: invalid transport_url %q", tk.TransportURL)
	}
	t.tk, t.tku, t.at = tk, u, time.Now()
	return tk, u, nil
}

// RoundTrip implements http.RoundTripper.
func (t *ServiceTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.roundTrip(req)
	if err != nil && req.Body != nil {
		req.Body.Close()
	}
	return resp, err
}

func (t *ServiceTransport) roundTrip(req *http.Request) (*http.Response, error) {
	if req.URL == nil {
		return nil, errors.New("cloud: request without URL")
	}
	if err := CheckServiceRequest(req.Method, req.URL.EscapedPath(), req.URL.RawQuery); err != nil {
		return nil, err
	}
	if HasCloudCredential(req.Header) {
		return nil, &Error{Type: ProblemType(CodeInvalidRequest), Title: "invalid request", Status: 400, Code: CodeInvalidRequest,
			Detail: "an Agent Cloud credential never travels to a machine",
			Errors: []FieldError{{Field: "Authorization", Code: "cloud_credential", Message: "remove the Agent Cloud credential"}}}
	}
	fwd, _ := req.Context().Value(forwardedKey{}).(Forwarded)
	if err := fwd.Validate(); err != nil {
		return nil, err
	}
	tk, base, err := t.ticket(req.Context(), nil)
	if err != nil {
		return nil, err
	}
	resp, err := t.send(req, tk, base, fwd, req.Body)
	if err != nil {
		return nil, err
	}
	if resp.Header.Get(HeaderTransportError) == "" {
		return resp, nil
	}
	perr := decodeProblem(resp)
	if perr.Code != CodeTicketExpired {
		return nil, perr
	}
	// Nothing reached the machine: send once more with a new ticket, when the body can be sent again.
	body := io.ReadCloser(nil)
	if req.Body != nil && req.Body != http.NoBody {
		if req.GetBody == nil {
			return nil, perr
		}
		if body, err = req.GetBody(); err != nil {
			return nil, perr
		}
	}
	if tk, base, err = t.ticket(req.Context(), tk); err != nil {
		return nil, err
	}
	if resp, err = t.send(req, tk, base, fwd, body); err != nil {
		return nil, err
	}
	if resp.Header.Get(HeaderTransportError) != "" {
		return nil, decodeProblem(resp)
	}
	return resp, nil
}

func (t *ServiceTransport) send(req *http.Request, tk *ServiceTicket, base *url.URL, fwd Forwarded, body io.ReadCloser) (*http.Response, error) {
	out := req.Clone(req.Context())
	out.Body = body
	if body == nil {
		out.Body = nil
	}
	out.URL = &url.URL{Scheme: base.Scheme, Host: base.Host, Path: base.Path + req.URL.Path,
		RawPath: base.EscapedPath() + req.URL.EscapedPath(), RawQuery: req.URL.RawQuery}
	out.Host = ""
	out.RequestURI = ""
	for k := range out.Header {
		if strings.HasPrefix(http.CanonicalHeaderKey(k), "Cloud-") {
			delete(out.Header, k)
		}
	}
	out.Header.Set(HeaderTicket, tk.Ticket)
	if fwd.Host != "" {
		out.Header.Set(HeaderForwardedHost, fwd.Host)
	}
	if fwd.Proto != "" {
		out.Header.Set(HeaderForwardedProto, fwd.Proto)
	}
	if len(fwd.For) > 0 {
		out.Header.Set(HeaderForwardedFor, strings.Join(fwd.For, ", "))
	}
	return t.base.RoundTrip(out)
}

// Upgrade sends an upgrade request (a WebSocket handshake: the caller sets Connection,
// Upgrade, Sec-WebSocket-Key, Sec-WebSocket-Version and any Sec-WebSocket-Protocol) and
// returns the upgraded connection when the application answers 101. Any other answer of the
// application is returned with a nil connection (its body for the caller to read and close).
func (t *ServiceTransport) Upgrade(req *http.Request) (*http.Response, io.ReadWriteCloser, error) {
	resp, err := t.RoundTrip(req)
	if err != nil {
		return nil, nil, err
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		return resp, nil, nil
	}
	rwc, ok := resp.Body.(io.ReadWriteCloser)
	if !ok {
		resp.Body.Close()
		return nil, nil, errors.New("cloud: the base transport did not return an upgraded connection")
	}
	return resp, rwc, nil
}

// CloseIdleConnections closes the base transport's idle connections.
func (t *ServiceTransport) CloseIdleConnections() {
	if c, ok := t.base.(interface{ CloseIdleConnections() }); ok {
		c.CloseIdleConnections()
	}
}
