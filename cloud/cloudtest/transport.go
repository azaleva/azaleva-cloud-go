package cloudtest

// The machine-service transport (see the Azaleva Cloud documentation) in the fake: the control
// operations (capabilities, service lists, tickets, companion discovery) and a transport
// endpoint of its own (Server.TransportURL, a second local listener, as the real transport
// endpoint is another host than the API) that forwards to fake guest services. Every machine service and every
// machine's agent-companion is a local HTTP server: by default an echo service (EchoHandler)
// and a fake agent-companion; Options.Services, Options.Companion, HandleService and
// HandleCompanion replace them, so a consumer can serve its own fake application and test
// its gateway end to end.
//
// The fake enforces what the contract suite checks: ticket, scope and ownership on every
// request, the path, method and header rules, the connect and header timeouts, the
// concurrency ceilings, no redirect following, and closing connections when the machine
// leaves ready, the key is revoked, the consumer is disabled or the service is removed (a
// sweep every 50 ms, well within close_bound_seconds). The idle timeout and the longest
// connection are reported, not enforced.

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/azaleva/azaleva-cloud-go/cloud"
)

// transportPrefix is the path of the fake's transport_url on its listener (a base path, so
// clients must join it, as with any installation's transport_url).
const transportPrefix = "/transport"

type ticketRec struct {
	id, consumer, keyHash, machine, service, policy, context, actor string
	expires                                                         time.Time
}

type guest struct {
	mu        sync.Mutex
	srv       *httptest.Server
	handler   http.Handler
	listening bool
}

func (g *guest) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	g.mu.Lock()
	h := g.handler
	g.mu.Unlock()
	if h == nil {
		http.Error(w, "no handler", http.StatusServiceUnavailable)
		return
	}
	h.ServeHTTP(w, r)
}

type tconn struct {
	consumer, keyHash, machine, service, policy string
	cancel                                      context.CancelFunc
}

type transportState struct {
	tickets  map[string]*ticketRec // by hash of the secret
	guests   map[string]*guest     // machine + "/" + service ("companion" for agent-companion)
	removed  map[string]bool       // machine + "/" + service removed by RemoveService
	compDown map[string]bool       // machines whose agent-companion does not answer
	compKeys map[string]string     // machine → the injected agent-companion key
	conns    map[int64]*tconn
	nextConn int64
	secret   string
}

func newTransportState() *transportState {
	return &transportState{tickets: map[string]*ticketRec{}, guests: map[string]*guest{}, removed: map[string]bool{},
		compDown: map[string]bool{}, compKeys: map[string]string{}, conns: map[int64]*tconn{}, secret: randHex(16)}
}

func (s *Server) limits() cloud.TransportLimits {
	l, d := s.opts.Transport, cloud.DefaultTransportLimits
	if l.TicketTTLSecondsMax == 0 {
		l.TicketTTLSecondsMax = d.TicketTTLSecondsMax
	}
	if l.ConnectTimeoutSeconds == 0 {
		l.ConnectTimeoutSeconds = d.ConnectTimeoutSeconds
	}
	if l.HeaderTimeoutSeconds == 0 {
		l.HeaderTimeoutSeconds = d.HeaderTimeoutSeconds
	}
	if l.IdleTimeoutSeconds == 0 {
		l.IdleTimeoutSeconds = d.IdleTimeoutSeconds
	}
	if l.MaxConnectionSeconds == 0 {
		l.MaxConnectionSeconds = d.MaxConnectionSeconds
	}
	if l.MaxRequestHeaderBytes == 0 {
		l.MaxRequestHeaderBytes = d.MaxRequestHeaderBytes
	}
	if l.MaxRequestHeaderFields == 0 {
		l.MaxRequestHeaderFields = d.MaxRequestHeaderFields
	}
	if l.MaxTargetBytes == 0 {
		l.MaxTargetBytes = d.MaxTargetBytes
	}
	if l.MaxResponseHeaderBytes == 0 {
		l.MaxResponseHeaderBytes = d.MaxResponseHeaderBytes
	}
	if l.MaxRequestBodyBytes == 0 {
		l.MaxRequestBodyBytes = d.MaxRequestBodyBytes
	}
	if l.ConnectionsPerMachine == 0 {
		l.ConnectionsPerMachine = d.ConnectionsPerMachine
	}
	if l.CompanionConnectionsPerMachine == 0 {
		l.CompanionConnectionsPerMachine = d.CompanionConnectionsPerMachine
	}
	if l.ConnectionsPerConsumer == 0 {
		l.ConnectionsPerConsumer = d.ConnectionsPerConsumer
	}
	if l.CloseBoundSeconds == 0 {
		l.CloseBoundSeconds = d.CloseBoundSeconds
	}
	return l
}

// startTransport starts the transport listener and the sweep that closes connections.
func (s *Server) startTransport() {
	s.edge = httptest.NewServer(http.HandlerFunc(s.serveTransport))
	s.TransportURL = s.edge.URL + transportPrefix
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		t := time.NewTicker(50 * time.Millisecond)
		defer t.Stop()
		for {
			select {
			case <-s.closed:
				return
			case <-t.C:
			}
			s.mu.Lock()
			for id, cn := range s.st.tr.conns {
				if s.st.connRevoked(cn) {
					cn.cancel()
					delete(s.st.tr.conns, id)
				}
			}
			s.mu.Unlock()
		}
	}()
}

func (s *Server) closeTransport() {
	s.edge.CloseClientConnections()
	s.edge.Close()
	s.mu.Lock()
	var gs []*guest
	for _, g := range s.st.tr.guests {
		gs = append(gs, g)
	}
	s.mu.Unlock()
	for _, g := range gs {
		if g.srv != nil {
			g.srv.CloseClientConnections()
			g.srv.Close()
		}
	}
}

// ---- hooks for tests ----

// HandleService replaces the fake application behind a machine's declared service (nil: the
// service does not listen, so requests answer app_not_listening).
func (s *Server) HandleService(machine, service string, h http.Handler) {
	s.mu.Lock()
	defer s.mu.Unlock()
	g := s.st.guest(machine, service)
	g.mu.Lock()
	g.handler, g.listening = h, h != nil
	g.mu.Unlock()
}

// HandleCompanion replaces the fake agent-companion of a machine. The handler receives the
// requests as agent-companion would: Authorization carries CompanionKey(machine), and
// X-Session-Id the session the node derived from the ticket's caller context.
func (s *Server) HandleCompanion(machine string, h http.Handler) {
	s.HandleService(machine, cloud.CompanionService, h)
}

// SetServiceListening makes a declared service (or "companion") stop or start accepting
// connections without replacing its handler.
func (s *Server) SetServiceListening(machine, service string, up bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.st.machines[machine] == nil {
		return fmt.Errorf("cloudtest: no machine %s", machine)
	}
	g := s.st.guest(machine, service)
	g.mu.Lock()
	g.listening = up && g.handler != nil
	g.mu.Unlock()
	if service == cloud.CompanionService {
		s.st.tr.compDown[machine] = !up
	}
	return nil
}

// RemoveService removes a declared service from one machine, as a reset onto a template
// version without it would: new requests answer service_absent and open connections close.
func (s *Server) RemoveService(machine, service string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.st.machines[machine] == nil {
		return fmt.Errorf("cloudtest: no machine %s", machine)
	}
	s.st.tr.removed[machine+"/"+service] = true
	return nil
}

// CompanionKey is the credential the fake node injects into a machine's agent-companion
// requests (consumers never see it on the API; tests of a custom companion handler check it).
func (s *Server) CompanionKey(machine string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.st.companionKey(machine)
}

// ---- state helpers (under s.mu) ----

func (st *state) companionKey(machine string) string {
	k := st.tr.compKeys[machine]
	if k == "" {
		k = randHex(16)
		st.tr.compKeys[machine] = k
	}
	return k
}

// guest returns (creating) the fake server of a machine's service.
func (st *state) guest(machine, service string) *guest {
	key := machine + "/" + service
	g := st.tr.guests[key]
	if g != nil {
		return g
	}
	g = &guest{listening: true}
	switch {
	case service == cloud.CompanionService && st.s.opts.Companion != nil:
		g.handler = st.s.opts.Companion(machine)
	case service == cloud.CompanionService:
		g.handler = companionHandler(st.companionKey(machine))
	case st.s.opts.Services != nil:
		var decl cloud.ServiceDeclaration
		if m := st.machines[machine]; m != nil {
			for _, d := range st.declaredServices(m) {
				if d.Name == service {
					decl = d
				}
			}
		}
		g.handler = st.s.opts.Services(machine, decl)
	default:
		g.handler = EchoHandler()
	}
	g.listening = g.handler != nil
	g.srv = httptest.NewServer(g)
	st.tr.guests[key] = g
	return g
}

func (st *state) templateOf(m *machine) *template {
	for _, t := range st.allTemplates() {
		if t.ID == m.Template {
			return t
		}
	}
	return nil
}

// declaredServices are the machine's services: its template's, minus RemoveService's.
func (st *state) declaredServices(m *machine) []cloud.ServiceDeclaration {
	t := st.templateOf(m)
	if t == nil {
		return nil
	}
	var out []cloud.ServiceDeclaration
	for _, d := range t.Services {
		if !st.tr.removed[m.ID+"/"+d.Name] {
			out = append(out, d)
		}
	}
	return out
}

func (st *state) declared(m *machine, name string) *cloud.ServiceDeclaration {
	for _, d := range st.declaredServices(m) {
		if d.Name == name {
			return &d
		}
	}
	return nil
}

func (st *state) runsCompanion(m *machine) bool {
	return st.profiles[m.EffectiveProfile].Backend == "companion"
}

// machineReachable: ready on a connected node (the transport never changes a machine's state).
func (st *state) machineReachable(m *machine) bool {
	if m.State != cloud.MachineReady {
		return false
	}
	n := st.nodes[deref(m.Node)]
	return n == nil || n.connected
}

func (st *state) machineUnavailable(m *machine) *problemError {
	e := perr(409, cloud.CodeMachineUnavailable, "the machine is "+m.State+"; the transport never starts or resumes it")
	switch m.State {
	case cloud.MachineCreating, cloud.MachineStarting, cloud.MachineRestarting, cloud.MachineMigrating:
		e.Retryable, e.RetryAfter = true, 5
	case cloud.MachineReady: // its node is away
		e.Detail = "the machine's node is unavailable"
		e.Retryable, e.RetryAfter = true, 30
	}
	return e
}

func scopeOf(policy string) string {
	if policy == cloud.PolicyCompanion {
		return string(cloud.ScopeMachinesCompanion)
	}
	return string(cloud.ScopeMachinesServices)
}

// connRevoked reports whether an open connection must close (checked by the sweep).
func (st *state) connRevoked(cn *tconn) bool {
	k := st.keys[cn.keyHash]
	if k == nil || k.revokedAt != nil || (k.expiresAt != nil && st.s.now().After(*k.expiresAt)) || !k.hasScope(scopeOf(cn.policy)) {
		return true
	}
	if cs := st.consumers[cn.consumer]; cs == nil || cs.state != "active" {
		return true
	}
	m := st.machines[cn.machine]
	if m == nil || !st.machineReachable(m) {
		return true
	}
	if cn.policy == cloud.PolicyApp {
		return st.declared(m, cn.service) == nil
	}
	return !st.runsCompanion(m)
}

// ---- control operations ----

func getCapabilities(c *ctx) {
	out := cloud.Capabilities{API: "v1", Release: "cloudtest", ServiceTransport: &cloud.ServiceTransportCapability{
		Versions: []string{cloud.TransportVersion}, Policies: []string{cloud.PolicyApp, cloud.PolicyCompanion}, Limits: c.s.limits()}}
	c.json(200, &out)
}

func listMachineServices(c *ctx) {
	m := c.machine(c.r.PathValue("machine"))
	out := struct {
		Data []cloud.MachineService `json:"data"`
	}{Data: []cloud.MachineService{}}
	now := c.s.now()
	for _, d := range c.st.declaredServices(m) {
		ms := cloud.MachineService{Name: d.Name, Port: d.Port, Protocol: d.Protocol, Description: d.Description, Policy: cloud.PolicyApp,
			Readiness: cloud.ServiceReadiness{State: "unknown"}}
		if c.st.machineReachable(m) {
			g := c.st.guest(m.ID, d.Name)
			g.mu.Lock()
			ms.Readiness = cloud.ServiceReadiness{State: map[bool]string{true: "listening", false: "not_listening"}[g.listening], CheckedAt: &now}
			g.mu.Unlock()
		}
		out.Data = append(out.Data, ms)
	}
	c.json(200, &out)
}

func (c *ctx) ticketTTL(ttl int) time.Duration {
	if ttl == 0 {
		ttl = 300
	}
	if max := c.s.limits().TicketTTLSecondsMax; ttl < 30 || ttl > max {
		invalid("ttl_seconds", "invalid", "ttl_seconds is between 30 and %d", max)
	}
	return time.Duration(ttl) * time.Second
}

func (c *ctx) mintTicket(m *machine, service, policy, callerContext, actor string, ttl time.Duration) {
	if len(actor) > 255 {
		invalid("actor", "too_long", "actor is at most 255 characters")
	}
	if m.State == cloud.MachineDestroyed {
		panic(c.st.machineUnavailable(m))
	}
	id := "ctk_" + randHex(8)
	secret := id + "_" + randHex(16)
	now := c.s.now()
	rec := &ticketRec{id: id, consumer: c.csm.id, keyHash: hashToken(c.r.Header.Get("Authorization")[len("Bearer "):]), machine: m.ID,
		service: service, policy: policy, context: callerContext, actor: actor, expires: now.Add(ttl)}
	c.st.tr.tickets[hashToken(secret)] = rec
	out := cloud.ServiceTicket{ID: id, Ticket: secret, Policy: policy, Machine: m.ID, Service: service, Context: callerContext,
		Actor: actor, TransportURL: c.s.TransportURL, ExpiresAt: rec.expires, CreatedAt: now}
	c.json(201, &out)
}

func createServiceTicket(c *ctx) {
	m := c.machine(c.r.PathValue("machine"))
	var in cloud.ServiceTicketCreate
	c.decode(&in)
	ttl := c.ticketTTL(in.TTLSeconds)
	name := c.r.PathValue("service")
	if c.st.declared(m, name) == nil {
		fail(404, cloud.CodeServiceAbsent, "the machine declares no service %q", name)
	}
	c.mintTicket(m, name, cloud.PolicyApp, "", in.Actor, ttl)
}

func validCallerContext(s string) bool {
	if len(s) < 1 || len(s) > 128 {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("._:@-", r)) {
			return false
		}
	}
	return true
}

func createCompanionTicket(c *ctx) {
	m := c.machine(c.r.PathValue("machine"))
	var in cloud.CompanionTicketCreate
	c.decode(&in)
	if !validCallerContext(in.Context) {
		invalid("context", "invalid", "context is 1-128 characters of [A-Za-z0-9._:@-]")
	}
	ttl := c.ticketTTL(in.TTLSeconds)
	if !c.st.runsCompanion(m) {
		fail(404, cloud.CodeServiceAbsent, "the machine's profile does not run agent-companion")
	}
	c.mintTicket(m, cloud.CompanionService, cloud.PolicyCompanion, in.Context, in.Actor, ttl)
}

func getMachineCompanion(c *ctx) {
	m := c.machine(c.r.PathValue("machine"))
	now := c.s.now()
	out := cloud.MachineCompanion{State: "absent", Fallback: "none", CheckedAt: &now}
	if c.st.runsCompanion(m) {
		out.PinnedVersion = CompanionVersion
		out.Tooling = maps.Clone(CompanionTooling)
		switch {
		case !c.st.machineReachable(m):
			out.State = "unavailable"
		case c.st.tr.compDown[m.ID]:
			out.State, out.Fallback = "unavailable", "envd"
		default:
			out.State, out.Version = "ready", CompanionVersion
		}
		n := 0
		for _, cn := range c.st.tr.conns {
			if cn.machine == m.ID && cn.policy == cloud.PolicyCompanion {
				n++
			}
		}
		out.Activity = &struct {
			Connections int `json:"connections"`
			Terminals   int `json:"terminals"`
			Processes   int `json:"processes"`
			Notebooks   int `json:"notebooks"`
		}{Connections: n}
	}
	c.json(200, &out)
}

// ---- the transport endpoint ----

// hopHeaders are removed in both directions (RFC 9110 §7.6.1), with the forwarding headers a
// caller could forge; the WebSocket upgrade is re-added by the proxy.
var dropRequestHeaders = []string{"Forwarded", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto", "X-Forwarded-Port",
	"X-Forwarded-Prefix", "X-Forwarded-Server", "X-Real-Ip", "X-Client-Ip", "True-Client-Ip", "Via", "Proxy-Authorization"}

func transportProblem(w http.ResponseWriter, r *http.Request, e *problemError) {
	w.Header().Set(cloud.HeaderTransportError, string(e.Code))
	writeProblem(w, r, e)
}

func (s *Server) serveTransport(w http.ResponseWriter, r *http.Request) {
	w.Header().Set(cloud.HeaderTransportRequest, newID("trq"))
	if s.opts.Logf != nil { // routing data only: never the path, query, headers or bodies
		s.opts.Logf("cloudtest transport: %s", r.Method)
	}
	bad := func(field, code, msg string) {
		e := perr(400, cloud.CodeInvalidRequest, msg)
		e.Errors = []cloud.FieldError{{Field: field, Code: code, Message: msg}}
		transportProblem(w, r, e)
	}
	if !strings.HasPrefix(r.RequestURI, "/") {
		bad("path", "invalid", "the target is a path starting with / (never an absolute URL)")
		return
	}
	rawPath, rawQuery, _ := strings.Cut(r.RequestURI, "?")
	rest, ok := strings.CutPrefix(rawPath, transportPrefix)
	if !ok || (rest != "" && !strings.HasPrefix(rest, "/")) {
		transportProblem(w, r, perr(404, cloud.CodeNotFound, "not a transport path"))
		return
	}
	if rest == "" {
		rest = "/"
	}
	if err := cloud.CheckServiceRequest(r.Method, rest, rawQuery); err != nil {
		e, _ := cloud.AsError(err)
		transportProblem(w, r, e)
		return
	}
	if r.Header.Get("Upgrade") != "" && !IsWebSocketUpgrade(r) {
		bad("Upgrade", "not_allowed", "only WebSocket upgrades are forwarded")
		return
	}
	if cloud.HasCloudCredential(r.Header) {
		bad("Authorization", "cloud_credential", "an Agent Cloud credential never travels to a machine")
		return
	}
	fwd := cloud.ParseForwarded(r.Header)
	if err := fwd.Validate(); err != nil {
		e, _ := cloud.AsError(err)
		transportProblem(w, r, e)
		return
	}
	lim := s.limits()
	if r.ContentLength > lim.MaxRequestBodyBytes {
		bad("body", "too_large", fmt.Sprintf("the request body is at most %d bytes", lim.MaxRequestBodyBytes))
		return
	}
	if len(rest)+len(rawQuery) > lim.MaxTargetBytes {
		bad("path", "too_long", fmt.Sprintf("path and query are at most %d bytes", lim.MaxTargetBytes))
		return
	}
	hb, hf := 0, 0
	for k, vs := range r.Header {
		for _, v := range vs {
			hb, hf = hb+len(k)+len(v)+4, hf+1
		}
	}
	if hb > lim.MaxRequestHeaderBytes || hf > lim.MaxRequestHeaderFields {
		bad("headers", "too_large", fmt.Sprintf("at most %d header fields and %d bytes of headers", lim.MaxRequestHeaderFields, lim.MaxRequestHeaderBytes))
		return
	}

	// The connection's context: the sweep cancels it to close the connection (an upgraded one
	// too: the proxy closes both sides when it ends).
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	s.mu.Lock()
	cn, port, g, compKey, session, pe := s.admitTransport(r, lim, cancel)
	s.mu.Unlock()
	if pe != nil {
		transportProblem(w, r, pe)
		return
	}
	defer func() {
		s.mu.Lock()
		delete(s.st.tr.conns, cn)
		s.mu.Unlock()
	}()

	target, _ := url.Parse(g.srv.URL)
	path, err := url.PathUnescape(rest)
	if err != nil {
		bad("path", "invalid", "invalid percent-encoding")
		return
	}
	host := "localhost:" + strconv.Itoa(port) // the only Host the sandbox runtime's proxy accepts
	if compKey != "" && IsWebSocketUpgrade(r) {
		s.companionWebSocket(ctx, w, r, target.Host, host, rest, rawQuery, guestHeaders(r.Header, fwd, compKey, session, true), compKey, lim)
		return
	}
	rp := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.URL.Scheme, pr.Out.URL.Host = target.Scheme, target.Host
			pr.Out.URL.Path, pr.Out.URL.RawPath, pr.Out.URL.RawQuery = path, rest, rawQuery
			pr.Out.Host = host
			pr.Out.Header = guestHeaders(pr.Out.Header, fwd, compKey, session, false)
		},
		Transport: &http.Transport{
			DialContext:            (&net.Dialer{Timeout: time.Duration(lim.ConnectTimeoutSeconds) * time.Second}).DialContext,
			ResponseHeaderTimeout:  time.Duration(lim.HeaderTimeoutSeconds) * time.Second,
			MaxResponseHeaderBytes: int64(lim.MaxResponseHeaderBytes), DisableCompression: true, DisableKeepAlives: true,
		},
		FlushInterval: -1,
		ModifyResponse: func(resp *http.Response) error {
			// The application cannot speak for the transport (Cloud-Transport-Error) or Cloud.
			for k := range resp.Header {
				if strings.HasPrefix(http.CanonicalHeaderKey(k), "Cloud-") {
					delete(resp.Header, k)
				}
			}
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			var e *problemError
			var ne net.Error
			var oe *net.OpError
			switch {
			case errors.As(err, &oe) && oe.Op == "dial":
				e = perr(502, cloud.CodeAppNotListening, "the service does not accept connections")
				e.Retryable, e.RetryAfter = true, 1
			case errors.As(err, &ne) && ne.Timeout() || strings.Contains(err.Error(), "timeout awaiting response headers"):
				e = perr(504, cloud.CodeAppTimeout, "the service sent no response headers in time; the request is not replayed")
			default:
				e = perr(502, cloud.CodeConnectionLost, "the connection to the service ended; the request may have reached it and is not replayed")
			}
			transportProblem(w, r, e)
		},
	}
	rp.ServeHTTP(w, r.WithContext(ctx))
}

// admitTransport authorises one request (the ticket, its key and scope, the machine and the
// service, the machine's state, the ceilings) and registers its connection.
func (s *Server) admitTransport(r *http.Request, lim cloud.TransportLimits, cancel context.CancelFunc) (id int64, port int, g *guest, compKey, session string, e *problemError) {
	st := s.st
	tk := st.tr.tickets[hashToken(r.Header.Get(cloud.HeaderTicket))]
	if r.Header.Get(cloud.HeaderTicket) == "" || tk == nil {
		return 0, 0, nil, "", "", perr(401, cloud.CodeUnauthenticated, "missing or unknown ticket (Cloud-Ticket)")
	}
	if s.now().After(tk.expires) {
		e := perr(401, cloud.CodeTicketExpired, "the ticket expired; mint a new one (nothing was sent)")
		e.Retryable = true
		return 0, 0, nil, "", "", e
	}
	k := st.keys[tk.keyHash]
	if k == nil || k.revokedAt != nil || (k.expiresAt != nil && s.now().After(*k.expiresAt)) {
		return 0, 0, nil, "", "", perr(401, cloud.CodeUnauthenticated, "the key that minted the ticket is revoked or expired")
	}
	if cs := st.consumers[tk.consumer]; cs == nil || cs.state != "active" {
		return 0, 0, nil, "", "", perr(401, cloud.CodeUnauthenticated, "the consumer is disabled")
	}
	if sc := scopeOf(tk.policy); !k.hasScope(sc) {
		e := perr(403, cloud.CodeScopeMissing, "the API key lacks the scope "+sc)
		e.Scope = sc
		return 0, 0, nil, "", "", e
	}
	m := st.machines[tk.machine]
	if m == nil || m.consumer != tk.consumer || (k.project != "" && k.project != m.Project) {
		return 0, 0, nil, "", "", perr(404, cloud.CodeNotFound, "machine not found")
	}
	if tk.policy == cloud.PolicyApp {
		d := st.declared(m, tk.service)
		if d == nil {
			return 0, 0, nil, "", "", perr(404, cloud.CodeServiceAbsent, "the machine declares no service "+tk.service)
		}
		port = d.Port
	} else {
		if !st.runsCompanion(m) {
			return 0, 0, nil, "", "", perr(404, cloud.CodeServiceAbsent, "the machine's profile does not run agent-companion")
		}
		port = 8000
		compKey = st.companionKey(m.ID)
		// The companion session: (machine, consumer, ticket context, the caller's X-Session-Id).
		sum := sha256.Sum256([]byte(st.tr.secret + "\x00" + m.ID + "\x00" + tk.consumer + "\x00" + tk.context + "\x00" + r.Header.Get("X-Session-Id")))
		session = hex.EncodeToString(sum[:16])
	}
	if !st.machineReachable(m) {
		return 0, 0, nil, "", "", st.machineUnavailable(m)
	}
	perMachine, perConsumer := 0, 0
	for _, cn := range st.tr.conns {
		if cn.consumer == tk.consumer {
			perConsumer++
		}
		if cn.machine == m.ID && cn.policy == tk.policy {
			perMachine++
		}
	}
	ceiling := lim.ConnectionsPerMachine
	if tk.policy == cloud.PolicyCompanion {
		ceiling = lim.CompanionConnectionsPerMachine
	}
	throttled := func(name string, limit, used int) *problemError {
		e := perr(429, cloud.CodeThrottled, fmt.Sprintf("%s is %d", name, limit))
		e.Retryable, e.RetryAfter = true, 1
		e.Quota = &cloud.QuotaViolation{Name: name, Limit: int64(limit), Used: int64(used), Requested: 1}
		return e
	}
	if perMachine >= ceiling {
		name := "connections_per_machine"
		if tk.policy == cloud.PolicyCompanion {
			name = "companion_connections_per_machine"
		}
		return 0, 0, nil, "", "", throttled(name, ceiling, perMachine)
	}
	if perConsumer >= lim.ConnectionsPerConsumer {
		return 0, 0, nil, "", "", throttled("connections_per_consumer", lim.ConnectionsPerConsumer, perConsumer)
	}
	g = st.guest(m.ID, tk.service)
	g.mu.Lock()
	up := g.listening
	g.mu.Unlock()
	if !up || (tk.policy == cloud.PolicyCompanion && st.tr.compDown[m.ID]) {
		e := perr(502, cloud.CodeAppNotListening, "the service does not accept connections")
		e.Retryable, e.RetryAfter = true, 1
		return 0, 0, nil, "", "", e
	}
	st.tr.nextConn++
	id = st.tr.nextConn
	st.tr.conns[id] = &tconn{consumer: tk.consumer, keyHash: tk.keyHash, machine: m.ID, service: tk.service, policy: tk.policy, cancel: cancel}
	return id, port, g, compKey, session, nil
}

// hopHeaders are hop-by-hop (RFC 9110 §7.6.1); an upgrade re-establishes Connection and
// Upgrade itself.
var hopHeaders = []string{"Connection", "Keep-Alive", "Proxy-Connection", "Te", "Trailer", "Transfer-Encoding", "Upgrade"}

// guestHeaders are the headers the application receives: the caller's minus every Cloud-*,
// forwarding and (raw) hop-by-hop header, plus the validated public origin as
// Cloud-Forwarded-* and, under policy companion, the node's credential and session.
func guestHeaders(in http.Header, fwd cloud.Forwarded, compKey, session string, raw bool) http.Header {
	h := in.Clone()
	if raw { // not through httputil.ReverseProxy, which removes hop-by-hop headers itself
		for _, c := range h.Values("Connection") {
			for _, k := range strings.Split(c, ",") {
				h.Del(strings.TrimSpace(k))
			}
		}
		for _, k := range hopHeaders {
			h.Del(k)
		}
	}
	for k := range h {
		if strings.HasPrefix(http.CanonicalHeaderKey(k), "Cloud-") {
			delete(h, k)
		}
	}
	for _, k := range dropRequestHeaders {
		h.Del(k)
	}
	if fwd.Host != "" {
		h.Set(cloud.HeaderForwardedHost, fwd.Host)
	}
	if fwd.Proto != "" {
		h.Set(cloud.HeaderForwardedProto, fwd.Proto)
	}
	if len(fwd.For) > 0 {
		h.Set(cloud.HeaderForwardedFor, strings.Join(fwd.For, ", "))
	}
	if compKey != "" { // policy companion: the node's credential and session, never the caller's
		h.Set("Authorization", "Bearer "+compKey)
		h.Set("X-Session-Id", session)
	}
	return h
}

// companionWebSocket carries a policy-companion WebSocket: agent-companion takes its credential
// from the first client message ({"type":"auth","token":…}), not from headers, so the
// transport requires the caller's first message to be such a message and replaces its token
// with the key before splicing the rest unchanged. Any other first message closes the
// connection before anything reaches agent-companion.
func (s *Server) companionWebSocket(ctx context.Context, w http.ResponseWriter, r *http.Request, addr, host, path, rawQuery string,
	h http.Header, key string, lim cloud.TransportLimits) {
	notListening := func() {
		e := perr(502, cloud.CodeAppNotListening, "the service does not accept connections")
		e.Retryable, e.RetryAfter = true, 1
		transportProblem(w, r, e)
	}
	gc, err := net.DialTimeout("tcp", addr, time.Duration(lim.ConnectTimeoutSeconds)*time.Second)
	if err != nil {
		notListening()
		return
	}
	defer gc.Close()
	target := path
	if rawQuery != "" {
		target += "?" + rawQuery
	}
	h.Set("Connection", "Upgrade")
	h.Set("Upgrade", "websocket")
	var head strings.Builder
	fmt.Fprintf(&head, "%s %s HTTP/1.1\r\nHost: %s\r\n", r.Method, target, host)
	_ = h.Write(&head)
	head.WriteString("\r\n")
	_ = gc.SetDeadline(time.Now().Add(time.Duration(lim.HeaderTimeoutSeconds) * time.Second))
	if _, err := io.WriteString(gc, head.String()); err != nil {
		notListening()
		return
	}
	gr := bufio.NewReader(gc)
	resp, err := http.ReadResponse(gr, nil)
	if err != nil {
		transportProblem(w, r, perr(502, cloud.CodeConnectionLost, "the connection to the service ended; the request may have reached it"))
		return
	}
	_ = gc.SetDeadline(time.Time{})
	for k := range resp.Header {
		if strings.HasPrefix(http.CanonicalHeaderKey(k), "Cloud-") {
			delete(resp.Header, k)
		}
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		defer resp.Body.Close()
		for k, vs := range resp.Header {
			if k != "Connection" && k != "Transfer-Encoding" {
				w.Header()[k] = vs
			}
		}
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
		return
	}
	cc, crw, err := http.NewResponseController(w).Hijack()
	if err != nil {
		return
	}
	defer cc.Close()
	var out strings.Builder
	out.WriteString("HTTP/1.1 101 Switching Protocols\r\n")
	_ = resp.Header.Write(&out)
	out.WriteString("\r\n")
	if _, err := io.WriteString(cc, out.String()); err != nil {
		return
	}
	// The first client message: an auth message, whose token becomes the node's key.
	_ = cc.SetReadDeadline(time.Now().Add(time.Duration(lim.HeaderTimeoutSeconds) * time.Second))
	fin, op, payload, err := ReadWebSocketFrame(crw.Reader)
	var msg map[string]any
	if err != nil || !fin || op != 0x1 || json.Unmarshal(payload, &msg) != nil || msg["type"] != "auth" {
		_ = WriteWebSocketFrame(cc, true, 0x8, []byte{0x03, 0xf0}, false) // 1008: the first message must authenticate
		return
	}
	_ = cc.SetReadDeadline(time.Time{})
	msg["token"] = key
	b, _ := json.Marshal(msg)
	if WriteWebSocketFrame(gc, true, 0x1, b, true) != nil {
		return
	}
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(gc, crw.Reader); done <- struct{}{} }()
	go func() { _, _ = io.Copy(cc, gr); done <- struct{}{} }()
	select { // either side ending, or the sweep closing the connection, ends both
	case <-done:
	case <-ctx.Done():
	}
}

// ---- fake guest services ----

// EchoHandler is the fake application cloudtest serves on every declared service unless
// Options.Services or HandleService replaces it:
//
//   - a WebSocket upgrade on any path: an echo of every frame (the first offered subprotocol is chosen);
//   - /redirect: 302 to /target (with a cookie), which the transport returns unfollowed;
//   - /cookies: 200 with two Set-Cookie headers;
//   - /spoof: 404 with a Cloud-Transport-Error header, which the transport removes;
//   - /drop: 200, part of a body, then the connection drops (the consumer must see an error);
//   - /stream?n=3: Server-Sent Events, one event every 10 ms, flushed;
//   - /status/<code>: that status;
//   - /slow?ms=<n>: waits before the response headers;
//   - anything else: JSON {method, path, query, host, headers, body_bytes, body_sha256}, the path
//     and query exactly as received.
func EchoHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if IsWebSocketUpgrade(r) {
			serveWebSocketEcho(w, r)
			return
		}
		rawPath, rawQuery, _ := strings.Cut(r.RequestURI, "?")
		switch {
		case rawPath == "/redirect":
			http.SetCookie(w, &http.Cookie{Name: "r", Value: "1", Path: "/"})
			w.Header().Set("Location", "/target")
			w.WriteHeader(http.StatusFound)
			return
		case rawPath == "/drop": // the application dies in the middle of its answer
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("partial"))
			http.NewResponseController(w).Flush()
			panic(http.ErrAbortHandler)
		case rawPath == "/spoof": // an application that pretends to be the transport
			w.Header().Set(cloud.HeaderTransportError, string(cloud.CodeServiceAbsent))
			w.WriteHeader(http.StatusNotFound)
			return
		case rawPath == "/cookies":
			w.Header().Add("Set-Cookie", "a=1; Path=/")
			w.Header().Add("Set-Cookie", "b=2; Path=/; HttpOnly")
			w.WriteHeader(http.StatusOK)
			return
		case rawPath == "/stream":
			n, _ := strconv.Atoi(r.URL.Query().Get("n"))
			if n <= 0 {
				n = 3
			}
			w.Header().Set("Content-Type", "text/event-stream")
			w.WriteHeader(http.StatusOK)
			f, _ := w.(http.Flusher)
			for i := 0; i < n; i++ {
				fmt.Fprintf(w, "id: %d\ndata: event %d\n\n", i, i)
				if f != nil {
					f.Flush()
				}
				select {
				case <-r.Context().Done():
					return
				case <-time.After(10 * time.Millisecond):
				}
			}
			return
		case strings.HasPrefix(rawPath, "/status/"):
			code, err := strconv.Atoi(strings.TrimPrefix(rawPath, "/status/"))
			if err != nil || code < 200 || code > 599 {
				code = 400
			}
			w.WriteHeader(code)
			return
		case rawPath == "/slow":
			ms, _ := strconv.Atoi(r.URL.Query().Get("ms"))
			select {
			case <-r.Context().Done():
				return
			case <-time.After(time.Duration(ms) * time.Millisecond):
			}
		}
		h := sha256.New()
		n, _ := io.Copy(h, r.Body)
		out := map[string]any{"method": r.Method, "path": rawPath, "query": rawQuery, "host": r.Host, "headers": r.Header,
			"body_bytes": n, "body_sha256": hex.EncodeToString(h.Sum(nil))}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	})
}
