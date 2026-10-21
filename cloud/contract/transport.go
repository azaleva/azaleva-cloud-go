package contract

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/azaleva/azaleva-cloud-go/cloud"
)

// testServiceTransport: the machine-service transport (see the Azaleva Cloud documentation). Where the
// installation does not offer it (capabilities.service_transport null), the operations must
// still exist, check scope and ownership, and answer not_implemented. Otherwise: declared
// services in a template, the two policies and their separate scopes, ownership on every
// request (foreign = missing), the path, method and header rules, cookies, redirects,
// streaming, bodies and WebSockets end to end, ticket expiry and renewal, no wake of a stopped
// machine, and the close bound on stop, key revocation, service removal and delete.
func (s *suite) testServiceTransport(t *testing.T) {
	a, b := s.a, s.b
	caps, err := a.c.Capabilities(s.ctx)
	must(t, err)
	if caps.API != "v1" {
		t.Fatalf("capabilities api %q", caps.API)
	}
	if !caps.ServiceTransport.Supports(cloud.PolicyApp) {
		s.testServiceTransportAbsent(t)
		t.Skip("the installation does not offer the machine-service transport (capabilities.service_transport is null)")
	}
	lim := caps.ServiceTransport.Limits
	if lim.CloseBoundSeconds <= 0 || lim.TicketTTLSecondsMax < 300 || lim.ConnectionsPerMachine <= 0 {
		t.Fatalf("transport limits: %+v", lim)
	}
	closeBound := time.Duration(lim.CloseBoundSeconds)*time.Second + 2*time.Second

	// A machine template that declares a service; the machine's own ports are refused.
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	must(t, err)
	provisioned(t, s.prov.AddTemplateSigner(s.ctx, a.id, pub, []string{TemplatePrefix + "svc-*"}))
	upload := func(name string, svcs []cloud.ServiceDeclaration) (*cloud.Template, error) {
		files := map[string][]byte{"recipe.py": []byte("print('service machine')\n")}
		if s.env.RealRecipes {
			files = echoRecipe(8080)
		}
		pkg, err := cloud.BuildTemplatePackage(cloud.TemplateManifest{Name: name, Kind: cloud.KindMachine, Recipe: "recipe.py",
			SDK: "e2b==2.52.0", Services: svcs}, files)
		must(t, err)
		return a.c.Templates.Upload(s.ctx, pkg, cloud.SignTemplatePackage(priv, pkg))
	}
	for _, bad := range []struct {
		svc  cloud.ServiceDeclaration
		code string
	}{
		{cloud.ServiceDeclaration{Name: "web", Port: 8000, Protocol: "http"}, "reserved_port"},
		{cloud.ServiceDeclaration{Name: "web", Port: 49983, Protocol: "http"}, "reserved_port"},
		{cloud.ServiceDeclaration{Name: "web", Port: 9090, Protocol: "http"}, "reserved_port"},
		{cloud.ServiceDeclaration{Name: "web", Port: 8642, Protocol: "http"}, "reserved_port"},
		{cloud.ServiceDeclaration{Name: "companion", Port: 8080, Protocol: "http"}, "invalid"},
		{cloud.ServiceDeclaration{Name: "web", Port: 80, Protocol: "http"}, "invalid"},
	} {
		_, err := upload(s.templateName("svc-bad"), []cloud.ServiceDeclaration{bad.svc})
		if e := wantCode(t, err, cloud.CodeInvalidTemplatePackage); len(e.Errors) == 0 || e.Errors[0].Code != bad.code {
			t.Fatalf("service %+v: %+v, want %s", bad.svc, e.Errors, bad.code)
		}
	}
	var tp *cloud.Template
	if s.env.ServiceTemplate != "" {
		// An installation's existing template that declares web:8080 (no build); the echo
		// service is started in each machine through the API (startEcho).
		tp, err = a.c.Templates.Get(s.ctx, s.env.ServiceTemplate)
		must(t, err)
	} else {
		tp, err = upload(s.templateName("svc-echo"), []cloud.ServiceDeclaration{{Name: "web", Port: 8080, Protocol: "http", Description: "echo"}})
		must(t, err)
		tp = s.waitTemplate(t, a, tp.ID)
	}
	if tp.State != "ready" || len(tp.Services) != 1 || tp.Services[0].Name != "web" || tp.Services[0].Port != 8080 {
		t.Fatalf("template: %+v", tp)
	}
	m := s.machine(t, a, a.project.ID, func(in *cloud.MachineCreate) { in.Template = tp.Ref() })
	defer a.c.Machines.Delete(s.ctx, m.ID)
	s.startEcho(t, a, m.ID)

	// Separate scopes: neither transport scope opens the other policy, nor does machines.
	svcKey, err := s.prov.CreateKey(s.ctx, a.id, "", []cloud.Scope{cloud.ScopeMachinesServices})
	provisioned(t, err)
	svc, err := cloud.New(s.env.URL, svcKey)
	must(t, err)
	comp := s.keyWith(t, a, "", cloud.ScopeMachinesCompanion)
	plain := s.keyWith(t, a, "", cloud.ScopeMachines)
	_, err = plain.Machines.ListServices(s.ctx, m.ID)
	if e := wantCode(t, err, cloud.CodeScopeMissing); e.Scope != string(cloud.ScopeMachinesServices) {
		t.Fatalf("scope %q", e.Scope)
	}
	_, err = svc.Machines.CreateCompanionTicket(s.ctx, m.ID, cloud.CompanionTicketCreate{Context: "c1"})
	wantCode(t, err, cloud.CodeScopeMissing)
	_, err = comp.Machines.CreateServiceTicket(s.ctx, m.ID, "web", cloud.ServiceTicketCreate{})
	wantCode(t, err, cloud.CodeScopeMissing)

	// Declared services and readiness (on real nodes the echo service starts with the machine).
	ls, err := svc.Machines.ListServices(s.ctx, m.ID)
	for end := time.Now().Add(time.Minute); err == nil && len(ls) == 1 && ls[0].Readiness.State != "listening" && time.Now().Before(end); {
		time.Sleep(time.Second)
		ls, err = svc.Machines.ListServices(s.ctx, m.ID)
	}
	must(t, err)
	if len(ls) != 1 || ls[0].Name != "web" || ls[0].Port != 8080 || ls[0].Policy != cloud.PolicyApp || ls[0].Readiness.State != "listening" {
		t.Fatalf("services: %+v", ls)
	}

	// Foreign = missing; an undeclared service is service_absent; the companion is never an app service.
	_, err = b.c.Machines.ListServices(s.ctx, m.ID)
	wantCode(t, err, cloud.CodeNotFound)
	_, err = b.c.Machines.CreateServiceTicket(s.ctx, m.ID, "web", cloud.ServiceTicketCreate{})
	wantCode(t, err, cloud.CodeNotFound)
	_, err = b.c.Machines.CreateCompanionTicket(s.ctx, m.ID, cloud.CompanionTicketCreate{Context: "c1"})
	wantCode(t, err, cloud.CodeNotFound)
	_, err = b.c.Machines.Companion(s.ctx, m.ID)
	wantCode(t, err, cloud.CodeNotFound)
	_, err = b.c.Machines.CreateServiceTicket(s.ctx, "mch_doesnotexist0", "web", cloud.ServiceTicketCreate{})
	wantCode(t, err, cloud.CodeNotFound)
	_, err = svc.Machines.CreateServiceTicket(s.ctx, m.ID, "nope", cloud.ServiceTicketCreate{})
	wantCode(t, err, cloud.CodeServiceAbsent)
	_, err = svc.Machines.CreateServiceTicket(s.ctx, m.ID, "companion", cloud.ServiceTicketCreate{})
	wantCode(t, err, cloud.CodeServiceAbsent)

	// Tickets: shape, bounds, never replayed by Idempotency-Key.
	tk, err := svc.Machines.CreateServiceTicket(s.ctx, m.ID, "web", cloud.ServiceTicketCreate{Actor: "user-9"})
	must(t, err)
	if !strings.HasPrefix(tk.ID, "ctk_") || !strings.HasPrefix(tk.Ticket, tk.ID+"_") || tk.Policy != cloud.PolicyApp || tk.Machine != m.ID ||
		tk.Service != "web" || tk.Actor != "user-9" || tk.TransportURL == "" || tk.ExpiresAt.Sub(tk.CreatedAt) != 300*time.Second {
		t.Fatalf("ticket: %+v", tk)
	}
	for _, ttl := range []int{5, lim.TicketTTLSecondsMax + 1} {
		_, err = svc.Machines.CreateServiceTicket(s.ctx, m.ID, "web", cloud.ServiceTicketCreate{TTLSeconds: ttl})
		wantCode(t, err, cloud.CodeInvalidRequest)
	}
	key := cloud.WithIdempotencyKey("ticket-" + s.tag)
	_, err = svc.Machines.CreateServiceTicket(s.ctx, m.ID, "web", cloud.ServiceTicketCreate{}, key)
	must(t, err)
	_, err = noRetryClient(svc).Machines.CreateServiceTicket(s.ctx, m.ID, "web", cloud.ServiceTicketCreate{}, key)
	wantCode(t, err, cloud.CodeConflict)

	forwardedFor := map[string]cloud.Forwarded{}
	tr := svc.Machines.ServiceTransport(m.ID, "web", &cloud.ServiceTransportOptions{Actor: "user-9"})
	defer tr.CloseIdleConnections()
	hc := &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	get := func(path string, mod func(*http.Request)) *http.Response {
		t.Helper()
		req, err := http.NewRequestWithContext(s.ctx, http.MethodGet, "http://ignored.invalid"+path, nil)
		must(t, err)
		if fwd, ok := forwardedFor[path]; ok {
			req = req.WithContext(cloud.WithForwarded(req.Context(), fwd))
		}
		if mod != nil {
			mod(req)
		}
		resp, err := hc.Do(req)
		must(t, err)
		return resp
	}
	echo := func(resp *http.Response) (out struct {
		Method, Path, Query, Host string
		Headers                   http.Header
		BodyBytes                 int64  `json:"body_bytes"`
		BodySHA256                string `json:"body_sha256"`
	}) {
		t.Helper()
		defer resp.Body.Close()
		if resp.StatusCode != 200 || resp.Header.Get(cloud.HeaderTransportError) != "" {
			t.Fatalf("echo: %d %v", resp.StatusCode, resp.Header)
		}
		must(t, json.NewDecoder(resp.Body).Decode(&out))
		return out
	}

	// Path and query byte for byte; the public origin only from the consumer's Forwarded;
	// forged forwarding headers, Cloud-* headers and the ticket never reach the application;
	// the application's own Authorization and cookies do.
	forwardedFor["/echo/a%2Fb/c?x=1&x=2&y=%20z"] = cloud.Forwarded{Host: "app.example.com", Proto: "https", For: []string{"203.0.113.7"}}
	resp := get("/echo/a%2Fb/c?x=1&x=2&y=%20z", func(r *http.Request) {
		r.Header.Set("Authorization", "Basic YXBwOnVzZXI=")
		r.Header.Set("Cookie", "sid=1")
		r.Header.Set("X-Forwarded-For", "6.6.6.6")
		r.Header.Set("Forwarded", "for=6.6.6.6")
		r.Header.Set("X-Real-IP", "6.6.6.6")
		r.Header.Set("Cloud-Forwarded-Host", "evil.example")
	})
	if resp.Header.Get(cloud.HeaderTransportRequest) == "" {
		t.Fatal("no Cloud-Transport-Request on the answer")
	}
	e := echo(resp)
	h := e.Headers
	// Host is always localhost:<port>; the origin arrives only as Cloud-Forwarded-*.
	if e.Method != "GET" || e.Path != "/echo/a%2Fb/c" || e.Query != "x=1&x=2&y=%20z" || e.Host != "localhost:8080" ||
		h.Get(cloud.HeaderForwardedHost) != "app.example.com" || h.Get(cloud.HeaderForwardedProto) != "https" ||
		h.Get(cloud.HeaderForwardedFor) != "203.0.113.7" || h.Get("X-Forwarded-For") != "" || h.Get("X-Forwarded-Host") != "" ||
		h.Get("Forwarded") != "" || h.Get("Authorization") != "Basic YXBwOnVzZXI=" || h.Get("Cookie") != "sid=1" || h.Get("X-Real-Ip") != "" ||
		h.Get(cloud.HeaderTicket) != "" || h.Get("Idempotency-Key") != "" {
		t.Fatalf("echo: %+v", e)
	}
	if e := echo(get("/plain", nil)); e.Host != "localhost:8080" || e.Headers.Get(cloud.HeaderForwardedHost) != "" || e.Headers.Get(cloud.HeaderForwardedFor) != "" {
		t.Fatalf("echo without an origin: %+v", e)
	}
	// Several Set-Cookie; a redirect returned, not followed; the application's statuses as they are.
	resp = get("/cookies", nil)
	resp.Body.Close()
	if n := len(resp.Header.Values("Set-Cookie")); n != 2 {
		t.Fatalf("Set-Cookie: %d", n)
	}
	resp = get("/redirect", nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "/target" || resp.Header.Get("Set-Cookie") == "" {
		t.Fatalf("redirect: %d %v", resp.StatusCode, resp.Header)
	}
	resp = get("/status/404", nil)
	resp.Body.Close()
	if resp.StatusCode != 404 || resp.Header.Get(cloud.HeaderTransportError) != "" {
		t.Fatalf("an application 404: %d %v", resp.StatusCode, resp.Header)
	}
	// A response cut in the middle is an error for the consumer, never a clean end: an aborted
	// response, or connection_lost when nothing of it had reached the consumer yet (a real
	// machine's runtime may answer a guest that cut its response with a 502 of its own).
	if resp, err := hc.Get("http://ignored.invalid/drop"); err != nil {
		wantCode(t, err, cloud.CodeConnectionLost)
	} else {
		if _, err := io.ReadAll(resp.Body); err == nil {
			t.Fatal("a truncated response ended cleanly")
		}
		resp.Body.Close()
	}
	// Header bounds are the transport's (the sandbox runtime has none).
	many := http.Header{}
	for i := 0; i <= lim.MaxRequestHeaderFields; i++ {
		many.Set(fmt.Sprintf("X-Many-%d", i), "1")
	}
	if raw := s.rawTransport(t, tk, http.MethodGet, "/x", many); raw.StatusCode != 400 {
		t.Fatalf("%d header fields: %d", lim.MaxRequestHeaderFields+1, raw.StatusCode)
	}
	if raw := s.rawTransport(t, tk, http.MethodGet, "/x", http.Header{"X-Big": {strings.Repeat("a", lim.MaxRequestHeaderBytes)}}); raw.StatusCode != 400 {
		t.Fatalf("a header block over %d bytes: %d", lim.MaxRequestHeaderBytes, raw.StatusCode)
	}
	resp = get("/spoof", nil)
	resp.Body.Close()
	if resp.StatusCode != 404 || resp.Header.Get(cloud.HeaderTransportError) != "" {
		t.Fatalf("the application spoke for the transport: %d %v", resp.StatusCode, resp.Header)
	}
	// A binary body, streamed; no Idempotency-Key is added to a POST.
	body := make([]byte, 1<<20)
	_, _ = rand.Read(body)
	req, _ := http.NewRequestWithContext(s.ctx, http.MethodPost, "http://ignored.invalid/upload", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/octet-stream")
	resp, err = hc.Do(req)
	must(t, err)
	sum := sha256.Sum256(body)
	if e := echo(resp); e.BodyBytes != int64(len(body)) || e.BodySHA256 != hex.EncodeToString(sum[:]) || e.Method != "POST" || e.Headers.Get("Idempotency-Key") != "" {
		t.Fatalf("upload: %+v", e)
	}
	// Server-Sent Events arrive as a stream.
	resp = get("/stream?n=3", nil)
	sc := bufio.NewScanner(resp.Body)
	n := 0
	for sc.Scan() {
		if strings.HasPrefix(sc.Text(), "data: ") {
			n++
		}
	}
	resp.Body.Close()
	if n != 3 || resp.Header.Get("Content-Type") != "text/event-stream" {
		t.Fatalf("stream: %d events", n)
	}

	// WebSocket: the subprotocol is negotiated with the application; frames pass unchanged.
	ws := s.dialWS(t, tr, "/ws", "chat.v2, chat.v1")
	if ws.protocol != "chat.v2" {
		t.Fatalf("subprotocol %q", ws.protocol)
	}
	ws.roundTrip(t, 0x1, []byte("hello"))
	ws.roundTrip(t, 0x2, []byte{0, 1, 2, 255})
	ws.roundTrip(t, 0x9, []byte("ping")) // answered by a pong
	ws.close()

	// Refused before anything reaches the machine: traversal, absolute targets, CONNECT/TRACE,
	// a Cloud credential, an unknown ticket.
	for _, p := range []string{"/a/../b", "/a/%2e%2E/b", "/a/%5cb", "/a/%00b"} {
		raw := s.rawTransport(t, tk, http.MethodGet, p, nil)
		if raw.StatusCode != 400 || raw.Header.Get(cloud.HeaderTransportError) != string(cloud.CodeInvalidRequest) {
			t.Fatalf("path %s: %d %v", p, raw.StatusCode, raw.Header)
		}
	}
	_, err = hc.Get("http://ignored.invalid/a/../b")
	if !cloud.IsCode(err, cloud.CodeInvalidRequest) {
		t.Fatalf("the SDK sent a dot segment: %v", err)
	}
	if raw := s.rawTransport(t, tk, http.MethodTrace, "/x", nil); raw.StatusCode != 400 {
		t.Fatalf("TRACE: %d", raw.StatusCode)
	}
	if raw := s.rawTransport(t, tk, http.MethodGet, "/x", http.Header{"Authorization": {"Bearer " + a.key}}); raw.StatusCode != 400 {
		t.Fatalf("a Cloud credential reached the transport: %d", raw.StatusCode)
	}
	if raw := s.rawTransport(t, &cloud.ServiceTicket{Ticket: "ctk_0000000000000000_00000000000000000000000000000000", TransportURL: tk.TransportURL},
		http.MethodGet, "/x", nil); raw.StatusCode != 401 || raw.Header.Get(cloud.HeaderTransportError) != string(cloud.CodeUnauthenticated) {
		t.Fatalf("unknown ticket: %d", raw.StatusCode)
	}
	if u, _ := url.Parse(tk.TransportURL); u.Scheme == "http" {
		status := rawAbsoluteForm(t, u.Host, tk.Ticket)
		if !strings.Contains(status, " 400 ") {
			t.Fatalf("absolute-form target: %q", status)
		}
	}

	// The ticket expires for new requests; the SDK mints a new one and sends again (nothing
	// reached the machine).
	if s.env.Advance != nil {
		first, err := tr.Ticket(s.ctx)
		must(t, err)
		s.env.Advance(301 * time.Second)
		raw := s.rawTransport(t, first, http.MethodGet, "/x", nil)
		if raw.StatusCode != 401 || raw.Header.Get(cloud.HeaderTransportError) != string(cloud.CodeTicketExpired) {
			t.Fatalf("expired ticket: %d %v", raw.StatusCode, raw.Header)
		}
		echo(get("/after-expiry", nil))
		// The SDK's own clock did not move, so it learnt the expiry from the transport.
		if next, err := tr.Ticket(s.ctx); err != nil || next.ID == first.ID {
			t.Fatalf("no new ticket after ticket_expired: %v", err)
		}
	}

	// A service that does not listen; readiness follows.
	if s.env.SetServiceListening != nil {
		must(t, s.env.SetServiceListening(m.ID, "web", false))
		_, err = hc.Get("http://ignored.invalid/x")
		if e := wantCode(t, err, cloud.CodeAppNotListening); !e.Retryable {
			t.Fatal("app_not_listening is retryable")
		}
		if ls, err := svc.Machines.ListServices(s.ctx, m.ID); err != nil || ls[0].Readiness.State != "not_listening" {
			t.Fatalf("readiness: %+v %v", ls, err)
		}
		must(t, s.env.SetServiceListening(m.ID, "web", true))
	}

	// The per-machine ceiling.
	if c := lim.ConnectionsPerMachine; c <= 16 {
		var open []*wsConn
		for i := 0; i < c; i++ {
			open = append(open, s.dialWS(t, tr, "/ws", ""))
		}
		_, err = hc.Get("http://ignored.invalid/x")
		if e := wantCode(t, err, cloud.CodeThrottled); !e.Retryable {
			t.Fatal("throttled is retryable")
		}
		for _, w := range open {
			w.close()
		}
	}

	s.testCompanionPolicy(t, m, comp)

	// A stop closes open connections within the bound; the transport never starts the machine.
	ws = s.dialWS(t, tr, "/ws", "")
	_, err = a.c.Machines.Stop(s.ctx, m.ID)
	must(t, err)
	s.waitMachine(t, a, m.ID, cloud.MachineStopped)
	ws.waitClosed(t, closeBound)
	_, err = hc.Get("http://ignored.invalid/x")
	if e := wantCode(t, err, cloud.CodeMachineUnavailable); e.Retryable {
		t.Fatal("machine_unavailable of a stopped machine is not retryable")
	}
	if got, _ := a.c.Machines.Get(s.ctx, m.ID); got.State != cloud.MachineStopped {
		t.Fatalf("the transport changed a stopped machine: %s", got.State)
	}
	if ls, err := svc.Machines.ListServices(s.ctx, m.ID); err != nil || ls[0].Readiness.State != "unknown" {
		t.Fatalf("readiness of a stopped machine: %+v %v", ls, err)
	}
	_, err = a.c.Machines.Start(s.ctx, m.ID)
	must(t, err)
	s.waitMachine(t, a, m.ID, cloud.MachineReady)
	s.startEcho(t, a, m.ID)
	if s.env.ServiceTemplate != "" || s.env.RealRecipes {
		s.waitListening(t, svc, m.ID)
	}

	// Revoking the key that minted the ticket closes its connections and refuses the ticket.
	ws = s.dialWS(t, tr, "/ws", "")
	used, err := tr.Ticket(s.ctx)
	must(t, err)
	provisioned(t, s.prov.RevokeKey(s.ctx, a.id, svcKey))
	ws.waitClosed(t, closeBound)
	if raw := s.rawTransport(t, used, http.MethodGet, "/x", nil); raw.StatusCode != 401 {
		t.Fatalf("a revoked key's ticket: %d", raw.StatusCode)
	}

	// Removing the service closes its connections; new requests are service_absent.
	tr2 := a.c.Machines.ServiceTransport(m.ID, "web", nil)
	defer tr2.CloseIdleConnections()
	if s.env.RemoveService != nil {
		ws = s.dialWS(t, tr2, "/ws", "")
		must(t, s.env.RemoveService(m.ID, "web"))
		ws.waitClosed(t, closeBound)
		_, err = (&http.Client{Transport: tr2}).Get("http://ignored.invalid/x")
		wantCode(t, err, cloud.CodeServiceAbsent)
		return
	}
	// Deleting the machine closes its connections.
	ws = s.dialWS(t, tr2, "/ws", "")
	_, err = a.c.Machines.Delete(s.ctx, m.ID)
	must(t, err)
	ws.waitClosed(t, closeBound)
}

// testCompanionPolicy: agent-companion through policy companion — the node's credential, never
// the caller's; one session per (context, caller session), stable across tickets; and
// agent-companion's own API as a consumer meets it (agent-companion 0.14.0, the version
// cloudtest's fake follows): working directories, files, processes, terminals and their
// WebSocket, ownership on (X-User-Id, X-Session-Id), error bodies and status codes.
func (s *suite) testCompanionPolicy(t *testing.T, m *cloud.Machine, comp *cloud.Client) {
	c, err := comp.Machines.Companion(s.ctx, m.ID)
	must(t, err)
	if c.State == "absent" {
		t.Log("the machine's profile does not run agent-companion; policy companion not checked")
		_, err = comp.Machines.CreateCompanionTicket(s.ctx, m.ID, cloud.CompanionTicketCreate{Context: "c1"})
		wantCode(t, err, cloud.CodeServiceAbsent)
		return
	}
	if s.env.RealRecipes && c.State != "ready" {
		// The suite's service template is a consumer recipe without agent-companion; on real
		// nodes the policy is checked against a computer-base machine by the release's live
		// acceptance (see the Azaleva Cloud documentation).
		t.Logf("real nodes: agent-companion %s/%s; policy companion checked by tools/transportcheck", c.State, c.Fallback)
		return
	}
	if c.State != "ready" || c.Fallback != "none" || c.Version == "" || (c.PinnedVersion != "" && c.PinnedVersion != c.Version) {
		t.Fatalf("companion: %+v", c)
	}
	if c.PinnedVersion == "" {
		t.Logf("agent-companion %s: no pinned_version (a template built before it was recorded)", c.Version)
	}
	_, err = comp.Machines.CreateCompanionTicket(s.ctx, m.ID, cloud.CompanionTicketCreate{Context: "bad context!"})
	wantCode(t, err, cloud.CodeInvalidRequest)

	one := comp.Machines.CompanionTransport(m.ID, "user-1", &cloud.ServiceTransportOptions{Actor: "user-1"})
	defer one.CloseIdleConnections()
	again := comp.Machines.CompanionTransport(m.ID, "user-1", nil) // another transport, another ticket
	defer again.CloseIdleConnections()
	other := comp.Machines.CompanionTransport(m.ID, "user-2", nil) // another context
	defer other.CloseIdleConnections()
	chat := func(user, session string) http.Header {
		return http.Header{"X-User-Id": {user}, "X-Session-Id": {session}}
	}
	// do sends one request; the caller's bearer is never the key (the node replaces it).
	do := func(tr *cloud.ServiceTransport, h http.Header, method, path string, body any) (int, []byte) {
		t.Helper()
		var rd io.Reader
		if body != nil {
			b, _ := json.Marshal(body)
			rd = bytes.NewReader(b)
		}
		req, err := http.NewRequestWithContext(s.ctx, method, "http://ignored.invalid"+path, rd)
		must(t, err)
		for k, v := range h {
			req.Header[k] = v
		}
		req.Header.Set("Authorization", "Bearer not-the-key")
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := (&http.Client{Transport: tr}).Do(req)
		must(t, err)
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, b
	}
	decode := func(b []byte, v any) {
		t.Helper()
		if err := json.Unmarshal(b, v); err != nil {
			t.Fatalf("agent-companion answer %q: %v", b, err)
		}
	}
	type cwdAnswer struct {
		CWD  string `json:"cwd"`
		Home string `json:"home"`
		Root *struct {
			Path, Label string
		} `json:"root"`
	}
	getCWD := func(tr *cloud.ServiceTransport, h http.Header) cwdAnswer {
		t.Helper()
		st, b := do(tr, h, http.MethodGet, "/files/cwd", nil)
		if st != 200 {
			t.Fatalf("GET /files/cwd: %d %s", st, b)
		}
		var out cwdAnswer
		decode(b, &out)
		return out
	}
	wantDetail := func(st int, b []byte, status int, detail string) {
		t.Helper()
		var e struct {
			Detail string `json:"detail"`
			Error  string `json:"error"`
		}
		_ = json.Unmarshal(b, &e)
		if st != status || (e.Detail != detail && e.Error != detail) {
			t.Fatalf("got %d %s, want %d %q", st, b, status, detail)
		}
	}

	// Working directories: the home first, then per (context, caller session).
	start := getCWD(one, chat("u-1", "chat-1"))
	if start.Home == "" || start.CWD == "" || start.Root == nil || start.Root.Path == "" {
		t.Fatalf("GET /files/cwd: %+v", start)
	}
	home := start.Home
	dir := home + "/contract-" + fmt.Sprint(time.Now().UnixNano())
	st, b := do(one, nil, http.MethodPost, "/files/mkdir", map[string]string{"path": dir})
	if st != 200 {
		t.Fatalf("POST /files/mkdir: %d %s", st, b)
	}
	st, b = do(one, chat("u-1", "chat-1"), http.MethodPost, "/files/cwd", map[string]string{"path": dir + "/missing"})
	wantDetail(st, b, 404, "Directory not found")
	st, b = do(one, chat("u-1", "chat-1"), http.MethodPost, "/files/cwd", map[string]string{"path": dir})
	var set struct{ CWD string }
	decode(b, &set)
	if st != 200 || set.CWD != dir {
		t.Fatalf("POST /files/cwd: %d %s", st, b)
	}
	if got := getCWD(again, chat("u-1", "chat-1")); got.CWD != dir {
		t.Fatalf("the same context and caller session reached another session: %+v", got)
	}
	if got := getCWD(one, chat("u-1", "chat-2")); got.CWD == dir {
		t.Fatalf("two caller sessions of one context share a session: %+v", got)
	}
	if got := getCWD(other, chat("u-1", "chat-1")); got.CWD == dir {
		t.Fatalf("two contexts share a session: %+v", got)
	}
	// Files: relative paths are the session's working directory's.
	st, b = do(one, chat("u-1", "chat-1"), http.MethodPost, "/files/write", map[string]string{"path": "hello.txt", "content": "hello\nworld\n"})
	var wr struct {
		Path string
		Size int
	}
	decode(b, &wr)
	if st != 200 || wr.Path != dir+"/hello.txt" || wr.Size != 12 {
		t.Fatalf("POST /files/write: %d %s", st, b)
	}
	st, b = do(one, chat("u-1", "chat-1"), http.MethodGet, "/files/read?path=hello.txt&start_line=2", nil)
	var rd struct {
		Path       string
		TotalLines int `json:"total_lines"`
		Content    string
	}
	decode(b, &rd)
	if st != 200 || rd.Path != dir+"/hello.txt" || rd.TotalLines != 2 || rd.Content != "world\n" {
		t.Fatalf("GET /files/read: %d %s", st, b)
	}
	st, b = do(one, nil, http.MethodGet, "/files/read?path="+url.QueryEscape(dir+"/nope.txt"), nil)
	wantDetail(st, b, 404, "File not found")
	st, b = do(one, nil, http.MethodGet, "/files/read", nil)
	if st != 422 || !strings.Contains(string(b), `"missing"`) {
		t.Fatalf("GET /files/read without path: %d %s", st, b)
	}
	st, b = do(one, nil, http.MethodGet, "/files/list?directory="+url.QueryEscape(dir), nil)
	var ls struct {
		Dir     string
		Entries []struct{ Name, Type string }
	}
	decode(b, &ls)
	if st != 200 || ls.Dir != dir || len(ls.Entries) != 1 || ls.Entries[0].Name != "hello.txt" || ls.Entries[0].Type != "file" {
		t.Fatalf("GET /files/list: %d %s", st, b)
	}
	st, b = do(one, nil, http.MethodGet, "/files/view?path="+url.QueryEscape(dir+"/hello.txt"), nil)
	if st != 200 || string(b) != "hello\nworld\n" {
		t.Fatalf("GET /files/view: %d %q", st, b)
	}
	st, b = do(one, nil, http.MethodGet, "/files/grep?query=wor&path="+url.QueryEscape(dir), nil)
	var gr struct {
		Matches []struct {
			File    string
			Line    int
			Content string
		}
	}
	decode(b, &gr)
	if st != 200 || len(gr.Matches) != 1 || gr.Matches[0].Line != 2 || gr.Matches[0].Content != "world" {
		t.Fatalf("GET /files/grep: %d %s", st, b)
	}
	st, b = do(one, nil, http.MethodGet, "/no-such-route", nil)
	wantDetail(st, b, 404, "Not Found")
	st, b = do(one, nil, http.MethodGet, "/notebooks/x", nil) // off in Azaleva Cloud's machines
	wantDetail(st, b, 404, "Not Found")

	// Processes: owned by (X-User-Id, X-Session-Id); output comes from a PTY.
	type procAnswer struct {
		ID       string
		Status   string
		ExitCode *int `json:"exit_code"`
		Output   []struct{ Type, Data string }
	}
	output := func(p procAnswer) string {
		var o strings.Builder
		for _, e := range p.Output {
			o.WriteString(e.Data)
		}
		return o.String()
	}
	st, b = do(one, chat("u-1", "chat-1"), http.MethodPost, "/execute?wait=10", map[string]string{"command": "echo contract-$((6*7)) && pwd"})
	var pr procAnswer
	decode(b, &pr)
	if st != 200 || pr.Status != "done" || pr.ExitCode == nil || *pr.ExitCode != 0 || !strings.Contains(output(pr), "contract-42\r\n"+dir+"\r\n") {
		t.Fatalf("POST /execute: %d %s", st, b)
	}
	st, _ = do(one, chat("u-1", "chat-1"), http.MethodGet, "/execute/"+pr.ID+"/status", nil)
	st2, b2 := do(one, chat("u-2", "chat-1"), http.MethodGet, "/execute/"+pr.ID+"/status", nil)
	if st != 200 {
		t.Fatalf("GET /execute/{id}/status: %d", st)
	}
	wantDetail(st2, b2, 404, "Process not found")
	st, b = do(one, chat("u-1", "chat-1"), http.MethodPost, "/execute", map[string]string{"command": "read x; echo got-$x"})
	decode(b, &pr)
	if st != 200 || pr.ID == "" {
		t.Fatalf("POST /execute: %d %s", st, b)
	}
	st, b = do(one, chat("u-1", "chat-1"), http.MethodPost, "/execute/"+pr.ID+"/input", map[string]string{"input": "abc\n"})
	if st != 200 || !strings.Contains(string(b), `"ok"`) {
		t.Fatalf("POST /execute/{id}/input: %d %s", st, b)
	}
	_, b = do(one, chat("u-1", "chat-1"), http.MethodGet, "/execute/"+pr.ID+"/status?wait=10", nil)
	decode(b, &pr)
	if pr.Status != "done" || pr.ExitCode == nil || *pr.ExitCode != 0 || !strings.Contains(output(pr), "got-abc") {
		t.Fatalf("process input: %s", b)
	}
	_, b = do(one, chat("u-1", "chat-1"), http.MethodPost, "/execute", map[string]string{"command": "sleep 30"})
	decode(b, &pr)
	st, b = do(one, chat("u-1", "chat-1"), http.MethodDelete, "/execute/"+pr.ID, nil)
	if st != 200 || !strings.Contains(string(b), `"killed"`) {
		t.Fatalf("DELETE /execute/{id}: %d %s", st, b)
	}
	_, b = do(one, chat("u-1", "chat-1"), http.MethodGet, "/execute/"+pr.ID+"/status", nil)
	decode(b, &pr)
	if pr.Status != "killed" || pr.ExitCode == nil || *pr.ExitCode == 0 {
		t.Fatalf("a killed process: %s", b)
	}

	// Terminals: owned by (X-User-Id, X-Session-Id) of their context.
	chat1 := chat("u-1", "chat-1")
	newTerm := func() string {
		t.Helper()
		st, b := do(one, chat1, http.MethodPost, "/api/terminals", nil)
		var term struct {
			ID        string
			CreatedAt string `json:"created_at"`
			PID       int
		}
		decode(b, &term)
		if st != 200 || term.ID == "" || term.CreatedAt == "" || term.PID <= 0 {
			t.Fatalf("POST /api/terminals: %d %s", st, b)
		}
		return term.ID
	}
	tid := newTerm()
	getTerm := func(tr *cloud.ServiceTransport, h http.Header) (int, []byte) {
		t.Helper()
		return do(tr, h, http.MethodGet, "/api/terminals/"+tid, nil)
	}
	if st, _ := getTerm(one, chat1); st != 200 {
		t.Fatalf("GET /api/terminals/{id}: %d", st)
	}
	st, b = getTerm(one, chat("u-1", "chat-2"))
	wantDetail(st, b, 404, "Session not found")
	if st, _ := getTerm(one, chat("u-2", "chat-1")); st != 404 { // X-User-Id reaches agent-companion unchanged
		t.Fatalf("a terminal is visible to another X-User-Id: %d", st)
	}
	if st, _ := getTerm(other, chat1); st != 404 {
		t.Fatalf("a terminal is visible to another context: %d", st)
	}
	st, b = do(one, chat1, http.MethodGet, "/api/terminals", nil)
	if st != 200 || !strings.Contains(string(b), `"`+tid+`"`) {
		t.Fatalf("GET /api/terminals: %d %s", st, b)
	}
	// Terminal WebSocket: the first message authenticates (the transport replaces its token
	// with the key); close codes 4004 (unknown or foreign terminal) and 4009 (already
	// connected); input in binary frames, output in binary frames.
	auth := []byte(`{"type":"auth","token":"anything"}`)
	closeCode := func(ws *wsConn) int {
		t.Helper()
		defer ws.rwc.Close()
		for {
			op, p, err := ws.read()
			if err != nil {
				t.Fatalf("the WebSocket ended without a close frame: %v", err)
			}
			if op == 0x8 {
				if len(p) < 2 {
					return 0
				}
				return int(binary.BigEndian.Uint16(p))
			}
		}
	}
	foreign := s.dialWS(t, one, "/api/terminals/"+tid, "", chat("u-1", "chat-2"))
	must(t, foreign.write(0x1, auth))
	if code := closeCode(foreign); code != 4004 {
		t.Fatalf("a foreign terminal's WebSocket closed %d", code)
	}
	unknown := s.dialWS(t, one, "/api/terminals/does-not-exist", "", chat1)
	must(t, unknown.write(0x1, auth))
	if code := closeCode(unknown); code != 4004 {
		t.Fatalf("an unknown terminal's WebSocket closed %d", code)
	}
	ws := s.dialWS(t, one, "/api/terminals/"+tid, "", chat1)
	must(t, ws.write(0x1, auth))
	must(t, ws.write(0x1, []byte(`{"type":"resize","rows":30,"cols":100}`)))
	must(t, ws.write(0x2, []byte("echo contract-$((40+2))\r")))
	var seen strings.Builder
	for !strings.Contains(seen.String(), "contract-42\r\n") {
		if d, ok := ws.rwc.(interface{ SetReadDeadline(time.Time) error }); ok {
			_ = d.SetReadDeadline(time.Now().Add(15 * time.Second))
		}
		op, p, err := ws.read()
		if err != nil || op != 0x2 {
			t.Fatalf("terminal output: op %x %v after %q", op, err, seen.String())
		}
		seen.Write(p)
	}
	if d, ok := ws.rwc.(interface{ SetReadDeadline(time.Time) error }); ok {
		_ = d.SetReadDeadline(time.Time{})
	}
	second := s.dialWS(t, one, "/api/terminals/"+tid, "", chat1)
	must(t, second.write(0x1, auth))
	if code := closeCode(second); code != 4009 {
		t.Fatalf("a second WebSocket of a terminal closed %d", code)
	}
	ws.close() // the terminal ends with its WebSocket
	deadline := time.Now().Add(5 * time.Second)
	for {
		if st, _ := getTerm(one, chat1); st == 404 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the terminal outlived its WebSocket")
		}
		time.Sleep(50 * time.Millisecond)
	}
	// A first message that is not an auth message closes the connection before agent-companion.
	tid2 := newTerm()
	bad := s.dialWS(t, one, "/api/terminals/"+tid2, "", chat1)
	must(t, bad.write(0x1, []byte("not an auth message")))
	if op, _, err := bad.read(); err == nil && op != 0x8 {
		t.Fatalf("a WebSocket without an auth message stayed open (op %x)", op)
	}
	bad.rwc.Close()
	st, b = do(one, chat1, http.MethodDelete, "/api/terminals/"+tid2, nil)
	if st != 200 || !strings.Contains(string(b), `"deleted"`) {
		t.Fatalf("DELETE /api/terminals/{id}: %d %s", st, b)
	}
	if c, err := comp.Machines.Companion(s.ctx, m.ID); err != nil || c.Activity == nil {
		t.Fatalf("companion activity: %+v %v", c, err)
	}
	do(one, nil, http.MethodDelete, "/files/delete?path="+url.QueryEscape(dir), nil)
}

// testServiceTransportAbsent: an installation without the transport still has its operations,
// with scope and ownership checked first.
func (s *suite) testServiceTransportAbsent(t *testing.T) {
	a, b := s.a, s.b
	m := s.machine(t, a, a.project.ID, nil)
	defer a.c.Machines.Delete(s.ctx, m.ID)
	_, err := b.c.Machines.ListServices(s.ctx, m.ID)
	wantCode(t, err, cloud.CodeNotFound)
	_, err = s.keyWith(t, a, "", cloud.ScopeMachines).Machines.ListServices(s.ctx, m.ID)
	wantCode(t, err, cloud.CodeScopeMissing)
	_, err = a.c.Machines.ListServices(s.ctx, m.ID)
	wantCode(t, err, cloud.CodeNotImplemented)
	_, err = a.c.Machines.CreateServiceTicket(s.ctx, m.ID, "web", cloud.ServiceTicketCreate{})
	wantCode(t, err, cloud.CodeNotImplemented)
	_, err = a.c.Machines.Companion(s.ctx, m.ID)
	wantCode(t, err, cloud.CodeNotImplemented)
	_, err = a.c.Machines.CreateCompanionTicket(s.ctx, m.ID, cloud.CompanionTicketCreate{Context: "c1"})
	wantCode(t, err, cloud.CodeNotImplemented)
}

// rawTransport sends one request to the transport endpoint without the SDK's checks.
func (s *suite) rawTransport(t *testing.T, tk *cloud.ServiceTicket, method, path string, h http.Header) *http.Response {
	t.Helper()
	req, err := http.NewRequestWithContext(s.ctx, method, tk.TransportURL+path, nil)
	must(t, err)
	for k, v := range h {
		req.Header[k] = v
	}
	req.Header.Set(cloud.HeaderTicket, tk.Ticket)
	resp, err := http.DefaultTransport.RoundTrip(req)
	must(t, err)
	resp.Body.Close()
	return resp
}

// rawAbsoluteForm sends an absolute-form request target over plain TCP and returns the status line.
func rawAbsoluteForm(t *testing.T, host, ticket string) string {
	t.Helper()
	c, err := net.DialTimeout("tcp", host, 5*time.Second)
	must(t, err)
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	_, err = io.WriteString(c, "GET http://169.254.169.254/latest HTTP/1.1\r\nHost: 169.254.169.254\r\n"+cloud.HeaderTicket+": "+ticket+"\r\nConnection: close\r\n\r\n")
	must(t, err)
	line, _ := bufio.NewReader(c).ReadString('\n')
	return line
}

// ---- a minimal WebSocket client (RFC 6455) over ServiceTransport.Upgrade ----

type wsConn struct {
	rwc      io.ReadWriteCloser
	br       *bufio.Reader
	protocol string
}

func (s *suite) dialWS(t *testing.T, tr *cloud.ServiceTransport, path, protocols string, extra ...http.Header) *wsConn {
	t.Helper()
	k := make([]byte, 16)
	_, _ = rand.Read(k)
	key := base64.StdEncoding.EncodeToString(k)
	req, err := http.NewRequestWithContext(s.ctx, http.MethodGet, "http://ignored.invalid"+path, nil)
	must(t, err)
	for _, h := range extra {
		for k, v := range h {
			req.Header[k] = v
		}
	}
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Sec-WebSocket-Version", "13")
	req.Header.Set("Sec-WebSocket-Key", key)
	if protocols != "" {
		req.Header.Set("Sec-WebSocket-Protocol", protocols)
	}
	resp, rwc, err := tr.Upgrade(req)
	must(t, err)
	if rwc == nil {
		resp.Body.Close()
		t.Fatalf("upgrade: %d", resp.StatusCode)
	}
	sum := sha1.Sum([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	if resp.Header.Get("Sec-WebSocket-Accept") != base64.StdEncoding.EncodeToString(sum[:]) {
		t.Fatalf("Sec-WebSocket-Accept %q", resp.Header.Get("Sec-WebSocket-Accept"))
	}
	return &wsConn{rwc: rwc, br: bufio.NewReader(rwc), protocol: resp.Header.Get("Sec-WebSocket-Protocol")}
}

func (w *wsConn) write(op byte, payload []byte) error {
	b := []byte{0x80 | op}
	switch n := len(payload); {
	case n < 126:
		b = append(b, 0x80|byte(n))
	case n <= 0xffff:
		b = append(b, 0x80|126, byte(n>>8), byte(n))
	default:
		b = append(b, 0x80|127)
		b = binary.BigEndian.AppendUint64(b, uint64(n))
	}
	mask := make([]byte, 4)
	_, _ = rand.Read(mask)
	b = append(b, mask...)
	for i, c := range payload {
		b = append(b, c^mask[i%4])
	}
	_, err := w.rwc.Write(b)
	return err
}

func (w *wsConn) read() (op byte, payload []byte, err error) {
	var h [2]byte
	if _, err = io.ReadFull(w.br, h[:]); err != nil {
		return
	}
	op, n := h[0]&0x0f, uint64(h[1]&0x7f)
	if h[1]&0x80 != 0 {
		return 0, nil, errors.New("a server frame is masked")
	}
	switch n {
	case 126:
		var x [2]byte
		if _, err = io.ReadFull(w.br, x[:]); err != nil {
			return
		}
		n = uint64(binary.BigEndian.Uint16(x[:]))
	case 127:
		var x [8]byte
		if _, err = io.ReadFull(w.br, x[:]); err != nil {
			return
		}
		n = binary.BigEndian.Uint64(x[:])
	}
	payload = make([]byte, n)
	_, err = io.ReadFull(w.br, payload)
	return
}

// roundTrip sends a frame and expects its echo (a pong for a ping).
func (w *wsConn) roundTrip(t *testing.T, op byte, payload []byte) {
	t.Helper()
	must(t, w.write(op, payload))
	want := op
	if op == 0x9 {
		want = 0xA
	}
	gotOp, got, err := w.read()
	must(t, err)
	if gotOp != want || !bytes.Equal(got, payload) {
		t.Fatalf("websocket echo: op %x %q, want op %x %q", gotOp, got, want, payload)
	}
}

func (w *wsConn) close() {
	_ = w.write(0x8, []byte{0x03, 0xe8})
	w.rwc.Close()
}

// waitClosed fails unless the server ends the connection within d.
func (w *wsConn) waitClosed(t *testing.T, d time.Duration) {
	t.Helper()
	done := make(chan error, 1)
	go func() {
		for {
			if _, _, err := w.read(); err != nil {
				done <- err
				return
			}
		}
	}()
	select {
	case <-done:
		w.rwc.Close()
	case <-time.After(d):
		w.rwc.Close()
		t.Fatalf("the connection stayed open longer than %s", d)
	}
}

// startEcho starts the echo service in a machine of Env.ServiceTemplate (whose template declares
// web:8080 but does not run it): echo.py written with the files API, run in the background by an
// exec as the agent user. Nothing to do otherwise (the template's machines serve it).
func (s *suite) startEcho(t *testing.T, tn *tenant, machine string) {
	t.Helper()
	if s.env.ServiceTemplate == "" {
		return
	}
	_, err := tn.c.Machines.WriteFile(s.ctx, machine, "/tmp/svc-echo.py", echoPy, cloud.FileOptions{Mode: "0644"})
	must(t, err)
	ex, err := tn.c.Machines.Exec(s.ctx, machine, cloud.ExecRequest{Shell: "nohup python3 /tmp/svc-echo.py 8080 >/dev/null 2>&1 &"})
	must(t, err)
	_ = ex
}

// waitListening waits until the machine's service web listens (a minute at most).
func (s *suite) waitListening(t *testing.T, c *cloud.Client, machine string) {
	t.Helper()
	for end := time.Now().Add(time.Minute); ; {
		ls, err := c.Machines.ListServices(s.ctx, machine)
		if err == nil && len(ls) == 1 && ls[0].Readiness.State == "listening" {
			return
		}
		if time.Now().After(end) {
			t.Fatalf("service web never listening: %+v %v", ls, err)
		}
		time.Sleep(time.Second)
	}
}
