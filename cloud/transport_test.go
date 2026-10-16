package cloud

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestCheckServiceRequest(t *testing.T) {
	ok := []struct{ m, p, q string }{
		{"GET", "/", ""}, {"POST", "/a/b", "x=1&y=%0A"}, {"GET", "/a%2Fb//c", ""}, {"PATCH", "/.well-known/x", ""}, {"GET", "/a..b/...", ""},
	}
	for _, c := range ok {
		if err := CheckServiceRequest(c.m, c.p, c.q); err != nil {
			t.Errorf("%s %s?%s refused: %v", c.m, c.p, c.q, err)
		}
	}
	bad := []struct{ m, p, q, code string }{
		{"GET", "http://x/", "", "invalid"}, {"GET", "", "", "invalid"}, {"CONNECT", "/", "", "not_allowed"}, {"TRACE", "/", "", "not_allowed"},
		{"GET", "/a/../b", "", "traversal"}, {"GET", "/..", "", "traversal"}, {"GET", "/a/%2E%2e", "", "traversal"}, {"GET", "/a/./b", "", "traversal"},
		{"GET", "/a/%2e/b", "", "traversal"}, {"GET", `/a\b`, "", "invalid"}, {"GET", "/a%5Cb", "", "invalid"}, {"GET", "/a%00", "", "invalid"},
		{"GET", "/a%1f", "", "invalid"}, {"GET", "/a", "x=\n", "invalid"}, {"GET", "/" + strings.Repeat("a", 9000), "", "too_long"},
	}
	for _, c := range bad {
		err := CheckServiceRequest(c.m, c.p, c.q)
		e, ok := AsError(err)
		if !ok || e.Code != CodeInvalidRequest || e.Errors[0].Code != c.code {
			t.Errorf("%s %q?%q: %v, want %s", c.m, c.p, c.q, err, c.code)
		}
	}
}

func TestValidateServiceDeclarations(t *testing.T) {
	if errs := ValidateServiceDeclarations([]ServiceDeclaration{{Name: "web", Port: 9119, Protocol: "http"}, {Name: "gw", Port: 18789, Protocol: "http"}}); len(errs) > 0 {
		t.Fatal(errs)
	}
	for _, c := range []struct {
		svcs []ServiceDeclaration
		code string
	}{
		{[]ServiceDeclaration{{Name: "web", Port: 8000, Protocol: "http"}}, "reserved_port"},
		{[]ServiceDeclaration{{Name: "web", Port: 47801, Protocol: "http"}}, "reserved_port"},
		{[]ServiceDeclaration{{Name: "web", Port: 9090, Protocol: "http"}}, "reserved_port"},
		{[]ServiceDeclaration{{Name: "web", Port: 8642, Protocol: "http"}}, "reserved_port"},
		{[]ServiceDeclaration{{Name: "web", Port: 22, Protocol: "http"}}, "invalid"},
		{[]ServiceDeclaration{{Name: "companion", Port: 9000, Protocol: "http"}}, "invalid"},
		{[]ServiceDeclaration{{Name: "Web", Port: 9000, Protocol: "http"}}, "invalid"},
		{[]ServiceDeclaration{{Name: "web", Port: 9000, Protocol: "tcp"}}, "invalid"},
		{[]ServiceDeclaration{{Name: "web", Port: 9000, Protocol: "http"}, {Name: "web", Port: 9001, Protocol: "http"}}, "duplicate"},
		{[]ServiceDeclaration{{Name: "a", Port: 9000, Protocol: "http"}, {Name: "b", Port: 9000, Protocol: "http"}}, "duplicate"},
	} {
		if errs := ValidateServiceDeclarations(c.svcs); len(errs) == 0 || errs[0].Code != c.code {
			t.Errorf("%+v: %+v, want %s", c.svcs, errs, c.code)
		}
	}
}

func TestForwardedValidate(t *testing.T) {
	good := []Forwarded{{}, {Host: "app.example.com", Proto: "https", For: []string{"203.0.113.7", "2001:db8::1"}}, {Host: "[2001:db8::1]:8443"}, {Host: "a.b:443"}}
	for _, f := range good {
		if err := f.Validate(); err != nil {
			t.Errorf("%+v: %v", f, err)
		}
	}
	for _, f := range []Forwarded{{Host: "evil.example/path"}, {Host: "user@host"}, {Host: "a b"}, {Proto: "ftp"}, {For: []string{"not-an-ip"}}} {
		if err := f.Validate(); err == nil {
			t.Errorf("%+v accepted", f)
		}
	}
}

// The transport sends the path and query below the ticket's base URL, the ticket and the
// forwarded origin, no Cloud-* header of the caller and no Idempotency-Key; it mints tickets
// without an Idempotency-Key; it sends again once (only) after ticket_expired; a transport
// answer is an *Error, an application answer a response.
func TestServiceTransportRoundTrip(t *testing.T) {
	var mints, sends atomic.Int32
	var lastTicket atomic.Value
	lastTicket.Store("")
	var edge *httptest.Server
	edge = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := sends.Add(1)
		if r.Header.Get(HeaderTicket) != lastTicket.Load().(string) {
			t.Errorf("ticket %q, want %q", r.Header.Get(HeaderTicket), lastTicket.Load())
		}
		if r.Header.Get("Idempotency-Key") != "" || r.Header.Get("Cloud-Smuggled") != "" {
			t.Errorf("headers: %v", r.Header)
		}
		switch {
		case r.URL.Path == "/base/expire" && n == 1:
			w.Header().Set(HeaderTransportError, string(CodeTicketExpired))
			w.Header().Set("Content-Type", "application/problem+json")
			w.WriteHeader(401)
			_, _ = w.Write([]byte(`{"type":"urn:agent-cloud:problem:ticket_expired","title":"t","status":401,"code":"ticket_expired","retryable":true}`))
		case r.URL.Path == "/base/down":
			w.Header().Set(HeaderTransportError, string(CodeAppNotListening))
			w.Header().Set("Content-Type", "application/problem+json")
			w.WriteHeader(502)
			_, _ = w.Write([]byte(`{"type":"urn:agent-cloud:problem:app_not_listening","title":"t","status":502,"code":"app_not_listening","retryable":true}`))
		default:
			body, _ := io.ReadAll(r.Body)
			_ = json.NewEncoder(w).Encode(map[string]string{"uri": r.RequestURI, "host": r.Header.Get(HeaderForwardedHost),
				"for": r.Header.Get(HeaderForwardedFor), "body": string(body)})
		}
	}))
	defer edge.Close()
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != "/v1/machines/mch_1/services/web/tickets" || r.Header.Get("Idempotency-Key") != "" {
			t.Errorf("mint: %s %s %v", r.Method, r.URL.Path, r.Header)
		}
		n := mints.Add(1)
		now := time.Now().UTC()
		tk := "ctk_000" + string(rune('0'+n)) + "_secret"
		lastTicket.Store(tk)
		_ = json.NewEncoder(w).Encode(ServiceTicket{ID: "ctk_000", Ticket: tk, Policy: PolicyApp, Machine: "mch_1", Service: "web",
			TransportURL: edge.URL + "/base", CreatedAt: now, ExpiresAt: now.Add(5 * time.Minute)})
	}))
	defer api.Close()
	c, _ := New(api.URL, "ack_x_y")
	tr := c.Machines.ServiceTransport("mch_1", "web", nil)
	hc := &http.Client{Transport: tr}

	req, _ := http.NewRequest("POST", "http://ignored.example/a%2Fb/c?x=1&x=2", strings.NewReader("payload"))
	req.Header.Set("Cloud-Smuggled", "1")
	req.Header.Set("Cloud-Forwarded-Host", "evil.example")
	req = req.WithContext(WithForwarded(req.Context(), Forwarded{Host: "app.example.com", For: []string{"203.0.113.7"}}))
	resp, err := hc.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]string
	_ = json.NewDecoder(resp.Body).Decode(&got)
	resp.Body.Close()
	if got["uri"] != "/base/a%2Fb/c?x=1&x=2" || got["host"] != "app.example.com" || got["for"] != "203.0.113.7" || got["body"] != "payload" {
		t.Fatalf("sent: %v", got)
	}
	if mints.Load() != 1 {
		t.Fatalf("%d mints", mints.Load())
	}
	// ticket_expired: one new ticket, one more send, then success.
	sends.Store(0)
	req, _ = http.NewRequest("PUT", "http://ignored.example/expire", strings.NewReader("again"))
	resp, err = hc.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = json.NewDecoder(resp.Body).Decode(&got)
	resp.Body.Close()
	if sends.Load() != 2 || mints.Load() != 2 || got["body"] != "again" {
		t.Fatalf("after ticket_expired: %d sends, %d mints, %v", sends.Load(), mints.Load(), got)
	}
	// Any other transport answer: an *Error, never retried.
	sends.Store(0)
	_, err = hc.Get("http://ignored.example/down")
	if e, ok := AsError(err); !ok || e.Code != CodeAppNotListening || sends.Load() != 1 {
		t.Fatalf("down: %v, %d sends", err, sends.Load())
	}
	// Refused before sending.
	sends.Store(0)
	if _, err = hc.Get("http://ignored.example/a/../b"); !IsCode(err, CodeInvalidRequest) || sends.Load() != 0 {
		t.Fatalf("traversal: %v", err)
	}
	req, _ = http.NewRequest("GET", "http://ignored.example/x", nil)
	req.Header.Set("Authorization", "Bearer ack_0123456789ab_"+strings.Repeat("ab", 24))
	if _, err = hc.Do(req); !IsCode(err, CodeInvalidRequest) || sends.Load() != 0 {
		t.Fatalf("cloud credential: %v", err)
	}
}

func TestHasCloudCredential(t *testing.T) {
	for _, v := range []string{
		"Bearer ack_0123456789ab_" + strings.Repeat("ab", 24), "Bearer aco_0123456789abcdef_" + strings.Repeat("cd", 16),
		"ctk_0123456789abcdef_" + strings.Repeat("ef", 16), "Basic x, Bearer ack_0123456789ab_0123456789abcdef0123",
	} {
		if !HasCloudCredential(http.Header{"Authorization": {v}}) {
			t.Errorf("not detected: %q", v)
		}
	}
	for _, v := range []string{
		// A JWT and base64url tokens that contain the prefixes as substrings.
		"Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhY2tfMTIzIn0.ack_0123456789ab_0123456789abcdef0123xyz",
		"Bearer Zack_0123456789ab_0123456789abcdef0123", "Bearer abc-ctk_0123456789abcdef_0123456789abcdef-x",
		"Bearer ack_notHex_secret", "Basic YWNrX3VzZXI6cGFzcw==", "Bearer ack_0123_0123456789abcdef",
	} {
		if HasCloudCredential(http.Header{"Authorization": {v}}) {
			t.Errorf("an application token taken for a Cloud credential: %q", v)
		}
	}
}
