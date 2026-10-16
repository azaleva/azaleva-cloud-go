package cloud

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func problem(w http.ResponseWriter, status int, code Code, retryable bool) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(Error{Type: ProblemType(code), Title: string(code), Status: status, Code: code, Retryable: retryable})
}

func TestRetryReusesIdempotencyKey(t *testing.T) {
	var mu sync.Mutex
	var keys []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		keys = append(keys, r.Header.Get("Idempotency-Key"))
		n := len(keys)
		mu.Unlock()
		if n < 3 {
			problem(w, 503, CodeUnavailable, true)
			return
		}
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"id":"job_1","state":"placing"}`))
	}))
	defer srv.Close()
	c, err := New(srv.URL, "ack_x_y", WithRetry(RetryPolicy{MaxAttempts: 4, BaseDelay: time.Millisecond, MaxDelay: 5 * time.Millisecond}))
	if err != nil {
		t.Fatal(err)
	}
	var meta ResponseMeta
	j, err := c.Jobs.Create(context.Background(), JobCreate{Project: "p", Template: "t", Profile: "x", Exec: JobExec{Argv: []string{"true"}}}, WithResponse(&meta))
	if err != nil {
		t.Fatal(err)
	}
	if j.ID != "job_1" || meta.StatusCode != 202 {
		t.Fatalf("got %+v %+v", j, meta)
	}
	if len(keys) != 3 || keys[0] == "" || keys[0] != keys[1] || keys[1] != keys[2] {
		t.Fatalf("idempotency keys across retries: %q", keys)
	}
}

func TestNonRetryableIsNotRetried(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		problem(w, 404, CodeNotFound, false)
	}))
	defer srv.Close()
	c, _ := New(srv.URL+"/v1", "ack_x_y")
	_, err := c.Machines.Get(context.Background(), "mch_1")
	if !IsCode(err, CodeNotFound) || calls != 1 {
		t.Fatalf("err=%v calls=%d", err, calls)
	}
}

func TestNonProblemErrorsAreClassified(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "bad gateway", http.StatusBadGateway)
	}))
	defer srv.Close()
	c, _ := New(srv.URL, "", WithRetry(RetryPolicy{MaxAttempts: 1}))
	_, err := c.Consumer(context.Background())
	e, ok := AsError(err)
	if !ok || e.Code != CodeUnavailable || !e.Retryable {
		t.Fatalf("got %v", err)
	}
}

func TestIfMatchHeader(t *testing.T) {
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("If-Match")
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()
	c, _ := New(srv.URL, "t")
	if _, err := c.Machines.Update(context.Background(), "mch_1", MachineUpdate{Hold: Bool(true)}, IfMatch(7)); err != nil {
		t.Fatal(err)
	}
	if got != `"7"` {
		t.Fatalf("If-Match = %q", got)
	}
}

func TestSignatures(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	body := []byte(`{"id":"evt_1"}`)
	h := SignPayload(now, body, "new", "old")
	for _, secret := range []string{"new", "old"} {
		if err := VerifyPayload(h, body, now, time.Minute, secret); err != nil {
			t.Fatalf("%s: %v", secret, err)
		}
	}
	if VerifyPayload(h, body, now, time.Minute, "other") == nil {
		t.Fatal("wrong secret accepted")
	}
	if VerifyPayload(h, append(body, ' '), now, time.Minute, "new") == nil {
		t.Fatal("tampered body accepted")
	}
	if VerifyPayload(h, body, now.Add(10*time.Minute), 5*time.Minute, "new") == nil {
		t.Fatal("stale signature accepted")
	}
	if VerifyPayload("garbage", body, now, time.Minute, "new") == nil {
		t.Fatal("garbage accepted")
	}

	req := httptest.NewRequest(http.MethodPost, "/run/v1/tool?x=1", nil)
	gbody := []byte("payload")
	req.Header.Set(HeaderSandbox, "sbx_1")
	req.Header.Set(HeaderProject, "prj_1")
	sig := SignGateway(now, GatewayPayload("POST", "/run/v1/tool", "x=1", "sbx_1", gbody), "cb")
	req.Header.Set(HeaderSignature, sig)
	id, err := VerifyGatewayRequest(req, gbody, now, "cb")
	if err != nil || id.Sandbox != "sbx_1" {
		t.Fatalf("gateway verify: %v %+v", err, id)
	}
	// The query is signed: a changed, added or removed query is refused.
	for _, target := range []string{"/run/v1/tool?x=2", "/run/v1/tool?x=1&admin=1", "/run/v1/tool", "/run/v1/tool/?x=1"} {
		tr := httptest.NewRequest(http.MethodPost, target, nil)
		tr.Header = req.Header.Clone()
		if _, err := VerifyGatewayRequest(tr, gbody, now, "cb"); !errors.Is(err, ErrBadSignature) {
			t.Fatalf("%s: tampered request accepted: %v", target, err)
		}
	}
	// The schemes do not mix: a v1 (webhook) signature over the same payload is not a gateway
	// signature, and a v1-only verifier refuses a v2 header.
	req.Header.Set(HeaderSignature, SignPayload(now, GatewayPayload("POST", "/run/v1/tool", "x=1", "sbx_1", gbody), "cb"))
	if _, err := VerifyGatewayRequest(req, gbody, now, "cb"); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("a v1 signature was accepted as a gateway signature: %v", err)
	}
	if err := VerifyPayload(sig, GatewayPayload("POST", "/run/v1/tool", "x=1", "sbx_1", gbody), now, time.Minute, "cb"); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("a v1 verifier accepted a v2 signature: %v", err)
	}
	req.Header.Set(HeaderSignature, sig)
	req.Header.Set(HeaderSandbox, "sbx_2") // another sandbox claims the same signature
	if _, err := VerifyGatewayRequest(req, gbody, now, "cb"); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("forged sandbox accepted: %v", err)
	}
}

func TestTemplatePackageRoundTrip(t *testing.T) {
	m := TemplateManifest{Name: "runner", Kind: KindMachine, Recipe: "recipe.py", SDK: "e2b==2.52.0",
		Services: []ServiceDeclaration{{Name: "web", Port: 8080, Protocol: "http"}}}
	files := map[string][]byte{"recipe.py": []byte("print('build')\n"), "ctx/app.txt": []byte("x")}
	a, err := BuildTemplatePackage(m, files)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := BuildTemplatePackage(m, files)
	if !bytes.Equal(a, b) {
		t.Fatal("package is not deterministic")
	}
	got, gotFiles, err := ReadTemplatePackage(a)
	if err != nil || !reflect.DeepEqual(*got, m) || string(gotFiles["ctx/app.txt"]) != "x" {
		t.Fatalf("read back: %v %+v", err, got)
	}
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	sig := SignTemplatePackage(priv, a)
	if sig.KeyID != KeyID(pub) || VerifyTemplatePackage(pub, a, sig.Signature) != nil {
		t.Fatal("signature does not verify")
	}
	if VerifyTemplatePackage(pub, append(a, 0), sig.Signature) == nil {
		t.Fatal("tampered package verified")
	}
	if _, err := BuildTemplatePackage(TemplateManifest{Name: "Bad Name", Kind: KindJob, Recipe: "r", SDK: "x"}, map[string][]byte{"r": nil}); err == nil {
		t.Fatal("invalid name accepted")
	}
	if !TemplateNameAllowed([]string{"runner-*"}, "runner-v2") || TemplateNameAllowed([]string{"runner"}, "runner-v2") {
		t.Fatal("name patterns")
	}
	for ref, want := range map[string]string{"tpl_a@3": "a 3", "a@1": "a 1", "a": "a 0"} {
		n, v, err := ParseTemplateRef(ref)
		if err != nil || n+" "+itoa(v) != want {
			t.Fatalf("%s: %s %d %v", ref, n, v, err)
		}
	}
}

func TestOutputReaderResumes(t *testing.T) {
	data := "line 1\nline 2\nline 3\n"
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		var after int
		_, _ = io.WriteString(io.Discard, r.URL.Query().Get("after"))
		_ = json.Unmarshal([]byte(r.URL.Query().Get("after")), &after)
		rest := data[after:]
		switch calls {
		case 1: // first response: a few bytes, then the server ends it (as a follow timeout would)
			w.Header().Set("Cloud-Output-Complete", "false")
			_, _ = io.WriteString(w, rest[:4])
		default:
			w.Header().Set("Cloud-Output-Complete", "true")
			_, _ = io.WriteString(w, rest)
		}
	}))
	defer srv.Close()
	c, _ := New(srv.URL, "t")
	r, _ := c.Jobs.Output(context.Background(), "job_1", OutputOptions{})
	b, err := io.ReadAll(r)
	if err != nil || string(b) != data || r.Offset() != int64(len(data)) {
		t.Fatalf("got %q off=%d err=%v", b, r.Offset(), err)
	}
	if !strings.Contains(srv.URL, "127.0.0.1") || calls != 2 {
		t.Fatalf("calls=%d", calls)
	}
}

// An answer that is not a problem document is classified by its status, with an empty Type.
func TestNonProblemAnswersAreClassifiedByStatus(t *testing.T) {
	cases := []struct {
		status    int
		code      Code
		retryable bool
	}{
		{400, CodeInvalidRequest, false}, {401, CodeUnauthenticated, false}, {403, CodeForbidden, false},
		{404, CodeNotFound, false}, {408, CodeUnavailable, true}, {409, CodeConflict, false}, {410, CodeGone, false},
		{412, CodePreconditionFailed, false}, {413, CodeInvalidRequest, false}, {429, CodeRateLimited, true},
		{500, CodeInternal, true}, {502, CodeUnavailable, true}, {503, CodeUnavailable, true}, {504, CodeUnavailable, true},
	}
	for _, tc := range cases {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(tc.status)
			_, _ = w.Write([]byte("<html>proxy</html>"))
		}))
		c, err := New(srv.URL, "ack_x", WithRetry(RetryPolicy{MaxAttempts: 1}))
		if err != nil {
			t.Fatal(err)
		}
		_, err = c.Projects.Get(context.Background(), "prj_1")
		srv.Close()
		e, ok := AsError(err)
		if !ok || e.Code != tc.code || e.Retryable != tc.retryable || e.Status != tc.status || e.Type != "" {
			t.Errorf("status %d: got %+v (%v), want code %s retryable %v and an empty Type", tc.status, e, err, tc.code, tc.retryable)
		}
	}
}

// New uses a client of its own with a bound on response headers; WithHTTPClient replaces it, and
// a service transport over the default client does not inherit the bound.
func TestDefaultHTTPClient(t *testing.T) {
	c, err := New("https://cloud.example", "")
	if err != nil {
		t.Fatal(err)
	}
	if c.hc == http.DefaultClient || c.hc.Timeout != 0 {
		t.Fatalf("default client %+v: want an own client without an overall timeout", c.hc)
	}
	tr, ok := c.hc.Transport.(*http.Transport)
	if !ok || tr.ResponseHeaderTimeout != DefaultResponseHeaderTimeout || tr == http.DefaultTransport {
		t.Fatalf("default transport %+v", c.hc.Transport)
	}
	if st := c.Machines.CompanionTransport("mch_1", "ctx", nil); st.base.(*http.Transport).ResponseHeaderTimeout != 0 {
		t.Fatal("the service transport inherited the API's header timeout")
	}
	if cp := c.WithToken("x"); cp.hc != c.hc || !cp.defaultHC {
		t.Fatal("WithToken lost the default client")
	}
	mine := &http.Client{Transport: &http.Transport{ResponseHeaderTimeout: time.Second}}
	c2, _ := New("https://cloud.example", "", WithHTTPClient(mine))
	if c2.hc != mine {
		t.Fatal("WithHTTPClient did not replace the default client")
	}
	if st := c2.Machines.CompanionTransport("mch_1", "ctx", nil); st.base.(*http.Transport).ResponseHeaderTimeout != time.Second {
		t.Fatal("the service transport did not clone the caller's transport")
	}
}

// A slow server fails the call at the header timeout instead of hanging it.
func TestResponseHeaderTimeout(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-release }))
	defer srv.Close()
	defer close(release)
	c, _ := New(srv.URL, "", WithRetry(RetryPolicy{MaxAttempts: 1}))
	c.hc.Transport.(*http.Transport).ResponseHeaderTimeout = 100 * time.Millisecond
	start := time.Now()
	if _, err := c.Projects.Get(context.Background(), "prj_1"); err == nil || time.Since(start) > 10*time.Second {
		t.Fatalf("err %v after %s", err, time.Since(start))
	}
}

// WaitState ends when the machine is destroyed or in error (unless that is what it waits for).
func TestWaitStateEndsOnDestroyedOrError(t *testing.T) {
	for _, final := range []string{MachineDestroyed, MachineError} {
		var n int
		var mu sync.Mutex
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			n++
			st := MachineStarting
			if n > 1 {
				st = final
			}
			mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"id": "mch_1", "state": st, "state_reason": "node_unavailable"})
		}))
		c, _ := New(srv.URL, "ack_x")
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		m, err := c.Machines.WaitState(ctx, "mch_1", MachineReady)
		if !errors.Is(err, ErrMachineState) || m == nil || m.State != final || !strings.Contains(err.Error(), "node_unavailable") {
			t.Errorf("%s: machine %+v, err %v", final, m, err)
		}
		// Waiting for that state itself returns it.
		if m, err := c.Machines.WaitState(ctx, "mch_1", final); err != nil || m.State != final {
			t.Errorf("waiting for %s: %+v, %v", final, m, err)
		}
		cancel()
		srv.Close()
	}
}

// Templates.Pin, Unpin, Restore and Delete with WithPurge send the documented requests.
func TestTemplatePinRestorePurgeRequests(t *testing.T) {
	var got []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = append(got, r.Method+" "+r.URL.RequestURI())
		if r.Method == http.MethodDelete && r.URL.Path == "/v1/templates/tool@3" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.URL.Path == "/v1/templates/tool@4/restore" {
			problem(w, 410, CodeGone, false)
			return
		}
		pinned := r.Method == http.MethodPut
		_, _ = w.Write([]byte(`{"id":"tpl_tool@3","name":"tool","version":3,"kind":"job","origin":"consumer","state":"ready","builds":[],` +
			`"created_at":"2026-10-16T00:00:00Z","pinned":` + strconv.FormatBool(pinned) +
			map[bool]string{true: `,"pinned_at":"2026-10-16T01:00:00Z"}`, false: `}`}[pinned]))
	}))
	defer srv.Close()
	c, _ := New(srv.URL+"/v1", "ack_x_y")
	ctx := context.Background()
	p, err := c.Templates.Pin(ctx, "tool@3")
	if err != nil || !p.Pinned || p.PinnedAt == nil {
		t.Fatalf("pin: %+v %v", p, err)
	}
	u, err := c.Templates.Unpin(ctx, "tool@3")
	if err != nil || u.Pinned || u.PinnedAt != nil {
		t.Fatalf("unpin: %+v %v", u, err)
	}
	if r, err := c.Templates.Restore(ctx, "tool@3"); err != nil || r.Version != 3 {
		t.Fatalf("restore: %+v %v", r, err)
	}
	if _, err := c.Templates.Restore(ctx, "tool@4"); !IsCode(err, CodeGone) {
		t.Fatalf("restore after the grace period: %v", err)
	}
	if err := c.Templates.Delete(ctx, "tool@3"); err != nil {
		t.Fatal(err)
	}
	if err := c.Templates.Delete(ctx, "tool@3", WithPurge()); err != nil {
		t.Fatal(err)
	}
	want := []string{"PUT /v1/templates/tool@3/pin", "DELETE /v1/templates/tool@3/pin", "POST /v1/templates/tool@3/restore",
		"POST /v1/templates/tool@4/restore", "DELETE /v1/templates/tool@3", "DELETE /v1/templates/tool@3?purge=true"}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("requests:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}
