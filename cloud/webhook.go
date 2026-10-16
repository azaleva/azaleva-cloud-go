package cloud

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Header names of signed Azaleva Cloud requests.
const (
	HeaderSignature = "Cloud-Signature"
	HeaderEventID   = "Cloud-Event-Id"
	HeaderEventType = "Cloud-Event-Type"
	HeaderSandbox   = "Cloud-Sandbox"
	HeaderJob       = "Cloud-Job"
	HeaderMachine   = "Cloud-Machine"
	HeaderProject   = "Cloud-Project"
	HeaderNode      = "Cloud-Node"
)

// DefaultSignatureTolerance is how old a signature's timestamp may be.
const DefaultSignatureTolerance = 5 * time.Minute

// ErrBadSignature is returned for a missing, malformed, stale or wrong signature.
var ErrBadSignature = errors.New("cloud: bad signature")

func mac(secret string, ts int64, payload []byte) string {
	m := hmac.New(sha256.New, []byte(secret))
	m.Write([]byte(strconv.FormatInt(ts, 10)))
	m.Write([]byte("."))
	m.Write(payload)
	return hex.EncodeToString(m.Sum(nil))
}

// Signature schemes: the key of each value in a Cloud-Signature header. Webhooks are signed
// with SchemeWebhook over the body; consumer gateway requests with SchemeGateway over
// GatewayPayload (which covers the query string). A verifier only accepts its own scheme, so a
// verifier that knows only v1 refuses a gateway request outright instead of accepting a
// signature that does not cover the query.
const (
	SchemeWebhook = "v1"
	SchemeGateway = "v2"
)

// SignPayload returns a webhook Cloud-Signature header value for payload, with one v1 value per
// secret (the current secret first; during a rotation also the previous one).
func SignPayload(t time.Time, payload []byte, secrets ...string) string {
	return sign(SchemeWebhook, t, payload, secrets...)
}

// SignGateway returns a consumer gateway Cloud-Signature header value (scheme v2) for a
// GatewayPayload.
func SignGateway(t time.Time, payload []byte, secrets ...string) string {
	return sign(SchemeGateway, t, payload, secrets...)
}

func sign(scheme string, t time.Time, payload []byte, secrets ...string) string {
	ts := t.Unix()
	parts := []string{"t=" + strconv.FormatInt(ts, 10)}
	for _, s := range secrets {
		parts = append(parts, scheme+"="+mac(s, ts, payload))
	}
	return strings.Join(parts, ",")
}

// VerifyPayload checks a webhook Cloud-Signature header (v1) against any of secrets.
func VerifyPayload(header string, payload []byte, now time.Time, tolerance time.Duration, secrets ...string) error {
	return verify(SchemeWebhook, header, payload, now, tolerance, secrets...)
}

func verify(scheme, header string, payload []byte, now time.Time, tolerance time.Duration, secrets ...string) error {
	var ts int64 = -1
	var sigs []string
	for _, part := range strings.Split(header, ",") {
		k, v, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			continue
		}
		switch k {
		case "t":
			n, err := strconv.ParseInt(v, 10, 64)
			if err != nil {
				return ErrBadSignature
			}
			ts = n
		case scheme:
			sigs = append(sigs, v)
		}
	}
	if ts < 0 {
		return ErrBadSignature
	}
	if len(sigs) == 0 {
		return fmt.Errorf("%w: no %s signature (signed with another scheme?)", ErrBadSignature, scheme)
	}
	if d := now.Sub(time.Unix(ts, 0)); d > tolerance || d < -tolerance {
		return fmt.Errorf("%w: timestamp outside tolerance", ErrBadSignature)
	}
	for _, s := range secrets {
		want := mac(s, ts, payload)
		for _, got := range sigs {
			if hmac.Equal([]byte(want), []byte(got)) {
				return nil
			}
		}
	}
	return ErrBadSignature
}

// VerifyWebhook verifies a webhook request body and decodes the event.
func VerifyWebhook(r *http.Request, body []byte, now time.Time, secrets ...string) (*Event, error) {
	if err := VerifyPayload(r.Header.Get(HeaderSignature), body, now, DefaultSignatureTolerance, secrets...); err != nil {
		return nil, err
	}
	var ev Event
	if err := json.Unmarshal(body, &ev); err != nil {
		return nil, fmt.Errorf("cloud: webhook body: %w", err)
	}
	return &ev, nil
}

// WebhookHandler returns an http.Handler that verifies webhooks and passes each event to fn.
// It answers 400 for a bad signature, 500 when fn fails (so Azaleva Cloud retries), 204 otherwise.
// Remember that webhooks are a nudge: deduplicate on Event.ID and read the event cursor.
func WebhookHandler(fn func(*Event) error, secrets ...string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, 4<<20))
		if err != nil {
			http.Error(w, "read error", http.StatusBadRequest)
			return
		}
		ev, err := VerifyWebhook(r, body, time.Now(), secrets...)
		if err != nil {
			http.Error(w, "bad signature", http.StatusBadRequest)
			return
		}
		if err := fn(ev); err != nil {
			http.Error(w, "handler error", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
}

// GatewayPayload is the signed content of a consumer gateway request (scheme v2):
// method "\n" path "\n" query "\n" sandbox "\n" hex(sha256(body)), where path is the escaped
// path and query the raw query string (without "?"), both exactly as the consumer receives them.
func GatewayPayload(method, path, rawQuery, sandbox string, body []byte) []byte {
	h := sha256.Sum256(body)
	return []byte(method + "\n" + path + "\n" + rawQuery + "\n" + sandbox + "\n" + hex.EncodeToString(h[:]))
}

// GatewayIdentity is who sent a consumer gateway request.
type GatewayIdentity struct {
	Sandbox string
	Job     string
	Machine string
	Project string
	Node    string // informational only
}

// VerifyGatewayRequest verifies a request forwarded by the consumer gateway (scheme v2: method,
// path, query, sandbox and body) and returns the sending instance. Bind credentials to Sandbox
// (an sbx_ or mch_ ID), never to Node.
func VerifyGatewayRequest(r *http.Request, body []byte, now time.Time, secrets ...string) (*GatewayIdentity, error) {
	id := &GatewayIdentity{
		Sandbox: r.Header.Get(HeaderSandbox), Job: r.Header.Get(HeaderJob), Machine: r.Header.Get(HeaderMachine),
		Project: r.Header.Get(HeaderProject), Node: r.Header.Get(HeaderNode),
	}
	if id.Sandbox == "" {
		return nil, ErrBadSignature
	}
	payload := GatewayPayload(r.Method, r.URL.EscapedPath(), r.URL.RawQuery, id.Sandbox, body)
	if err := verify(SchemeGateway, r.Header.Get(HeaderSignature), payload, now, DefaultSignatureTolerance, secrets...); err != nil {
		return nil, err
	}
	return id, nil
}
