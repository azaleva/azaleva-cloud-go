package cloudtest

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/url"
	"path"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// CompanionVersion is the agent-companion release whose API cloudtest's fake agent-companion
// follows (the version Azaleva Cloud's machine templates pin): what getMachineCompanion reports as
// version and pinned_version for a fake machine.
const CompanionVersion = "0.14.0"

// CompanionTooling is what the fake reports as a machine's tooling (computer-base's, as its
// build records it in /opt/agent-companion/build-info.json).
var CompanionTooling = map[string]string{"bash": "5.2.37", "git": "2.47.3", "python": "3.12.12"}

// The fake machine, as Azaleva Cloud's machines run agent-companion (its systemd service): as
// the user agent in /workspace (its home
// and every session's first working directory), notebooks and the system prompt off, four
// terminal sessions at most, one user.
const (
	acHome     = "/workspace"
	acUserHome = "/home/agent"
	acLogDir   = acUserHome + "/.local/state/agent-companion/logs"
	acMaxTerms = 4
	acHostname = "machine"
)

// companionHandler is cloudtest's fake agent-companion behind a machine's policy-companion
// transport: agent-companion 0.14.0's routes, answers, status codes and error bodies on the
// surfaces consumers use, over an in-memory file system and a small shell (see FakeCompanion).
func companionHandler(key string) http.Handler {
	return &acServer{key: key, fs: newACFS(), cwds: map[string]string{}}
}

// acOwner is what agent-companion keys processes and terminals on: (X-User-Id, X-Session-Id).
// Working directories are keyed on X-Session-Id alone.
type acOwner struct{ user, session string }

type acServer struct {
	key string

	mu      sync.Mutex
	fs      *acFS
	cwds    map[string]string // X-Session-Id -> working directory
	procs   []*acProc
	terms   []*acTerm
	nextPID int
}

// acErr is an error answer: {"detail": …} (most routes) or {"error": …} (terminals).
type acErr struct {
	status int
	body   any
	header http.Header
}

func (e *acErr) Error() string { return fmt.Sprint(e.status, e.body) }

func acDetail(status int, msg string) *acErr {
	return &acErr{status: status, body: map[string]any{"detail": msg}}
}

func acTermErr(status int, msg string) *acErr {
	return &acErr{status: status, body: map[string]any{"error": msg}}
}

// acValidation is a 422 with FastAPI's list of errors.
func acValidation(errs []map[string]any) *acErr {
	return &acErr{status: 422, body: map[string]any{"detail": errs}}
}

func acReply(w http.ResponseWriter, status int, v any) {
	b, _ := json.Marshal(v)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(b)
}

// acBinary answers a file's bytes (text types with charset=utf-8, as agent-companion does).
func acBinary(w http.ResponseWriter, data []byte, mimeType string) {
	if strings.HasPrefix(mimeType, "text/") {
		mimeType += "; charset=utf-8"
	}
	w.Header().Set("Content-Type", mimeType)
	_, _ = w.Write(data)
}

func (s *acServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if err := s.dispatch(w, r); err != nil {
		var e *acErr
		if !errors.As(err, &e) {
			e = acDetail(500, err.Error())
		}
		for k, v := range e.header {
			w.Header()[k] = v
		}
		acReply(w, e.status, e.body)
	}
}

func (s *acServer) dispatch(w http.ResponseWriter, r *http.Request) error {
	p, method := r.URL.Path, r.Method
	owner := acOwner{user: r.Header.Get("X-User-Id"), session: r.Header.Get("X-Session-Id")}
	if strings.HasPrefix(p, "/api/terminals/") && strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		_, hasSession := r.Header[http.CanonicalHeaderKey("X-Session-Id")]
		return s.terminalSocket(w, r, owner, strings.TrimPrefix(p, "/api/terminals/"), hasSession)
	}
	switch {
	case p == "/health" && method == http.MethodGet:
		acReply(w, 200, map[string]string{"status": "ok"})
		return nil
	case p == "/api/config" && method == http.MethodGet:
		acReply(w, 200, map[string]any{"features": map[string]bool{"terminal": true, "notebooks": false, "system": false}})
		return nil
	case p == "/openapi.json" && method == http.MethodGet:
		paths := map[string]any{}
		for _, t := range acTemplates() {
			ops := map[string]any{}
			for m := range acRoutes[t] {
				ops[m] = map[string]any{}
			}
			paths[t] = ops
		}
		acReply(w, 200, map[string]any{"openapi": "3.1.0", "paths": paths,
			"info": map[string]string{"title": "Agent Companion", "description": "A remote terminal API.", "version": CompanionVersion}})
		return nil
	case (p == "/docs" || p == "/redoc" || p == "/docs/oauth2-redirect") && method == http.MethodGet:
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = io.WriteString(w, "<!DOCTYPE html><html><head><title>Agent Companion</title></head><body></body></html>")
		return nil
	}
	if !acEnabled(p) {
		return acDetail(404, "Not Found")
	}
	if strings.HasSuffix(p, "/") {
		if op, _ := acRoute(strings.TrimRight(p, "/"), method); op != nil {
			loc := strings.TrimRight(p, "/")
			if r.URL.RawQuery != "" {
				loc += "?" + r.URL.RawQuery
			}
			w.Header().Set("Location", loc)
			w.WriteHeader(http.StatusTemporaryRedirect)
			return nil
		}
	}
	op, params := acRoute(p, method)
	if op == nil {
		var allowed []string
		for _, m := range []string{"get", "post", "put", "patch", "delete", "head", "options"} {
			if o, _ := acRoute(p, m); o != nil {
				allowed = append(allowed, strings.ToUpper(m))
			}
		}
		if len(allowed) > 0 {
			e := acDetail(405, "Method Not Allowed")
			e.header = http.Header{"Allow": {strings.Join(allowed, ", ")}}
			return e
		}
	}
	if !s.authenticated(r.Header.Get("Authorization")) {
		if op != nil {
			return acDetail(401, "Invalid API key")
		}
		return acDetail(404, "Not Found")
	}
	if op == nil {
		return acDetail(404, "Not Found")
	}
	q := acParseQuery(r.URL.RawQuery)
	if p == "/files/upload" && method == http.MethodPost {
		if err := acValidate(op, params, q, nil, false); err != nil {
			return err
		}
		return s.upload(w, r, owner, q)
	}
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		return acDetail(400, err.Error())
	}
	if strings.HasPrefix(p, "/proxy/") {
		return proxyAnswer(p)
	}
	var body any
	if len(raw) > 0 {
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.UseNumber()
		if err := dec.Decode(&body); err != nil {
			col := 0 // serde's column, less one
			var se *json.SyntaxError
			if errors.As(err, &se) {
				col = max(int(se.Offset)-1, 0)
			}
			return acValidation([]map[string]any{{"type": "json_invalid", "loc": []any{"body", col}, "msg": "JSON decode error",
				"input": map[string]any{}, "ctx": map[string]any{"error": err.Error()}}})
		}
	}
	if err := acValidate(op, params, q, &body, true); err != nil {
		return err
	}
	b, _ := body.(map[string]any)
	return s.execute(w, owner, p, method, params, q, b)
}

func (s *acServer) authenticated(h string) bool {
	scheme, key, ok := strings.Cut(h, " ")
	return ok && strings.EqualFold(scheme, "bearer") && key == s.key
}

// acEnabled: notebooks, the system prompt and /info are off in Azaleva Cloud's machines.
func acEnabled(p string) bool {
	return !strings.HasPrefix(p, "/notebooks") && p != "/system" && p != "/info"
}

func proxyAnswer(p string) error {
	port, _, _ := strings.Cut(strings.TrimPrefix(p, "/proxy/"), "/")
	if n, err := strconv.ParseUint(port, 10, 32); err != nil || n < 1 || n > 65535 {
		return acDetail(422, "Port must be between 1 and 65535")
	}
	return acDetail(404, "Port not found") // nothing listens in the fake machine
}

func (s *acServer) execute(w http.ResponseWriter, owner acOwner, p, method string, params map[string]string, q acQuery, b map[string]any) error {
	switch {
	case strings.HasPrefix(p, "/execute"):
		v, err := s.processes(owner, p, method, q, b)
		if err != nil {
			return err
		}
		acReply(w, 200, v)
		return nil
	case strings.HasPrefix(p, "/api/terminals"):
		v, err := s.terminals(owner, p, method, b)
		if err != nil {
			return err
		}
		acReply(w, 200, v)
		return nil
	case p == "/files/compare":
		return acDetail(501, "cloudtest's fake agent-companion does not model /files/compare")
	case p == "/ports":
		acReply(w, 200, map[string]any{"ports": []any{}})
		return nil
	}
	return s.files(w, owner, p, method, q, b)
}

// ---- routes and validation (agent-companion's contract, tests/fixtures/contract.json) ----

type acParam struct {
	name, in, kind string // kind: string, int, number, bool, array; a trailing "?" also allows null
	required       bool
	min, max       *float64
	pattern        string
}

type acField struct {
	name, kind string // string, string?, bool, object?, array:string, array:chunk
	required   bool
	minLen     int
}

type acOp struct {
	params  []acParam
	body    []acField // nil: no JSON body
	hasBody bool
}

func fp(v float64) *float64 { return &v }

var (
	pPath     = acParam{name: "path", in: "query", kind: "string"}
	pPathReq  = acParam{name: "path", in: "query", kind: "string", required: true}
	pHidden   = acParam{name: "show_hidden", in: "query", kind: "bool"}
	pTypeAny  = acParam{name: "type", in: "query", kind: "string?", pattern: "^(file|directory|any)$"}
	pMaxRes   = acParam{name: "max_results", in: "query", kind: "int", min: fp(1), max: fp(500)}
	pWait     = acParam{name: "wait", in: "query", kind: "number?", min: fp(0), max: fp(300)}
	pTail     = acParam{name: "tail", in: "query", kind: "int?", min: fp(1)}
	pProcID   = acParam{name: "process_id", in: "path", kind: "string", required: true}
	pTermID   = acParam{name: "session_id", in: "path", kind: "string", required: true}
	mkdirBody = []acField{{name: "path", kind: "string", required: true}}
	inputBody = []acField{{name: "input", kind: "string", required: true}}
)

var acRoutes = map[string]map[string]acOp{
	"/health":      {"get": {}},
	"/api/config":  {"get": {}},
	"/files/cwd":   {"get": {}, "post": {body: mkdirBody, hasBody: true}},
	"/skills":      {"get": {}},
	"/skills/read": {"get": {params: []acParam{{name: "name", in: "query", kind: "string", required: true}}}},
	"/files/list":  {"get": {params: []acParam{{name: "directory", in: "query", kind: "string"}}}},
	"/files/compare": {"post": {hasBody: true, body: []acField{{name: "original", kind: "string", required: true, minLen: 1},
		{name: "revised", kind: "string", required: true, minLen: 1}, {name: "ignore_whitespace", kind: "bool"}}}},
	"/files/read": {"get": {params: []acParam{pPathReq, {name: "start_line", in: "query", kind: "int?", min: fp(1)},
		{name: "end_line", in: "query", kind: "int?", min: fp(1)}}}},
	"/files/display":      {"get": {params: []acParam{pPathReq}}},
	"/files/view":         {"get": {params: []acParam{pPathReq, {name: "preview", in: "query", kind: "bool"}}}},
	"/files/serve/{path}": {"get": {params: []acParam{{name: "path", in: "path", kind: "string", required: true}}}},
	"/files/write": {"post": {hasBody: true, body: []acField{{name: "path", kind: "string", required: true},
		{name: "content", kind: "string", required: true}}}},
	"/files/mkdir":  {"post": {hasBody: true, body: mkdirBody}},
	"/files/delete": {"delete": {params: []acParam{pPathReq}}},
	"/files/move": {"post": {hasBody: true, body: []acField{{name: "source", kind: "string", required: true},
		{name: "destination", kind: "string", required: true}}}},
	"/files/replace": {"post": {hasBody: true, body: []acField{{name: "path", kind: "string", required: true},
		{name: "replacements", kind: "array:chunk", required: true}}}},
	"/files/grep": {"get": {params: []acParam{{name: "query", in: "query", kind: "string", required: true}, pPath,
		{name: "regex", in: "query", kind: "bool"}, {name: "case_insensitive", in: "query", kind: "bool"},
		{name: "include", in: "query", kind: "array?"}, {name: "match_per_line", in: "query", kind: "bool"}, pMaxRes}}},
	"/files/matches": {"get": {params: []acParam{{name: "query", in: "query", kind: "string", required: true}, pPath, pHidden,
		{name: "offset", in: "query", kind: "int", min: fp(0)}, {name: "limit", in: "query", kind: "int", min: fp(1), max: fp(100)}}}},
	"/files/search": {"get": {params: []acParam{{name: "query", in: "query", kind: "string"}, pPath,
		{name: "limit", in: "query", kind: "int", min: fp(1), max: fp(100)}, pTypeAny, pHidden}}},
	"/files/glob": {"get": {params: []acParam{{name: "pattern", in: "query", kind: "string", required: true}, pPath,
		{name: "exclude", in: "query", kind: "array?"}, pTypeAny, pMaxRes}}},
	"/files/upload":  {"post": {params: []acParam{{name: "directory", in: "query", kind: "string", required: true}}}},
	"/files/archive": {"post": {hasBody: true, body: []acField{{name: "paths", kind: "array:string", required: true}}}},
	"/execute": {"get": {}, "post": {params: []acParam{pWait, pTail}, hasBody: true, body: []acField{
		{name: "command", kind: "string", required: true}, {name: "cwd", kind: "string?"}, {name: "env", kind: "object?"}}}},
	"/execute/{process_id}/status": {"get": {params: []acParam{pProcID, pWait,
		{name: "offset", in: "query", kind: "int", min: fp(0)}, pTail}}},
	"/execute/{process_id}/input": {"post": {params: []acParam{pProcID}, hasBody: true, body: inputBody}},
	"/execute/{process_id}":       {"delete": {params: []acParam{pProcID, {name: "force", in: "query", kind: "bool"}}}},
	"/ports":                      {"get": {}},
	"/proxy/{port}/{path}":        {"get": {}, "head": {}, "post": {}, "put": {}, "patch": {}, "delete": {}, "options": {}},
	"/api/terminals":              {"get": {}, "post": {}},
	"/api/terminals/user/output":  {"get": {}},
	"/api/terminals/user/input":   {"post": {hasBody: true, body: inputBody}},
	"/api/terminals/{session_id}": {"get": {params: []acParam{pTermID}}, "delete": {params: []acParam{pTermID}}},
}

func acTemplates() []string {
	ts := make([]string, 0, len(acRoutes))
	for t := range acRoutes {
		ts = append(ts, t)
	}
	sort.Strings(ts) // agent-companion walks its schema's paths in this order
	return ts
}

// acRoute finds the operation of a path and method as agent-companion does: the first path
// template (in order) that matches the path decides; {path} takes the rest of the path.
func acRoute(p, method string) (*acOp, map[string]string) {
	method = strings.ToLower(method)
	b := strings.Split(p, "/")
	for _, t := range acTemplates() {
		a := strings.Split(t, "/")
		params := map[string]string{}
		match := true
		for i, x := range a {
			if strings.HasPrefix(x, "{") {
				if i >= len(b) {
					match = false
					break
				}
				k := strings.Trim(x, "{}")
				if k == "path" {
					params[k] = strings.Join(b[i:], "/")
					break
				}
				params[k] = b[i]
			} else if i >= len(b) || b[i] != x {
				match = false
				break
			}
		}
		if len(a) != len(b) && !strings.Contains(t, "{path}") {
			match = false
		}
		if match {
			if op, ok := acRoutes[t][method]; ok {
				return &op, params
			}
			return nil, nil
		}
	}
	return nil, nil
}

// acQuery is a query string as agent-companion reads it: values "null" are absent; the last
// value of a name wins, arrays take every value.
type acQuery [][2]string

func acParseQuery(raw string) acQuery {
	var q acQuery
	for _, part := range strings.Split(raw, "&") {
		if part == "" {
			continue
		}
		k, v, _ := strings.Cut(part, "=")
		k, _ = url.QueryUnescape(strings.ReplaceAll(k, "+", " "))
		v, _ = url.QueryUnescape(strings.ReplaceAll(v, "+", " "))
		if strings.EqualFold(v, "null") {
			continue
		}
		q = append(q, [2]string{k, v})
	}
	return q
}

func (q acQuery) get(k string) (string, bool) {
	for i := len(q) - 1; i >= 0; i-- {
		if q[i][0] == k {
			return q[i][1], true
		}
	}
	return "", false
}

func (q acQuery) str(k, def string) string {
	if v, ok := q.get(k); ok {
		return v
	}
	return def
}

func (q acQuery) all(k string) []string {
	var out []string
	for _, kv := range q {
		if kv[0] == k {
			out = append(out, kv[1])
		}
	}
	return out
}

func (q acQuery) flag(k string, def bool) bool {
	v, ok := q.get(k)
	if !ok {
		return def
	}
	switch strings.ToLower(v) {
	case "true", "1", "yes", "on", "t", "y":
		return true
	}
	return false
}

func (q acQuery) num(k string, def float64) float64 {
	if v, ok := q.get(k); ok {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			return f
		}
	}
	return def
}

func acFmt(f float64) string { return strconv.FormatFloat(f, 'f', -1, 64) }

// acValidate checks parameters and the JSON body as agent-companion's contract does (422 with
// FastAPI's error list).
func acValidate(op *acOp, params map[string]string, q acQuery, body *any, checkBody bool) error {
	var errs []map[string]any
	add := func(typ string, loc []any, input any, msg string, ctx map[string]any) {
		e := map[string]any{"type": typ, "loc": loc, "msg": msg, "input": input}
		if ctx != nil {
			e["ctx"] = ctx
		}
		errs = append(errs, e)
	}
	for _, p := range op.params {
		var v string
		var ok bool
		if p.in == "path" {
			v, ok = params[p.name]
		} else {
			v, ok = q.get(p.name)
		}
		loc := []any{p.in, p.name}
		if !ok {
			if p.required {
				add("missing", loc, nil, "Field required", nil)
			}
			continue
		}
		kind := strings.TrimSuffix(p.kind, "?")
		switch kind {
		case "int", "number":
			f, err := strconv.ParseFloat(strings.TrimSpace(v), 64)
			if err != nil {
				if kind == "int" {
					add("int_parsing", loc, v, "Input should be a valid integer, unable to parse string as an integer", nil)
				} else {
					add("float_parsing", loc, v, "Input should be a valid number, unable to parse string as a number", nil)
				}
				continue
			}
			if kind == "int" && f != float64(int64(f)) {
				add("int_from_float", loc, v, "Input should be a valid integer, got a number with a fractional part", nil)
				continue
			}
			if p.min != nil && f < *p.min {
				add("greater_than_equal", loc, v, "Input should be greater than or equal to "+acFmt(*p.min), map[string]any{"ge": *p.min})
			}
			if p.max != nil && f > *p.max {
				add("less_than_equal", loc, v, "Input should be less than or equal to "+acFmt(*p.max), map[string]any{"le": *p.max})
			}
		case "bool":
			switch strings.ToLower(v) {
			case "true", "1", "yes", "on", "t", "y", "false", "0", "no", "off", "f", "n":
			default:
				add("bool_parsing", loc, v, "Input should be a valid boolean, unable to interpret input", nil)
			}
		case "string":
			if p.pattern != "" && !acPatternOK(p.pattern, v) {
				add("string_pattern_mismatch", loc, v, "String should match pattern '"+p.pattern+"'", map[string]any{"pattern": p.pattern})
			}
		}
	}
	if checkBody && op.hasBody {
		switch b := (*body).(type) {
		case nil:
			add("missing", []any{"body"}, nil, "Field required", nil)
		case map[string]any:
			for _, f := range op.body {
				loc := []any{"body", f.name}
				v, ok := b[f.name]
				if !ok {
					if f.required {
						add("missing", loc, b, "Field required", nil)
					}
					continue
				}
				acCheckField(f, v, loc, add)
			}
		default:
			add("model_attributes_type", []any{"body"}, b, "Input should be a valid dictionary or object to extract fields from", nil)
		}
	}
	if len(errs) > 0 {
		return acValidation(errs)
	}
	return nil
}

func acPatternOK(pattern, v string) bool {
	if pattern == "^(file|directory|any)$" {
		return v == "file" || v == "directory" || v == "any"
	}
	return true
}

func acCheckField(f acField, v any, loc []any, add func(string, []any, any, string, map[string]any)) {
	strType := func(v any, loc []any) bool {
		if _, ok := v.(string); !ok {
			add("string_type", loc, v, "Input should be a valid string", nil)
			return false
		}
		return true
	}
	switch f.kind {
	case "string":
		if strType(v, loc) && f.minLen > 0 && len([]rune(v.(string))) < f.minLen {
			add("string_too_short", loc, v, fmt.Sprintf("String should have at least %d character", f.minLen), map[string]any{"min_length": f.minLen})
		}
	case "string?":
		if v != nil {
			strType(v, loc)
		}
	case "bool":
		if _, ok := v.(bool); !ok {
			add("bool_parsing", loc, v, "Input should be a valid boolean, unable to interpret input", nil)
		}
	case "object?":
		if v == nil {
			return
		}
		m, ok := v.(map[string]any)
		if !ok {
			add("model_attributes_type", loc, v, "Input should be a valid dictionary or object to extract fields from", nil)
			return
		}
		for k, x := range m {
			strType(x, append(slices.Clone(loc), k))
		}
	case "array:string", "array:chunk":
		a, ok := v.([]any)
		if !ok {
			add("list_type", loc, v, "Input should be a valid list", nil)
			return
		}
		for i, x := range a {
			l := append(slices.Clone(loc), i)
			if f.kind == "array:string" {
				strType(x, l)
				continue
			}
			c, ok := x.(map[string]any)
			if !ok {
				add("model_attributes_type", l, x, "Input should be a valid dictionary or object to extract fields from", nil)
				continue
			}
			for _, k := range []string{"target", "replacement"} {
				if y, ok := c[k]; !ok {
					add("missing", append(slices.Clone(l), k), c, "Field required", nil)
				} else {
					strType(y, append(slices.Clone(l), k))
				}
			}
		}
	}
}

// acText is a string field of a JSON body ("" if absent).
func acText(b map[string]any, k string) string {
	s, _ := b[k].(string)
	return s
}

// ---- uploads ----

func (s *acServer) upload(w http.ResponseWriter, r *http.Request, owner acOwner, q acQuery) error {
	_, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || params["boundary"] == "" {
		return acDetail(400, "Missing boundary in multipart.")
	}
	mr := multipart.NewReader(r.Body, params["boundary"])
	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			return acDetail(400, err.Error())
		}
		if part.FormName() != "file" {
			continue
		}
		name := part.FileName()
		if name == "" {
			name = "upload"
		}
		name = name[strings.LastIndex(name, "/")+1:]
		data, err := io.ReadAll(part)
		if err != nil {
			return acDetail(400, err.Error())
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		target := acNormalize(path.Join(s.fs.resolve(q.str("directory", ""), ""), name))
		if err := s.fs.write(target, data); err != nil {
			return err
		}
		acReply(w, 200, map[string]any{"path": target, "size": len(data)})
		return nil
	}
	return acValidation([]map[string]any{{"type": "missing", "loc": []any{"body", "file"}, "msg": "Field required", "input": nil}})
}

// acNow is a timestamp as agent-companion reports it (seconds since the epoch).
func acNow() float64 { return float64(time.Now().UnixNano()) / 1e9 }
