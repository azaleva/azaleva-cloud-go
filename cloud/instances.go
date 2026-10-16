package cloud

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// instanceOps are the exec and file operations shared by sandboxes and machines.
type instanceOps struct {
	c    *Client
	kind string // "sandboxes" or "machines"
}

// Exec runs a command. Without req.Async it waits for the exit (≤ 300 s) and returns the
// output; with req.Async it returns the running exec at once.
//
// An exec completes when its command (the main process) exits: background processes it
// started (`sleep 300 & echo started`) keep running, and what they write after that is not
// the exec's output. While the command runs, the timeout and CancelExec kill it and every
// process it started (they carry CLOUD_EXEC_ID=<exec id> in their environment).
func (s instanceOps) Exec(ctx context.Context, id string, req ExecRequest, opts ...CallOption) (*Exec, error) {
	path, err := p(s.kind, id, "exec")
	if err != nil {
		return nil, err
	}
	var out Exec
	return &out, s.c.call(ctx, http.MethodPost, path, nil, req, &out, opts...)
}

// ListExecs lists running execs and those that exited in the last hour.
func (s instanceOps) ListExecs(ctx context.Context, id string, o ListOptions) (*Page[Exec], error) {
	path, err := p(s.kind, id, "execs")
	if err != nil {
		return nil, err
	}
	var out Page[Exec]
	return &out, s.c.call(ctx, http.MethodGet, path, o.values(), nil, &out)
}

// GetExec returns an exec.
func (s instanceOps) GetExec(ctx context.Context, id, execID string) (*Exec, error) {
	path, err := p(s.kind, id, "execs", execID)
	if err != nil {
		return nil, err
	}
	var out Exec
	return &out, s.c.call(ctx, http.MethodGet, path, nil, nil, &out)
}

// WaitExec polls an exec until it has exited.
func (s instanceOps) WaitExec(ctx context.Context, id, execID string) (*Exec, error) {
	return pollUntil(ctx, func() (*Exec, bool, error) {
		e, err := s.GetExec(ctx, id, execID)
		if err != nil {
			return nil, false, err
		}
		return e, e.State == "exited", nil
	})
}

// ExecOutput reads an exec's output like JobsService.Output.
func (s instanceOps) ExecOutput(ctx context.Context, id, execID string, o OutputOptions) (*OutputReader, error) {
	path, err := p(s.kind, id, "execs", execID, "output")
	if err != nil {
		return nil, err
	}
	return newOutputReader(ctx, s.c, path, o), nil
}

// CancelExec kills a running exec.
func (s instanceOps) CancelExec(ctx context.Context, id, execID string, opts ...CallOption) (*Exec, error) {
	path, err := p(s.kind, id, "execs", execID, "cancel")
	if err != nil {
		return nil, err
	}
	var out Exec
	return &out, s.c.call(ctx, http.MethodPost, path, nil, nil, &out, opts...)
}

// FileOptions are optional file operation parameters.
type FileOptions struct {
	User      string // agent (default) or root
	Mode      string // for writes, octal (default 0644)
	Recursive bool   // for deletes
}

func fileQuery(path string, o FileOptions) url.Values {
	q := url.Values{"path": {path}}
	if o.User != "" {
		q.Set("user", o.User)
	}
	if o.Mode != "" {
		q.Set("mode", o.Mode)
	}
	if o.Recursive {
		q.Set("recursive", "true")
	}
	return q
}

// ListFiles lists a directory.
func (s instanceOps) ListFiles(ctx context.Context, id, dir string, o FileOptions) (*FileList, error) {
	path, err := p(s.kind, id, "files")
	if err != nil {
		return nil, err
	}
	var out FileList
	return &out, s.c.call(ctx, http.MethodGet, path, fileQuery(dir, o), nil, &out)
}

// DeleteFile removes a file (or a directory with o.Recursive).
func (s instanceOps) DeleteFile(ctx context.Context, id, file string, o FileOptions, opts ...CallOption) error {
	path, err := p(s.kind, id, "files")
	if err != nil {
		return err
	}
	return s.c.call(ctx, http.MethodDelete, path, fileQuery(file, o), nil, nil, opts...)
}

// ReadFile returns a file's content.
func (s instanceOps) ReadFile(ctx context.Context, id, file string, o FileOptions) ([]byte, error) {
	path, err := p(s.kind, id, "files")
	if err != nil {
		return nil, err
	}
	r := &request{method: http.MethodGet, path: path + "/content", query: fileQuery(file, o), accept: "application/octet-stream"}
	resp, err := s.c.do(ctx, r)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}

// WriteFile writes a file, creating parent directories.
func (s instanceOps) WriteFile(ctx context.Context, id, file string, content []byte, o FileOptions, opts ...CallOption) (*FileEntry, error) {
	path, err := p(s.kind, id, "files")
	if err != nil {
		return nil, err
	}
	r := &request{method: http.MethodPut, path: path + "/content", query: fileQuery(file, o),
		body: content, ctype: "application/octet-stream", accept: "application/json"}
	if r.body == nil {
		r.body = []byte{}
	}
	resp, err := s.c.do(ctx, r, opts...)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var out FileEntry
	return &out, json.NewDecoder(resp.Body).Decode(&out)
}

// PutTree atomically replaces a directory with a root-owned, read-only tree.
func (s instanceOps) PutTree(ctx context.Context, id string, tree FileTree, opts ...CallOption) (*FileTreeResult, error) {
	path, err := p(s.kind, id, "files")
	if err != nil {
		return nil, err
	}
	var out FileTreeResult
	return &out, s.c.call(ctx, http.MethodPut, path+"/tree", nil, tree, &out, opts...)
}

// Archive returns a gzip-compressed tar stream of a directory; the caller closes it.
func (s instanceOps) Archive(ctx context.Context, id string, req ArchiveRequest, opts ...CallOption) (io.ReadCloser, error) {
	path, err := p(s.kind, id, "archive")
	if err != nil {
		return nil, err
	}
	r, err := s.c.newRequest(http.MethodPost, path, nil, req)
	if err != nil {
		return nil, err
	}
	r.accept = "application/gzip"
	resp, err := s.c.do(ctx, r, opts...)
	if err != nil {
		return nil, err
	}
	return resp.Body, nil
}

// SandboxesService manages ephemeral sandboxes.
type SandboxesService struct{ instanceOps }

// Create creates a sandbox (202; it is being created).
func (s *SandboxesService) Create(ctx context.Context, in SandboxCreate, opts ...CallOption) (*Sandbox, error) {
	var out Sandbox
	return &out, s.c.call(ctx, http.MethodPost, "/sandboxes", nil, in, &out, opts...)
}

// List lists sandboxes.
func (s *SandboxesService) List(ctx context.Context, o ListOptions) (*Page[Sandbox], error) {
	var out Page[Sandbox]
	return &out, s.c.call(ctx, http.MethodGet, "/sandboxes", o.values(), nil, &out)
}

// Get returns a sandbox.
func (s *SandboxesService) Get(ctx context.Context, id string) (*Sandbox, error) {
	path, err := p("sandboxes", id)
	if err != nil {
		return nil, err
	}
	var out Sandbox
	return &out, s.c.call(ctx, http.MethodGet, path, nil, nil, &out)
}

// Delete kills a sandbox.
func (s *SandboxesService) Delete(ctx context.Context, id string, opts ...CallOption) (*Sandbox, error) {
	path, err := p("sandboxes", id)
	if err != nil {
		return nil, err
	}
	var out Sandbox
	return &out, s.c.call(ctx, http.MethodDelete, path, nil, nil, &out, opts...)
}

// RenewLease renews the sandbox's lease (0 keeps the current lease_seconds).
func (s *SandboxesService) RenewLease(ctx context.Context, id string, leaseSeconds int, opts ...CallOption) (*Lease, error) {
	path, err := p("sandboxes", id, "lease")
	if err != nil {
		return nil, err
	}
	var in any
	if leaseSeconds > 0 {
		in = map[string]int{"lease_seconds": leaseSeconds}
	}
	var out Lease
	return &out, s.c.call(ctx, http.MethodPost, path, nil, in, &out, opts...)
}

// WaitReady polls the sandbox until it is ready (or failed).
func (s *SandboxesService) WaitReady(ctx context.Context, id string) (*Sandbox, error) {
	return pollUntil(ctx, func() (*Sandbox, bool, error) {
		sb, err := s.Get(ctx, id)
		if err != nil {
			return nil, false, err
		}
		return sb, sb.State != "creating", nil
	})
}

// MachinesService manages persistent machines, their terminals and network.
type MachinesService struct{ instanceOps }

// Create creates a machine (202; it is being created).
func (s *MachinesService) Create(ctx context.Context, in MachineCreate, opts ...CallOption) (*Machine, error) {
	var out Machine
	return &out, s.c.call(ctx, http.MethodPost, "/machines", nil, in, &out, opts...)
}

// List lists machines.
func (s *MachinesService) List(ctx context.Context, o ListOptions) (*Page[Machine], error) {
	var out Page[Machine]
	return &out, s.c.call(ctx, http.MethodGet, "/machines", o.values(), nil, &out)
}

// Get returns a machine.
func (s *MachinesService) Get(ctx context.Context, id string) (*Machine, error) {
	path, err := p("machines", id)
	if err != nil {
		return nil, err
	}
	var out Machine
	return &out, s.c.call(ctx, http.MethodGet, path, nil, nil, &out)
}

// Update changes a machine's profile, mode, hold or labels.
func (s *MachinesService) Update(ctx context.Context, id string, in MachineUpdate, opts ...CallOption) (*Machine, error) {
	path, err := p("machines", id)
	if err != nil {
		return nil, err
	}
	var out Machine
	return &out, s.c.call(ctx, http.MethodPatch, path, nil, in, &out, opts...)
}

// Delete destroys a machine.
func (s *MachinesService) Delete(ctx context.Context, id string, opts ...CallOption) (*Machine, error) {
	path, err := p("machines", id)
	if err != nil {
		return nil, err
	}
	var out Machine
	return &out, s.c.call(ctx, http.MethodDelete, path, nil, nil, &out, opts...)
}

func (s *MachinesService) action(ctx context.Context, id, action string, in any, opts []CallOption) (*Machine, error) {
	path, err := p("machines", id, action)
	if err != nil {
		return nil, err
	}
	var out Machine
	return &out, s.c.call(ctx, http.MethodPost, path, nil, in, &out, opts...)
}

// Start starts (resumes) a machine.
func (s *MachinesService) Start(ctx context.Context, id string, opts ...CallOption) (*Machine, error) {
	return s.action(ctx, id, "start", nil, opts)
}

// Stop stops (pauses) a machine.
func (s *MachinesService) Stop(ctx context.Context, id string, opts ...CallOption) (*Machine, error) {
	return s.action(ctx, id, "stop", nil, opts)
}

// Restart recreates a machine from its newest template build, carrying /workspace over.
func (s *MachinesService) Restart(ctx context.Context, id string, opts ...CallOption) (*Machine, error) {
	return s.action(ctx, id, "restart", nil, opts)
}

// Reset rebuilds the machine from its template's newest ready version (or in.Template),
// keeping /workspace only; in.ConfirmDiskReset must be true.
func (s *MachinesService) Reset(ctx context.Context, id string, in MachineReset, opts ...CallOption) (*Machine, error) {
	return s.action(ctx, id, "reset", in, opts)
}

// Migrate moves a machine to another node ("" lets placement choose).
func (s *MachinesService) Migrate(ctx context.Context, id, node string, opts ...CallOption) (*Machine, error) {
	var in any
	if node != "" {
		in = map[string]string{"node": node}
	}
	return s.action(ctx, id, "migrate", in, opts)
}

// Metrics returns a running machine's resource use.
func (s *MachinesService) Metrics(ctx context.Context, id string) (*MachineMetrics, error) {
	path, err := p("machines", id, "metrics")
	if err != nil {
		return nil, err
	}
	var out MachineMetrics
	return &out, s.c.call(ctx, http.MethodGet, path, nil, nil, &out)
}

// ErrMachineState is returned (wrapped) by WaitState when the machine reached destroyed or
// error and that state is not one of the states waited for: a destroyed machine stays so, and
// a machine leaves error only through an explicit reset or migrate, so waiting longer is
// pointless. The machine is returned with the error.
var ErrMachineState = errors.New("cloud: the machine cannot reach the state waited for")

// WaitState polls the machine until its state is one of states. It returns early with an error
// wrapping ErrMachineState (and the machine) when the machine is destroyed or in error and that
// state was not asked for.
func (s *MachinesService) WaitState(ctx context.Context, id string, states ...string) (*Machine, error) {
	return pollUntil(ctx, func() (*Machine, bool, error) {
		m, err := s.Get(ctx, id)
		if err != nil {
			return nil, false, err
		}
		for _, st := range states {
			if m.State == st {
				return m, true, nil
			}
		}
		if m.State == MachineDestroyed || m.State == MachineError {
			why := ""
			if m.StateReason != nil && *m.StateReason != "" {
				why = " (" + *m.StateReason + ")"
			}
			return m, true, fmt.Errorf("%w: machine %s is %s%s, waiting for %v", ErrMachineState, id, m.State, why, states)
		}
		return m, false, nil
	})
}

// Egress returns the machine's egress policy.
func (s *MachinesService) Egress(ctx context.Context, id string) (*MachineEgress, error) {
	path, err := p("machines", id, "egress")
	if err != nil {
		return nil, err
	}
	var out MachineEgress
	return &out, s.c.call(ctx, http.MethodGet, path, nil, nil, &out)
}

// SetEgress replaces the machine's egress policy (use IfMatch with the egress version).
func (s *MachinesService) SetEgress(ctx context.Context, id string, in EgressPut, opts ...CallOption) (*MachineEgress, error) {
	path, err := p("machines", id, "egress")
	if err != nil {
		return nil, err
	}
	var out MachineEgress
	return &out, s.c.call(ctx, http.MethodPut, path, nil, in, &out, opts...)
}

// AssignAddress assigns a public IPv6 address (or returns the existing one).
func (s *MachinesService) AssignAddress(ctx context.Context, id string, actor ChangeActor, opts ...CallOption) (*Address, error) {
	path, err := p("machines", id, "address")
	if err != nil {
		return nil, err
	}
	var out Address
	return &out, s.c.call(ctx, http.MethodPost, path, nil, actor, &out, opts...)
}

// ReleaseAddress releases the machine's public address.
func (s *MachinesService) ReleaseAddress(ctx context.Context, id string, opts ...CallOption) (*Address, error) {
	path, err := p("machines", id, "address")
	if err != nil {
		return nil, err
	}
	var out Address
	return &out, s.c.call(ctx, http.MethodDelete, path, nil, nil, &out, opts...)
}

// SetInbound replaces the inbound rules of the machine's address.
func (s *MachinesService) SetInbound(ctx context.Context, id string, in InboundPut, opts ...CallOption) (*MachineInbound, error) {
	path, err := p("machines", id, "inbound")
	if err != nil {
		return nil, err
	}
	if in.Rules == nil {
		in.Rules = []InboundRule{}
	}
	var out MachineInbound
	return &out, s.c.call(ctx, http.MethodPut, path, nil, in, &out, opts...)
}

// Network returns the machine's effective network state.
func (s *MachinesService) Network(ctx context.Context, id string) (*MachineNetwork, error) {
	path, err := p("machines", id, "network")
	if err != nil {
		return nil, err
	}
	var out MachineNetwork
	return &out, s.c.call(ctx, http.MethodGet, path, nil, nil, &out)
}

// CreateTerminal opens a PTY on a running machine.
func (s *MachinesService) CreateTerminal(ctx context.Context, id string, in TerminalCreate, opts ...CallOption) (*Terminal, error) {
	path, err := p("machines", id, "terminals")
	if err != nil {
		return nil, err
	}
	var out Terminal
	return &out, s.c.call(ctx, http.MethodPost, path, nil, in, &out, opts...)
}

// ListTerminals lists the machine's open terminals.
func (s *MachinesService) ListTerminals(ctx context.Context, id string, o ListOptions) (*Page[Terminal], error) {
	path, err := p("machines", id, "terminals")
	if err != nil {
		return nil, err
	}
	var out Page[Terminal]
	return &out, s.c.call(ctx, http.MethodGet, path, o.values(), nil, &out)
}

// GetTerminal returns a terminal.
func (s *MachinesService) GetTerminal(ctx context.Context, id, terminal string) (*Terminal, error) {
	path, err := p("machines", id, "terminals", terminal)
	if err != nil {
		return nil, err
	}
	var out Terminal
	return &out, s.c.call(ctx, http.MethodGet, path, nil, nil, &out)
}

// CloseTerminal closes a terminal.
func (s *MachinesService) CloseTerminal(ctx context.Context, id, terminal string, opts ...CallOption) (*Terminal, error) {
	path, err := p("machines", id, "terminals", terminal)
	if err != nil {
		return nil, err
	}
	var out Terminal
	return &out, s.c.call(ctx, http.MethodDelete, path, nil, nil, &out, opts...)
}

// SendTerminalInput sends keystrokes.
func (s *MachinesService) SendTerminalInput(ctx context.Context, id, terminal string, data []byte, opts ...CallOption) error {
	path, err := p("machines", id, "terminals", terminal, "input")
	if err != nil {
		return err
	}
	return s.c.call(ctx, http.MethodPost, path, nil, map[string]string{"data_b64": base64.StdEncoding.EncodeToString(data)}, nil, opts...)
}

// ResizeTerminal resizes a terminal.
func (s *MachinesService) ResizeTerminal(ctx context.Context, id, terminal string, rows, cols int, opts ...CallOption) (*Terminal, error) {
	path, err := p("machines", id, "terminals", terminal, "resize")
	if err != nil {
		return nil, err
	}
	var out Terminal
	return &out, s.c.call(ctx, http.MethodPost, path, nil, map[string]int{"rows": rows, "cols": cols}, &out, opts...)
}

// StreamTerminal opens the terminal's output as Server-Sent Events from offset after.
func (s *MachinesService) StreamTerminal(ctx context.Context, id, terminal string, after int64) (*TerminalStream, error) {
	path, err := p("machines", id, "terminals", terminal, "stream")
	if err != nil {
		return nil, err
	}
	return openTerminalStream(ctx, s.c, path, after)
}

// TerminalEvent is one event of a terminal stream: output bytes, or the close.
type TerminalEvent struct {
	Type     string // "output" or "closed"
	Offset   int64
	Data     []byte
	Reason   string
	ExitCode *int
}

// TerminalStream reads a terminal's SSE stream.
type TerminalStream struct {
	body io.ReadCloser
	r    *bufio.Reader
}

func openTerminalStream(ctx context.Context, c *Client, path string, after int64) (*TerminalStream, error) {
	q := url.Values{}
	if after > 0 {
		q.Set("after", strconv.FormatInt(after, 10))
	}
	r := &request{method: http.MethodGet, path: path, query: q, accept: "text/event-stream", noRetry: true}
	resp, err := c.do(ctx, r)
	if err != nil {
		return nil, err
	}
	return &TerminalStream{body: resp.Body, r: bufio.NewReader(resp.Body)}, nil
}

// Next returns the next event; io.EOF after the stream ends.
func (t *TerminalStream) Next() (*TerminalEvent, error) {
	var typ, data string
	for {
		line, err := t.r.ReadString('\n')
		if err != nil && line == "" {
			if typ != "" {
				return parseTerminalEvent(typ, data)
			}
			if errors.Is(err, io.EOF) {
				return nil, io.EOF
			}
			return nil, err
		}
		line = strings.TrimRight(line, "\r\n")
		switch {
		case line == "":
			if typ != "" {
				return parseTerminalEvent(typ, data)
			}
		case strings.HasPrefix(line, "event:"):
			typ = strings.TrimSpace(line[len("event:"):])
		case strings.HasPrefix(line, "data:"):
			data += strings.TrimSpace(line[len("data:"):])
		}
	}
}

func parseTerminalEvent(typ, data string) (*TerminalEvent, error) {
	ev := &TerminalEvent{Type: typ}
	var raw struct {
		Offset   int64  `json:"offset"`
		DataB64  string `json:"data_b64"`
		Reason   string `json:"reason"`
		ExitCode *int   `json:"exit_code"`
	}
	if err := json.Unmarshal([]byte(data), &raw); err != nil {
		return nil, fmt.Errorf("cloud: terminal event: %w", err)
	}
	ev.Offset, ev.Reason, ev.ExitCode = raw.Offset, raw.Reason, raw.ExitCode
	if raw.DataB64 != "" {
		b, err := base64.StdEncoding.DecodeString(raw.DataB64)
		if err != nil {
			return nil, err
		}
		ev.Data = b
	}
	return ev, nil
}

// Close closes the stream.
func (t *TerminalStream) Close() error { return t.body.Close() }

// pollUntil calls f with backoff (100 ms doubling to 2 s) until it reports done.
func pollUntil[T any](ctx context.Context, f func() (T, bool, error)) (T, error) {
	d := 100 * time.Millisecond
	for {
		v, done, err := f()
		if err != nil || done {
			return v, err
		}
		t := time.NewTimer(d)
		select {
		case <-ctx.Done():
			t.Stop()
			return v, ctx.Err()
		case <-t.C:
		}
		if d < 2*time.Second {
			d *= 2
		}
	}
}
