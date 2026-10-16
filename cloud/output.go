package cloud

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

// OutputOptions select which output to read.
type OutputOptions struct {
	// After is the byte offset to start at.
	After int64
	// Stream is "stdout" (default) or "stderr".
	Stream string
	// NoFollow reads what is journaled now and stops, instead of following until the exit.
	NoFollow bool
}

// OutputReader reads journaled output from an offset, reconnecting as needed. Read returns
// io.EOF once the exec has exited and every byte was delivered (or, with NoFollow, at the end
// of what was journaled when the call was made).
type OutputReader struct {
	ctx      context.Context
	c        *Client
	path     string
	opts     OutputOptions
	offset   int64
	body     io.ReadCloser
	complete bool // the open response reaches the end of a finished stream
	eof      bool
	failures int
}

func newOutputReader(ctx context.Context, c *Client, path string, o OutputOptions) *OutputReader {
	return &OutputReader{ctx: ctx, c: c, path: path, opts: o, offset: o.After}
}

// Offset is the offset of the next byte Read returns; pass it as After to resume elsewhere.
func (r *OutputReader) Offset() int64 { return r.offset }

// Complete reports whether the whole stream has been read.
func (r *OutputReader) Complete() bool { return r.eof && !r.opts.NoFollow }

func (r *OutputReader) open() error {
	q := url.Values{"after": {strconv.FormatInt(r.offset, 10)}}
	if r.opts.Stream != "" {
		q.Set("stream", r.opts.Stream)
	}
	if !r.opts.NoFollow {
		q.Set("follow", "true")
	}
	req := &request{method: http.MethodGet, path: r.path, query: q, accept: "application/octet-stream"}
	resp, err := r.c.do(r.ctx, req)
	if err != nil {
		return err
	}
	r.body = resp.Body
	r.complete = resp.Header.Get("Cloud-Output-Complete") == "true"
	return nil
}

// Read implements io.Reader.
func (r *OutputReader) Read(p []byte) (int, error) {
	for {
		if r.eof {
			return 0, io.EOF
		}
		if r.body == nil {
			if err := r.open(); err != nil {
				return 0, err
			}
		}
		n, err := r.body.Read(p)
		r.offset += int64(n)
		if n > 0 {
			r.failures = 0
		}
		if err == nil {
			return n, nil
		}
		r.body.Close()
		r.body = nil
		switch {
		case errors.Is(err, io.EOF):
			if r.complete || r.opts.NoFollow {
				r.eof = true
			}
			// Otherwise the server ended a follow response (exit or its time limit): reconnect;
			// the next response says whether the stream is complete.
		default:
			// A dropped connection: reconnect from the current offset, with a short backoff.
			if r.ctx.Err() != nil {
				return n, r.ctx.Err()
			}
			r.failures++
			if r.failures > r.c.retry.MaxAttempts {
				return n, err
			}
			t := time.NewTimer(r.c.backoff(r.failures))
			select {
			case <-r.ctx.Done():
				t.Stop()
				return n, r.ctx.Err()
			case <-t.C:
			}
		}
		if n > 0 {
			return n, nil
		}
	}
}

// Close releases the open response, if any.
func (r *OutputReader) Close() error {
	if r.body != nil {
		err := r.body.Close()
		r.body = nil
		return err
	}
	return nil
}
