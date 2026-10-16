package cloud

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// EventsService reads the consumer's event log.
type EventsService struct{ c *Client }

// EventListOptions are the parameters of one event read.
type EventListOptions struct {
	// After returns events with seq > After; 0 starts at the oldest retained event.
	After int64
	// Wait is the long-poll time in seconds (0–30).
	Wait    int
	Limit   int
	Types   []EventType
	Project string
}

// List reads events after a sequence number (long poll with Wait).
func (s *EventsService) List(ctx context.Context, o EventListOptions) (*EventList, error) {
	q := url.Values{}
	if o.After > 0 {
		q.Set("after", strconv.FormatInt(o.After, 10))
	}
	if o.Wait > 0 {
		q.Set("wait", strconv.Itoa(o.Wait))
	}
	if o.Limit > 0 {
		q.Set("limit", strconv.Itoa(o.Limit))
	}
	for _, t := range o.Types {
		q.Add("type", string(t))
	}
	if o.Project != "" {
		q.Set("project", o.Project)
	}
	var out EventList
	return &out, s.c.call(ctx, http.MethodGet, "/events", q, nil, &out)
}

// Run long-polls the event log from after and calls handle for each event in order. The
// cursor passed to save (when non-nil) advances only after handle returned nil for an event,
// so a restart from the saved cursor redelivers nothing that was handled and loses nothing.
// Run returns when ctx ends or handle or save returns an error.
func (s *EventsService) Run(ctx context.Context, after int64, handle func(context.Context, Event) error, save func(seq int64) error) error {
	for {
		page, err := s.List(ctx, EventListOptions{After: after, Wait: 30, Limit: 500})
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if IsRetryable(err) || !isProblem(err) {
				t := time.NewTimer(time.Second)
				select {
				case <-ctx.Done():
					t.Stop()
					return ctx.Err()
				case <-t.C:
				}
				continue
			}
			return err
		}
		for _, ev := range page.Data {
			if err := handle(ctx, ev); err != nil {
				return err
			}
			after = ev.Seq
			if save != nil {
				if err := save(after); err != nil {
					return err
				}
			}
		}
		if page.NextAfter > after {
			after = page.NextAfter
		}
	}
}

func isProblem(err error) bool { _, ok := AsError(err); return ok }

// UsageService reads usage records.
type UsageService struct{ c *Client }

// UsageQuery selects usage records.
type UsageQuery struct {
	From, To time.Time
	// GroupBy is a subset of project, kind, label:<key>, hour, day.
	GroupBy []string
	Project string
	Labels  Labels
	Limit   int
	Cursor  string
}

func (q UsageQuery) values() url.Values {
	v := ListOptions{Limit: q.Limit, Cursor: q.Cursor, Project: q.Project, Labels: q.Labels}.values()
	v.Set("from", q.From.UTC().Format(time.RFC3339))
	v.Set("to", q.To.UTC().Format(time.RFC3339))
	if len(q.GroupBy) > 0 {
		v.Set("group_by", strings.Join(q.GroupBy, ","))
	}
	return v
}

// List returns usage records (or aggregates with GroupBy).
func (s *UsageService) List(ctx context.Context, q UsageQuery) (*Page[UsageRecord], error) {
	var out Page[UsageRecord]
	return &out, s.c.call(ctx, http.MethodGet, "/usage", q.values(), nil, &out)
}

// Export returns one UTC day of closed usage records as CSV.
func (s *UsageService) Export(ctx context.Context, day time.Time) ([]byte, error) {
	r := &request{method: http.MethodGet, path: "/usage/export",
		query: url.Values{"day": {day.UTC().Format("2006-01-02")}}, accept: "text/csv"}
	resp, err := s.c.do(ctx, r)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}
