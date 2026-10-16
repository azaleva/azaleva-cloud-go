package cloud

import (
	"context"
	"iter"
	"net/http"
	"net/url"
	"sort"
	"strconv"
)

func (o ListOptions) values() url.Values {
	q := url.Values{}
	if o.Limit > 0 {
		q.Set("limit", strconv.Itoa(o.Limit))
	}
	if o.Cursor != "" {
		q.Set("cursor", o.Cursor)
	}
	if o.Project != "" {
		q.Set("project", o.Project)
	}
	keys := make([]string, 0, len(o.Labels))
	for k := range o.Labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		q.Add("label", k+"="+o.Labels[k])
	}
	for _, s := range o.States {
		q.Add("state", s)
	}
	if o.Node != "" {
		q.Set("node", o.Node)
	}
	return q
}

// Iterate walks every page of a list call, starting at opts.
func Iterate[T any](ctx context.Context, opts ListOptions, list func(context.Context, ListOptions) (*Page[T], error)) iter.Seq2[T, error] {
	return func(yield func(T, error) bool) {
		for {
			page, err := list(ctx, opts)
			if err != nil {
				var zero T
				yield(zero, err)
				return
			}
			for _, v := range page.Data {
				if !yield(v, nil) {
					return
				}
			}
			if page.NextCursor == nil || *page.NextCursor == "" {
				return
			}
			opts.Cursor = *page.NextCursor
		}
	}
}

// Consumer returns the calling consumer, its pools, ceilings and the key's scopes.
func (c *Client) Consumer(ctx context.Context) (*ConsumerSelf, error) {
	var out ConsumerSelf
	return &out, c.call(ctx, http.MethodGet, "/consumer", nil, nil, &out)
}

// Capacity returns a capacity hint for a pool and profile (both optional).
func (c *Client) Capacity(ctx context.Context, pool, profile string) (*Capacity, error) {
	q := url.Values{}
	if pool != "" {
		q.Set("pool", pool)
	}
	if profile != "" {
		q.Set("profile", profile)
	}
	var out Capacity
	return &out, c.call(ctx, http.MethodGet, "/capacity", q, nil, &out)
}

// ProjectsService manages projects.
type ProjectsService struct{ c *Client }

// Create creates a project; with ExternalID it is idempotent on it (an equal request returns the
// existing project with status 200, see WithResponse).
func (s *ProjectsService) Create(ctx context.Context, in ProjectCreate, opts ...CallOption) (*Project, error) {
	var out Project
	return &out, s.c.call(ctx, http.MethodPost, "/projects", nil, in, &out, opts...)
}

// List lists projects.
func (s *ProjectsService) List(ctx context.Context, o ListOptions) (*Page[Project], error) {
	var out Page[Project]
	return &out, s.c.call(ctx, http.MethodGet, "/projects", o.values(), nil, &out)
}

// GetByExternalID returns the project with this external ID.
func (s *ProjectsService) GetByExternalID(ctx context.Context, externalID string) (*Project, error) {
	return s.Get(ctx, externalID)
}

// Get returns a project by ID or external ID.
func (s *ProjectsService) Get(ctx context.Context, project string) (*Project, error) {
	path, err := p("projects", project)
	if err != nil {
		return nil, err
	}
	var out Project
	return &out, s.c.call(ctx, http.MethodGet, path, nil, nil, &out)
}

// Update changes a project (use IfMatch for a conditional write).
func (s *ProjectsService) Update(ctx context.Context, project string, in ProjectUpdate, opts ...CallOption) (*Project, error) {
	path, err := p("projects", project)
	if err != nil {
		return nil, err
	}
	var out Project
	return &out, s.c.call(ctx, http.MethodPatch, path, nil, in, &out, opts...)
}

// Delete deletes an empty project.
func (s *ProjectsService) Delete(ctx context.Context, project string, opts ...CallOption) error {
	path, err := p("projects", project)
	if err != nil {
		return err
	}
	return s.c.call(ctx, http.MethodDelete, path, nil, nil, nil, opts...)
}

// Quotas returns the project's quotas, use and ceilings.
func (s *ProjectsService) Quotas(ctx context.Context, project string) (*ProjectQuotas, error) {
	path, err := p("projects", project, "quotas")
	if err != nil {
		return nil, err
	}
	var out ProjectQuotas
	return &out, s.c.call(ctx, http.MethodGet, path, nil, nil, &out)
}

// SetQuotas replaces the project's quotas.
func (s *ProjectsService) SetQuotas(ctx context.Context, project string, q Quotas, opts ...CallOption) (*ProjectQuotas, error) {
	path, err := p("projects", project, "quotas")
	if err != nil {
		return nil, err
	}
	var out ProjectQuotas
	return &out, s.c.call(ctx, http.MethodPut, path, nil, q, &out, opts...)
}

// SetPool sets the project's pool.
func (s *ProjectsService) SetPool(ctx context.Context, project, pool string, opts ...CallOption) (*Project, error) {
	path, err := p("projects", project, "pool")
	if err != nil {
		return nil, err
	}
	var out Project
	return &out, s.c.call(ctx, http.MethodPut, path, nil, map[string]string{"pool": pool}, &out, opts...)
}

// ReportReferences sends the full list of machine IDs the consumer holds in the project.
func (s *ProjectsService) ReportReferences(ctx context.Context, project string, machines []string, opts ...CallOption) (*ReferenceReport, error) {
	path, err := p("projects", project, "references")
	if err != nil {
		return nil, err
	}
	if machines == nil {
		machines = []string{}
	}
	var out ReferenceReport
	return &out, s.c.call(ctx, http.MethodPut, path, nil, map[string][]string{"machines": machines}, &out, opts...)
}

// References returns the last two reference reports and the unreferenced machines.
func (s *ProjectsService) References(ctx context.Context, project string) (*ProjectReferences, error) {
	path, err := p("projects", project, "references")
	if err != nil {
		return nil, err
	}
	var out ProjectReferences
	return &out, s.c.call(ctx, http.MethodGet, path, nil, nil, &out)
}

// JobsService manages one-shot jobs.
type JobsService struct{ c *Client }

// Create creates and starts a job (202; the job is being placed).
func (s *JobsService) Create(ctx context.Context, in JobCreate, opts ...CallOption) (*Job, error) {
	var out Job
	return &out, s.c.call(ctx, http.MethodPost, "/jobs", nil, in, &out, opts...)
}

// List lists jobs.
func (s *JobsService) List(ctx context.Context, o ListOptions) (*Page[Job], error) {
	var out Page[Job]
	return &out, s.c.call(ctx, http.MethodGet, "/jobs", o.values(), nil, &out)
}

// Get returns a job.
func (s *JobsService) Get(ctx context.Context, id string) (*Job, error) {
	path, err := p("jobs", id)
	if err != nil {
		return nil, err
	}
	var out Job
	return &out, s.c.call(ctx, http.MethodGet, path, nil, nil, &out)
}

// Cancel kills the job's sandbox.
func (s *JobsService) Cancel(ctx context.Context, id string, opts ...CallOption) (*Job, error) {
	path, err := p("jobs", id, "cancel")
	if err != nil {
		return nil, err
	}
	var out Job
	return &out, s.c.call(ctx, http.MethodPost, path, nil, nil, &out, opts...)
}

// RenewLease renews the job's lease (0 keeps the current lease_seconds).
func (s *JobsService) RenewLease(ctx context.Context, id string, leaseSeconds int, opts ...CallOption) (*Lease, error) {
	path, err := p("jobs", id, "lease")
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

// Output returns a reader of the job's stdout (or stderr) from offset after. It follows the
// output, reconnects with the current offset after a dropped connection, and returns io.EOF
// once the job has exited and every byte was read.
func (s *JobsService) Output(ctx context.Context, id string, o OutputOptions) (*OutputReader, error) {
	path, err := p("jobs", id, "output")
	if err != nil {
		return nil, err
	}
	return newOutputReader(ctx, s.c, path, o), nil
}

// Wait polls the job until it has exited (or ctx ends).
func (s *JobsService) Wait(ctx context.Context, id string) (*Job, error) {
	return pollUntil(ctx, func() (*Job, bool, error) {
		j, err := s.Get(ctx, id)
		if err != nil {
			return nil, false, err
		}
		return j, j.Done(), nil
	})
}

// AddressesService lists public addresses.
type AddressesService struct{ c *Client }

// List lists the consumer's addresses, including released ones.
func (s *AddressesService) List(ctx context.Context, o ListOptions) (*Page[Address], error) {
	var out Page[Address]
	return &out, s.c.call(ctx, http.MethodGet, "/addresses", o.values(), nil, &out)
}

// Get returns one address with its history.
func (s *AddressesService) Get(ctx context.Context, address string) (*Address, error) {
	path, err := p("addresses", address)
	if err != nil {
		return nil, err
	}
	var out Address
	return &out, s.c.call(ctx, http.MethodGet, path, nil, nil, &out)
}

// PresetsService reads built-in presets and manages project presets.
type PresetsService struct{ c *Client }

// List lists built-in presets, plus the project's presets when o.Project is set.
func (s *PresetsService) List(ctx context.Context, o ListOptions) (*Page[Preset], error) {
	var out Page[Preset]
	return &out, s.c.call(ctx, http.MethodGet, "/presets", o.values(), nil, &out)
}

// Get returns a built-in preset ("name" or "name@version").
func (s *PresetsService) Get(ctx context.Context, name string) (*Preset, error) {
	path, err := p("presets", name)
	if err != nil {
		return nil, err
	}
	var out Preset
	return &out, s.c.call(ctx, http.MethodGet, path, nil, nil, &out)
}

// ListProject lists a project's presets.
func (s *PresetsService) ListProject(ctx context.Context, project string, o ListOptions) (*Page[Preset], error) {
	path, err := p("projects", project, "presets")
	if err != nil {
		return nil, err
	}
	o.Project = ""
	var out Page[Preset]
	return &out, s.c.call(ctx, http.MethodGet, path, o.values(), nil, &out)
}

// GetProject returns a project preset.
func (s *PresetsService) GetProject(ctx context.Context, project, name string) (*Preset, error) {
	path, err := p("projects", project, "presets", name)
	if err != nil {
		return nil, err
	}
	var out Preset
	return &out, s.c.call(ctx, http.MethodGet, path, nil, nil, &out)
}

// PutProject creates a new version of a project preset.
func (s *PresetsService) PutProject(ctx context.Context, project, name string, in PresetPut, opts ...CallOption) (*Preset, error) {
	path, err := p("projects", project, "presets", name)
	if err != nil {
		return nil, err
	}
	var out Preset
	return &out, s.c.call(ctx, http.MethodPut, path, nil, in, &out, opts...)
}

// DeleteProject deletes a project preset.
func (s *PresetsService) DeleteProject(ctx context.Context, project, name string, opts ...CallOption) error {
	path, err := p("projects", project, "presets", name)
	if err != nil {
		return err
	}
	return s.c.call(ctx, http.MethodDelete, path, nil, nil, nil, opts...)
}

// ProfilesService reads profiles.
type ProfilesService struct{ c *Client }

// List lists the profiles the consumer may use (kind "" for all).
func (s *ProfilesService) List(ctx context.Context, kind TemplateKind) ([]Profile, error) {
	q := url.Values{}
	if kind != "" {
		q.Set("kind", string(kind))
	}
	var out struct {
		Data []Profile `json:"data"`
	}
	return out.Data, s.c.call(ctx, http.MethodGet, "/profiles", q, nil, &out)
}

// Get returns one profile.
func (s *ProfilesService) Get(ctx context.Context, name string) (*Profile, error) {
	path, err := p("profiles", name)
	if err != nil {
		return nil, err
	}
	var out Profile
	return &out, s.c.call(ctx, http.MethodGet, path, nil, nil, &out)
}
