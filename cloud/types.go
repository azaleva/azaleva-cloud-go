package cloud

import (
	"encoding/json"
	"time"
)

// Labels are key/value data on a resource (≤ 32; keys ≤ 63, values ≤ 255 characters).
type Labels map[string]string

// Int returns a pointer to v (for optional and nullable integer fields).
func Int(v int) *int { return &v }

// Bool returns a pointer to v.
func Bool(v bool) *bool { return &v }

// String returns a pointer to v.
func String(v string) *string { return &v }

// Scope is an API key scope.
type Scope string

// API key scopes.
const (
	ScopeJobs             Scope = "jobs"
	ScopeJobsUnsupervised Scope = "jobs:unsupervised"
	ScopeSandboxes        Scope = "sandboxes"
	ScopeMachines         Scope = "machines"
	ScopeMachinesExec     Scope = "machines:exec"
	ScopeMachinesRoot     Scope = "machines:root"
	ScopeTerminals        Scope = "terminals"
	ScopeNetwork          Scope = "network"
	ScopeTemplates        Scope = "templates"
	ScopeProjects         Scope = "projects"
	ScopeUsage            Scope = "usage"
	ScopeEvents           Scope = "events"
	// ScopeMachinesServices opens the transport to a machine's declared services (policy app).
	ScopeMachinesServices Scope = "machines:services"
	// ScopeMachinesCompanion opens the transport to a machine's agent-companion (policy
	// companion). Neither transport scope implies the other.
	ScopeMachinesCompanion Scope = "machines:companion"
)

// AllScopes lists every consumer scope.
var AllScopes = []Scope{ScopeJobs, ScopeJobsUnsupervised, ScopeSandboxes, ScopeMachines, ScopeMachinesExec,
	ScopeMachinesRoot, ScopeTerminals, ScopeNetwork, ScopeTemplates, ScopeProjects, ScopeUsage, ScopeEvents,
	ScopeMachinesServices, ScopeMachinesCompanion}

// Page is one page of a list.
type Page[T any] struct {
	Data       []T     `json:"data"`
	NextCursor *string `json:"next_cursor"`
}

// ListOptions are the common list parameters.
type ListOptions struct {
	Limit  int
	Cursor string
	// Project filters by project ID or external ID.
	Project string
	// Labels filters by labels (all must match).
	Labels Labels
	States []string
	Node   string
}

// ConsumerSelf is the calling consumer.
type ConsumerSelf struct {
	ID                       string   `json:"id"`
	Name                     string   `json:"name"`
	Pools                    []string `json:"pools"`
	Ceilings                 Quotas   `json:"ceilings"`
	AllowedProfiles          []string `json:"allowed_profiles"`
	AllowedTemplates         []string `json:"allowed_templates"`
	OperatorTerminalsDefault bool     `json:"operator_terminals_default,omitempty"`
	Key                      struct {
		ID        string     `json:"id"`
		Scopes    []Scope    `json:"scopes"`
		Project   *string    `json:"project"`
		ExpiresAt *time.Time `json:"expires_at"`
	} `json:"key"`
}

// Quotas are limits; nil is unlimited.
type Quotas struct {
	ConcurrentJobs          *int         `json:"concurrent_jobs,omitempty"`
	ConcurrentSandboxes     *int         `json:"concurrent_sandboxes,omitempty"`
	RunningVCPU             *int         `json:"running_vcpu,omitempty"`
	RunningMemoryMiB        *int         `json:"running_memory_mib,omitempty"`
	Machines                *int         `json:"machines,omitempty"`
	AlwaysOnMachines        *int         `json:"always_on_machines,omitempty"`
	AlwaysOnMemoryMiB       *int         `json:"always_on_memory_mib,omitempty"`
	PublicAddresses         *int         `json:"public_addresses,omitempty"`
	InboundPortsPerMachine  *int         `json:"inbound_ports_per_machine,omitempty"`
	CustomDomainsPerMachine *int         `json:"custom_domains_per_machine,omitempty"`
	AllowedEgressModes      []EgressMode `json:"allowed_egress_modes,omitempty"`
	Templates               *int         `json:"templates,omitempty"`
	TemplateVersionsKept    *int         `json:"template_versions_kept,omitempty"`
}

// QuotaUse is the current use of the counted quotas.
type QuotaUse struct {
	ConcurrentJobs      int `json:"concurrent_jobs"`
	ConcurrentSandboxes int `json:"concurrent_sandboxes"`
	RunningVCPU         int `json:"running_vcpu"`
	RunningMemoryMiB    int `json:"running_memory_mib"`
	Machines            int `json:"machines"`
	AlwaysOnMachines    int `json:"always_on_machines"`
	AlwaysOnMemoryMiB   int `json:"always_on_memory_mib"`
	PublicAddresses     int `json:"public_addresses"`
}

// ProjectQuotas is a project's limits, use and the consumer's ceilings.
type ProjectQuotas struct {
	Project  string   `json:"project"`
	Limits   Quotas   `json:"limits"`
	Used     QuotaUse `json:"used"`
	Ceilings Quotas   `json:"ceilings"`
	Version  int64    `json:"version"`
}

// Project groups a consumer's resources.
type Project struct {
	ID               string    `json:"id"`
	Consumer         string    `json:"consumer,omitempty"`
	ExternalID       *string   `json:"external_id"`
	Name             string    `json:"name"`
	Pool             string    `json:"pool"`
	Quotas           Quotas    `json:"quotas"`
	Labels           Labels    `json:"labels"`
	OperatorTerminal bool      `json:"operator_terminal"`
	State            string    `json:"state"`
	CreatedAt        time.Time `json:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"`
	Version          int64     `json:"version"`
}

// ProjectCreate creates a project.
type ProjectCreate struct {
	ExternalID       string  `json:"external_id,omitempty"`
	Name             string  `json:"name"`
	Pool             string  `json:"pool,omitempty"`
	Quotas           *Quotas `json:"quotas,omitempty"`
	Labels           Labels  `json:"labels,omitempty"`
	OperatorTerminal *bool   `json:"operator_terminal,omitempty"`
}

// ProjectUpdate changes a project; nil fields are left unchanged.
type ProjectUpdate struct {
	Name             *string `json:"name,omitempty"`
	Labels           Labels  `json:"labels,omitempty"`
	OperatorTerminal *bool   `json:"operator_terminal,omitempty"`
}

// ReferenceReport is a stored reference report.
type ReferenceReport struct {
	ID            string    `json:"id"`
	Project       string    `json:"project"`
	ReceivedAt    time.Time `json:"received_at"`
	MachinesCount int       `json:"machines_count"`
	Unknown       []string  `json:"unknown"`
}

// ProjectReferences is the last two reports and the unreferenced machines.
type ProjectReferences struct {
	Project      string            `json:"project"`
	Reports      []ReferenceReport `json:"reports"`
	Unreferenced []string          `json:"unreferenced"`
}

// EgressMode is none, allowlist or internet.
type EgressMode string

// Egress modes.
const (
	EgressNone      EgressMode = "none"
	EgressAllowlist EgressMode = "allowlist"
	EgressInternet  EgressMode = "internet"
)

// EgressRule is a non-HTTP egress rule (host or cidr).
type EgressRule struct {
	Proto string `json:"proto"`
	Host  string `json:"host,omitempty"`
	CIDR  string `json:"cidr,omitempty"`
	Ports string `json:"ports"`
}

// EgressPolicy is a sandbox's, job's or machine's egress policy.
type EgressPolicy struct {
	Mode    EgressMode   `json:"mode"`
	Presets []string     `json:"presets,omitempty"`
	Domains []string     `json:"domains,omitempty"`
	Rules   []EgressRule `json:"rules,omitempty"`
}

// InboundRule opens a port range of a machine's public address.
type InboundRule struct {
	Proto  string `json:"proto"`
	Ports  string `json:"ports"`
	Source string `json:"source,omitempty"`
}

// ChangeActor is opaque attribution for the change log.
type ChangeActor struct {
	Actor  string `json:"actor,omitempty"`
	Reason string `json:"reason,omitempty"`
}

// NetworkChange is one network change and its delivery state.
type NetworkChange struct {
	ID        string     `json:"id"`
	Machine   string     `json:"machine,omitempty"`
	Kind      string     `json:"kind"`
	State     string     `json:"state"`
	Actor     string     `json:"actor,omitempty"`
	Reason    string     `json:"reason,omitempty"`
	Version   int64      `json:"version,omitempty"`
	Error     string     `json:"error,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
	AppliedAt *time.Time `json:"applied_at"`
}

// EgressPut replaces a machine's egress policy.
type EgressPut struct {
	EgressPolicy
	ChangeActor
}

// MachineEgress is a machine's egress policy.
type MachineEgress struct {
	Machine string         `json:"machine"`
	Policy  EgressPolicy   `json:"policy"`
	Version int64          `json:"version"`
	Change  *NetworkChange `json:"change,omitempty"`
}

// InboundPut replaces a machine's inbound rules.
type InboundPut struct {
	Rules []InboundRule `json:"rules"`
	ChangeActor
}

// MachineInbound is a machine's inbound rules.
type MachineInbound struct {
	Machine string         `json:"machine"`
	Rules   []InboundRule  `json:"rules"`
	Version int64          `json:"version"`
	Change  *NetworkChange `json:"change,omitempty"`
}

// AddressAssignment is one past assignment of an address.
type AddressAssignment struct {
	Machine    string     `json:"machine"`
	AssignedAt time.Time  `json:"assigned_at"`
	ReleasedAt *time.Time `json:"released_at"`
	Actor      string     `json:"actor,omitempty"`
}

// Address is a public IPv6 address.
type Address struct {
	Address       string              `json:"address"`
	Project       string              `json:"project"`
	Machine       *string             `json:"machine"`
	Node          string              `json:"node"`
	State         string              `json:"state"`
	AssignedAt    time.Time           `json:"assigned_at"`
	ReleasedAt    *time.Time          `json:"released_at"`
	ReusableAfter *time.Time          `json:"reusable_after"`
	History       []AddressAssignment `json:"history,omitempty"`
}

// EgressDecision is one entry of the decisions log.
type EgressDecision struct {
	Time        time.Time `json:"time"`
	Proto       string    `json:"proto"`
	Destination string    `json:"destination"`
	Port        int       `json:"port"`
	Decision    string    `json:"decision"`
	Reason      string    `json:"reason,omitempty"`
}

// MachineNetwork is the effective network state of a machine.
type MachineNetwork struct {
	Machine  string         `json:"machine"`
	Egress   MachineEgress  `json:"egress"`
	Address  *Address       `json:"address"`
	Inbound  MachineInbound `json:"inbound"`
	Delivery struct {
		State      string     `json:"state"`
		Generation int64      `json:"generation"`
		AppliedAt  *time.Time `json:"applied_at"`
		Error      string     `json:"error,omitempty"`
	} `json:"delivery"`
	Binding        string           `json:"binding,omitempty"`
	AddressState   string           `json:"address_state,omitempty"`
	EffectiveRules []string         `json:"effective_rules,omitempty"`
	Changes        []NetworkChange  `json:"changes,omitempty"`
	Decisions      []EgressDecision `json:"decisions,omitempty"`
}

// Preset is a named set of egress domains and rules.
type Preset struct {
	Name        string       `json:"name"`
	Version     int          `json:"version"`
	Scope       string       `json:"scope"`
	Project     string       `json:"project,omitempty"`
	Category    string       `json:"category,omitempty"`
	Description string       `json:"description,omitempty"`
	Domains     []string     `json:"domains"`
	Rules       []EgressRule `json:"rules"`
	CreatedAt   time.Time    `json:"created_at"`
}

// PresetPut creates a new version of a project preset.
type PresetPut struct {
	Category    string       `json:"category,omitempty"`
	Description string       `json:"description,omitempty"`
	Domains     []string     `json:"domains"`
	Rules       []EgressRule `json:"rules,omitempty"`
}

// TemplateKind is job or machine.
type TemplateKind string

// Template kinds.
const (
	KindJob     TemplateKind = "job"
	KindMachine TemplateKind = "machine"
)

// TemplateBuild is a template's build on one node.
type TemplateBuild struct {
	Node       string     `json:"node"`
	State      string     `json:"state"`
	BuildID    string     `json:"build_id,omitempty"`
	StartedAt  *time.Time `json:"started_at"`
	FinishedAt *time.Time `json:"finished_at"`
	Error      string     `json:"error,omitempty"`
}

// Template is a built-in or consumer template version.
type Template struct {
	ID         string          `json:"id"`
	Name       string          `json:"name"`
	Version    int             `json:"version"`
	Kind       TemplateKind    `json:"kind"`
	Origin     string          `json:"origin"`
	Consumer   string          `json:"consumer,omitempty"`
	RecipeHash string          `json:"recipe_hash,omitempty"`
	Signer     string          `json:"signer,omitempty"`
	SDK        string          `json:"sdk,omitempty"`
	SizeBytes  int64           `json:"size_bytes,omitempty"`
	State      string          `json:"state"`
	Builds     []TemplateBuild `json:"builds"`
	// Services are the guest services machines of this template run (policy app).
	Services  []ServiceDeclaration `json:"services,omitempty"`
	CreatedAt time.Time            `json:"created_at"`
	// Pinned: the consumer pinned this version (Templates.Pin); it cannot be deleted, or pruned
	// by template_versions_kept, until it is unpinned. PinnedAt is when (absent: not pinned).
	Pinned   bool       `json:"pinned"`
	PinnedAt *time.Time `json:"pinned_at,omitempty"`
}

// Ref returns "name@version".
func (t Template) Ref() string { return t.Name + "@" + itoa(t.Version) }

// Profile is a size.
type Profile struct {
	Name             string        `json:"name"`
	Kind             TemplateKind  `json:"kind"`
	Description      string        `json:"description,omitempty"`
	VCPU             int           `json:"vcpu"`
	MemoryMiB        int           `json:"memory_mib"`
	DiskMiB          int           `json:"disk_mib"`
	TimeoutSeconds   int           `json:"timeout_seconds,omitempty"`
	Modes            []MachineMode `json:"modes,omitempty"`
	IdlePauseSeconds int           `json:"idle_pause_seconds,omitempty"`
	Egress           *struct {
		Max     EgressMode `json:"max"`
		Default EgressMode `json:"default"`
	} `json:"egress,omitempty"`
	Backend  string `json:"backend,omitempty"`
	Hostname string `json:"hostname,omitempty"`
	// Templates are the templates that may use the profile (names, exact or with a trailing
	// "*"); empty: every template. See AllowsTemplate.
	Templates          []string `json:"templates,omitempty"`
	MaxConcurrentExecs int      `json:"max_concurrent_execs,omitempty"`
	MaxTerminals       int      `json:"max_terminals,omitempty"`
	// CheckpointSeconds is how long a running machine of this profile runs before its node
	// checkpoints it (pause and resume); 0: the node's default (30 min). The node keeps it inside
	// the run cap of its sandbox runtime (one hour by default, up to 24 hours), so a long period
	// takes effect only where runs are allowed to be that long. Each checkpoint writes a snapshot
	// layer that can hold the machine's whole memory, so longer is cheaper.
	CheckpointSeconds int `json:"checkpoint_seconds,omitempty"`
	// Pools are the pools whose nodes run this profile; empty: every pool. A project in another
	// pool cannot use it (400, field error on profile, code not_in_pool).
	Pools []string `json:"pools,omitempty"`
	// DefaultMode (machine profiles) is the mode of a machine created without one; absent:
	// on_demand.
	DefaultMode MachineMode `json:"default_mode,omitempty"`
	// Restart (machine profiles) overrides what a restart keeps: keep_disk (the whole disk) or
	// fresh_template (a new machine from the template, /workspace carried over). Absent: by the
	// machine's mode (always_on keeps the disk, on_demand starts from the template).
	Restart string `json:"restart,omitempty"`
	// DefaultUser (machine profiles) is the user execs, files and terminals run as when a request
	// names none: `agent` (absent) or `root`. Root still needs the machines:root scope.
	DefaultUser string `json:"default_user,omitempty"`
}

// AllowsPool reports whether the profile may run in a pool.
func (p Profile) AllowsPool(pool string) bool {
	if len(p.Pools) == 0 {
		return true
	}
	for _, x := range p.Pools {
		if x == pool {
			return true
		}
	}
	return false
}

// AllowsTemplate reports whether a template (by name, without its version) may use the
// profile: a profile with no Templates allows every template; otherwise the name must match an
// entry exactly, or an entry ending in "*" by prefix (TemplateNameAllowed).
func (p Profile) AllowsTemplate(name string) bool {
	return len(p.Templates) == 0 || TemplateNameAllowed(p.Templates, name)
}

// Capacity is a capacity hint for a pool.
type Capacity struct {
	Pool             string `json:"pool"`
	Profile          string `json:"profile,omitempty"`
	NodesSchedulable int    `json:"nodes_schedulable"`
	JobSlotsFree     int    `json:"job_slots_free"`
	MemoryFreeMiB    int    `json:"memory_free_mib"`
	// VCPUFree is the vCPUs the pool's nodes may still give (node CPUs times the overcommit).
	VCPUFree int `json:"vcpu_free"`
	// DiskAllocatableMiB is the disk the pool's nodes may still allocate (machine disks are
	// sparse: allocated is what they may grow to, not what they use).
	DiskAllocatableMiB int `json:"disk_allocatable_mib"`
	// BuildReservedMiB is the sandbox memory the pool's template builds hold (MemoryFreeMiB
	// leaves it out).
	BuildReservedMiB int       `json:"build_reserved_mib"`
	Fits             int       `json:"fits,omitempty"`
	AsOf             time.Time `json:"as_of"`
}

// Lease is a renewed lease.
type Lease struct {
	LeaseSeconds   int       `json:"lease_seconds"`
	LeaseExpiresAt time.Time `json:"lease_expires_at"`
}

// JobFile is written into the job's sandbox before the exec starts.
type JobFile struct {
	Path    string `json:"path"`
	Content []byte `json:"content_b64"`
	Owner   string `json:"owner,omitempty"` // root (default) or user
	Mode    string `json:"mode,omitempty"`  // default 0400
}

// JobFileInfo describes a written job file (without content).
type JobFileInfo struct {
	Path  string `json:"path"`
	Owner string `json:"owner"`
	Mode  string `json:"mode"`
	Size  int64  `json:"size"`
}

// Supervisor configures cloud-guest for a job's exec. The zero value means the defaults;
// Unsupervised (needs the jobs:unsupervised scope) runs the program without it.
type Supervisor struct {
	Unsupervised bool
	UID          int
	Seccomp      string // default or strict
	RLimits      *RLimits
}

// RLimits are resource limits for a supervised program.
type RLimits struct {
	Processes     int   `json:"processes,omitempty"`
	OpenFiles     int   `json:"open_files,omitempty"`
	FileSizeBytes int64 `json:"file_size_bytes,omitempty"`
	CPUSeconds    int   `json:"cpu_seconds,omitempty"`
}

type supervisorConfig struct {
	UID     int      `json:"uid,omitempty"`
	Seccomp string   `json:"seccomp,omitempty"`
	RLimits *RLimits `json:"rlimits,omitempty"`
}

// MarshalJSON encodes "none" or the configuration object.
func (s Supervisor) MarshalJSON() ([]byte, error) {
	if s.Unsupervised {
		return []byte(`"none"`), nil
	}
	return json.Marshal(supervisorConfig{UID: s.UID, Seccomp: s.Seccomp, RLimits: s.RLimits})
}

// UnmarshalJSON decodes "none" or the configuration object.
func (s *Supervisor) UnmarshalJSON(b []byte) error {
	if string(b) == `"none"` {
		*s = Supervisor{Unsupervised: true}
		return nil
	}
	var c supervisorConfig
	if err := json.Unmarshal(b, &c); err != nil {
		return err
	}
	*s = Supervisor{UID: c.UID, Seccomp: c.Seccomp, RLimits: c.RLimits}
	return nil
}

// JobExec is the program a job runs.
type JobExec struct {
	Argv           []string          `json:"argv"`
	Cwd            string            `json:"cwd,omitempty"`
	Env            map[string]string `json:"env,omitempty"`
	SecretEnv      map[string]string `json:"secret_env,omitempty"`
	Stdin          []byte            `json:"stdin_b64,omitempty"`
	TimeoutSeconds int               `json:"timeout_seconds,omitempty"`
}

// JobOutputSpec controls the output journal.
type JobOutputSpec struct {
	Framing       string `json:"framing,omitempty"` // raw (default) or lines
	MaxFrameBytes int    `json:"max_frame_bytes,omitempty"`
}

// JobCreate creates a job.
type JobCreate struct {
	Project      string         `json:"project"`
	Template     string         `json:"template"`
	Profile      string         `json:"profile"`
	TTLSeconds   int            `json:"ttl_seconds,omitempty"`
	LeaseSeconds *int           `json:"lease_seconds,omitempty"`
	Egress       *EgressPolicy  `json:"egress,omitempty"`
	Gateway      bool           `json:"gateway,omitempty"`
	Files        []JobFile      `json:"files,omitempty"`
	Exec         JobExec        `json:"exec"`
	Output       *JobOutputSpec `json:"output,omitempty"`
	Supervisor   *Supervisor    `json:"supervisor,omitempty"`
	Labels       Labels         `json:"labels,omitempty"`
}

// Job states and outcomes.
const (
	JobPlacing  = "placing"
	JobCreating = "creating"
	JobBinding  = "binding"
	JobStarting = "starting"
	JobRunning  = "running"
	JobExited   = "exited"

	OutcomeSucceeded   = "succeeded"
	OutcomeFailed      = "failed"
	OutcomeKilled      = "killed"
	OutcomeInterrupted = "interrupted"
	OutcomeRefused     = "refused"
)

// Job is a one-shot job.
type Job struct {
	ID             string        `json:"id"`
	Project        string        `json:"project"`
	Template       string        `json:"template"`
	Profile        string        `json:"profile"`
	Sandbox        *string       `json:"sandbox"`
	Node           *string       `json:"node"`
	State          string        `json:"state"`
	Outcome        *string       `json:"outcome"`
	OutcomeReason  *string       `json:"outcome_reason"`
	ExitCode       *int          `json:"exit_code"`
	TTLSeconds     int           `json:"ttl_seconds"`
	ExpiresAt      time.Time     `json:"expires_at"`
	LeaseSeconds   *int          `json:"lease_seconds"`
	LeaseExpiresAt *time.Time    `json:"lease_expires_at"`
	Egress         EgressPolicy  `json:"egress"`
	Gateway        bool          `json:"gateway"`
	Files          []JobFileInfo `json:"files,omitempty"`
	Exec           struct {
		Argv           []string          `json:"argv"`
		Cwd            string            `json:"cwd,omitempty"`
		Env            map[string]string `json:"env,omitempty"`
		SecretEnvKeys  []string          `json:"secret_env_keys,omitempty"`
		StdinBytes     int               `json:"stdin_bytes,omitempty"`
		TimeoutSeconds int               `json:"timeout_seconds,omitempty"`
	} `json:"exec"`
	Output struct {
		Framing       string     `json:"framing"`
		MaxFrameBytes int        `json:"max_frame_bytes"`
		StdoutBytes   int64      `json:"stdout_bytes"`
		StderrBytes   int64      `json:"stderr_bytes"`
		RetainedUntil *time.Time `json:"retained_until"`
	} `json:"output"`
	Supervisor *Supervisor `json:"supervisor,omitempty"`
	Labels     Labels      `json:"labels"`
	CreatedAt  time.Time   `json:"created_at"`
	StartedAt  *time.Time  `json:"started_at"`
	ExitedAt   *time.Time  `json:"exited_at"`
	Version    int64       `json:"version"`
}

// Done reports whether the job has exited (it has an outcome).
func (j *Job) Done() bool { return j.State == JobExited }

// SandboxCreate creates a sandbox.
type SandboxCreate struct {
	Project      string        `json:"project"`
	Template     string        `json:"template"`
	Profile      string        `json:"profile"`
	TTLSeconds   int           `json:"ttl_seconds,omitempty"`
	LeaseSeconds *int          `json:"lease_seconds,omitempty"`
	Egress       *EgressPolicy `json:"egress,omitempty"`
	Gateway      bool          `json:"gateway,omitempty"`
	Labels       Labels        `json:"labels,omitempty"`
}

// Sandbox is an ephemeral sandbox.
type Sandbox struct {
	ID             string       `json:"id"`
	Project        string       `json:"project"`
	Template       string       `json:"template"`
	Profile        string       `json:"profile"`
	Node           *string      `json:"node"`
	State          string       `json:"state"`
	StateReason    *string      `json:"state_reason"`
	Job            *string      `json:"job"`
	TTLSeconds     int          `json:"ttl_seconds"`
	ExpiresAt      time.Time    `json:"expires_at"`
	LeaseSeconds   *int         `json:"lease_seconds"`
	LeaseExpiresAt *time.Time   `json:"lease_expires_at"`
	Egress         EgressPolicy `json:"egress"`
	Gateway        bool         `json:"gateway"`
	Labels         Labels       `json:"labels"`
	CreatedAt      time.Time    `json:"created_at"`
	DestroyedAt    *time.Time   `json:"destroyed_at"`
	Version        int64        `json:"version"`
}

// ExecRequest runs a command on a machine or sandbox. Set exactly one of Argv or Shell.
type ExecRequest struct {
	Argv  []string          `json:"argv,omitempty"`
	Shell string            `json:"shell,omitempty"`
	User  string            `json:"user,omitempty"` // agent (default) or root
	Cwd   string            `json:"cwd,omitempty"`
	Env   map[string]string `json:"env,omitempty"`
	Stdin []byte            `json:"stdin_b64,omitempty"`
	// TimeoutSeconds (default 60, ≤ 300 without Async): then the command and every process
	// it started are killed. The exec completes when its command exits: background
	// processes it started keep running, and their later output is not the exec's.
	TimeoutSeconds int    `json:"timeout_seconds,omitempty"`
	OutputCapBytes int    `json:"output_cap_bytes,omitempty"`
	Async          bool   `json:"async,omitempty"`
	Actor          string `json:"actor,omitempty"`
}

// Exec is a command on a machine or sandbox.
type Exec struct {
	ID     string `json:"id"`
	Target struct {
		Kind string `json:"kind"`
		ID   string `json:"id"`
	} `json:"target"`
	Argv          []string   `json:"argv,omitempty"`
	Shell         string     `json:"shell,omitempty"`
	User          string     `json:"user"`
	Cwd           string     `json:"cwd,omitempty"`
	State         string     `json:"state"`
	Outcome       *string    `json:"outcome"`
	OutcomeReason *string    `json:"outcome_reason"`
	ExitCode      *int       `json:"exit_code"`
	Stdout        []byte     `json:"stdout_b64,omitempty"`
	Stderr        []byte     `json:"stderr_b64,omitempty"`
	StdoutBytes   int64      `json:"stdout_bytes"`
	StderrBytes   int64      `json:"stderr_bytes"`
	Truncated     bool       `json:"truncated"`
	Actor         string     `json:"actor,omitempty"`
	StartedAt     time.Time  `json:"started_at"`
	ExitedAt      *time.Time `json:"exited_at"`
}

// FileEntry is a directory entry.
type FileEntry struct {
	Name       string    `json:"name"`
	Path       string    `json:"path"`
	Type       string    `json:"type"`
	Size       int64     `json:"size"`
	Mode       string    `json:"mode"`
	Owner      string    `json:"owner,omitempty"`
	Target     string    `json:"target,omitempty"`
	ModifiedAt time.Time `json:"modified_at"`
}

// FileList is a directory listing.
type FileList struct {
	Path    string      `json:"path"`
	Entries []FileEntry `json:"entries"`
}

// TreeFile is one file of a read-only tree.
type TreeFile struct {
	Path    string `json:"path"`
	Content []byte `json:"content_b64,omitempty"`
	Mode    string `json:"mode,omitempty"`
	Symlink string `json:"symlink,omitempty"`
}

// FileTree replaces a directory atomically with a root-owned read-only tree.
type FileTree struct {
	Root  string     `json:"root"`
	Files []TreeFile `json:"files"`
}

// FileTreeResult is the stored tree.
type FileTreeResult struct {
	Root    string `json:"root"`
	Digest  string `json:"digest"`
	Files   int    `json:"files"`
	Bytes   int64  `json:"bytes"`
	Changed bool   `json:"changed"`
}

// ArchiveRequest asks for a tar.gz of a directory.
type ArchiveRequest struct {
	Path   string `json:"path"`
	Format string `json:"format,omitempty"`
	User   string `json:"user,omitempty"`
}

// MachineMode is on_demand or always_on.
type MachineMode string

// Machine modes.
const (
	OnDemand MachineMode = "on_demand"
	AlwaysOn MachineMode = "always_on"
)

// Machine states.
const (
	MachineCreating   = "creating"
	MachineStarting   = "starting"
	MachineReady      = "ready"
	MachinePaused     = "paused"
	MachineStopped    = "stopped"
	MachineRestarting = "restarting"
	MachineMigrating  = "migrating"
	MachineError      = "error"
	MachineDestroyed  = "destroyed"
)

// MachineCreate creates a machine.
type MachineCreate struct {
	Project  string        `json:"project"`
	Template string        `json:"template"`
	Profile  string        `json:"profile"`
	Mode     MachineMode   `json:"mode,omitempty"`
	Hold     bool          `json:"hold,omitempty"`
	Hostname string        `json:"hostname,omitempty"`
	Egress   *EgressPolicy `json:"egress,omitempty"`
	Address  bool          `json:"address,omitempty"`
	Inbound  []InboundRule `json:"inbound,omitempty"`
	Gateway  bool          `json:"gateway,omitempty"`
	Labels   Labels        `json:"labels,omitempty"`
}

// MachineUpdate changes a machine; nil fields are left unchanged.
type MachineUpdate struct {
	Profile *string      `json:"profile,omitempty"`
	Mode    *MachineMode `json:"mode,omitempty"`
	Hold    *bool        `json:"hold,omitempty"`
	Labels  Labels       `json:"labels,omitempty"`
}

// Machine is a persistent machine.
type Machine struct {
	ID                     string        `json:"id"`
	Project                string        `json:"project"`
	Template               string        `json:"template"`
	Profile                string        `json:"profile"`
	EffectiveProfile       string        `json:"effective_profile"`
	Mode                   MachineMode   `json:"mode"`
	Hold                   bool          `json:"hold"`
	Node                   *string       `json:"node"`
	State                  string        `json:"state"`
	StateReason            *string       `json:"state_reason"`
	Hostname               string        `json:"hostname,omitempty"`
	RunningSince           *time.Time    `json:"running_since"`
	LastCheckpointAt       *time.Time    `json:"last_checkpoint_at"`
	Egress                 EgressPolicy  `json:"egress"`
	EgressVersion          int64         `json:"egress_version,omitempty"`
	Address                *string       `json:"address"`
	Inbound                []InboundRule `json:"inbound"`
	Gateway                bool          `json:"gateway"`
	Labels                 Labels        `json:"labels"`
	Protected              bool          `json:"protected"`
	NewerTemplateAvailable bool          `json:"newer_template_available,omitempty"`
	// LatestTemplate is the newest ready version of the machine's template (set with
	// NewerTemplateAvailable): Reset moves the machine to it.
	LatestTemplate string `json:"latest_template,omitempty"`
	// Restart is what a restart keeps: keep_disk or fresh_template (the profile's restart, else
	// by mode: always_on keeps the disk).
	Restart string `json:"restart,omitempty"`
	Usage   *struct {
		RunningSeconds int64 `json:"running_seconds"`
		PausedSeconds  int64 `json:"paused_seconds"`
	} `json:"usage,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Version   int64     `json:"version"`
}

// Restart policies of a machine (Machine.Restart, Profile.Restart).
const (
	RestartKeepDisk      = "keep_disk"
	RestartFreshTemplate = "fresh_template"
)

// MachineReset rebuilds a machine from its template's newest ready version (or Template),
// keeping /workspace only: everything else on its disk is lost, so ConfirmDiskReset must be
// true.
type MachineReset struct {
	ConfirmDiskReset bool   `json:"confirm_disk_reset"`
	Template         string `json:"template,omitempty"`
}

// MachineMetrics is a sample of a machine's resource use.
type MachineMetrics struct {
	Machine        string    `json:"machine"`
	CPUPercent     float64   `json:"cpu_percent"`
	MemoryUsedMiB  int       `json:"memory_used_mib"`
	MemoryTotalMiB int       `json:"memory_total_mib"`
	DiskUsedMiB    int       `json:"disk_used_mib"`
	DiskTotalMiB   int       `json:"disk_total_mib"`
	SampledAt      time.Time `json:"sampled_at"`
}

// TerminalCreate opens a PTY.
type TerminalCreate struct {
	Rows               int      `json:"rows,omitempty"`
	Cols               int      `json:"cols,omitempty"`
	User               string   `json:"user,omitempty"`
	Command            []string `json:"command,omitempty"`
	Actor              string   `json:"actor,omitempty"`
	IdleTimeoutSeconds int      `json:"idle_timeout_seconds,omitempty"`
	MaxSeconds         int      `json:"max_seconds,omitempty"`
}

// Terminal is a PTY session.
type Terminal struct {
	ID                 string     `json:"id"`
	Machine            string     `json:"machine"`
	Actor              string     `json:"actor,omitempty"`
	Operator           string     `json:"operator,omitempty"`
	User               string     `json:"user"`
	Rows               int        `json:"rows"`
	Cols               int        `json:"cols"`
	State              string     `json:"state"`
	CloseReason        *string    `json:"close_reason"`
	ExitCode           *int       `json:"exit_code"`
	IdleTimeoutSeconds int        `json:"idle_timeout_seconds,omitempty"`
	MaxSeconds         int        `json:"max_seconds,omitempty"`
	CreatedAt          time.Time  `json:"created_at"`
	ClosedAt           *time.Time `json:"closed_at"`
}

// EventType is an event type. Consumers must ignore types they do not know.
type EventType string

// Event types of v1.
const (
	EventJobStarted            EventType = "job.started"
	EventJobExited             EventType = "job.exited"
	EventSandboxState          EventType = "sandbox.state"
	EventMachineState          EventType = "machine.state"
	EventMachineOperatorAction EventType = "machine.operator_action"
	EventTerminalClosed        EventType = "terminal.closed"
	EventNetworkChange         EventType = "network.change"
	EventAddressAssigned       EventType = "address.assigned"
	EventAddressReleased       EventType = "address.released"
	EventTemplateBuild         EventType = "template.build"
	EventNodeUnavailable       EventType = "node.unavailable"
	EventNodeAvailable         EventType = "node.available"
	EventUsagePeriodClosed     EventType = "usage.period_closed"
)

// EventTypes lists the event types of v1.
var EventTypes = []EventType{EventJobStarted, EventJobExited, EventSandboxState, EventMachineState, EventMachineOperatorAction,
	EventTerminalClosed, EventNetworkChange, EventAddressAssigned, EventAddressReleased, EventTemplateBuild,
	EventNodeUnavailable, EventNodeAvailable, EventUsagePeriodClosed}

// Event is one entry of the consumer's event log.
type Event struct {
	ID       string    `json:"id"`
	Seq      int64     `json:"seq"`
	Type     EventType `json:"type"`
	Time     time.Time `json:"time"`
	Project  *string   `json:"project"`
	Resource struct {
		Kind string `json:"kind"`
		ID   string `json:"id"`
	} `json:"resource"`
	Data json.RawMessage `json:"data"`
}

// DecodeData decodes the event's data into v (for example EventJobData).
func (e *Event) DecodeData(v any) error { return json.Unmarshal(e.Data, v) }

// EventJobData is the data of job.started and job.exited.
type EventJobData struct {
	Job           string `json:"job"`
	Sandbox       string `json:"sandbox,omitempty"`
	Node          string `json:"node,omitempty"`
	State         string `json:"state"`
	Outcome       string `json:"outcome,omitempty"`
	OutcomeReason string `json:"outcome_reason,omitempty"`
	ExitCode      *int   `json:"exit_code,omitempty"`
	Labels        Labels `json:"labels,omitempty"`
}

// EventStateData is the data of sandbox.state and machine.state.
type EventStateData struct {
	State    string `json:"state"`
	Previous string `json:"previous,omitempty"`
	Reason   string `json:"reason,omitempty"`
	Node     string `json:"node,omitempty"`
	Labels   Labels `json:"labels,omitempty"`
}

// EventOperatorActionData is the data of machine.operator_action.
type EventOperatorActionData struct {
	Action   string `json:"action"`
	Operator string `json:"operator"`
	Reason   string `json:"reason,omitempty"`
	Override bool   `json:"override,omitempty"`
}

// EventTerminalClosedData is the data of terminal.closed.
type EventTerminalClosedData struct {
	Terminal string `json:"terminal"`
	Machine  string `json:"machine"`
	Reason   string `json:"reason"`
	Actor    string `json:"actor,omitempty"`
}

// EventTemplateBuildData is the data of template.build.
type EventTemplateBuildData struct {
	Template string `json:"template"`
	Node     string `json:"node"`
	State    string `json:"state"`
	Error    string `json:"error,omitempty"`
}

// EventNodeData is the data of node.unavailable and node.available.
type EventNodeData struct {
	Node     string   `json:"node"`
	Machines []string `json:"machines,omitempty"`
}

// EventUsagePeriodData is the data of usage.period_closed.
type EventUsagePeriodData struct {
	PeriodStart time.Time `json:"period_start"`
	PeriodEnd   time.Time `json:"period_end"`
	Records     int       `json:"records"`
}

// EventList is a page of events.
type EventList struct {
	Data      []Event `json:"data"`
	NextAfter int64   `json:"next_after"`
	LatestSeq int64   `json:"latest_seq"`
	HasMore   bool    `json:"has_more,omitempty"`
}

// UsageRecord is one resource in one hour, or one group.
type UsageRecord struct {
	Consumer string `json:"consumer,omitempty"`
	Project  string `json:"project,omitempty"`
	Resource *struct {
		Kind string `json:"kind"`
		ID   string `json:"id"`
	} `json:"resource,omitempty"`
	Kind             string            `json:"kind,omitempty"`
	Node             string            `json:"node,omitempty"`
	Group            map[string]string `json:"group,omitempty"`
	PeriodStart      time.Time         `json:"period_start"`
	PeriodEnd        time.Time         `json:"period_end"`
	RunningSeconds   float64           `json:"running_seconds"`
	PausedSeconds    float64           `json:"paused_seconds"`
	VCPUSeconds      float64           `json:"vcpu_seconds"`
	MemoryMiBSeconds float64           `json:"memory_mib_seconds"`
	DiskGiBHours     float64           `json:"disk_gib_hours"`
	AddressHours     float64           `json:"address_hours"`
	Labels           Labels            `json:"labels,omitempty"`
	Closed           bool              `json:"closed"`
}

func itoa(v int) string {
	b, _ := json.Marshal(v)
	return string(b)
}
