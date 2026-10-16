package cloudtest_test

import (
	"context"
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/azaleva/azaleva-cloud-go/cloud"
	"github.com/azaleva/azaleva-cloud-go/cloud/cloudtest"
	"github.com/azaleva/azaleva-cloud-go/cloud/contract"
)

// TestContract runs the contract suite against the in-memory fake, with every optional hook.
func TestContract(t *testing.T) {
	// Profiles with a templates list (the suite checks that they refuse other templates).
	srv := cloudtest.Start(t, cloudtest.Options{Profiles: []cloud.Profile{
		{Name: "job-pinned", Kind: cloud.KindJob, VCPU: 2, MemoryMiB: 2048, DiskMiB: 4096, TimeoutSeconds: 3600, Backend: "envd",
			Templates: []string{"hub-runner"}},
		{Name: "machine-pinned", Kind: cloud.KindMachine, VCPU: 2, MemoryMiB: 4096, DiskMiB: 10240, Backend: "companion",
			Modes: []cloud.MachineMode{cloud.OnDemand}, Hostname: "machine", Templates: []string{"hub-*"}},
	}, Transport: cloud.TransportLimits{ConnectionsPerMachine: 4}})
	contract.Run(t, contract.Env{
		URL:                 srv.URL,
		Provisioner:         provisioner{srv},
		Advance:             func(d time.Duration) { srv.Advance(d) },
		SetNodeConnected:    srv.SetNodeConnected,
		WebhooksReachable:   true,
		SetServiceListening: srv.SetServiceListening,
		RemoveService:       srv.RemoveService,
	})
}

// provisioner is the contract suite's Provisioner over the fake's setup methods.
type provisioner struct{ s *cloudtest.Server }

func (p provisioner) Pools(context.Context) (string, string, error) {
	// The default fleet: node-1 and node-2 in pool default.
	if err := p.s.CreatePool("contract-empty"); err != nil {
		return "", "", err
	}
	return "default", "contract-empty", nil
}

func (p provisioner) CreateConsumer(_ context.Context, name string, pools []string) (string, string, error) {
	id, err := p.s.CreateConsumer(cloudtest.Consumer{Name: name, Pools: pools})
	if err != nil {
		return "", "", err
	}
	key, err := p.s.CreateKey(id, "")
	return id, key, err
}

func (p provisioner) CreateKey(_ context.Context, consumer, project string, scopes []cloud.Scope) (string, error) {
	return p.s.CreateKey(consumer, project, scopes...)
}

func (p provisioner) RevokeKey(_ context.Context, _, key string) error { return p.s.RevokeKey(key) }

func (p provisioner) DisableConsumer(_ context.Context, consumer string) error {
	return p.s.DisableConsumer(consumer)
}

func (p provisioner) SetCeilings(_ context.Context, consumer string, q cloud.Quotas) error {
	return p.s.SetCeilings(consumer, q)
}

func (p provisioner) AddTemplateSigner(_ context.Context, consumer string, pub ed25519.PublicKey, names []string) error {
	return p.s.AddTemplateSigner(consumer, pub, names...)
}

func (p provisioner) SetWebhook(_ context.Context, consumer, url string) (string, error) {
	return p.s.SetWebhook(consumer, url)
}
