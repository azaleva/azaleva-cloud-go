package contract_test

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/azaleva/azaleva-cloud-go/cloud"
	"github.com/azaleva/azaleva-cloud-go/cloud/contract"
)

// TestContractRemote runs the suite against a running installation, as two consumers set up
// beforehand:
//
//	CLOUD_CONTRACT_URL=https://… \
//	CLOUD_CONTRACT_KEY_A=ack_… CLOUD_CONTRACT_KEY_B=ack_… \
//	CLOUD_CONTRACT_POOL=default CLOUD_CONTRACT_EMPTY_POOL=empty \
//	go test -run TestContractRemote ./cloud/contract
//
// The keys have every scope and belong to two consumers that may use both pools: one with at
// least two schedulable nodes, one without nodes. The cases that need more setup (more
// consumers or keys, ceilings, signers, webhooks) skip; an installation's own tests run them
// with a Provisioner wired to its tooling. Without the clock and node hooks, the tests that
// need them skip too. CLOUD_CONTRACT_MACHINE_WAIT (a Go duration, e.g. 10m) lengthens each
// wait for a machine state, for nodes joined by a slow link (a migration carries /workspace
// between them).
func TestContractRemote(t *testing.T) {
	url := os.Getenv("CLOUD_CONTRACT_URL")
	if url == "" {
		t.Skip("set CLOUD_CONTRACT_URL, CLOUD_CONTRACT_KEY_A, CLOUD_CONTRACT_KEY_B, CLOUD_CONTRACT_POOL and " +
			"CLOUD_CONTRACT_EMPTY_POOL to run the suite against a running installation")
	}
	var wait time.Duration
	if v := os.Getenv("CLOUD_CONTRACT_MACHINE_WAIT"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil || d <= 0 {
			t.Fatalf("CLOUD_CONTRACT_MACHINE_WAIT=%q: a positive Go duration such as 10m", v)
		}
		wait = d
	}
	contract.Run(t, contract.Env{
		URL: url,
		Provisioner: &fixedConsumers{url: url, pool: os.Getenv("CLOUD_CONTRACT_POOL"), empty: os.Getenv("CLOUD_CONTRACT_EMPTY_POOL"),
			keys: []string{os.Getenv("CLOUD_CONTRACT_KEY_A"), os.Getenv("CLOUD_CONTRACT_KEY_B")}},
		WebhooksReachable: os.Getenv("CLOUD_CONTRACT_WEBHOOKS") != "",
		NoEgressBinding:   os.Getenv("CLOUD_CONTRACT_NO_EGRESS_BINDING") != "",
		RealRecipes:       os.Getenv("CLOUD_CONTRACT_REAL_RECIPES") != "",
		ServiceTemplate:   os.Getenv("CLOUD_CONTRACT_SERVICE_TEMPLATE"),
		MachineWait:       wait,
	})
}

// fixedConsumers is a Provisioner over consumers set up beforehand: it hands out their keys
// and supports nothing else.
type fixedConsumers struct {
	url         string
	pool, empty string
	mu          sync.Mutex
	keys        []string
}

func (f *fixedConsumers) Pools(context.Context) (string, string, error) { return f.pool, f.empty, nil }

func (f *fixedConsumers) CreateConsumer(ctx context.Context, _ string, _ []string) (string, string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.keys) == 0 {
		return "", "", fmt.Errorf("no more consumers set up: %w", errors.ErrUnsupported)
	}
	key := f.keys[0]
	if key == "" {
		return "", "", errors.New("set CLOUD_CONTRACT_KEY_A and CLOUD_CONTRACT_KEY_B")
	}
	c, err := cloud.New(f.url, key)
	if err != nil {
		return "", "", err
	}
	me, err := c.Consumer(ctx)
	if err != nil {
		return "", "", err
	}
	f.keys = f.keys[1:]
	return me.ID, key, nil
}

func (*fixedConsumers) CreateKey(context.Context, string, string, []cloud.Scope) (string, error) {
	return "", errors.ErrUnsupported
}

func (*fixedConsumers) RevokeKey(context.Context, string, string) error { return errors.ErrUnsupported }

func (*fixedConsumers) DisableConsumer(context.Context, string) error { return errors.ErrUnsupported }

func (*fixedConsumers) SetCeilings(context.Context, string, cloud.Quotas) error {
	return errors.ErrUnsupported
}

func (*fixedConsumers) AddTemplateSigner(context.Context, string, ed25519.PublicKey, []string) error {
	return errors.ErrUnsupported
}

func (*fixedConsumers) SetWebhook(context.Context, string, string) (string, error) {
	return "", errors.ErrUnsupported
}
