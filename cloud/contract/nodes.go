package contract

import (
	"testing"

	"github.com/azaleva/azaleva-cloud-go/cloud"
)

func (s *suite) testNodeUnavailable(t *testing.T) {
	if s.env.SetNodeConnected == nil {
		t.Skip("needs Env.SetNodeConnected")
	}
	a := s.a
	m := s.machine(t, a, a.project.ID, nil)
	_, err := a.c.Machines.Stop(s.ctx, m.ID)
	must(t, err)
	s.waitMachine(t, a, m.ID, cloud.MachineStopped)
	after := s.latestSeq(t, a)
	must(t, s.env.SetNodeConnected(*m.Node, false))
	ev := s.waitEvent(t, a, after, func(ev cloud.Event) bool { return ev.Type == cloud.EventNodeUnavailable })
	var d cloud.EventNodeData
	must(t, ev.DecodeData(&d))
	if d.Node != *m.Node || !contains(d.Machines, m.ID) {
		t.Fatalf("node.unavailable: %+v", d)
	}
	_, err = noRetryClient(a.c).Machines.Start(s.ctx, m.ID)
	if e := wantCode(t, err, cloud.CodeNodeUnavailable); !e.Retryable {
		t.Fatal("node_unavailable must be retryable")
	}
	must(t, s.env.SetNodeConnected(*m.Node, true))
	s.waitEvent(t, a, after, func(ev cloud.Event) bool { return ev.Type == cloud.EventNodeAvailable })
	_, err = a.c.Machines.Start(s.ctx, m.ID)
	must(t, err)
	s.waitMachine(t, a, m.ID, cloud.MachineReady)
	_, err = a.c.Machines.Delete(s.ctx, m.ID)
	must(t, err)
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}
