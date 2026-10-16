package cloudtest

import "net/http"

// FakeCompanion is cloudtest's fake agent-companion for a machine whose node injects key: what
// HandleCompanion replaces by default. Other fakes of the transport's guest side (a mock node of
// an implementation's own tests) serve it behind their own transport.
func FakeCompanion(key string) http.Handler { return companionHandler(key) }
