package resolver

import (
	"log/slog"
	"testing"

	"github.com/rancher-sandbox/runtime-enforcer/internal/bpf"
	"github.com/rancher-sandbox/runtime-enforcer/internal/types/policymode"
	"github.com/stretchr/testify/require"
)

func mockPolicyUpdateBinariesFunc(_ PolicyID, _ []string, _ bpf.PolicyValuesOperation) error {
	return nil
}

func mockPolicyModeUpdateFunc(_ PolicyID, _ policymode.Mode, _ bpf.PolicyModeOperation) error {
	return nil
}

func mockCgTrackerUpdateFunc(_ uint64, _ string) error {
	return nil
}

func mockCgroupToPolicyMapUpdateFunc(_ PolicyID, _ []CgroupID, _ bpf.CgroupPolicyOperation) error {
	return nil
}

type testWriter struct {
	t testing.TB
}

func (w testWriter) Write(p []byte) (int, error) {
	w.t.Helper()
	w.t.Log(string(p))
	return len(p), nil
}

func NewTestResolver(t testing.TB) *Resolver {
	t.Helper()
	r, err := NewResolver(
		slog.New(slog.NewJSONHandler(testWriter{t}, nil)),
		mockCgTrackerUpdateFunc,
		mockCgroupToPolicyMapUpdateFunc,
		mockPolicyUpdateBinariesFunc,
		mockPolicyModeUpdateFunc,
	)
	require.NoError(t, err)
	return r
}
