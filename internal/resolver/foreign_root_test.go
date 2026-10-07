package resolver

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/kubewarden/runtime-enforcer/api/v1alpha1"
	"github.com/kubewarden/runtime-enforcer/internal/bpf"
	"github.com/kubewarden/runtime-enforcer/internal/testutil"
	"github.com/kubewarden/runtime-enforcer/internal/types/policymode"
)

// TestReconcileWP_AllowForeignRootExec verifies that the per-container
// allowForeignRootExec flag is threaded from the WorkloadPolicy spec down to the
// BPF foreign-root update function, keyed by the container's policy ID, and that
// it is cleared when the container is removed from the policy.
func TestReconcileWP_AllowForeignRootExec(t *testing.T) {
	type foreignRootCall struct {
		allow bool
		op    bpf.PolicyForeignRootOperation
	}
	foreignRootCalls := make(map[PolicyID]foreignRootCall)

	r, err := NewResolver(
		testutil.NewTestLogger(t),
		func(_ uint64, _ string) error { return nil },
		func(_ PolicyID, _ []CgroupID, _ bpf.CgroupPolicyOperation) error { return nil },
		func(_ PolicyID, _ []string, _ bpf.PolicyValuesOperation) error { return nil },
		func(_ PolicyID, _ policymode.Mode, _ bpf.PolicyModeOperation) error { return nil },
		func(policyID PolicyID, allow bool, op bpf.PolicyForeignRootOperation) error {
			foreignRootCalls[policyID] = foreignRootCall{allow: allow, op: op}
			return nil
		},
	)
	require.NoError(t, err)

	wp := &v1alpha1.WorkloadPolicy{
		Name: "example", Namespace: "test-ns",
		Spec: v1alpha1.WorkloadPolicySpec{
			Mode: "protect",
			RulesByContainer: map[string]*v1alpha1.WorkloadPolicyRules{
				c1: {
					Executables:          v1alpha1.WorkloadPolicyExecutables{Allowed: []string{"/service"}},
					AllowForeignRootExec: true,
				},
				c2: {
					Executables: v1alpha1.WorkloadPolicyExecutables{Allowed: []string{"/bin/cat"}},
				},
			},
		},
	}
	key := wp.NamespacedName()

	r.mu.Lock()
	r.podCache["test-pod-uid"] = &podEntry{
		meta: &PodMeta{
			ID:           "test-pod-uid",
			Namespace:    "test-ns",
			Name:         "test-pod",
			WorkloadName: "test",
			WorkloadType: "Deployment",
			Labels:       map[string]string{v1alpha1.PolicyLabelKey: "example"},
		},
		containers: map[ContainerID]*ContainerMeta{
			cid1: {CgroupID: 100, Name: c1, ID: cid1},
			cid2: {CgroupID: 101, Name: c2, ID: cid2},
		},
	}
	r.mu.Unlock()

	require.NoError(t, r.ReconcileWP(wp))

	state := r.wpState[key]
	polC1 := state.polByContainer[c1]
	polC2 := state.polByContainer[c2]

	require.Equal(t, foreignRootCall{allow: true, op: bpf.UpdateForeignRoot}, foreignRootCalls[polC1],
		"container opting in must enable foreign-root execs")
	require.Equal(t, foreignRootCall{allow: false, op: bpf.UpdateForeignRoot}, foreignRootCalls[polC2],
		"container without the flag must be blocked by default")

	// Removing c1 from the spec must delete its foreign-root entry.
	delete(wp.Spec.RulesByContainer, c1)
	require.NoError(t, r.ReconcileWP(wp))
	require.Equal(t, bpf.DeleteForeignRoot, foreignRootCalls[polC1].op,
		"removed container must have its foreign-root entry deleted")
}
