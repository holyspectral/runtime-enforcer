package resolver

import (
	"testing"

	"github.com/rancher-sandbox/runtime-enforcer/api/v1alpha1"
	agentv1 "github.com/rancher-sandbox/runtime-enforcer/proto/agent/v1"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/events"
)

const (
	c1   = "c1"
	c2   = "c2"
	c3   = "c3"
	cid1 = "cid1"
	cid2 = "cid2"
	cid3 = "cid3"
)

// TestHandleWP_Lifecycle exercises add → update → delete in one test so the policy is created once.
func TestHandleWP_Lifecycle(t *testing.T) {
	r := NewTestResolver(t)
	wp := &v1alpha1.WorkloadPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "example", Namespace: "test-ns"},
		Spec: v1alpha1.WorkloadPolicySpec{
			Mode: "monitor",
			RulesByContainer: map[string]*v1alpha1.WorkloadPolicyRules{
				c1: {Executables: v1alpha1.WorkloadPolicyExecutables{Allowed: []string{"/bin/sleep"}}},
				c2: {Executables: v1alpha1.WorkloadPolicyExecutables{Allowed: []string{"/bin/cat"}}},
			},
		},
	}
	key := wp.NamespacedName()

	// A matching pod is required because policy deletion now happens
	// during cgroup detachment, not purely from wpState transitions.
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
			cid3: {CgroupID: 102, Name: c3, ID: cid3},
		},
	}
	r.mu.Unlock()

	// Add
	require.NoError(t, r.ReconcileWP(wp))
	require.Contains(t, r.wpState, key)
	state := r.wpState[key]
	require.Len(t, state.polByContainer, 2)
	require.Contains(t, state.polByContainer, c1)
	require.Contains(t, state.polByContainer, c2)
	ids := make(map[PolicyID]struct{})
	for _, id := range state.polByContainer {
		ids[id] = struct{}{}
	}
	require.Equal(t, map[PolicyID]struct{}{PolicyID(1): {}, PolicyID(2): {}}, ids)
	initialState := r.wpState[key]

	statuses := r.GetPolicyStatuses()
	require.Contains(t, statuses, key)
	require.Equal(t, PolicyStatus{
		State:   agentv1.PolicyState_POLICY_STATE_READY,
		Mode:    agentv1.PolicyMode_POLICY_MODE_MONITOR,
		Message: "",
	}, statuses[key])

	// Update: remove c1, update c2 allowed list, add c3
	delete(wp.Spec.RulesByContainer, c1)
	wp.Spec.RulesByContainer[c2] = &v1alpha1.WorkloadPolicyRules{
		Executables: v1alpha1.WorkloadPolicyExecutables{Allowed: []string{"/bin/cat", "/bin/echo"}},
	}
	wp.Spec.RulesByContainer[c3] = &v1alpha1.WorkloadPolicyRules{
		Executables: v1alpha1.WorkloadPolicyExecutables{Allowed: []string{"/bin/ls"}},
	}
	require.NoError(t, r.ReconcileWP(wp))
	state = r.wpState[key]
	require.Len(t, state.polByContainer, 2)
	require.NotContains(t, state.polByContainer, c1)
	require.Equal(t, initialState.polByContainer[c2], state.polByContainer[c2], "c2 keeps its policy ID")
	require.Equal(t, PolicyID(3), state.polByContainer[c3])

	// Delete
	require.NoError(t, r.HandleWPDelete(wp))
	require.NotContains(t, r.wpState, key)
	statuses = r.GetPolicyStatuses()
	require.NotContains(t, statuses, key)
}

// TestApplyPolicyToPod_RecordsEvent verifies that when a pod references a
// WorkloadPolicy that does not exist in the resolver cache, a Kubernetes Warning event is recorded
// on the Pod and the expected error is still returned.
func TestApplyPolicyToPod_RecordsEvent(t *testing.T) {
	fakeRecorder := events.NewFakeRecorder(10)
	r := NewTestResolverWithOptions(t, WithEventRecorder(fakeRecorder))

	tcs := []struct {
		name        string
		input       PodInput
		expectedErr bool
		verify      func(t *testing.T)
	}{
		{
			name: "pod references non-existing policy",
			input: PodInput{
				Meta: PodMeta{
					ID:        "uid",
					Name:      "pod",
					Namespace: "namespace",
					Labels:    map[string]string{v1alpha1.PolicyLabelKey: "policy-not-existing"},
				},
				Containers: map[ContainerID]ContainerInput{
					cid1: {
						ContainerMeta: ContainerMeta{CgroupID: 200, Name: c1, ID: cid1},
						CgroupPath:    "",
					},
				},
			},
			expectedErr: true,
			verify: func(t *testing.T) {
				// Exactly one Warning event should have been recorded.
				require.Len(t, fakeRecorder.Events, 1)
				evt := <-fakeRecorder.Events
				require.Contains(t, evt, corev1.EventTypeWarning)
				require.Contains(t, evt, "PolicyNotFound")
				require.Contains(t, evt, "namespace")
				require.Contains(t, evt, "pod")
				require.Contains(t, evt, "policy-not-existing")
			},
		},
		{
			name: "pod doesn't reference any policy",
			input: PodInput{
				Meta: PodMeta{
					ID:        "uid2",
					Name:      "pod2",
					Namespace: "namespace",
				},
				Containers: map[ContainerID]ContainerInput{
					cid2: {
						ContainerMeta: ContainerMeta{CgroupID: 201, Name: c2, ID: cid2},
						CgroupPath:    "",
					},
				},
			},
			expectedErr: false,
			verify: func(t *testing.T) {
				require.Empty(t, fakeRecorder.Events)
			},
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			err := r.AddPodContainerFromNri(tc.input)
			if tc.expectedErr {
				require.Error(t, err)
				require.ErrorContains(t, err, "policy does not exist")
			} else {
				require.NoError(t, err)
			}
			tc.verify(t)
		})
	}
}
