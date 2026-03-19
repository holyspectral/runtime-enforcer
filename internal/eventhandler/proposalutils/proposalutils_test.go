package proposalutils_test

import (
	"testing"

	"github.com/rancher-sandbox/runtime-enforcer/internal/eventhandler/proposalutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetWorkloadPolicyProposalName(t *testing.T) {
	tests := []struct {
		name string // description of this test case
		// Named input parameters for target function.
		kind         string
		resourceName string
		want         string
	}{
		{
			kind:         "Deployment",
			resourceName: "my-deployment",
			want:         "deploy-my-deployment",
		},
		{
			kind:         "ReplicaSet",
			resourceName: "my-replica-set",
			want:         "rs-my-replica-set",
		},
		{
			kind:         "DaemonSet",
			resourceName: "my-daemon-set",
			want:         "ds-my-daemon-set",
		},
		{
			kind:         "StatefulSet",
			resourceName: "my-stateful-set",
			want:         "sts-my-stateful-set",
		},
		{
			kind:         "CronJob",
			resourceName: "my-cron-job",
			want:         "cronjob-my-cron-job",
		},
		{
			kind:         "Job",
			resourceName: "my-job",
			want:         "job-my-job",
		},
		{
			kind:         "UnknownKind",
			resourceName: "my-resource",
			want:         "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := proposalutils.GetWorkloadPolicyProposalName(tt.kind, tt.resourceName)
			if tt.want == "" {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)

			assert.Equal(t, tt.want, got)
		})
	}
}
