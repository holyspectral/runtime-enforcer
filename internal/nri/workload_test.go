//nolint:testpackage  // we are testing unexported functions
package nri

import (
	"strings"
	"testing"

	"github.com/containerd/nri/pkg/api"
	"github.com/neuvector/runtime-enforcer/internal/types/workloadkind"
	"github.com/stretchr/testify/require"
)

func TestGetPodInfo(t *testing.T) {
	tests := []struct {
		name     string
		pod      *api.PodSandbox
		wantName string
		wantType workloadkind.Kind
	}{
		{
			name: "deployment",
			pod: &api.PodSandbox{
				Name: "ubuntu-deployment-674bcc58f4-pwvps",
				Labels: map[string]string{
					podTemplateHashLabel: "674bcc58f4",
				},
				Annotations: map[string]string{},
			},
			wantName: "ubuntu-deployment",
			wantType: workloadkind.Deployment,
		},
		{
			name: "deployment truncated",
			pod: &api.PodSandbox{
				Name: strings.Repeat("a", 58) + "q8fcg",
				Labels: map[string]string{
					podTemplateHashLabel: "674bcc58f4",
				},
				Annotations: map[string]string{},
			},
			wantName: strings.Repeat("a", 58) + truncatedSuffix,
			wantType: workloadkind.Deployment,
		},
		{
			name: "deployment with one dash",
			pod: &api.PodSandbox{
				Name: strings.Repeat("a", 56) + "-65fb8c",
				Labels: map[string]string{
					podTemplateHashLabel: "674bcc58f4",
				},
				Annotations: map[string]string{},
			},
			wantName: strings.Repeat("a", 56),
			wantType: workloadkind.Deployment,
		},
		{
			name: "statefulset",
			pod: &api.PodSandbox{
				Name: "ubuntu-statefulset-0",
				Labels: map[string]string{
					"apps.kubernetes.io/pod-index": "0",
					"controller-revision-hash":     "ubuntu-statefulset-7b5845dd9c",
					statefulsetLabel:               "ubuntu-statefulset-0",
				},
				Annotations: map[string]string{},
			},
			wantName: "ubuntu-statefulset",
			wantType: workloadkind.StatefulSet,
		},
		{
			name: "daemonset",
			pod: &api.PodSandbox{
				Name: "ubuntu-daemonset-6qq8v",
				Labels: map[string]string{
					daemonsetLabel:            "568bcd7685",
					"pod-template-generation": "1",
				},
				Annotations: map[string]string{},
			},
			wantName: "ubuntu-daemonset",
			wantType: workloadkind.DaemonSet,
		},
		{
			name: "daemonset truncated",
			pod: &api.PodSandbox{
				Name: strings.Repeat("a", 58) + "q8fcg",
				Labels: map[string]string{
					daemonsetLabel:            "568bcd7685",
					"pod-template-generation": "1",
				},
				Annotations: map[string]string{},
			},
			wantName: strings.Repeat("a", 58) + truncatedSuffix,
			wantType: workloadkind.DaemonSet,
		},
		{
			name: "cronjob both label",
			pod: &api.PodSandbox{
				Name: "ubuntu-cronjob-29483273-vthf9",
				Labels: map[string]string{
					"batch.kubernetes.io/controller-uid": "0bebfe37-e018-4ff3-86fa-74cdd8dc2c67",
					newJobNameLabel:                      "ubuntu-cronjob-29483273",
					"controller-uid":                     "0bebfe37-e018-4ff3-86fa-74cdd8dc2c67",
					oldJobNameLabel:                      "ubuntu-cronjob-29483273",
				},
				Annotations: map[string]string{},
			},
			wantName: "ubuntu-cronjob",
			wantType: workloadkind.CronJob,
		},
		{
			name: "cronjob new label only",
			pod: &api.PodSandbox{
				Name: "ubuntu-cronjob-29483273-vthf9",
				Labels: map[string]string{
					"batch.kubernetes.io/controller-uid": "0bebfe37-e018-4ff3-86fa-74cdd8dc2c67",
					"controller-uid":                     "0bebfe37-e018-4ff3-86fa-74cdd8dc2c67",
					newJobNameLabel:                      "ubuntu-cronjob-29483273",
				},
				Annotations: map[string]string{},
			},
			wantName: "ubuntu-cronjob",
			wantType: workloadkind.CronJob,
		},
		{
			name: "cronjob old label only",
			pod: &api.PodSandbox{
				Name: "ubuntu-cronjob-29483273-vthf9",
				Labels: map[string]string{
					"batch.kubernetes.io/controller-uid": "0bebfe37-e018-4ff3-86fa-74cdd8dc2c67",
					"controller-uid":                     "0bebfe37-e018-4ff3-86fa-74cdd8dc2c67",
					oldJobNameLabel:                      "ubuntu-cronjob-29483273",
				},
				Annotations: map[string]string{},
			},
			wantName: "ubuntu-cronjob",
			wantType: workloadkind.CronJob,
		},
		{
			name: "job",
			pod: &api.PodSandbox{
				Name: "ubuntu-job-9bq97",
				Labels: map[string]string{
					"batch.kubernetes.io/controller-uid": "bdd392e0-262c-4fdf-8825-6e7d7351fec9",
					newJobNameLabel:                      "ubuntu-job",
					"controller-uid":                     "bdd392e0-262c-4fdf-8825-6e7d7351fec9",
					oldJobNameLabel:                      "ubuntu-job",
				},
				Annotations: map[string]string{},
			},
			wantName: "ubuntu-job",
			wantType: workloadkind.Job,
		},
		{
			name: "simple pod",
			pod: &api.PodSandbox{
				Name:        "ubuntu-pod",
				Labels:      map[string]string{},
				Annotations: map[string]string{},
			},
			wantName: "ubuntu-pod",
			wantType: workloadkind.Pod,
		},
		{
			name: "replicaset ignored",
			pod: &api.PodSandbox{
				Name:        "ubuntu-replicaset-rnswg",
				Labels:      map[string]string{},
				Annotations: map[string]string{},
			},
			wantName: "ubuntu-replicaset-rnswg",
			wantType: workloadkind.Pod,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotName, gotType := getWorkloadInfo(tt.pod)
			require.Equal(t, tt.wantName, gotName)
			require.Equal(t, tt.wantType, gotType)
		})
	}
}
