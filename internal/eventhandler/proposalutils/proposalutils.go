package proposalutils

import (
	"fmt"

	"github.com/rancher-sandbox/runtime-enforcer/internal/types/workloadkind"
	"k8s.io/apimachinery/pkg/util/validation"
)

func getKindShortName(kind string) (string, error) {
	var shortname string
	switch workloadkind.Kind(kind) {
	case workloadkind.Deployment:
		shortname = "deploy"
	case workloadkind.ReplicaSet:
		shortname = "rs"
	case workloadkind.DaemonSet:
		shortname = "ds"
	case workloadkind.CronJob:
		shortname = "cronjob"
	case workloadkind.Job:
		shortname = "job"
	case workloadkind.StatefulSet:
		shortname = "sts"
	case workloadkind.Pod:
		fallthrough
	case workloadkind.Unknown:
		fallthrough
	default:
		return "", fmt.Errorf("unknown kind: %s", kind)
	}
	return shortname, nil
}

// GetWorkloadPolicyProposalName returns the name of WorkloadPolicyProposal
// based on a high level resource and its name.
func GetWorkloadPolicyProposalName(kind string, resourceName string) (string, error) {
	var shortname string
	var err error
	if shortname, err = getKindShortName(kind); err != nil {
		return "", err
	}
	ret := shortname + "-" + resourceName

	// The max name length in k8s
	if len(ret) > validation.DNS1123SubdomainMaxLength {
		return "", fmt.Errorf("the name %s exceeds the maximum name length", ret)
	}

	return shortname + "-" + resourceName, nil
}
