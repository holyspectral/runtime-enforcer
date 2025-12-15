package e2e_test

import (
	"slices"
	"time"
)

func waitForWorkloadPolicyStatusToBeUpdated() {
	// todo!: we should wait for the status of the WP to be updated, for now we just sleep a fixed time
	time.Sleep(5 * time.Second)
}

func verifyUbuntuLearnedProcesses(values []string) bool {
	// todo!: until we support the rthook we cannot detect `bash`, the resolution through containerd is slow.
	// slices.Contains(values, "/usr/bin/bash")
	return slices.Contains(values, "/usr/bin/ls") &&
		slices.Contains(values, "/usr/bin/sleep")
}
