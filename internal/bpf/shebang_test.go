package bpf

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/rancher-sandbox/runtime-enforcer/internal/types/policymode"
	"github.com/stretchr/testify/require"
)

// resolveInterpreterPath returns the real filesystem path of the given
// interpreter binary, resolving any symlinks. This matches what the
// kernel's VFS layer does before the BPF hook sees bprm->file->f_path.
func resolveInterpreterPath(t *testing.T, interpreter string) string {
	t.Helper()
	resolved, err := filepath.EvalSymlinks(interpreter)
	require.NoError(t, err, "failed to resolve interpreter path %s", interpreter)
	return resolved
}

// createShebangScript creates a temporary executable script with the
// given shebang line and returns its path.
func createShebangScript(t *testing.T, interpreter string) string {
	t.Helper()
	script := []byte("#!" + interpreter + "\n")

	// Use a short, predictable path so it falls in the first string map bucket.
	path := filepath.Join(t.TempDir(), "test.sh")
	err := os.WriteFile(path, script, 0755)
	require.NoError(t, err, "failed to write shebang script")
	return path
}

func TestShebangScriptLearning(t *testing.T) {
	runner, err := newCgroupRunner(t)
	require.NoError(t, err, "Failed to create cgroup runner")
	defer runner.close()

	scriptPath := createShebangScript(t, "/usr/bin/bash")

	// When a shebang script is executed, the LSM hook fires for
	// both the script and the interpreter. Without the fix, only
	// the interpreter would appear on the learning channel.
	require.NoError(t, runner.runAndFindCommand(&runCommandArgs{
		command:         scriptPath,
		channel:         learningChannel,
		shouldFindEvent: true,
	}), "script path must be learned via the LSM hook")
}

func TestShebangScriptEnforcement(t *testing.T) {
	runner, err := newCgroupRunner(t)
	require.NoError(t, err, "Failed to create cgroup runner")
	defer runner.close()

	const interpreter = "/usr/bin/bash"
	resolvedInterpreter := resolveInterpreterPath(t, interpreter)
	scriptPath := createShebangScript(t, interpreter)

	mockPolicyID := uint64(44)

	// A policy that allows only the interpreter but NOT the script.
	// This simulates the bug: learning captured the interpreter but
	// missed the script path.
	t.Log("Setting up policy with interpreter only (missing script)")
	err = runner.manager.GetPolicyUpdateBinariesFunc()(
		mockPolicyID,
		[]string{resolvedInterpreter},
		AddValuesToPolicy,
	)
	require.NoError(t, err)

	err = runner.manager.GetPolicyModeUpdateFunc()(mockPolicyID, policymode.Protect, UpdateMode)
	require.NoError(t, err)

	err = runner.manager.GetCgroupPolicyUpdateFunc()(
		mockPolicyID, []uint64{runner.cgInfo.id}, AddPolicyToCgroups,
	)
	require.NoError(t, err)

	// The script should be blocked because its path is not in the
	// allowed list, even though the interpreter is.
	t.Log("Executing script with incomplete policy (expect EPERM)")
	require.NoError(t, runner.runAndFindCommand(&runCommandArgs{
		command:         scriptPath,
		channel:         monitoringChannel,
		shouldFindEvent: true,
		shouldEPERM:     true,
	}), "script must be blocked when not in the allowed list")

	// Now add the script to the policy (simulating correct learning).
	t.Log("Adding script path to the allowed list")
	err = runner.manager.GetPolicyUpdateBinariesFunc()(
		mockPolicyID,
		[]string{resolvedInterpreter, scriptPath},
		ReplaceValuesInPolicy,
	)
	require.NoError(t, err)

	// The script should now be allowed.
	t.Log("Executing script with complete policy (expect success)")
	require.NoError(t, runner.runAndFindCommand(&runCommandArgs{
		command:         scriptPath,
		channel:         monitoringChannel,
		shouldFindEvent: false,
	}), "script must be allowed when both script and interpreter are in the allowed list")
}
