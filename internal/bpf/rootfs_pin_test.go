package bpf

import (
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/kubewarden/runtime-enforcer/internal/types/policymode"
)

// copyExecutable copies src to dst, creating parent directories, and marks dst
// executable. It is used to stage a binary inside a throwaway root filesystem.
func copyExecutable(t *testing.T, src, dst string) {
	t.Helper()

	require.NoError(t, os.MkdirAll(filepath.Dir(dst), 0o755))

	in, err := os.Open(src)
	require.NoError(t, err)
	defer in.Close()

	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o755)
	require.NoError(t, err)
	defer out.Close()

	_, err = io.Copy(out, in)
	require.NoError(t, err)
}

// TestRootfsPinChrootBypass verifies the rootfs pin: a process that chroots into
// a sub-directory of its own root filesystem must not be able to shorten the
// resolved exec path to match an allow-listed entry.
//
// We allow-list only "/usr/bin/true". A normal exec of /usr/bin/true is allowed.
// We then stage a copy at <rootfs>/usr/bin/true and exec it while chrooted into
// <rootfs>. Without the pin the resolver would report "/usr/bin/true" (relative
// to the chroot) and wrongly allow it; with the pin it resolves to the real,
// full path which is not allow-listed and is therefore denied.
func TestRootfsPinChrootBypass(t *testing.T) {
	runner, err := newCgroupRunner(t)
	require.NoError(t, err, "Failed to create cgroup runner")
	defer runner.close()

	// Stage a copy of /usr/bin/true inside a throwaway root filesystem.
	rootfs, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)
	stagedTrue := filepath.Join(rootfs, "usr", "bin", "true")
	copyExecutable(t, "/usr/bin/true", stagedTrue)

	// Allow only the real /usr/bin/true, in protect mode.
	const mockPolicyID = uint64(77)
	require.NoError(t, runner.populatePolicyForRunnerCgroup(
		mockPolicyID, policymode.Protect, []string{"/usr/bin/true"},
	))

	// A normal (non-chroot) exec of the allow-listed binary is permitted and
	// produces no violation. This also confirms the pin does not false-flag a
	// legitimate in-container exec running in a fresh mount namespace.
	require.NoError(t, runner.runAndFindCommand(&runCommandArgs{
		command:         "/usr/bin/true",
		channel:         monitoringChannel,
		shouldFindEvent: false,
	}), "allow-listed binary must be permitted")

	// The chrooted exec resolves to the real, full path of the staged copy, which
	// is NOT allow-listed, so it must be denied with EPERM and reported with the
	// full path (proving the chroot no longer shortens the resolved path).
	require.NoError(t, runner.runAndFindCommand(&runCommandArgs{
		command:         "/usr/bin/true",
		chroot:          rootfs,
		expectedPath:    stagedTrue,
		channel:         monitoringChannel,
		shouldEPERM:     true,
		shouldFindEvent: true,
	}), "chrooted exec must resolve to the full path and be denied")
}

// TestForeignRootExec documents the vector-A coverage (procfs magic links into a
// foreign root such as /proc/1/root/<allowed>). Faithfully exercising it requires
// the container to have a root filesystem with a different superblock than the
// host, which the current test harness (running directly on the host filesystem)
// does not provide. Reproducing it needs a minimal separate rootfs entered via
// pivot_root so that /proc/1/root points at a foreign superblock.
//
// Manual reproduction:
//  1. In a privileged container with hostPID, allow-list only the container
//     entrypoint (e.g. /service).
//  2. From inside, exec /proc/1/root/service (the host's /service).
//  3. With the pin, the resolution terminates at the host rootfs (a foreign
//     superblock), is reported via LOG_FOREIGN_ROOT_EXEC, and is denied in
//     protect mode.
//  4. Setting allowForeignRootExec: true for that container in the
//     WorkloadPolicy makes the same exec succeed, as the foreign-root check is
//     bypassed for the container's policy id (see
//     policy_allow_foreign_root_map). The Go wiring for this flag is covered by
//     resolver.TestReconcileWP_AllowForeignRootExec.
func TestForeignRootExec(t *testing.T) {
	t.Skip("vector A requires a separate container rootfs (pivot_root); see test doc for manual repro")
}
