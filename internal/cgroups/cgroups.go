// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon
// Copyright 2025 Authors of Runtime-enforcer

package cgroups

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

const (
	// CgroupSubsysCount is the max cgroup subsystems count we find in x86 vmlinux kernels.
	// See `enum cgroup_subsys_id` and value `CGROUP_SUBSYS_COUNT`.
	CgroupSubsysCount = 14

	// defaultProcFSPath is the default path to the proc filesystem.
	defaultProcFSPath = "/proc"

	// defaultCgroupMountPoint is the default mount point for cgroups.
	defaultCgroupMountPoint = defaultProcFSPath + "/1/root/sys/fs/cgroup"

	// procCgroupPath is the path to the cgroup file under the proc filesystem.
	procCgroupPath = defaultProcFSPath + "/cgroups"
)

var (
	cgroupResolutionPrefix string //nolint:gochecknoglobals // we want it global for a global function.
)

// GetCgroupResolutionPrefix returns the prefix used for cgroupID resolution.
// For cgroupv2 it is the cgroup mount point path. (e.g. /sys/fs/cgroup)
// For cgroupv1 it is the cgroup mount point path + the controller chosen at runtime. (e.g. /sys/fs/cgroup/memory).
// This is set once during cgroup detection (see setCgroupResolutionPrefix).
func GetCgroupResolutionPrefix() string {
	return cgroupResolutionPrefix
}

// setCgroupResolutionPrefix sets the prefix used for cgroupID resolution.
func setCgroupResolutionPrefix(path string) {
	cgroupResolutionPrefix = path
}

type FileHandle struct {
	ID uint64
}

// GetCgroupIDFromPath returns the cgroup ID from the given path.
func GetCgroupIDFromPath(cgroupPath string) (uint64, error) {
	var fh FileHandle

	handle, _, err := unix.NameToHandleAt(unix.AT_FDCWD, cgroupPath, 0)
	if err != nil {
		return 0, fmt.Errorf("nameToHandle on %s failed: %w", cgroupPath, err)
	}

	err = binary.Read(bytes.NewBuffer(handle.Bytes()), binary.LittleEndian, &fh)
	if err != nil {
		return 0, fmt.Errorf("decoding NameToHandleAt data failed: %w", err)
	}

	return fh.ID, nil
}

type CgroupInfo struct {
	fsMagic     uint64
	subsysV1Idx uint32
}

func (c *CgroupInfo) CgroupFsMagic() uint64 {
	return c.fsMagic
}

func (c *CgroupInfo) CgroupV1SubsysIdx() uint32 {
	return c.subsysV1Idx
}

func CgroupFsMagicString(fsMagic uint64) string {
	switch fsMagic {
	case unix.CGROUP_SUPER_MAGIC:
		return "cgroupv1"
	case unix.CGROUP2_SUPER_MAGIC:
		return "cgroupv2"
	default:
		panic("unknown cgroup fs magic")
	}
}

// findInterestingControllerV1 returns the name and the index of the most "interesting" controller
// we find under /proc/cgroups. If we don't find any of them we return an error.
// In cgroupv1, k8s containers could share the same cgroup under some controllers (e.g cpuset),
// but usually there are controllers under which each container has its own cgroup (e.g memory, pids, cpu, ...),
// these controllers are the ones we define as "interesting".
func findInterestingControllerV1(path string) (string, uint32, error) {
	//nolint:gosec // path is always set internally by us not by the user.
	file, err := os.Open(path)
	if err != nil {
		return "", 0, fmt.Errorf("failed to open %s: %w", path, err)
	}
	defer file.Close()

	// Expected format cgroupv1:
	//
	// #subsys_name	hierarchy	num_cgroups	enabled
	// cpuset	       12	       192	       1
	// cpu	           7	       610	       1
	// cpuacct	       7	       610	       1
	// blkio	       10	       610	       1
	// memory	       13	       623	       1
	// devices	       2	       610	       1
	// freezer	       9	       193	       1
	// net_cls	       6	       192	       1
	// perf_event	   3	       192	       1
	// net_prio	       6	       192	       1
	// hugetlb	       5	       192	       1
	// pids	       	   4	       613	       1
	// rdma	           8	       192	       1
	// misc	          11	       192	       1
	//
	// We can see it from the above numbers, the `num_cgroups` for controllers like `memory` and `pids` are really high.
	// `memory` has a higher number because probably on the host there are other memory cgroups not related to k8s containers.

	// ignore first entry with fields name.
	scanner := bufio.NewScanner(file)
	scanner.Scan()
	var idx uint32
	// we save the controller names in order
	var allControllersNames []string
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) == 0 {
			return "", 0, fmt.Errorf("failed to parse cgroupv1 controllers: line has no fields: %s", line)
		}
		allControllersNames = append(allControllersNames, fields[0])
		idx++
		// in ebpf we don't go beyond CgroupSubsysCount so it is useless to parse more
		if idx >= CgroupSubsysCount {
			break
		}
	}

	// as we said memory, pids and cpu are usually the controllers under which containers have their own cgroup.
	// We want to find their indices in this order.
	for _, interestingController := range []string{"memory", "pids", "cpu"} {
		for i, name := range allControllersNames {
			if name == interestingController {
				// found the index for the most interesting controller
				return interestingController, uint32(i), nil
			}
		}
	}

	return "", 0, fmt.Errorf("no interesting controllers among: %v", allControllersNames)
}

// getMountPointType returns error if the provided path is not a mount point. If it is a mount point, it returns the filesystem type.
func getMountPointType(path string) (int64, error) {
	var st, pst unix.Stat_t
	if err := unix.Lstat(path, &st); err != nil {
		return 0, fmt.Errorf("error accessing path '%s': %w", path, err)
	}

	parent := filepath.Dir(path)
	if err := unix.Lstat(parent, &pst); err != nil {
		return 0, fmt.Errorf("error accessing parent path '%s': %w", parent, err)
	}

	// path should be a mount point if it is a cgroup root so the dev ID must differ from the parent.
	if st.Dev == pst.Dev {
		return 0, fmt.Errorf("'%s' does not appear to be a mount point", path)
	}

	fst := unix.Statfs_t{}
	if err := unix.Statfs(path, &fst); err != nil {
		return 0, fmt.Errorf("failed to get fs info for '%s'", path)
	}
	return fst.Type, nil
}

// GetCgroupInfo retrieves cgroup information such as cgroup root, fs magic and subsys index.
func GetCgroupInfo(logger *slog.Logger) (*CgroupInfo, error) {
	// Today we don't let the user to specify a custom mount point, we just use the default one.
	// Both in cgroupv1 and cgroupv2 we should have a mount point in `defaultCgroupMountPoint`.
	// What changes is the type of the filesystem.
	fsType, err := getMountPointType(defaultCgroupMountPoint)
	if err != nil {
		return nil, fmt.Errorf("cannot get mount point type for '%s': %w", defaultCgroupMountPoint, err)
	}

	defer func() {
		// on return we log the resolution prefix
		if err == nil {
			logger.Info("cgroup resolution prefix detected", "path", GetCgroupResolutionPrefix())
		}
	}()

	switch fsType {
	// for cgroupv2 the fs type is CGROUP2_SUPER_MAGIC
	case unix.CGROUP2_SUPER_MAGIC:
		setCgroupResolutionPrefix(defaultCgroupMountPoint)
		return &CgroupInfo{
			fsMagic:     unix.CGROUP2_SUPER_MAGIC,
			subsysV1Idx: 0, // we are in v2 we don't need the index ebpf side.
		}, nil
	// for cgroupv1 or hybrid setup the fs type is TMPFS_MAGIC
	case unix.TMPFS_MAGIC:
		// If we use Cgroupv1, we need the subsys idx for ebpf.
		var controllerName string
		var idx uint32
		controllerName, idx, err = findInterestingControllerV1(procCgroupPath)
		if err != nil {
			return nil, fmt.Errorf("cannot find interesting controller: %w", err)
		}
		controllerPath := filepath.Join(defaultCgroupMountPoint, controllerName)
		// we should have a mount point under this controller
		_, err = getMountPointType(controllerPath)
		if err != nil {
			return nil, fmt.Errorf("cannot get mount point type for '%s': %w", controllerPath, err)
		}
		setCgroupResolutionPrefix(controllerPath)
		return &CgroupInfo{
			fsMagic:     unix.CGROUP_SUPER_MAGIC,
			subsysV1Idx: idx,
		}, nil
	default:
		// we don't support other fs types
		return nil, fmt.Errorf("unsupported cgroup filesystem type: %d", fsType)
	}
}

// SystemdExpandSlice expands a systemd slice name into its full path.
//
// taken from github.com/opencontainers/runc/libcontainer/cgroups/systemd
// which does not work due to a ebpf incompatibility:
// # github.com/opencontainers/runc/libcontainer/cgroups/ebpf
// vendor/github.com/opencontainers/runc/libcontainer/cgroups/ebpf/ebpf_linux.go:190:3: unknown field Replace in struct literal of type link.RawAttachProgramOptions
//
// systemd represents slice hierarchy using `-`, so we need to follow suit when
// generating the path of slice. Essentially, test-a-b.slice becomes
// /test.slice/test-a.slice/test-a-b.slice.
func SystemdExpandSlice(slice string) (string, error) {
	suffix := ".slice"
	// Name has to end with ".slice", but can't be just ".slice".
	if len(slice) <= len(suffix) || !strings.HasSuffix(slice, suffix) {
		return "", fmt.Errorf("invalid slice name: %s", slice)
	}

	// Path-separators are not allowed.
	if strings.Contains(slice, "/") {
		return "", fmt.Errorf("invalid slice name: %s", slice)
	}

	sliceName := strings.TrimSuffix(slice, suffix)
	// if input was -.slice, we should just return root now
	if sliceName == "-" {
		return "/", nil
	}

	var (
		pathBuilder   strings.Builder
		prefixBuilder strings.Builder
	)

	for _, component := range strings.Split(sliceName, "-") {
		// test--a.slice isn't permitted, nor is -test.slice.
		if component == "" {
			return "", fmt.Errorf("invalid slice name: %s", slice)
		}

		pathBuilder.WriteByte('/')
		pathBuilder.WriteString(prefixBuilder.String())
		pathBuilder.WriteString(component)
		pathBuilder.WriteString(suffix)

		prefixBuilder.WriteString(component)
		prefixBuilder.WriteByte('-')
	}
	return pathBuilder.String(), nil
}

// ParseCgroupsPath parses the cgroup path from the CRI response.
//
// Example input: kubelet-kubepods-besteffort-pod83b090de_9676_407c_99aa_d33dc6aa0c0d.slice:cri-containerd:18b2adc8507104e412c946bec11679590801f547eee513fa298054f14fbf4240
//
// Example output:
// /kubelet.slice/kubelet-kubepods.slice/kubelet-kubepods-besteffort.slice/kubelet-kubepods-besteffort-pod83b090de_9676_407c_99aa_d33dc6aa0c0d.slice/cri-containerd-18b2adc8507104e412c946bec11679590801f547eee513fa298054f14fbf4240.scope
func ParseCgroupsPath(cgroupPath string) (string, error) {
	if strings.Contains(cgroupPath, "/") {
		return cgroupPath, nil
	}

	// There are some cases where CgroupsPath  is specified as "slice:prefix:name"
	// From runc --help
	//   --systemd-cgroup    enable systemd cgroup support, expects cgroupsPath to be of form "slice:prefix:name"
	//                       for e.g. "system.slice:runc:434234"
	//
	// https://github.com/opencontainers/runc/blob/5cf9bb229feed19a767cbfdf9702f6487341e29e/libcontainer/specconv/spec_linux.go#L655-L663
	parts := strings.Split(cgroupPath, ":")
	const cgroupPathSlicePrefixNameParts = 3
	if len(parts) == cgroupPathSlicePrefixNameParts {
		var err error
		// kubelet-kubepods-besteffort-pod83b090de_9676_407c_99aa_d33dc6aa0c0d.slice:cri-containerd:18b2adc8507104e412c946bec11679590801f547eee513fa298054f14fbf4240
		slice, containerRuntimeName, containerID := parts[0], parts[1], parts[2]
		slice, err = SystemdExpandSlice(slice)
		if err != nil {
			return "", fmt.Errorf("failed to parse cgroup path: %s (%s does not seem to be a slice)", cgroupPath, slice)
		}
		// https://github.com/opencontainers/runc/blob/5cf9bb229feed19a767cbfdf9702f6487341e29e/libcontainer/cgroups/systemd/common.go#L95-L101
		if !strings.HasSuffix(containerID, ".slice") {
			// We want something like this: cri-containerd-18b2adc8507104e412c946bec11679590801f547eee513fa298054f14fbf4240.scope
			containerID = containerRuntimeName + "-" + containerID + ".scope"
		}
		return filepath.Join(slice, containerID), nil
	}

	return "", fmt.Errorf("unknown cgroup path: %s", cgroupPath)
}
