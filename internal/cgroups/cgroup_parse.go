package cgroups

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

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
// /kubelet.slice/kubelet-kubepods.slice/kubelet-kubepods-besteffort.slice/kubelet-kubepods-besteffort-pod83b090de_9676_407c_99aa_d33dc6aa0c0d.slice/cri-containerd-18b2adc8507104e412c946bec11679590801f547eee513fa298054f14fbf4240.scope.
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
