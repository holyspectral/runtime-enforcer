//nolint:testpackage // we are testing unexported functions
package cgroups

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseCgroupsPath(t *testing.T) {
	tests := []struct {
		name     string
		in       string
		expected string
	}{
		{
			// example input taken from a kind cluster with cri-containerd
			name:     "cri-containerd kind cluster",
			in:       "kubelet-kubepods-besteffort-pod83b090de_9676_407c_99aa_d33dc6aa0c0d.slice:cri-containerd:18b2adc8507104e412c946bec11679590801f547eee513fa298054f14fbf4240",
			expected: "/kubelet.slice/kubelet-kubepods.slice/kubelet-kubepods-besteffort.slice/kubelet-kubepods-besteffort-pod83b090de_9676_407c_99aa_d33dc6aa0c0d.slice/cri-containerd-18b2adc8507104e412c946bec11679590801f547eee513fa298054f14fbf4240.scope",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, err := ParseCgroupsPath(tt.in)
			require.NoError(t, err)
			require.Equal(t, tt.expected, out)
		})
	}
}

func TestSystemdExpandSlice(t *testing.T) {
	tests := []struct {
		in       string
		expected string
	}{
		{
			in:       "kubelet-kubepods-besteffort-pod83b090de_9676_407c_99aa_d33dc6aa0c0d.slice",
			expected: "/kubelet.slice/kubelet-kubepods.slice/kubelet-kubepods-besteffort.slice/kubelet-kubepods-besteffort-pod83b090de_9676_407c_99aa_d33dc6aa0c0d.slice",
		},
		{
			in:       "-.slice",
			expected: "/",
		},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			out, err := SystemdExpandSlice(tt.in)
			require.NoError(t, err)
			require.Equal(t, tt.expected, out)
		})
	}
}

func TestFindInterestingControllerV1(t *testing.T) {
	tests := []struct {
		name        string
		fileContent string
		wantName    string
		wantIdx     uint32
	}{
		{
			name: "memory first",
			fileContent: `#subsys_name	hierarchy	num_cgroups	enabled
memory 6 42 1
cpuset 2 5 1
pids 9 17 1
`,
			wantName: "memory",
			wantIdx:  0,
		},
		{
			name: "memory last",
			fileContent: `#subsys_name	hierarchy	num_cgroups	enabled
cpuset 2 5 1
pids 9 17 1
memory 6 42 1
`,
			wantName: "memory",
			wantIdx:  2,
		},
		{
			name: "no memory",
			fileContent: `#subsys_name	hierarchy	num_cgroups	enabled
cpuset 2 5 1
foo 1 1 1
bar 2 2 1
foo1 1 1 1
bar1 2 2 1
pids 3 3 1
`,
			wantName: "pids",
			wantIdx:  5,
		},
		{
			name: "no interesting controller",
			fileContent: `#subsys_name	hierarchy	num_cgroups	enabled
foo 1 1 1
bar 2 2 1
`,
			wantName: "",
			wantIdx:  0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpfile, err := os.CreateTemp(t.TempDir(), "cgroups_test")
			require.NoError(t, err)
			defer os.Remove(tmpfile.Name())

			_, err = tmpfile.WriteString(tt.fileContent)
			require.NoError(t, err)
			tmpfile.Close()

			gotName, gotIdx, err := findInterestingControllerV1(tmpfile.Name())
			if tt.wantName == "" {
				// it means we expect an error
				require.Error(t, err)
				require.Empty(t, gotName)
				require.Zero(t, gotIdx)
			} else {
				// no error
				require.NoError(t, err)
				require.Equal(t, tt.wantName, gotName)
				require.Equal(t, tt.wantIdx, gotIdx)
			}
		})
	}
}
