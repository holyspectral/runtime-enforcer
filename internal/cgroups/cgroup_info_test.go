//nolint:testpackage // we are testing unexported functions
package cgroups

import (
	"math"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFindMemoryController(t *testing.T) {
	tests := []struct {
		name        string
		fileContent string
		wantIdx     uint32
	}{
		{
			name: "memory first",
			fileContent: `#subsys_name	hierarchy	num_cgroups	enabled
memory 6 42 1
cpuset 2 5 1
pids 9 17 1
`,
			wantIdx: 0,
		},
		{
			name: "memory last",
			fileContent: `#subsys_name	hierarchy	num_cgroups	enabled
cpuset 2 5 1
pids 9 17 1
memory 6 42 1
`,
			wantIdx: 2,
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
			wantIdx: math.MaxUint32,
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

			gotIdx, err := findMemoryController(tmpfile.Name())
			if tt.wantIdx == math.MaxUint32 {
				// it means we expect an error
				require.Error(t, err)
			} else {
				// no error
				require.NoError(t, err)
				require.Equal(t, tt.wantIdx, gotIdx)
			}
		})
	}
}
