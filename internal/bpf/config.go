package bpf

import (
	"fmt"
	"log/slog"

	"github.com/neuvector/runtime-enforcer/internal/cgroups"
)

func getLoadTimeConfig(logger *slog.Logger) (*bpfLoadConf, error) {
	cgInfo, err := cgroups.GetCgroupInfo(logger)
	if err != nil {
		return nil, fmt.Errorf("cannot get cgroup info: %w", err)
	}
	return &bpfLoadConf{
		CgrpFsMagic:     cgInfo.CgroupFsMagic(),
		Cgrpv1SubsysIdx: cgInfo.CgroupV1SubsysIdx(),
		DebugMode:       0, // disable debug mode for now
	}, nil
}
