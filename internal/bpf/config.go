package bpf

import (
	"fmt"
	"log/slog"

	"github.com/rancher-sandbox/runtime-enforcer/internal/cgroups"
)

func getLoadTimeConfig(logger *slog.Logger) (*bpfLoadConf, error) {
	cgInfo, err := cgroups.GetCgroupInfo()
	if err != nil {
		return nil, fmt.Errorf("cannot get cgroup info: %w", err)
	}

	logger.Info("cgroup info detected",
		"fs_magic", cgInfo.CgroupFsMagicString(),
		"v1_subsys_idx", cgInfo.CgroupV1SubsysIdx(),
		"resolution_path", cgInfo.CgroupResolutionPrefix(),
	)

	config := &bpfLoadConf{
		CgrpFsMagic:     cgInfo.CgroupFsMagic(),
		Cgrpv1SubsysIdx: cgInfo.CgroupV1SubsysIdx(),
		DebugMode:       0, // disable debug mode for now
	}

	logger.Info("bpf load config",
		"fs_magic_id", config.CgrpFsMagic,
		"v1_subsys_idx", config.Cgrpv1SubsysIdx,
		"debug_mode", config.DebugMode,
	)
	return config, nil
}
