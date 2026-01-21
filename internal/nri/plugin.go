package nri

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/containerd/nri/pkg/api"
	"github.com/containerd/nri/pkg/stub"
	"github.com/neuvector/runtime-enforcer/internal/resolver"
)

type plugin struct {
	stub     stub.Stub
	logger   *slog.Logger
	resolver *resolver.Resolver
}

func (p *plugin) StartContainer(
	ctx context.Context,
	pod *api.PodSandbox,
	container *api.Container,
) error {
	var err error
	defer func() {
		if err != nil {
			p.logger.ErrorContext(ctx, "failed to respond StartContainer hook", "error", err)
		}
	}()

	p.logger.DebugContext(
		ctx,
		"getting CreateContainer event",
		"container",
		container,
		"pod",
		pod,
	)

	err = p.resolver.AddPodFromNRI(ctx, pod, container)
	if err != nil {
		return fmt.Errorf("failed to add pod from NRI: %w", err)
	}

	return nil
}

// This would happen when container runtime restarts.
func (p *plugin) onClose() {
	p.logger.Info("Connection to the runtime lost...")
}
