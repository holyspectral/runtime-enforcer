package nri

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/containerd/nri/pkg/stub"
	"github.com/neuvector/runtime-enforcer/internal/resolver"
)

const (
	ReconnectWaitTime = time.Second * 1
	ConnectTimeout    = time.Second * 5
)

type Handler struct {
	socketPath  string
	pluginIndex string
	logger      *slog.Logger
	resolver    *resolver.Resolver
}

func NewNRIHandler(socketPath, pluginIndex string, logger *slog.Logger, r *resolver.Resolver) *Handler {
	return &Handler{
		socketPath:  socketPath,
		pluginIndex: pluginIndex,
		logger:      logger.With("component", "nri-handler"),
		resolver:    r,
	}
}

func (h *Handler) startNRIPlugin(ctx context.Context) error {
	var err error

	p := &plugin{
		logger:   h.logger,
		resolver: h.resolver,
	}

	opts := []stub.Option{
		stub.WithPluginIdx(h.pluginIndex),
		stub.WithSocketPath(h.socketPath),
		stub.WithOnClose(p.onClose),
	}

	p.stub, err = stub.New(p, opts...)
	if err != nil {
		return fmt.Errorf("failed to create NRI plugin stub: %w", err)
	}

	err = p.stub.Run(ctx)
	if err != nil {
		return fmt.Errorf("NRI plugin exited with error: %w", err)
	}
	return nil
}

func (h *Handler) Start(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}
		err := h.startNRIPlugin(ctx)
		if err != nil {
			h.logger.InfoContext(ctx, "nri hook restarted", "error", err)
		}
		time.Sleep(ReconnectWaitTime)
	}
}
