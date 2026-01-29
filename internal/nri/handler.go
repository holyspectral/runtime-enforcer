package nri

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"time"

	retry "github.com/avast/retry-go/v4"
	"github.com/containerd/nri/pkg/stub"
	"github.com/rancher-sandbox/runtime-enforcer/internal/resolver"
)

const (
	maxDelay = time.Minute * 1
)

type Handler struct {
	socketPath  string
	pluginIndex string
	logger      *slog.Logger
	resolver    *resolver.Resolver
}

func NewNRIHandler(socketPath, pluginIndex string, logger *slog.Logger, r *resolver.Resolver) (*Handler, error) {
	h := &Handler{
		socketPath:  socketPath,
		pluginIndex: pluginIndex,
		logger:      logger.With("component", "nri-handler"),
		resolver:    r,
	}
	if err := h.checkNRISupport(); err != nil {
		return nil, fmt.Errorf("NRI support check failed: %w", err)
	}
	return h, nil
}

func (h *Handler) checkNRISupport() error {
	const (
		connectionTimeout = 3 * time.Second
		attempts          = 5
	)

	tryConnect := func() error {
		h.logger.Info("connecting to NRI socket")
		d := net.Dialer{
			Timeout: connectionTimeout,
		}
		conn, err := d.DialContext(context.Background(), "unix", h.socketPath)
		if err != nil {
			return err
		}
		_ = conn.Close()
		return nil
	}
	return retry.Do(
		tryConnect,
		retry.Attempts(attempts),
		retry.Delay(time.Second),
		retry.DelayType(retry.BackOffDelay),
		retry.OnRetry(func(n uint, err error) {
			// n = 0 for the first retry
			h.logger.Warn("error during NRI socket connection, retrying...",
				"attempt", n+1,
				"error", err,
			)
		}),
	)
}

func (h *Handler) startNRIPlugin(ctx context.Context) error {
	var err error

	p := &plugin{
		logger:   h.logger.With("component", "nri-plugin"),
		resolver: h.resolver,
	}

	opts := []stub.Option{
		stub.WithPluginIdx(h.pluginIndex),
		stub.WithSocketPath(h.socketPath),
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
	// isRetryable is called only in case of err != nil
	isRetryable := func(err error) bool {
		// We stop in case of:
		// - context.Canceled/DeadlineExceeded
		if errors.Is(err, context.Canceled) ||
			errors.Is(err, context.DeadlineExceeded) {
			return false
		}
		return true
	}

	return retry.Do(
		func() error {
			return h.startNRIPlugin(ctx)
		},
		retry.Attempts(0), // infinite attempts
		retry.Delay(time.Second),
		retry.DelayType(retry.BackOffDelay),
		retry.MaxDelay(maxDelay),
		retry.RetryIf(isRetryable),
		retry.OnRetry(func(n uint, err error) {
			// n = 0 for the first retry
			h.logger.WarnContext(ctx, "error during NRI plugin execution, retrying...",
				"attempt", n+1,
				"error", err,
			)
		}),
	)
}
