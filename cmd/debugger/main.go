package main

import (
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/go-logr/logr"
	"github.com/rancher-sandbox/runtime-enforcer/internal/grpcexporter"
	"golang.org/x/sync/errgroup"
	ctrl "sigs.k8s.io/controller-runtime"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// +kubebuilder:rbac:groups="",resources=pods,verbs=get;list;watch

const (
	defaultInterval = 10 * time.Second
)

type conf struct {
	interval      time.Duration
	agentPoolConf grpcexporter.AgentClientPoolConfig
}

func getPodCache() (cache.Cache, error) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	c, err := cache.New(ctrl.GetConfigOrDie(), cache.Options{
		Scheme: scheme,
		ByObject: map[client.Object]cache.ByObject{
			&corev1.Pod{}: {}, // Only pod informer
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create cache: %w", err)
	}
	return c, nil
}

func main() {
	// Set the logger
	slogHandler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})
	slogger := slog.New(slogHandler).With("component", "debugger")
	slog.SetDefault(slogger)
	ctrl.SetLogger(logr.FromSlogHandler(slogger.Handler()))

	var config conf
	flag.IntVar(&config.agentPoolConf.Port,
		"grpc-port",
		grpcexporter.DefaultAgentPort,
		"The port the agent grpc server listens on.")
	flag.DurationVar(&config.interval,
		"interval",
		defaultInterval,
		"The interval at which the debugger checks everything is fine.")
	flag.StringVar(&config.agentPoolConf.LabelSelectorString,
		"agent-label-selector",
		grpcexporter.DefaultAgentLabelSelectorString,
		"The label selector for the agent pods as a comma concatenated string.")
	flag.StringVar(&config.agentPoolConf.CertDirPath,
		"cert-dir",
		grpcexporter.DefaultCertDirPath,
		"The directory where the agent certificates are stored.")
	flag.Parse()

	cache, err := getPodCache()
	if err != nil {
		slogger.Error("Failed to get pod cache", "error", err)
		return
	}

	// Enable mTLS by default
	config.agentPoolConf.MTLSEnabled = true
	var pool *grpcexporter.AgentClientPool
	pool, err = grpcexporter.NewAgentClientPool(config.agentPoolConf)
	if err != nil {
		slogger.Error("Failed to create agent client pool", "error", err)
		return
	}

	// we return in case of signals
	g, ctx := errgroup.WithContext(ctrl.SetupSignalHandler())

	// Start the cache
	g.Go(func() error {
		return cache.Start(ctx)
	})

	// Wait for the cache to be ready and then start the validation.
	g.Go(func() error {
		if !cache.WaitForCacheSync(ctx) {
			return errors.New("timeout cache synchronization")
		}

		for {
			select {
			case <-ctx.Done():
				// We terminate.
				return nil
			case <-time.After(config.interval):
				if err = validatePodCacheIntegrity(ctx, slogger, cache, pool); err != nil {
					slogger.Error("Failed to validate pod cache integrity", "error", err)
				}
			}
		}
	})

	if err = g.Wait(); err != nil {
		slogger.Error("Debugger stopped with error", "error", err)
	}
}
