package bpf

import (
	"context"
)

func (m *Manager) GetMonitoringChannel() <-chan ProcessEvent {
	return m.monitoringEventChan
}

func (m *Manager) monitoringStart(ctx context.Context) error {
	return m.setupEventConsumer(ctx, monitoring)
}
