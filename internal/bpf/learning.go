package bpf

import (
	"context"
)

func (m *Manager) GetLearningChannel() <-chan ProcessEvent {
	// if learning is not enabled, nobody will push events there
	return m.learningEventChan
}

func (m *Manager) learningStart(ctx context.Context) error {
	return m.setupEventConsumer(ctx, learning)
}
