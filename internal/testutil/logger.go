package testutil

import (
	"log/slog"
	"testing"
)

type testLogWriter struct {
	t *testing.T
}

func (w *testLogWriter) Write(p []byte) (int, error) {
	w.t.Logf("%s", string(p))
	return len(p), nil
}

// NewTestLogger returns an [slog.Logger] that writes to t.Logf.
func NewTestLogger(t *testing.T) *slog.Logger {
	return slog.New(slog.NewJSONHandler(&testLogWriter{t: t}, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	})).With("component", t.Name())
}
