//nolint:testpackage // we are testing unexported functions
package bpf

import (
	"context"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/time/rate"
)

type memoryWriter struct {
	mu   sync.Mutex
	logs []string
}

func (w *memoryWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.logs = append(w.logs, string(p))
	return len(p), nil
}

func (w *memoryWriter) Contains(s string) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, log := range w.logs {
		if strings.Contains(log, s) {
			return true
		}
	}
	return false
}

func (w *memoryWriter) Dump() []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]string(nil), w.logs...)
}

func TestLogRateLimiter(t *testing.T) {
	// 1 token per second, burst of 1
	rateLimiter := &logRateLimiter{limiter: rate.NewLimiter(rate.Every(1*time.Second), 1)}
	exampleMsg := "example_msg"

	memoryWriter := &memoryWriter{}
	logger := slog.New(slog.NewJSONHandler(memoryWriter, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})).With("component", "logging_test")

	// Create a burst of data
	for range 100 {
		rateLimiter.logEvent(t.Context(), logger, &bpfLogEvt{}, exampleMsg, slog.LevelInfo)
	}

	// We wait until there is a new token available
	require.Eventually(t, func() bool {
		return rateLimiter.limiter.Tokens() == 1
	}, 4*time.Second, 1*time.Second, "wait for a new token to be available")

	// When we are sure we have a new token, we log another event and we check for the suppression log
	rateLimiter.logEvent(t.Context(), logger, &bpfLogEvt{}, exampleMsg, slog.LevelInfo)

	t.Log("Dump logs for debugging:\n")
	for _, log := range memoryWriter.Dump() {
		t.Logf("log: %v", log)
	}
	require.True(t, memoryWriter.Contains(exampleMsg))
	require.True(t, memoryWriter.Contains(suppressionMsg))
}

func TestLogMissingPolicyMode(t *testing.T) {
	var m sync.RWMutex
	var foundEvent bpfLogEvt
	logTestFunc := func(_ context.Context, logger *slog.Logger, e *bpfLogEvt) {
		logger.Info("log event received", "evt", e, "comm", getComm(e))
		m.Lock()
		foundEvent = *e
		m.Unlock()
	}

	runner, err := newCgroupRunner(t)
	require.NoError(t, err, "Failed to create cgroup runner")
	defer runner.close()

	// replace the manager log handler with the test function
	runner.manager.logHandler = logTestFunc

	mockPolicyID := uint64(42)

	// populate policy values
	err = runner.manager.GetPolicyUpdateBinariesFunc()(mockPolicyID, []string{"/usr/bin/true"}, AddValuesToPolicy)
	require.NoError(t, err, "Failed to add policy values")

	// we don't populate the policy -> mode association on purpose so that we will trigger a log ebpf side.

	// populate cgroup to track
	err = runner.manager.GetCgroupPolicyUpdateFunc()(mockPolicyID, []uint64{runner.cgInfo.id}, AddPolicyToCgroups)
	require.NoError(t, err, "Failed to add policy to cgroup")

	// We throw a binary that is not allowed
	require.NoError(t, runner.runAndFindCommand(&runCommandArgs{
		command: "/usr/bin/who",
		channel: monitoringChannel,
		// we shouldn't find the event because we don't send it to userspace if we don't find the mode.
		shouldFindEvent: false,
	}))

	require.Eventually(t, func() bool {
		m.RLock()
		defer m.RUnlock()
		return foundEvent.Code == bpfLogEventCodeLOG_POLICY_MODE_MISSING
	}, 3*time.Second, 100*time.Millisecond, "log event is not generated")

	m.RLock()
	defer m.RUnlock()
	// we want our policy as argument
	require.Equal(t, mockPolicyID, foundEvent.Arg1)
	require.Equal(t, uint64(0), foundEvent.Arg2)
	require.Equal(t, runner.cgInfo.id, foundEvent.Cgid)
	// we don't set it in this test
	require.Equal(t, uint64(0), foundEvent.CgTrackerId)

	require.NotEmpty(t, getComm(&foundEvent))
	require.NotEqual(t, 0, foundEvent.Pid)
	require.NotEqual(t, 0, foundEvent.Tgid)

}
