package bpf

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"

	"github.com/cilium/ebpf/ringbuf"
)

// logEventHandler is a callback invoked for each BPF log event.
// It can be replaced in tests to capture log events without relying on slog output.
type logEventHandler func(ctx context.Context, logger *slog.Logger, evt *bpfLogEvt)

// defaultLogEventMsg is the default function used in production.
func defaultLogEventMsg(ctx context.Context, logger *slog.Logger, evt *bpfLogEvt) {
	switch evt.Code {
	case bpfLogEventCodeLOG_MISSING_PROCESS_EVT_MAP:
		// CPU
		logger.ErrorContext(ctx, "missing process evt per-cpu map")
	case bpfLogEventCodeLOG_MISSING_FILE_STRUCT:
		// CGROUP_TRACKER_ID, PID
		logger.ErrorContext(ctx, "executable with missing file struct")
	case bpfLogEventCodeLOG_FAIL_TO_RESOLVE_PATH:
		// CGROUP_TRACKER_ID, PID
		logger.WarnContext(ctx, "failed to resolve path")
	case bpfLogEventCodeLOG_EMPTY_PATH:
		// CGROUP_TRACKER_ID, PID
		logger.WarnContext(ctx, "empty path detected")
	case bpfLogEventCodeLOG_FAIL_TO_COPY_EXEC_PATH:
		// CGROUP_TRACKER_ID, PID
		logger.ErrorContext(ctx, "failed to copy exec path")
	case bpfLogEventCodeLOG_DROP_EXEC_EVENT:
		// CGROUP_TRACKER_ID, PID
		logger.WarnContext(ctx, "dropped exec event")
	case bpfLogEventCodeLOG_PATH_LEN_TOO_LONG:
		// CGROUP_TRACKER_ID, PID
		logger.WarnContext(ctx, "path length too long")
	case bpfLogEventCodeLOG_POLICY_MODE_MISSING:
		// CGROUP_TRACKER_ID, PID, POLICY
		logger.WarnContext(ctx, "policy mode missing")
	case bpfLogEventCodeLOG_DROP_VIOLATION:
		// CGROUP_TRACKER_ID, PID, POLICY
		logger.WarnContext(ctx, "dropped violation event")
	case bpfLogEventCodeLOG_FAIL_TO_RESOLVE_CGROUP_ID:
		logger.WarnContext(ctx, "failed to resolve cgroup id")
	case bpfLogEventCodeLOG_FAIL_TO_RESOLVE_PARENT_CGROUP_ID:
		logger.WarnContext(ctx, "failed to resolve parent cgroup id")
	default:
		logger.ErrorContext(ctx, "unknown log event type", "type", evt.Code)
	}
}

func (m *Manager) loggerStart(ctx context.Context) error {
	buf := m.objs.RingbufLogs
	rd, err := ringbuf.NewReader(buf)
	if err != nil {
		return fmt.Errorf("opening %s ringbuf reader: %w", buf.String(), err)
	}

	go func() {
		<-ctx.Done()
		if err = rd.Close(); err != nil {
			m.logger.ErrorContext(ctx, "closing ringbuf reader", "error", err)
		}
	}()

	var record ringbuf.Record
	for {
		record, err = rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				m.logger.InfoContext(ctx, "ringbuf reader closed")
				return nil
			}
			return fmt.Errorf("reading from reader: %w", err)
		}

		buf := bytes.NewBuffer(record.RawSample)
		var evt bpfLogEvt
		if err = binary.Read(buf, binary.LittleEndian, &evt); err != nil {
			m.logger.ErrorContext(ctx, "parsing ringbuf event", "error", err)
			continue
		}
		m.logHandler(ctx, m.logger, &evt)
	}
}
