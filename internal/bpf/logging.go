package bpf

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"unsafe"

	"github.com/cilium/ebpf/ringbuf"
)

// logEventHandler is a callback invoked for each BPF log event.
// It can be replaced in tests to capture log events without relying on slog output.
type logEventHandler func(ctx context.Context, logger *slog.Logger, evt *bpfLogEvt)

func getComm(evt *bpfLogEvt) string {
	// Reinterpret the []int8 (C char array) as []byte without copying,
	// then trim at the first NUL byte.
	commBytes := unsafe.Slice((*byte)(unsafe.Pointer(&evt.Comm[0])), len(evt.Comm))
	n := bytes.IndexByte(commBytes, 0)
	if n == -1 {
		// if there is no null terminator we return the full string
		n = len(commBytes)
	}
	return string(commBytes[:n])
}

func logEvent(
	ctx context.Context,
	logger *slog.Logger,
	evt *bpfLogEvt,
	msg string,
	level slog.Level,
	additionalArgs ...any,
) {
	attrs := []any{
		"tid", evt.Pid,
		"pid", evt.Tgid,
		"comm", getComm(evt),
		"cgroup", evt.Cgid,
		"cgroup_tracker_id", evt.CgTrackerId,
	}
	attrs = append(attrs, additionalArgs...)
	logger.Log(ctx, level, msg, attrs...)
}

// defaultLogEventMsg is the default function used in production.
func defaultLogEventMsg(ctx context.Context, logger *slog.Logger, evt *bpfLogEvt) {
	switch evt.Code {
	case bpfLogEventCodeLOG_MISSING_PROCESS_EVT_MAP:
		// arg1 is CPU
		logEvent(ctx, logger, evt, "missing process evt per-cpu map", slog.LevelError,
			"cpu", evt.Arg1)
	case bpfLogEventCodeLOG_MISSING_FILE_STRUCT:
		logEvent(ctx, logger, evt, "executable with missing file struct", slog.LevelError)
	case bpfLogEventCodeLOG_FAIL_TO_RESOLVE_PATH:
		logEvent(ctx, logger, evt, "failed to resolve path", slog.LevelWarn)
	case bpfLogEventCodeLOG_EMPTY_PATH:
		logEvent(ctx, logger, evt, "empty path detected", slog.LevelWarn)
	case bpfLogEventCodeLOG_FAIL_TO_COPY_EXEC_PATH:
		logEvent(ctx, logger, evt, "failed to copy exec path", slog.LevelError)
	case bpfLogEventCodeLOG_DROP_EXEC_EVENT:
		logEvent(ctx, logger, evt, "dropped exec event", slog.LevelWarn)
	case bpfLogEventCodeLOG_PATH_LEN_TOO_LONG:
		logEvent(ctx, logger, evt, "path length too long", slog.LevelWarn)
	case bpfLogEventCodeLOG_POLICY_MODE_MISSING:
		// arg1 is the policy ID
		logEvent(ctx, logger, evt, "policy mode missing", slog.LevelWarn,
			"policy_id", evt.Arg1)
	case bpfLogEventCodeLOG_DROP_VIOLATION:
		// arg1 is the policy ID
		// arg2 is the mode
		logEvent(ctx, logger, evt, "dropped violation event", slog.LevelWarn,
			"policy_id", evt.Arg1,
			"mode", evt.Arg2)
	case bpfLogEventCodeLOG_FAIL_TO_RESOLVE_CGROUP_ID:
		logEvent(ctx, logger, evt, "failed to resolve cgroup id", slog.LevelWarn)
	case bpfLogEventCodeLOG_FAIL_TO_RESOLVE_PARENT_CGROUP_ID:
		logEvent(ctx, logger, evt, "failed to resolve parent cgroup id", slog.LevelWarn)
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
