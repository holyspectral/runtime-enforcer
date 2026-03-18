package main

import (
	"context"
	"log/slog"
	"strings"
)

type serverErrorLogHandler struct {
	h slog.Handler
}

var _ slog.Handler = (*serverErrorLogHandler)(nil)

func newServerErrorLogHandler(h slog.Handler) *serverErrorLogHandler {
	return &serverErrorLogHandler{
		h: h,
	}
}

func (s *serverErrorLogHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return s.h.Enabled(ctx, level)
}

func (s *serverErrorLogHandler) Handle(ctx context.Context, r slog.Record) error {
	// handle TLS handshake error from probing client, which is not a real error and can be ignored
	if strings.HasPrefix(r.Message, "http: TLS handshake error from") &&
		strings.HasSuffix(r.Message, ": EOF") {
		return nil
	}
	return s.h.Handle(ctx, r)
}

func (s *serverErrorLogHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &serverErrorLogHandler{h: s.h.WithAttrs(attrs)}
}

func (s *serverErrorLogHandler) WithGroup(name string) slog.Handler {
	return &serverErrorLogHandler{h: s.h.WithGroup(name)}
}

/*
func (*serverErrorLogHandler) Write(p []byte) (int, error) {
	m := string(p)
	// https://github.com/golang/go/issues/26918
	if strings.HasPrefix(m, "http: TLS handshake error") && strings.HasSuffix(m, ": EOF\n") {
		// handle EOF error
	} else {
		// handle other errors
	}
	return len(p), nil
}
*/
