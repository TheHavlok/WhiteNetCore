// Package wnlog builds the structured logger used by the panel and the agent.
//
// It is a thin wrapper over log/slog: one place that turns the configured
// level and format strings into a handler, so Main and the agent cannot drift
// apart in how their logs read.
package wnlog

import (
	"io"
	"log/slog"
	"os"
	"strings"
)

// New returns a logger writing to stderr. An unrecognised level falls back to
// info and an unrecognised format to text, because refusing to start over a
// typo in a log setting would be worse than logging slightly differently.
func New(level, format string) *slog.Logger {
	return NewTo(os.Stderr, level, format)
}

// NewTo is New with an explicit destination, which the tests use.
func NewTo(w io.Writer, level, format string) *slog.Logger {
	opts := &slog.HandlerOptions{Level: ParseLevel(level)}
	var handler slog.Handler
	if strings.EqualFold(strings.TrimSpace(format), "json") {
		handler = slog.NewJSONHandler(w, opts)
	} else {
		handler = slog.NewTextHandler(w, opts)
	}
	return slog.New(handler)
}

// ParseLevel maps a configuration string to a slog level.
func ParseLevel(level string) slog.Level {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
