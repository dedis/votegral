package log

import (
	"context"
	"fmt" // Import the fmt package
	"io"
	"log/slog"
	"os"
	"runtime"
	"strings"
	"time"
)

// LogLevel is an alias for slog's Level
type LogLevel = slog.Level

const (
	LevelTrace = slog.Level(-8)
	LevelDebug = slog.LevelDebug
	LevelInfo  = slog.LevelInfo
	LevelError = slog.LevelError
)

// Global logger instance and its configuration.
var (
	L             *slog.Logger
	currentLevel  slog.Level = LevelInfo
	currentWriter io.Writer  = os.Stderr
)

func init() {
	rebuildLogger()
}

// rebuildLogger creates a new global logger. It's called on init and when settings change.
func rebuildLogger() {
	L = slog.New(slog.NewTextHandler(currentWriter, &slog.HandlerOptions{
		AddSource: true,
		Level:     currentLevel,
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if a.Key == slog.SourceKey {
				if source, ok := a.Value.Any().(*slog.Source); ok {
					// Shorten the path to be relative to the project root.
					idx := strings.LastIndex(source.File, "votegral/")
					if idx > -1 {
						source.File = source.File[idx:]
					}
				}
			}
			return a
		},
	}))
}

// SetLevel creates a new global logger with the specified minimum level.
func SetLevel(level LogLevel) {
	currentLevel = level
	rebuildLogger()
}

// SetOutput creates a new global logger with a different writer.
func SetOutput(w io.Writer) {
	currentWriter = w
	rebuildLogger()
}

// log is the internal logging function that correctly captures the call site.
func log(level LogLevel, format string, v ...any) {
	if !L.Handler().Enabled(context.Background(), level) {
		return
	}
	// Skip 3 frames to get to the original caller.
	var pcs [1]uintptr
	runtime.Callers(3, pcs[:])
	r := slog.NewRecord(time.Now(), level, fmt.Sprintf(format, v...), pcs[0])
	// Dispatch the record to the handler.
	_ = L.Handler().Handle(context.Background(), r)
}

// Helper functions to access the global logger easily.
func Trace(format string, v ...any) { log(LevelTrace, format, v...) }
func Debug(format string, v ...any) { log(LevelDebug, format, v...) }
func Info(format string, v ...any)  { log(LevelInfo, format, v...) }
func Error(format string, v ...any) { log(LevelError, format, v...) }

// Fatalf logs a message at the Error level and then calls os.Exit(1).
func Fatalf(format string, v ...any) {
	log(LevelError, format, v...)
	os.Exit(1)
}
