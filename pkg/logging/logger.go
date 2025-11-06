package logging

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/GhostN3xus/Huntsuite/pkg/config"
)

type Level int

const (
	LevelDebug Level = iota
	LevelInfo
	LevelWarn
	LevelError
	LevelFatal
)

// RuntimeOptions represents verbosity overrides coming from CLI flags.
type RuntimeOptions struct {
	Quiet   bool
	Verbose bool
	Debug   bool
}

// Fields represents contextual logging fields.
type Fields map[string]any

type loggerCore struct {
	mu           sync.Mutex
	level        Level
	consoleLevel Level
	color        bool
	console      io.Writer
	filePath     string
	file         *os.File
	maxSizeBytes int64
	maxBackups   int
}

// Logger provides structured logging with colored console output and JSON file output.
type Logger struct {
	core       *loggerCore
	baseFields Fields
}

// NewLogger creates a new Logger instance.
func NewLogger(cfg config.LoggingConfig, runtime RuntimeOptions) (*Logger, error) {
	level := parseLevel(cfg.Level)
	consoleLevel := parseLevel(cfg.ConsoleLevel)

	if runtime.Debug {
		level = LevelDebug
		consoleLevel = LevelDebug
	} else if runtime.Verbose {
		consoleLevel = LevelDebug
	} else if runtime.Quiet {
		consoleLevel = LevelError
	}

	core := &loggerCore{
		level:        level,
		consoleLevel: consoleLevel,
		color:        cfg.Color && !runtime.Quiet,
		console:      os.Stdout,
		filePath:     cfg.FilePath,
		maxSizeBytes: int64(cfg.MaxSizeMB) * 1024 * 1024,
		maxBackups:   cfg.MaxBackups,
	}

	if core.maxSizeBytes == 0 {
		core.maxSizeBytes = 10 * 1024 * 1024
	}
	if core.maxBackups == 0 {
		core.maxBackups = 5
	}

	logger := &Logger{core: core, baseFields: Fields{}}

	if cfg.FileEnabled {
		if err := logger.openLogFile(); err != nil {
			return nil, err
		}
	}

	return logger, nil
}

func (l *Logger) openLogFile() error {
	if l.core.filePath == "" {
		return errors.New("logger: file path not configured")
	}
	if err := os.MkdirAll(filepath.Dir(l.core.filePath), 0o755); err != nil {
		return err
	}
	f, err := os.OpenFile(l.core.filePath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	l.core.file = f
	return nil
}

// With attaches additional fields to the logger.
func (l *Logger) With(fields Fields) *Logger {
	return &Logger{core: l.core, baseFields: mergeFields(l.baseFields, fields)}
}

// Sync flushes log buffers.
func (l *Logger) Sync() error {
	l.core.mu.Lock()
	defer l.core.mu.Unlock()
	if l.core.file != nil {
		return l.core.file.Sync()
	}
	return nil
}

// Close releases underlying resources.
func (l *Logger) Close() error {
	l.core.mu.Lock()
	defer l.core.mu.Unlock()
	if l.core.file != nil {
		err := l.core.file.Close()
		l.core.file = nil
		return err
	}
	return nil
}

// Debug logs at debug level.
func (l *Logger) Debug(msg string, fields Fields) {
	l.log(LevelDebug, msg, fields)
}

// Info logs at info level.
func (l *Logger) Info(msg string, fields Fields) {
	l.log(LevelInfo, msg, fields)
}

// Warn logs at warn level.
func (l *Logger) Warn(msg string, fields Fields) {
	l.log(LevelWarn, msg, fields)
}

// Error logs at error level.
func (l *Logger) Error(msg string, fields Fields) {
	l.log(LevelError, msg, fields)
}

// Fatal logs at fatal level and exits.
func (l *Logger) Fatal(msg string, fields Fields) {
	l.log(LevelFatal, msg, fields)
	os.Exit(1)
}

func (l *Logger) log(level Level, msg string, fields Fields) {
	merged := mergeFields(l.baseFields, fields)
	entry := map[string]any{
		"time":  time.Now().Format(time.RFC3339Nano),
		"level": level.String(),
		"msg":   msg,
	}
	for k, v := range merged {
		entry[k] = v
	}

	if l.core.consoleLevel <= level || level == LevelFatal {
		l.printConsole(level, msg, merged)
	}
	if l.core.file != nil && level >= l.core.level {
		l.writeFile(entry)
	}
}

func (l *Logger) printConsole(level Level, msg string, fields Fields) {
	l.core.mu.Lock()
	defer l.core.mu.Unlock()

	color := levelColor(level, l.core.color)
	icon := levelIcon(level)
	reset := ""
	bold := ""
	dim := ""

	if l.core.color {
		reset = "\033[0m"
		bold = "\033[1m"
		dim = "\033[2m"
	}

	timestamp := dim + time.Now().Format("15:04:05") + reset
	levelTag := color + bold + "[" + level.Short() + "]" + reset

	// Special formatting for findings
	if severity, ok := fields["severity"]; ok {
		severityColor := getSeverityColor(fmt.Sprint(severity), l.core.color)
		severityIcon := getSeverityIcon(fmt.Sprint(severity))

		fmt.Fprintf(l.core.console, "%s %s %s %s%s%s\n",
			timestamp,
			severityColor+severityIcon+reset,
			severityColor+"["+strings.ToUpper(fmt.Sprint(severity))+"]"+reset,
			bold, msg, reset)

		// Print fields in organized manner
		if findingType, ok := fields["type"]; ok {
			fmt.Fprintf(l.core.console, "  %s└─%s Type:%s %s\n", dim, reset, bold, findingType)
		}
		if target, ok := fields["target"]; ok {
			fmt.Fprintf(l.core.console, "  %s└─%s Target:%s %s\n", dim, reset, bold, target)
		}
		if evidence, ok := fields["evidence"]; ok {
			evidenceStr := fmt.Sprint(evidence)
			if len(evidenceStr) > 100 {
				evidenceStr = evidenceStr[:97] + "..."
			}
			fmt.Fprintf(l.core.console, "  %s└─%s Evidence:%s %s\n", dim, reset, reset, evidenceStr)
		}
	} else {
		// Normal log formatting
		fmt.Fprintf(l.core.console, "%s %s %s %s\n", timestamp, icon, levelTag, msg)

		// Print fields in a more organized way
		if len(fields) > 0 {
			keys := make([]string, 0, len(fields))
			for k := range fields {
				keys = append(keys, k)
			}
			sort.Strings(keys)

			for i, k := range keys {
				connector := "├─"
				if i == len(keys)-1 {
					connector = "└─"
				}
				value := fields[k]
				valueStr := fmt.Sprint(value)
				if len(valueStr) > 80 {
					valueStr = valueStr[:77] + "..."
				}
				fmt.Fprintf(l.core.console, "  %s%s%s %s%s:%s %s\n",
					dim, connector, reset, color, k, reset, valueStr)
			}
		}
	}
}

func (l *Logger) writeFile(entry map[string]any) {
	l.core.mu.Lock()
	defer l.core.mu.Unlock()
	if l.core.file == nil {
		return
	}
	if info, err := l.core.file.Stat(); err == nil {
		if info.Size() >= l.core.maxSizeBytes {
			l.rotate()
		}
	}
	enc := json.NewEncoder(l.core.file)
	_ = enc.Encode(entry)
}

func (l *Logger) rotate() {
	if l.core.file == nil {
		return
	}
	_ = l.core.file.Close()
	timestamp := time.Now().Format("20060102-150405")
	rotated := fmt.Sprintf("%s.%s", l.core.filePath, timestamp)
	_ = os.Rename(l.core.filePath, rotated)
	files, _ := filepath.Glob(l.core.filePath + ".*")
	if len(files) > l.core.maxBackups {
		sort.Strings(files)
		for i := 0; i < len(files)-l.core.maxBackups; i++ {
			_ = os.Remove(files[i])
		}
	}
	_ = l.openLogFile()
}

func mergeFields(base Fields, fields Fields) Fields {
	merged := Fields{}
	for k, v := range base {
		merged[k] = v
	}
	for k, v := range fields {
		if merged == nil {
			merged = Fields{}
		}
		merged[k] = v
	}
	return merged
}

func formatFields(fields Fields) string {
	if len(fields) == 0 {
		return ""
	}
	keys := make([]string, 0, len(fields))
	for k := range fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%v", k, fields[k]))
	}
	return strings.Join(parts, " ")
}

func parseLevel(level string) Level {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "debug":
		return LevelDebug
	case "warn":
		return LevelWarn
	case "error":
		return LevelError
	case "fatal":
		return LevelFatal
	default:
		return LevelInfo
	}
}

func levelColor(level Level, enabled bool) string {
	if !enabled {
		return ""
	}
	switch level {
	case LevelDebug:
		return "\033[36m"
	case LevelInfo:
		return "\033[34m"
	case LevelWarn:
		return "\033[33m"
	case LevelError, LevelFatal:
		return "\033[31m"
	default:
		return ""
	}
}

func (l Level) String() string {
	switch l {
	case LevelDebug:
		return "debug"
	case LevelInfo:
		return "info"
	case LevelWarn:
		return "warn"
	case LevelError:
		return "error"
	case LevelFatal:
		return "fatal"
	default:
		return "info"
	}
}

func (l Level) Short() string {
	switch l {
	case LevelDebug:
		return "DBG"
	case LevelInfo:
		return "INF"
	case LevelWarn:
		return "WRN"
	case LevelError:
		return "ERR"
	case LevelFatal:
		return "FTL"
	default:
		return "INF"
	}
}

func levelIcon(level Level) string {
	switch level {
	case LevelDebug:
		return "🔍"
	case LevelInfo:
		return "ℹ️ "
	case LevelWarn:
		return "⚠️ "
	case LevelError, LevelFatal:
		return "❌"
	default:
		return "•"
	}
}

func getSeverityColor(severity string, enabled bool) string {
	if !enabled {
		return ""
	}
	switch strings.ToLower(severity) {
	case "critical":
		return "\033[1;35m" // Bold magenta
	case "high":
		return "\033[1;31m" // Bold red
	case "medium":
		return "\033[1;33m" // Bold yellow
	case "low":
		return "\033[1;36m" // Bold cyan
	case "info":
		return "\033[1;34m" // Bold blue
	default:
		return "\033[37m" // White
	}
}

func getSeverityIcon(severity string) string {
	switch strings.ToLower(severity) {
	case "critical":
		return "🔥"
	case "high":
		return "🚨"
	case "medium":
		return "⚡"
	case "low":
		return "💡"
	case "info":
		return "📌"
	default:
		return "•"
	}
}
