package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	defaultConfigName = "config.yaml"
	configDirName     = ".huntsuite"
)

// Config represents the full runtime configuration for HuntSuite.
type Config struct {
	General  GeneralConfig
	Database DatabaseConfig
	Logging  LoggingConfig
	Scanning ScanningConfig
	Output   OutputConfig
	Notify   NotificationsConfig
}

type GeneralConfig struct {
	DataDir string
	Proxy   string
}

type DatabaseConfig struct {
	Path        string
	AutoMigrate bool
}

type LoggingConfig struct {
	Level        string
	ConsoleLevel string
	FileEnabled  bool
	FilePath     string
	MaxSizeMB    int
	MaxBackups   int
	Color        bool
}

type ScanningConfig struct {
	TimeoutSeconds   int
	Threads          int
	RateLimitPerHost int
	UserAgent        string
	RequestDelay     time.Duration
	Headers          map[string]string
}

type OutputConfig struct {
	EnableColor bool
}

type NotificationsConfig struct {
	TelegramToken  string
	TelegramChatID string
}

// Load loads configuration from disk and applies defaults.
func Load(pathOverride string) (*Config, string, error) {
	cfgDir, err := ensureConfigDir()
	if err != nil {
		return nil, "", err
	}

	cfgPath := pathOverride
	if strings.TrimSpace(cfgPath) == "" {
		cfgPath = filepath.Join(cfgDir, defaultConfigName)
	}

	cfg := defaultConfig(cfgDir)

	if _, err := os.Stat(cfgPath); errors.Is(err, os.ErrNotExist) {
		if err := writeDefaultConfig(cfgPath, cfg); err != nil {
			return nil, "", err
		}
		return cfg, cfgPath, nil
	}

	data, err := os.ReadFile(cfgPath)
	if err != nil {
		return nil, "", err
	}

	if err := parseConfig(data, cfg); err != nil {
		return nil, "", err
	}

	hydrate(cfg, cfgDir)
	return cfg, cfgPath, nil
}

func ensureConfigDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	cfgDir := filepath.Join(home, configDirName)
	if err := os.MkdirAll(cfgDir, 0o700); err != nil {
		return "", err
	}
	return cfgDir, nil
}

func defaultConfig(cfgDir string) *Config {
	dataDir := filepath.Join(cfgDir, "data")
	logDir := filepath.Join(cfgDir, "logs")
	_ = os.MkdirAll(dataDir, 0o755)
	_ = os.MkdirAll(logDir, 0o755)

	return &Config{
		General: GeneralConfig{
			DataDir: dataDir,
		},
		Database: DatabaseConfig{
			Path:        filepath.Join(dataDir, "huntsuite.db"),
			AutoMigrate: true,
		},
		Logging: LoggingConfig{
			Level:        "info",
			ConsoleLevel: "info",
			FileEnabled:  true,
			FilePath:     filepath.Join(logDir, "huntsuite.log"),
			MaxSizeMB:    10,
			MaxBackups:   5,
			Color:        true,
		},
		Scanning: ScanningConfig{
			TimeoutSeconds:   20,
			Threads:          4,
			RateLimitPerHost: 0,
			UserAgent:        "HuntSuite/1.0",
			RequestDelay:     0,
			Headers:          map[string]string{},
		},
		Output: OutputConfig{EnableColor: true},
		Notify: NotificationsConfig{},
	}
}

func writeDefaultConfig(path string, cfg *Config) error {
	if cfg == nil {
		cfg = defaultConfig(filepath.Dir(path))
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}

	headerString := formatHeaderString(cfg.Scanning.Headers)

	builder := &strings.Builder{}
	fmt.Fprintf(builder, "general:\n")
	fmt.Fprintf(builder, "  data_dir: %s\n", strconv.Quote(cfg.General.DataDir))
	fmt.Fprintf(builder, "  proxy: %s\n", strconv.Quote(cfg.General.Proxy))
	fmt.Fprintf(builder, "database:\n")
	fmt.Fprintf(builder, "  path: %s\n", strconv.Quote(cfg.Database.Path))
	fmt.Fprintf(builder, "  auto_migrate: %t\n", cfg.Database.AutoMigrate)
	fmt.Fprintf(builder, "logging:\n")
	fmt.Fprintf(builder, "  level: %s\n", strconv.Quote(cfg.Logging.Level))
	fmt.Fprintf(builder, "  console_level: %s\n", strconv.Quote(cfg.Logging.ConsoleLevel))
	fmt.Fprintf(builder, "  file_enabled: %t\n", cfg.Logging.FileEnabled)
	fmt.Fprintf(builder, "  file_path: %s\n", strconv.Quote(cfg.Logging.FilePath))
	fmt.Fprintf(builder, "  max_size_mb: %d\n", cfg.Logging.MaxSizeMB)
	fmt.Fprintf(builder, "  max_backups: %d\n", cfg.Logging.MaxBackups)
	fmt.Fprintf(builder, "  color: %t\n", cfg.Logging.Color)
	fmt.Fprintf(builder, "scanning:\n")
	fmt.Fprintf(builder, "  timeout_seconds: %d\n", cfg.Scanning.TimeoutSeconds)
	fmt.Fprintf(builder, "  threads: %d\n", cfg.Scanning.Threads)
	fmt.Fprintf(builder, "  rate_limit_per_host: %d\n", cfg.Scanning.RateLimitPerHost)
	fmt.Fprintf(builder, "  user_agent: %s\n", strconv.Quote(cfg.Scanning.UserAgent))
	fmt.Fprintf(builder, "  request_delay: %s\n", strconv.Quote(cfg.Scanning.RequestDelay.String()))
	fmt.Fprintf(builder, "  headers: %s\n", strconv.Quote(headerString))
	fmt.Fprintf(builder, "output:\n")
	fmt.Fprintf(builder, "  enable_color: %t\n", cfg.Output.EnableColor)
	fmt.Fprintf(builder, "notifications:\n")
	fmt.Fprintf(builder, "  telegram_token: %s\n", strconv.Quote(cfg.Notify.TelegramToken))
	fmt.Fprintf(builder, "  telegram_chat_id: %s\n", strconv.Quote(cfg.Notify.TelegramChatID))

	return os.WriteFile(path, []byte(builder.String()), 0o644)
}

func formatHeaderString(headers map[string]string) string {
	if len(headers) == 0 {
		return ""
	}
	keys := make([]string, 0, len(headers))
	for k := range headers {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%s", strings.TrimSpace(k), strings.TrimSpace(headers[k])))
	}
	return strings.Join(parts, ", ")
}

func parseConfig(data []byte, cfg *Config) error {
	type section map[string]string
	sections := map[string]section{}
	var current string
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if !strings.Contains(line, ":") {
			continue
		}
		if strings.HasSuffix(trimmed, ":") && !strings.Contains(trimmed, " ") {
			current = strings.TrimSuffix(trimmed, ":")
			if _, ok := sections[current]; !ok {
				sections[current] = section{}
			}
			continue
		}
		if current == "" {
			continue
		}
		parts := strings.SplitN(strings.TrimSpace(line), ":", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		value = strings.Trim(value, "\"'")
		sections[current][key] = value
	}

	applySection := func(sec section, setters map[string]func(string) error) error {
		for key, set := range setters {
			if val, ok := sec[key]; ok {
				if err := set(val); err != nil {
					return fmt.Errorf("config: invalid value for %s: %w", key, err)
				}
			}
		}
		return nil
	}

	if sec, ok := sections["general"]; ok {
		if err := applySection(sec, map[string]func(string) error{
			"data_dir": func(v string) error { cfg.General.DataDir = v; return nil },
			"proxy":    func(v string) error { cfg.General.Proxy = v; return nil },
		}); err != nil {
			return err
		}
	}

	if sec, ok := sections["database"]; ok {
		if err := applySection(sec, map[string]func(string) error{
			"path": func(v string) error { cfg.Database.Path = v; return nil },
			"auto_migrate": func(v string) error {
				cfg.Database.AutoMigrate = parseBool(v, cfg.Database.AutoMigrate)
				return nil
			},
		}); err != nil {
			return err
		}
	}

	if sec, ok := sections["logging"]; ok {
		if err := applySection(sec, map[string]func(string) error{
			"level":         func(v string) error { cfg.Logging.Level = v; return nil },
			"console_level": func(v string) error { cfg.Logging.ConsoleLevel = v; return nil },
			"file_enabled": func(v string) error {
				cfg.Logging.FileEnabled = parseBool(v, cfg.Logging.FileEnabled)
				return nil
			},
			"file_path": func(v string) error { cfg.Logging.FilePath = v; return nil },
			"max_size_mb": func(v string) error {
				n, err := strconv.Atoi(v)
				if err != nil {
					return err
				}
				cfg.Logging.MaxSizeMB = n
				return nil
			},
			"max_backups": func(v string) error {
				n, err := strconv.Atoi(v)
				if err != nil {
					return err
				}
				cfg.Logging.MaxBackups = n
				return nil
			},
			"color": func(v string) error {
				cfg.Logging.Color = parseBool(v, cfg.Logging.Color)
				return nil
			},
		}); err != nil {
			return err
		}
	}

	if sec, ok := sections["scanning"]; ok {
		if err := applySection(sec, map[string]func(string) error{
			"timeout_seconds": func(v string) error {
				n, err := strconv.Atoi(v)
				if err != nil {
					return err
				}
				cfg.Scanning.TimeoutSeconds = n
				return nil
			},
			"threads": func(v string) error {
				n, err := strconv.Atoi(v)
				if err != nil {
					return err
				}
				cfg.Scanning.Threads = n
				return nil
			},
			"rate_limit_per_host": func(v string) error {
				n, err := strconv.Atoi(v)
				if err != nil {
					return err
				}
				cfg.Scanning.RateLimitPerHost = n
				return nil
			},
			"user_agent": func(v string) error { cfg.Scanning.UserAgent = v; return nil },
			"request_delay": func(v string) error {
				d, err := time.ParseDuration(v)
				if err != nil {
					return err
				}
				cfg.Scanning.RequestDelay = d
				return nil
			},
			"headers": func(v string) error {
				headers, err := parseHeaderMap(v)
				if err != nil {
					return err
				}
				cfg.Scanning.Headers = headers
				return nil
			},
		}); err != nil {
			return err
		}
	}

	if sec, ok := sections["output"]; ok {
		if err := applySection(sec, map[string]func(string) error{
			"enable_color": func(v string) error {
				cfg.Output.EnableColor = parseBool(v, cfg.Output.EnableColor)
				return nil
			},
		}); err != nil {
			return err
		}
	}

	if sec, ok := sections["notifications"]; ok {
		if err := applySection(sec, map[string]func(string) error{
			"telegram_token":   func(v string) error { cfg.Notify.TelegramToken = v; return nil },
			"telegram_chat_id": func(v string) error { cfg.Notify.TelegramChatID = v; return nil },
		}); err != nil {
			return err
		}
	}

	return nil
}

func hydrate(cfg *Config, cfgDir string) {
	if cfg.General.DataDir == "" {
		cfg.General.DataDir = filepath.Join(cfgDir, "data")
	}
	if cfg.Logging.FilePath == "" {
		cfg.Logging.FilePath = filepath.Join(cfgDir, "logs", "huntsuite.log")
	}
	if cfg.Database.Path == "" {
		cfg.Database.Path = filepath.Join(cfg.General.DataDir, "huntsuite.db")
	}
	if cfg.Scanning.Headers == nil {
		cfg.Scanning.Headers = map[string]string{}
	}
}

func parseBool(val string, def bool) bool {
	switch strings.ToLower(strings.TrimSpace(val)) {
	case "true", "1", "yes", "on":
		return true
	case "false", "0", "no", "off":
		return false
	default:
		return def
	}
}

// Save writes configuration back to disk.
func Save(cfg *Config, path string) error {
	return writeDefaultConfig(path, cfg)
}

func parseHeaderMap(val string) (map[string]string, error) {
	headers := map[string]string{}
	trimmed := strings.TrimSpace(val)
	if trimmed == "" {
		return headers, nil
	}
	tokens := strings.FieldsFunc(trimmed, func(r rune) bool {
		return r == ',' || r == ';' || r == '\n'
	})
	for _, token := range tokens {
		token = strings.TrimSpace(token)
		if token == "" {
			continue
		}
		var key, value string
		if parts := strings.SplitN(token, ":", 2); len(parts) == 2 {
			key = parts[0]
			value = parts[1]
		} else if parts := strings.SplitN(token, "=", 2); len(parts) == 2 {
			key = parts[0]
			value = parts[1]
		} else {
			return nil, fmt.Errorf("header %q missing separator", token)
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if key == "" {
			return nil, fmt.Errorf("empty header name in %q", token)
		}
		headers[key] = value
	}
	return headers, nil
}
