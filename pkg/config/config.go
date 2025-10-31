package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
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
		},
		Output: OutputConfig{EnableColor: true},
		Notify: NotificationsConfig{},
	}
}

func writeDefaultConfig(path string, cfg *Config) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	content := fmt.Sprintf(`general:
  data_dir: %s
  proxy: ""
database:
  path: %s
  auto_migrate: true
logging:
  level: info
  console_level: info
  file_enabled: true
  file_path: %s
  max_size_mb: 10
  max_backups: 5
  color: true
scanning:
  timeout_seconds: 20
  threads: 4
  rate_limit_per_host: 0
  user_agent: HuntSuite/1.0
  request_delay: 0s
output:
  enable_color: true
notifications:
  telegram_token: ""
  telegram_chat_id: ""
`, cfg.General.DataDir, cfg.Database.Path, cfg.Logging.FilePath)
	return os.WriteFile(path, []byte(content), 0o644)
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
