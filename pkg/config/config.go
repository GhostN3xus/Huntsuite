package config

import (
    "encoding/json"
    "os"
    "path/filepath"
    "runtime"
)

type Config struct {
    TelegramToken string `json:"telegram_token,omitempty"`
    TelegramChatID string `json:"telegram_chat_id,omitempty"`
    // future: add whatsapp configs etc.
}

func configPath() string {
    var home string
    if runtime.GOOS == "windows" {
        home = os.Getenv("USERPROFILE")
    } else {
        home = os.Getenv("HOME")
    }
    if home == "" {
        home = "."
    }
    dir := filepath.Join(home, ".huntsuite")
    _ = os.MkdirAll(dir, 0o700)
    return filepath.Join(dir, "config.json")
}

func Save(cfg *Config) error {
    p := configPath()
    f, err := os.OpenFile(p, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
    if err != nil {
        return err
    }
    defer f.Close()
    enc := json.NewEncoder(f)
    enc.SetIndent("", "  ")
    return enc.Encode(cfg)
}

func Load() (*Config, error) {
    p := configPath()
    f, err := os.Open(p)
    if err != nil {
        // return empty config if missing
        return &Config{}, nil
    }
    defer f.Close()
    var cfg Config
    dec := json.NewDecoder(f)
    if err := dec.Decode(&cfg); err != nil {
        return &Config{}, err
    }
    return &cfg, nil
}
