package bootstrap

import (
	"os"
	"strings"
)

const (
	defaultLogLevel  = "info"
	defaultLogFormat = "console"
	defaultWorkers   = 4
)

type Config struct {
	LogLevel  string
	LogFormat string
	Workers   int
}

func LoadConfig() Config {
	cfg := Config{
		LogLevel:  envOrDefault("SECFACTS_LOG_LEVEL", defaultLogLevel),
		LogFormat: envOrDefault("SECFACTS_LOG_FORMAT", defaultLogFormat),
		Workers:   defaultWorkers,
	}

	if value := strings.TrimSpace(os.Getenv("SECFACTS_WORKERS")); value != "" {
		if workers, ok := parsePositiveInt(value); ok {
			cfg.Workers = workers
		}
	}

	return cfg
}

func envOrDefault(key string, fallback string) string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}

	return value
}
