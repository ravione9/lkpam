// Package config centralizes environment variable parsing for all services.
package config

import (
	"os"
	"strconv"
	"time"
)

// Get returns the env value or fallback if unset/empty.
func Get(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// GetInt returns the env value parsed as int, or fallback on error/missing.
func GetInt(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return fallback
}

// GetDuration parses a duration like "30m" or "12h".
func GetDuration(key string, fallback time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return fallback
}
