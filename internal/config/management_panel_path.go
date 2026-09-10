package config

import (
	"fmt"
	"strings"

	log "github.com/sirupsen/logrus"
)

// DefaultManagementPanelPath is the path the control panel is served at when the
// operator does not choose another one.
const DefaultManagementPanelPath = "management.html"

// NormalizeManagementPanelPath maps a configured value to the path the panel is
// served at. An empty value selects the default.
//
// The result must stay a single, plain path segment: it becomes a route, so a
// slash, a dot-segment or a query character would either escape the intended
// location or register something the router cannot match.
func NormalizeManagementPanelPath(raw string) (string, bool) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return DefaultManagementPanelPath, true
	}
	if trimmed == "." || trimmed == ".." {
		return "", false
	}
	if strings.ContainsAny(trimmed, `/\?#`) {
		return "", false
	}
	if !strings.HasSuffix(strings.ToLower(trimmed), ".html") {
		return "", false
	}
	for _, r := range trimmed {
		switch {
		case r >= 'a' && r <= 'z',
			r >= 'A' && r <= 'Z',
			r >= '0' && r <= '9',
			r == '-', r == '_', r == '.':
		default:
			return "", false
		}
	}
	return trimmed, true
}

// ValidateManagementPanelPath reports an error for values that would be silently
// replaced, so management writes can reject them instead.
func ValidateManagementPanelPath(raw string) error {
	if _, ok := NormalizeManagementPanelPath(raw); !ok {
		return fmt.Errorf("unsupported panel-path %q (expected a single path segment ending in .html, or empty)", strings.TrimSpace(raw))
	}
	return nil
}

// SanitizeManagementPanelPath replaces an unusable panel path with the default.
// A value that reaches here already survived YAML parsing, so the warning is the
// only feedback an operator gets before the panel moves to an unexpected URL.
func (c *Config) SanitizeManagementPanelPath() {
	if c == nil {
		return
	}
	if strings.TrimSpace(c.RemoteManagement.PanelPath) == "" {
		return
	}
	normalized, ok := NormalizeManagementPanelPath(c.RemoteManagement.PanelPath)
	if !ok {
		log.Warnf("invalid remote-management.panel-path %q; serving the control panel at %q",
			c.RemoteManagement.PanelPath, DefaultManagementPanelPath)
		c.RemoteManagement.PanelPath = ""
		return
	}
	c.RemoteManagement.PanelPath = normalized
}

// ManagementPanelPath is the path the control panel is served at, always a
// usable value even when the configured one was rejected.
func (c *Config) ManagementPanelPath() string {
	if c == nil {
		return DefaultManagementPanelPath
	}
	if path, ok := NormalizeManagementPanelPath(c.RemoteManagement.PanelPath); ok {
		return path
	}
	return DefaultManagementPanelPath
}
