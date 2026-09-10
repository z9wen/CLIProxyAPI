package management

import (
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
)

// TestManagementAccessAllowed pins the rule the control panel and the management
// API must share. The panel used to ignore allow-remote-management entirely and
// was served to anyone who could reach the port, so a deployment that had turned
// remote management off still handed its admin UI to remote callers.
func TestManagementAccessAllowed(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		clientIP    string
		allowRemote bool
		envOverride bool
		want        bool
	}{
		{name: "loopback is always allowed", clientIP: "127.0.0.1", allowRemote: false, want: true},
		{name: "ipv6 loopback is always allowed", clientIP: "::1", allowRemote: false, want: true},
		{name: "ipv4-mapped loopback counts as local", clientIP: "::ffff:127.0.0.1", allowRemote: false, want: true},
		{name: "remote denied when allow-remote is off", clientIP: "203.0.113.10", allowRemote: false, want: false},
		{name: "remote allowed when allow-remote is on", clientIP: "203.0.113.10", allowRemote: true, want: true},
		{name: "env override allows remote even with allow-remote off", clientIP: "203.0.113.10", allowRemote: false, envOverride: true, want: true},
		{name: "unparseable address is not local", clientIP: "not-an-ip", allowRemote: false, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			h := &Handler{
				cfg:                 &config.Config{RemoteManagement: config.RemoteManagement{AllowRemote: tt.allowRemote}},
				allowRemoteOverride: tt.envOverride,
			}
			if got := h.ManagementAccessAllowed(tt.clientIP); got != tt.want {
				t.Fatalf("ManagementAccessAllowed(%q) = %v, want %v", tt.clientIP, got, tt.want)
			}
		})
	}
}

// TestManagementAccessAllowedNilHandler keeps the panel from panicking when the
// handler was never constructed.
func TestManagementAccessAllowedNilHandler(t *testing.T) {
	t.Parallel()

	var h *Handler
	if h.ManagementAccessAllowed("127.0.0.1") {
		t.Fatal("nil handler must not grant access")
	}
	if h.remoteManagementEnabled() {
		t.Fatal("nil handler must not report remote management enabled")
	}
}
