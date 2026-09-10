package config

import "testing"

// The panel path becomes a route, so anything that is not a single plain path
// segment must be rejected rather than registered.
func TestNormalizeManagementPanelPath(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		raw     string
		want    string
		wantErr bool
	}{
		{name: "empty selects the default", raw: "", want: DefaultManagementPanelPath},
		{name: "default is kept", raw: "management.html", want: "management.html"},
		{name: "renamed panel", raw: "console-a1b2.html", want: "console-a1b2.html"},
		{name: "uppercase suffix ok", raw: "Panel.HTML", want: "Panel.HTML"},
		{name: "surrounding space trimmed", raw: "  panel.html  ", want: "panel.html"},

		{name: "nested path", raw: "admin/panel.html", wantErr: true},
		{name: "traversal", raw: "../panel.html", wantErr: true},
		{name: "dot segment", raw: ".", wantErr: true},
		{name: "dot dot segment", raw: "..", wantErr: true},
		{name: "query character", raw: "panel.html?x=1", wantErr: true},
		{name: "fragment character", raw: "panel.html#frag", wantErr: true},
		{name: "backslash", raw: `panel\x.html`, wantErr: true},
		{name: "missing html suffix", raw: "panel", wantErr: true},
		{name: "empty name with suffix only", raw: ".html", want: ".html"},
		{name: "space inside", raw: "my panel.html", wantErr: true},
		{name: "percent escape", raw: "panel%2ehtml", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, ok := NormalizeManagementPanelPath(tt.raw)
			if tt.wantErr {
				if ok {
					t.Fatalf("NormalizeManagementPanelPath(%q) = %q, want rejection", tt.raw, got)
				}
				if errValidate := ValidateManagementPanelPath(tt.raw); errValidate == nil {
					t.Fatalf("ValidateManagementPanelPath(%q) = nil, want an error", tt.raw)
				}
				return
			}
			if !ok {
				t.Fatalf("NormalizeManagementPanelPath(%q) rejected, want %q", tt.raw, tt.want)
			}
			if got != tt.want {
				t.Fatalf("NormalizeManagementPanelPath(%q) = %q, want %q", tt.raw, got, tt.want)
			}
		})
	}
}

// TestManagementPanelPathAlwaysUsable pins the accessor the router uses: it must
// never hand back something that cannot be registered as a route, even when the
// configured value is junk.
func TestManagementPanelPathAlwaysUsable(t *testing.T) {
	t.Parallel()

	var nilConfig *Config
	if got := nilConfig.ManagementPanelPath(); got != DefaultManagementPanelPath {
		t.Fatalf("nil config panel path = %q, want %q", got, DefaultManagementPanelPath)
	}

	cfg := &Config{RemoteManagement: RemoteManagement{PanelPath: "admin/panel.html"}}
	if got := cfg.ManagementPanelPath(); got != DefaultManagementPanelPath {
		t.Fatalf("unusable panel path = %q, want the default", got)
	}

	// The sanitizer clears the bad value so a rejected config does not keep
	// reporting the value it was told to ignore.
	cfg.SanitizeManagementPanelPath()
	if cfg.RemoteManagement.PanelPath != "" {
		t.Fatalf("sanitizer left %q in place, want it cleared", cfg.RemoteManagement.PanelPath)
	}

	cfg.RemoteManagement.PanelPath = "console.html"
	cfg.SanitizeManagementPanelPath()
	if got := cfg.ManagementPanelPath(); got != "console.html" {
		t.Fatalf("panel path = %q, want console.html", got)
	}
}
