package api

import (
	"bytes"
	"context"
	"fmt"
	"html/template"
	"net/http"
	"os"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/managementasset"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/registry"
	log "github.com/sirupsen/logrus"
)

func (s *Server) registerManagementRoutes() {
	if s == nil || s.engine == nil || s.mgmt == nil {
		return
	}
	if !s.managementRoutesRegistered.CompareAndSwap(false, true) {
		return
	}

	log.Info("management routes registered after secret key configuration")

	s.engine.POST("/v0/management/oauth-callback", s.managementAvailabilityMiddleware(), s.mgmt.PostOAuthCallback)
	s.engine.GET("/v0/management/oauth-callback", s.managementAvailabilityMiddleware(), s.mgmt.GetOAuthCallback)

	mgmt := s.engine.Group("/v0/management")
	mgmt.Use(s.managementAvailabilityMiddleware(), s.mgmt.Middleware())
	{
		mgmt.GET("/config", s.mgmt.GetConfig)
		mgmt.GET("/config.yaml", s.mgmt.GetConfigYAML)
		mgmt.PUT("/config.yaml", s.mgmt.PutConfigYAML)
		mgmt.GET("/latest-version", s.mgmt.GetLatestVersion)
		mgmt.GET("/codex-profile", s.mgmt.GetCodexProfile)
		mgmt.POST("/codex-profile/refresh", s.mgmt.PostCodexProfileRefresh)
		mgmt.GET("/plugins", s.mgmt.ListPlugins)
		mgmt.GET("/plugin-store", s.mgmt.ListPluginStore)
		mgmt.POST("/plugin-store/:id/install", s.mgmt.InstallPluginFromStore)
		mgmt.DELETE("/plugins/:id", s.mgmt.DeletePlugin)
		mgmt.PATCH("/plugins/:id/enabled", s.mgmt.PatchPluginEnabled)
		mgmt.GET("/plugins/:id/config", s.mgmt.GetPluginConfig)
		mgmt.PUT("/plugins/:id/config", s.mgmt.PutPluginConfig)
		mgmt.PATCH("/plugins/:id/config", s.mgmt.PatchPluginConfig)

		mgmt.GET("/debug", s.mgmt.GetDebug)
		mgmt.PUT("/debug", s.mgmt.PutDebug)
		mgmt.PATCH("/debug", s.mgmt.PutDebug)

		mgmt.GET("/logging-to-file", s.mgmt.GetLoggingToFile)
		mgmt.PUT("/logging-to-file", s.mgmt.PutLoggingToFile)
		mgmt.PATCH("/logging-to-file", s.mgmt.PutLoggingToFile)

		mgmt.GET("/logs-max-total-size-mb", s.mgmt.GetLogsMaxTotalSizeMB)
		mgmt.PUT("/logs-max-total-size-mb", s.mgmt.PutLogsMaxTotalSizeMB)
		mgmt.PATCH("/logs-max-total-size-mb", s.mgmt.PutLogsMaxTotalSizeMB)

		mgmt.GET("/error-logs-max-files", s.mgmt.GetErrorLogsMaxFiles)
		mgmt.PUT("/error-logs-max-files", s.mgmt.PutErrorLogsMaxFiles)
		mgmt.PATCH("/error-logs-max-files", s.mgmt.PutErrorLogsMaxFiles)

		mgmt.GET("/usage-statistics-enabled", s.mgmt.GetUsageStatisticsEnabled)
		mgmt.PUT("/usage-statistics-enabled", s.mgmt.PutUsageStatisticsEnabled)
		mgmt.PATCH("/usage-statistics-enabled", s.mgmt.PutUsageStatisticsEnabled)

		mgmt.GET("/proxy-url", s.mgmt.GetProxyURL)
		mgmt.PUT("/proxy-url", s.mgmt.PutProxyURL)
		mgmt.PATCH("/proxy-url", s.mgmt.PutProxyURL)
		mgmt.DELETE("/proxy-url", s.mgmt.DeleteProxyURL)

		mgmt.POST("/api-call", s.mgmt.APICall)

		mgmt.GET("/quota-exceeded/switch-project", s.mgmt.GetSwitchProject)
		mgmt.PUT("/quota-exceeded/switch-project", s.mgmt.PutSwitchProject)
		mgmt.PATCH("/quota-exceeded/switch-project", s.mgmt.PutSwitchProject)

		mgmt.GET("/quota-exceeded/switch-preview-model", s.mgmt.GetSwitchPreviewModel)
		mgmt.PUT("/quota-exceeded/switch-preview-model", s.mgmt.PutSwitchPreviewModel)
		mgmt.PATCH("/quota-exceeded/switch-preview-model", s.mgmt.PutSwitchPreviewModel)
		mgmt.POST("/reset-quota", s.mgmt.ResetQuota)

		mgmt.GET("/api-keys", s.mgmt.GetAPIKeys)
		mgmt.PUT("/api-keys", s.mgmt.PutAPIKeys)
		mgmt.PATCH("/api-keys", s.mgmt.PatchAPIKeys)
		mgmt.DELETE("/api-keys", s.mgmt.DeleteAPIKeys)
		mgmt.GET("/api-key-usage", s.mgmt.GetAPIKeyUsage)
		mgmt.GET("/usage-queue", s.mgmt.GetUsageQueue)

		mgmt.GET("/gemini-api-key", s.mgmt.GetGeminiKeys)
		mgmt.PUT("/gemini-api-key", s.mgmt.PutGeminiKeys)
		mgmt.PATCH("/gemini-api-key", s.mgmt.PatchGeminiKey)
		mgmt.DELETE("/gemini-api-key", s.mgmt.DeleteGeminiKey)

		mgmt.GET("/interactions-api-key", s.mgmt.GetInteractionsKeys)
		mgmt.PUT("/interactions-api-key", s.mgmt.PutInteractionsKeys)
		mgmt.PATCH("/interactions-api-key", s.mgmt.PatchInteractionsKey)
		mgmt.DELETE("/interactions-api-key", s.mgmt.DeleteInteractionsKey)

		mgmt.GET("/logs", s.mgmt.GetLogs)
		mgmt.DELETE("/logs", s.mgmt.DeleteLogs)
		mgmt.GET("/request-error-logs", s.mgmt.GetRequestErrorLogs)
		mgmt.GET("/request-error-logs/:name", s.mgmt.DownloadRequestErrorLog)
		mgmt.GET("/request-log-by-id/:id", s.mgmt.GetRequestLogByID)
		mgmt.GET("/request-log", s.mgmt.GetRequestLog)
		mgmt.PUT("/request-log", s.mgmt.PutRequestLog)
		mgmt.PATCH("/request-log", s.mgmt.PutRequestLog)
		mgmt.GET("/ws-auth", s.mgmt.GetWebsocketAuth)
		mgmt.PUT("/ws-auth", s.mgmt.PutWebsocketAuth)
		mgmt.PATCH("/ws-auth", s.mgmt.PutWebsocketAuth)

		mgmt.GET("/request-retry", s.mgmt.GetRequestRetry)
		mgmt.PUT("/request-retry", s.mgmt.PutRequestRetry)
		mgmt.PATCH("/request-retry", s.mgmt.PutRequestRetry)
		mgmt.GET("/max-retry-credentials", s.mgmt.GetMaxRetryCredentials)
		mgmt.PUT("/max-retry-credentials", s.mgmt.PutMaxRetryCredentials)
		mgmt.PATCH("/max-retry-credentials", s.mgmt.PutMaxRetryCredentials)
		mgmt.GET("/max-retry-interval", s.mgmt.GetMaxRetryInterval)
		mgmt.PUT("/max-retry-interval", s.mgmt.PutMaxRetryInterval)
		mgmt.PATCH("/max-retry-interval", s.mgmt.PutMaxRetryInterval)

		mgmt.GET("/force-model-prefix", s.mgmt.GetForceModelPrefix)
		mgmt.PUT("/force-model-prefix", s.mgmt.PutForceModelPrefix)
		mgmt.PATCH("/force-model-prefix", s.mgmt.PutForceModelPrefix)

		mgmt.GET("/routing/strategy", s.mgmt.GetRoutingStrategy)
		mgmt.PUT("/routing/strategy", s.mgmt.PutRoutingStrategy)
		mgmt.PATCH("/routing/strategy", s.mgmt.PutRoutingStrategy)

		mgmt.GET("/claude-api-key", s.mgmt.GetClaudeKeys)
		mgmt.PUT("/claude-api-key", s.mgmt.PutClaudeKeys)
		mgmt.PATCH("/claude-api-key", s.mgmt.PatchClaudeKey)
		mgmt.DELETE("/claude-api-key", s.mgmt.DeleteClaudeKey)

		mgmt.GET("/codex-api-key", s.mgmt.GetCodexKeys)
		mgmt.PUT("/codex-api-key", s.mgmt.PutCodexKeys)
		mgmt.PATCH("/codex-api-key", s.mgmt.PatchCodexKey)
		mgmt.DELETE("/codex-api-key", s.mgmt.DeleteCodexKey)

		mgmt.GET("/xai-api-key", s.mgmt.GetXAIKeys)
		mgmt.PUT("/xai-api-key", s.mgmt.PutXAIKeys)
		mgmt.PATCH("/xai-api-key", s.mgmt.PatchXAIKey)
		mgmt.DELETE("/xai-api-key", s.mgmt.DeleteXAIKey)

		mgmt.GET("/openai-compatibility", s.mgmt.GetOpenAICompat)
		mgmt.PUT("/openai-compatibility", s.mgmt.PutOpenAICompat)
		mgmt.PATCH("/openai-compatibility", s.mgmt.PatchOpenAICompat)
		mgmt.DELETE("/openai-compatibility", s.mgmt.DeleteOpenAICompat)

		mgmt.GET("/vertex-api-key", s.mgmt.GetVertexCompatKeys)
		mgmt.PUT("/vertex-api-key", s.mgmt.PutVertexCompatKeys)
		mgmt.PATCH("/vertex-api-key", s.mgmt.PatchVertexCompatKey)
		mgmt.DELETE("/vertex-api-key", s.mgmt.DeleteVertexCompatKey)

		mgmt.GET("/oauth-excluded-models", s.mgmt.GetOAuthExcludedModels)
		mgmt.PUT("/oauth-excluded-models", s.mgmt.PutOAuthExcludedModels)
		mgmt.PATCH("/oauth-excluded-models", s.mgmt.PatchOAuthExcludedModels)
		mgmt.DELETE("/oauth-excluded-models", s.mgmt.DeleteOAuthExcludedModels)

		mgmt.GET("/oauth-model-alias", s.mgmt.GetOAuthModelAlias)
		mgmt.PUT("/oauth-model-alias", s.mgmt.PutOAuthModelAlias)
		mgmt.PATCH("/oauth-model-alias", s.mgmt.PatchOAuthModelAlias)
		mgmt.DELETE("/oauth-model-alias", s.mgmt.DeleteOAuthModelAlias)

		mgmt.GET("/oauth-request-scoped-errors", s.mgmt.GetOAuthRequestScopedErrors)
		mgmt.PUT("/oauth-request-scoped-errors", s.mgmt.PutOAuthRequestScopedErrors)
		mgmt.PATCH("/oauth-request-scoped-errors", s.mgmt.PatchOAuthRequestScopedErrors)
		mgmt.DELETE("/oauth-request-scoped-errors", s.mgmt.DeleteOAuthRequestScopedErrors)

		mgmt.GET("/auth-files", s.mgmt.ListAuthFiles)
		mgmt.GET("/auth-files/models", s.mgmt.GetAuthFileModels)
		mgmt.GET("/model-definitions/:channel", s.mgmt.GetStaticModelDefinitions)
		mgmt.GET("/auth-files/download", s.mgmt.DownloadAuthFile)
		mgmt.POST("/auth-files", s.mgmt.UploadAuthFile)
		mgmt.DELETE("/auth-files", s.mgmt.DeleteAuthFile)
		mgmt.PATCH("/auth-files/status", s.mgmt.PatchAuthFileStatus)
		mgmt.PATCH("/auth-files/fields", s.mgmt.PatchAuthFileFields)
		mgmt.POST("/auth-files/refresh", s.mgmt.RefreshAuthFiles)
		mgmt.POST("/vertex/import", s.mgmt.ImportVertexCredential)

		mgmt.GET("/anthropic-auth-url", s.mgmt.RequestAnthropicToken)
		mgmt.GET("/codex-auth-url", s.mgmt.RequestCodexToken)
		mgmt.GET("/antigravity-auth-url", s.mgmt.RequestAntigravityToken)
		mgmt.GET("/kimi-auth-url", s.mgmt.RequestKimiToken)
		mgmt.GET("/xai-auth-url", s.mgmt.RequestXAIToken)
		mgmt.GET("/get-auth-status", s.mgmt.GetAuthStatus)
		mgmt.DELETE("/oauth-session", s.mgmt.CancelAuthSession)
	}
}

func (s *Server) managementAvailabilityMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if !s.managementAvailable(c) {
			return
		}
		c.Next()
	}
}

func (s *Server) managementAvailable(c *gin.Context) bool {
	if s == nil || s.cfg == nil {
		c.AbortWithStatus(http.StatusNotFound)
		return false
	}
	if s.cfg.Home.Enabled {
		c.AbortWithStatus(http.StatusNotFound)
		return false
	}
	if !s.managementRoutesEnabled.Load() {
		c.AbortWithStatus(http.StatusNotFound)
		return false
	}
	return true
}

func (s *Server) refreshPluginManagementRoutes() {
	if s == nil || s.pluginHost == nil || s.engine == nil {
		return
	}
	s.pluginHost.RegisterManagementRoutes(context.Background(), s.registeredManagementRouteKeys())
}

// RefreshPluginManagementRoutes rebuilds plugin-owned Management API routes.
func (s *Server) RefreshPluginManagementRoutes() {
	s.refreshPluginManagementRoutes()
}

func (s *Server) registeredManagementRouteKeys() map[string]struct{} {
	out := make(map[string]struct{})
	if s == nil || s.engine == nil {
		return out
	}
	for _, route := range s.engine.Routes() {
		if strings.HasPrefix(route.Path, "/v0/management/") || route.Path == "/v0/management" {
			out[strings.ToUpper(strings.TrimSpace(route.Method))+" "+route.Path] = struct{}{}
		}
	}
	return out
}

func (s *Server) pluginManagementNoRoute(c *gin.Context) {
	if s == nil || c == nil || c.Request == nil || c.Request.URL == nil {
		if c != nil {
			c.AbortWithStatus(http.StatusNotFound)
		}
		return
	}
	path := c.Request.URL.Path
	if strings.HasPrefix(path, "/v0/resource/plugins/") {
		s.pluginResourceNoRoute(c)
		return
	}
	if path != "/v0/management" && !strings.HasPrefix(path, "/v0/management/") {
		c.AbortWithStatus(http.StatusNotFound)
		return
	}
	if s.pluginHost == nil || s.mgmt == nil {
		c.AbortWithStatus(http.StatusNotFound)
		return
	}
	if !s.managementAvailable(c) {
		return
	}
	s.mgmt.Middleware()(c)
	if c.IsAborted() {
		return
	}
	if s.mgmt.ServePluginAuthURL(c) {
		c.Abort()
		return
	}
	if s.pluginHost.ServeManagementHTTP(c.Writer, c.Request) {
		c.Abort()
		return
	}
	c.AbortWithStatus(http.StatusNotFound)
}

func (s *Server) pluginResourceNoRoute(c *gin.Context) {
	if s == nil || c == nil || c.Request == nil || c.Request.URL == nil {
		if c != nil {
			c.AbortWithStatus(http.StatusNotFound)
		}
		return
	}
	if s.cfg == nil || s.cfg.Home.Enabled || s.pluginHost == nil {
		c.AbortWithStatus(http.StatusNotFound)
		return
	}
	if s.pluginHost.ServeResourceHTTP(c.Writer, c.Request) {
		c.Abort()
		return
	}
	c.AbortWithStatus(http.StatusNotFound)
}

func (s *Server) serveManagementControlPanel(c *gin.Context) {
	cfg := s.cfg
	if cfg == nil || cfg.Home.Enabled || cfg.RemoteManagement.DisableControlPanel {
		c.AbortWithStatus(http.StatusNotFound)
		return
	}
	// The panel is part of the management surface, so it follows the same
	// allow-remote rule as the API. It used to be served to anyone who could
	// reach the port, which meant a deployment that had explicitly disabled
	// remote management still handed its admin UI to remote callers. 404 rather
	// than 403 so a remote probe learns nothing about what lives here.
	if s.mgmt == nil || !s.mgmt.ManagementAccessAllowed(c.ClientIP()) {
		c.AbortWithStatus(http.StatusNotFound)
		return
	}
	filePath := managementasset.FilePath(s.configFilePath)
	if strings.TrimSpace(filePath) == "" {
		c.AbortWithStatus(http.StatusNotFound)
		return
	}

	if _, err := os.Stat(filePath); err != nil {
		if os.IsNotExist(err) {
			// Synchronously ensure management.html is available with a detached context.
			// Control panel bootstrap should not be canceled by client disconnects.
			if !managementasset.EnsureLatestManagementHTML(context.Background(), managementasset.StaticDir(s.configFilePath), cfg.ProxyURL, cfg.RemoteManagement.PanelGitHubRepository) {
				c.AbortWithStatus(http.StatusNotFound)
				return
			}
		} else {
			log.WithError(err).Error("failed to stat management control panel asset")
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}
	}

	// When the captured Codex profile no longer describes the newest release, the
	// advertised identity is held back (see registry.CodexProfileIsCurrent). That
	// is a safe state, not a broken one, so it must not read as an error — but it
	// is also invisible unless someone reads the log, which is how a re-capture
	// gets forgotten. The panel is where the operator already looks.
	//
	// The notice is appended to the panel response rather than fetched by a
	// script: no API call, no coupling to the panel's own auth storage, and it
	// applies to whatever panel revision is on disk. It is only added when there
	// is something to say, and only ever inserted, never rewritten.
	panel, errRead := os.ReadFile(filePath)
	if errRead != nil {
		log.WithError(errRead).Error("failed to read management control panel asset")
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}
	// The control is on every panel load, so a re-capture is reachable without
	// waiting for the profile to fall behind; the banner only when there is
	// something to say. Injected in this order so the script runs after the
	// banner markup it wires up.
	if notice := codexProfileNoticeHTML(); notice != "" {
		panel = injectBeforeBodyClose(panel, notice)
	}
	panel = injectBeforeBodyClose(panel, codexProfileControlScript)
	c.Data(http.StatusOK, "text/html; charset=utf-8", panel)
}

// codexProfileNoticeHTML renders the banner shown when the advertised Codex
// version is held back, with the control that clears it. Returns "" when there
// is nothing to report.
func codexProfileNoticeHTML() string {
	if registry.CodexProfileIsCurrent() {
		return ""
	}
	advertised := template.HTMLEscapeString(registry.CodexClientVersion())
	return fmt.Sprintf(`<div id="cpa-codex-notice" style="position:fixed;top:0;left:0;right:0;z-index:2147483647;`+
		`padding:10px 14px;background:#7c2d12;color:#fff;`+
		`font:13px/1.5 -apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;text-align:center">`+
		`Codex profile is behind upstream: this proxy advertises %s because a newer release changed its TLS `+
		`stack and the handshake was not re-captured yet.`+
		`<button id="cpa-codex-refresh" style="margin-left:10px;padding:3px 12px;border:1px solid #fff;`+
		`border-radius:4px;background:transparent;color:#fff;font:inherit;cursor:pointer">Re-capture now</button>`+
		`<span id="cpa-codex-refresh-status" style="margin-left:10px"></span></div>`,
		advertised)
}

// codexProfileRefreshScript drives the re-capture from the notice.
//
// The management key is needed to call the endpoint, and the panel already holds
// it in localStorage. Reading it by storage key does not work: the panel is a
// minified bundle whose storage keys are mangled, and they change with each panel
// build. The property name the panel reads the key by survives minification, so
// the key is found by scanning stored values for it instead.
//
// Three fallbacks, in order: our own remembered copy, that scan, and finally
// asking. A failure at any of them leaves the panel untouched — the notice simply
// reports it.
const codexProfileControlScript = `<script>(function () {
  var REMEMBERED = 'cpa-codex-management-key';
  // The panel labels its own "check for updates" button in each locale it ships.
  // Matching those labels is how the permanent control finds the management
  // centre page: the panel exposes no id or test hook, and its CSS-module class
  // names are per-build hashes. A panel that renames them gets no control rather
  // than a broken one.
  var ANCHORS = [
    { label: '检查更新', ours: '更新 Codex 指纹' },
    { label: '檢查更新', ours: '更新 Codex 指紋' },
    { label: 'Check for updates', ours: 'Update Codex profile' },
    { label: 'Проверить обновления', ours: 'Обновить профиль Codex' }
  ];
  var ID = 'cpa-codex-recapture';

  function stored(name) { try { return localStorage.getItem(name) || ''; } catch (e) { return ''; } }
  function remember(key) { try { localStorage.setItem(REMEMBERED, key); } catch (e) { /* private mode */ } }
  function forget() { try { localStorage.removeItem(REMEMBERED); } catch (e) { /* private mode */ } }

  // Depth-first over a parsed value, looking for the property the panel reads
  // the management key by. Its storage key is mangled and changes per build.
  function hunt(value, depth) {
    if (!value || depth > 5) { return ''; }
    if (Array.isArray(value)) {
      for (var i = 0; i < value.length; i++) { var a = hunt(value[i], depth + 1); if (a) { return a; } }
      return '';
    }
    if (typeof value !== 'object') { return ''; }
    if (typeof value.managementKey === 'string' && value.managementKey.trim()) {
      return value.managementKey.trim();
    }
    for (var k in value) {
      if (!Object.prototype.hasOwnProperty.call(value, k)) { continue; }
      var b = hunt(value[k], depth + 1); if (b) { return b; }
    }
    return '';
  }

  function discover() {
    var kept = stored(REMEMBERED);
    if (kept) { return kept; }
    try {
      for (var i = 0; i < localStorage.length; i++) {
        var raw = localStorage.getItem(localStorage.key(i));
        if (!raw) { continue; }
        var parsed;
        try { parsed = JSON.parse(raw); } catch (e) { continue; }
        var found = hunt(parsed, 0);
        if (found) { remember(found); return found; }
      }
    } catch (e) { /* storage unavailable */ }
    return '';
  }

  function keyFor() {
    var key = discover();
    if (key) { return key; }
    key = (window.prompt('Management key, to authorise the re-capture:') || '').trim();
    if (key) { remember(key); }
    return key;
  }

  function headers(key) { return { 'Authorization': 'Bearer ' + key }; }

  function poll(key, startedAt, say, button) {
    fetch('/v0/management/codex-profile', { headers: headers(key) })
      .then(function (r) { return r.json(); })
      .then(function (state) {
        if (state.capture && state.capture.running) {
          if (Date.now() - startedAt > 1800000) {
            if (button) { button.disabled = false; }
            say('Gave up waiting; check the proxy log.', '#b91c1c');
            return;
          }
          say('capturing, this takes a minute or two...', '#b45309');
          setTimeout(function () { poll(key, startedAt, say, button); }, 3000);
          return;
        }
        if (button) { button.disabled = false; }
        if (state.capture && state.capture.error) {
          say('Failed: ' + state.capture.error, '#b91c1c');
          return;
        }
        say(state.current ? 'Done; the profile matches upstream again'
                          : 'Finished, but the profile still reads as behind upstream.',
            state.current ? '#15803d' : '#b91c1c');
      })
      .catch(function () {
        // A dropped poll is not a failed capture; keep asking.
        setTimeout(function () { poll(key, startedAt, say, button); }, 5000);
      });
  }

  // Both controls run the same capture, so they cannot drift apart in behaviour.
  function run(say, button) {
    var key = keyFor();
    if (!key) { say('No management key, so nothing was started.', '#b91c1c'); return; }
    if (button) { button.disabled = true; }
    say('starting...', '#b45309');
    fetch('/v0/management/codex-profile/refresh', { method: 'POST', headers: headers(key) })
      .then(function (r) {
        if (r.status === 401 || r.status === 403) {
          // A stale copy would otherwise be retried on every press.
          forget();
          throw new Error('the management key was rejected');
        }
        if (r.status === 409) { poll(key, Date.now(), say, button); return null; }
        if (!r.ok) {
          return r.json().then(function (body) { throw new Error(body.message || ('HTTP ' + r.status)); },
                               function () { throw new Error('HTTP ' + r.status); });
        }
        poll(key, Date.now(), say, button);
        return null;
      })
      .catch(function (err) {
        if (button) { button.disabled = false; }
        say('Failed: ' + err.message, '#b91c1c');
      });
  }

  // 1. The banner, present only while the profile is behind upstream.
  var banner = document.getElementById('cpa-codex-refresh');
  var bannerStatus = document.getElementById('cpa-codex-refresh-status');
  if (banner && bannerStatus) {
    var sayBanner = function (text, colour) { bannerStatus.textContent = text; bannerStatus.style.color = colour; };
    banner.addEventListener('click', function () { run(sayBanner, banner); });
  }

  // 2. The permanent control, beside the panel's own update button.
  function place() {
    if (document.getElementById(ID)) { return true; }
    var buttons = document.querySelectorAll('button');
    for (var i = 0; i < buttons.length; i++) {
      var label = (buttons[i].getAttribute('aria-label') || buttons[i].getAttribute('title') || '').trim();
      var ours = '';
      for (var j = 0; j < ANCHORS.length; j++) {
        if (ANCHORS[j].label === label) { ours = ANCHORS[j].ours; break; }
      }
      if (!ours) { continue; }
      var row = buttons[i].parentNode;
      if (!row) { continue; }

      var control = document.createElement('button');
      control.id = ID;
      control.type = 'button';
      control.textContent = ours;
      // Take the sibling's own classes. They are CSS-module hashes, but they are
      // the panel's real rules, so the control inherits its hover and focus
      // states too — which copying resolved styles cannot reproduce, and which is
      // what makes a borrowed copy look subtly wrong next to the original.
      if (buttons[i].className) {
        control.className = buttons[i].className;
      } else {
        var cs = window.getComputedStyle(buttons[i]);
        ['font', 'padding', 'border', 'borderRadius', 'background', 'color', 'cursor'].forEach(function (prop) {
          control.style[prop] = cs[prop];
        });
      }
      control.style.marginLeft = '6px';

      var status = document.createElement('span');
      status.style.cssText = 'margin-left:8px;font-size:12px';
      var say = function (text, colour) { status.textContent = text; status.style.color = colour; };

      control.addEventListener('click', function () { run(say, control); });
      row.appendChild(control);
      row.appendChild(status);
      return true;
    }
    return false;
  }

  if (!place()) {
    // The panel renders that page through its own router, so it may not be on
    // screen yet. Watch for it, but throttle: this observes the whole document.
    var last = 0;
    var observer = new MutationObserver(function () {
      var now = Date.now();
      if (now - last < 500) { return; }
      last = now;
      if (place()) { observer.disconnect(); }
    });
    observer.observe(document.documentElement, { childList: true, subtree: true });
  }
})();</script>`

// injectBeforeBodyClose appends fragment just before </body>. Falling back to a
// plain append keeps the panel working if the document has no closing body tag.
func injectBeforeBodyClose(page []byte, fragment string) []byte {
	marker := []byte("</body>")
	if index := bytes.LastIndex(bytes.ToLower(page), marker); index >= 0 {
		out := make([]byte, 0, len(page)+len(fragment))
		out = append(out, page[:index]...)
		out = append(out, fragment...)
		return append(out, page[index:]...)
	}
	return append(page, fragment...)
}
