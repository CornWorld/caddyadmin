package caddyadmin

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestConfigMarshalRoundTrip builds a Config that mirrors the semantics of
// the legacy docker/Caddyfile.prod (admin bind / on_demand_tls / storage / three servers:
// HTTPS / HTTP redirect / management port) and verifies:
//  1. It marshals to valid JSON without error.
//  2. The JSON round-trips back to an equivalent Config.
//  3. The marshaled JSON does NOT contain the insecure origins ["*"] value
//     (zero-trust default — admin API must never be exposed to the network).
func TestConfigMarshalRoundTrip(t *testing.T) {
	persist := false
	cfg := &Config{
		Admin: &AdminConfig{
			Listen:  "127.0.0.1:2019",
			Origins: []string{"127.0.0.1"},
			Persist: &persist,
		},
		Logs: &LogsConfig{
			Logs: map[string]LogEntry{
				"default": {
					Writer: &LogWriter{
						Output:   "file",
						Filename: "/var/log/caddy.log",
					},
					Level: "WARN",
				},
			},
		},
		Storage: &Storage{
			Module: "file_system",
			Root:   "/data/caddy",
		},
		Apps: &Apps{
			HTTP: &HTTPApp{
				Servers: map[string]*Server{
					// HTTPS server (:443) — main site with on-demand TLS.
					"srv0": {
						Listen: []string{":443"},
						Routes: []Route{
							{
								ID: "api-proxy",
								Match: []MatchRule{{
									Path: []string{"/api/*"},
								}},
								Handle: []Handler{{
									Handler:   "reverse_proxy",
									Upstreams: []Upstream{{Dial: "127.0.0.1:8090"}},
								}},
							},
							{
								ID: "pb-admin",
								Match: []MatchRule{{
									Path: []string{"/_/*"},
								}},
								Handle: []Handler{{
									Handler:   "reverse_proxy",
									Upstreams: []Upstream{{Dial: "127.0.0.1:8090"}},
								}},
							},
							{
								// Astro SSR fallback
								Handle: []Handler{{
									Handler:   "reverse_proxy",
									Upstreams: []Upstream{{Dial: "127.0.0.1:4321"}},
								}},
							},
						},
					},
					// HTTP redirect server (:80) — redirects everything to HTTPS.
					"srv1": {
						Listen: []string{":80"},
						ListenerWrappers: []ListenerWrapper{
							{Wrapper: "http_redirect"},
						},
					},
					// Management port (:8080) — plain HTTP admin access.
					"srv_mgmt": {
						Listen: []string{":8080"},
						Routes: []Route{
							{
								Match: []MatchRule{{Path: []string{"/api/*"}}},
								Handle: []Handler{{
									Handler:   "reverse_proxy",
									Upstreams: []Upstream{{Dial: "127.0.0.1:8090"}},
								}},
							},
							{
								Match: []MatchRule{{Path: []string{"/_/*"}}},
								Handle: []Handler{{
									Handler:   "reverse_proxy",
									Upstreams: []Upstream{{Dial: "127.0.0.1:8090"}},
								}},
							},
							{
								Handle: []Handler{{
									Handler:   "reverse_proxy",
									Upstreams: []Upstream{{Dial: "127.0.0.1:4321"}},
								}},
							},
						},
					},
				},
			},
			TLS: &TLSApp{
				Automation: &Automation{
					OnDemand: &OnDemandTLS{
						Ask: "http://127.0.0.1:8090/api/hooks/caddy/ask",
					},
					Policies: []AutomationPolicy{{
						OnDemand: true,
						Issuers: []Issuer{{
							Module: "acme",
							Email:  "admin@example.com",
						}},
					}},
				},
			},
		},
	}

	// 1. Marshal via the convenience method.
	data, err := cfg.JSON()
	if err != nil {
		t.Fatalf("Config.JSON() failed: %v", err)
	}

	jsonStr := string(data)
	t.Logf("marshaled config:\n%s", jsonStr)

	// 2. Security assertion: zero-trust default — origins must NEVER be ["*"].
	// This would expose the Caddy admin API to the network and is a remote
	// takeover vector.
	if strings.Contains(jsonStr, `"origins":["*"]`) {
		t.Fatal("SECURITY: marshaled config contains insecure origins [\"*\"] — admin API would be exposed to the network")
	}

	// 3. Round-trip: unmarshal back and verify key fields survived.
	var back Config
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatalf("round-trip unmarshal failed: %v", err)
	}
	if back.Admin == nil || back.Admin.Listen != "127.0.0.1:2019" {
		t.Fatalf("round-trip: admin.listen mismatch: %+v", back.Admin)
	}
	if back.Storage == nil || back.Storage.Root != "/data/caddy" {
		t.Fatalf("round-trip: storage.root mismatch: %+v", back.Storage)
	}
	if back.Apps == nil || back.Apps.HTTP == nil || back.Apps.TLS == nil {
		t.Fatalf("round-trip: apps missing http or tls: %+v", back.Apps)
	}
	if len(back.Apps.HTTP.Servers) != 3 {
		t.Fatalf("round-trip: expected 3 HTTP servers, got %d", len(back.Apps.HTTP.Servers))
	}
	srv0 := back.Apps.HTTP.Servers["srv0"]
	if srv0 == nil || len(srv0.Listen) != 1 || srv0.Listen[0] != ":443" {
		t.Fatalf("round-trip: srv0.listen mismatch: %+v", srv0)
	}
	if len(srv0.Routes) != 3 {
		t.Fatalf("round-trip: srv0 expected 3 routes, got %d", len(srv0.Routes))
	}
	srv1 := back.Apps.HTTP.Servers["srv1"]
	if srv1 == nil || len(srv1.ListenerWrappers) != 1 || srv1.ListenerWrappers[0].Wrapper != "http_redirect" {
		t.Fatalf("round-trip: srv1 http_redirect wrapper mismatch: %+v", srv1)
	}
	if back.Apps.TLS.Automation == nil ||
		back.Apps.TLS.Automation.OnDemand == nil ||
		back.Apps.TLS.Automation.OnDemand.Ask != "http://127.0.0.1:8090/api/hooks/caddy/ask" {
		t.Fatalf("round-trip: on_demand.ask mismatch: %+v", back.Apps.TLS.Automation)
	}
	if len(back.Apps.TLS.Automation.Policies) != 1 || !back.Apps.TLS.Automation.Policies[0].OnDemand {
		t.Fatalf("round-trip: automation policy mismatch: %+v", back.Apps.TLS.Automation.Policies)
	}
}

// TestConfigEmptyOmitsFields verifies that an empty Config marshals to a clean
// "{}" rather than leaking null/empty fields. This is what makes the pointer
// + omitempty design worthwhile — callers can build configs incrementally and
// only the fields they set appear in the output.
func TestConfigEmptyOmitsFields(t *testing.T) {
	cfg := &Config{}
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}
	if string(data) != "{}" {
		t.Fatalf("empty Config should marshal to {}, got: %s", string(data))
	}
}

// TestConfigJSONValidatesAdmin verifies that Config.JSON() refuses to
// serialize a config whose admin block would expose the unauthenticated admin
// API (wildcard origins or a non-loopback listen), even though a bare
// json.Marshal would happily emit it.
func TestConfigJSONValidatesAdmin(t *testing.T) {
	bad := []*Config{
		{Admin: &AdminConfig{Listen: "127.0.0.1:2019", Origins: []string{"*"}}},
		{Admin: &AdminConfig{Listen: "0.0.0.0:2019", Origins: []string{"127.0.0.1"}}},
		{Admin: &AdminConfig{Listen: ":2019"}},
	}
	for i, cfg := range bad {
		if _, err := cfg.JSON(); err == nil {
			t.Errorf("bad[%d]: Config.JSON() accepted an insecure admin block", i)
		}
		// A bare json.Marshal must NOT be blocked — only Config.JSON() enforces it.
		if _, err := json.Marshal(cfg); err != nil {
			t.Errorf("bad[%d]: json.Marshal should not validate: %v", i, err)
		}
	}
}

// TestHandlerUnmarshalJSONRoundTrip verifies Handler.UnmarshalJSON mirrors
// MarshalJSON for both the flat static_response header shape and the nested
// HeaderPolicy shape, so live configs round-trip losslessly.
func TestHandlerUnmarshalJSONRoundTrip(t *testing.T) {
	// static_response: flat http.Header map
	sr := Handler{Handler: "static_response", StatusCode: 200, Body: "ok", Headers: &HeaderPolicy{
		Response: &HeaderOps{Set: map[string][]string{"Content-Type": {"text/plain"}}},
	}}
	data, err := json.Marshal(sr)
	if err != nil {
		t.Fatalf("marshal static_response: %v", err)
	}
	var back Handler
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatalf("unmarshal static_response: %v", err)
	}
	if back.Headers == nil || back.Headers.Response == nil || back.Headers.Response.Set["Content-Type"][0] != "text/plain" {
		t.Fatalf("static_response headers lost in round-trip: %+v", back.Headers)
	}

	// reverse_proxy: nested HeaderPolicy
	rp := Handler{Handler: "reverse_proxy", Upstreams: []Upstream{{Dial: "127.0.0.1:8090"}}, Headers: &HeaderPolicy{
		Request: &HeaderOps{Set: map[string][]string{"X-Foo": {"bar"}}},
	}}
	data, err = json.Marshal(rp)
	if err != nil {
		t.Fatalf("marshal reverse_proxy: %v", err)
	}
	back = Handler{}
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatalf("unmarshal reverse_proxy: %v", err)
	}
	if back.Headers == nil || back.Headers.Request == nil || back.Headers.Request.Set["X-Foo"][0] != "bar" {
		t.Fatalf("reverse_proxy headers lost in round-trip: %+v", back.Headers)
	}
}

// TestConfigJSONMethodEquivalence verifies that Config.JSON() and
// json.Marshal(*Config) produce identical output for a VALID config. JSON()
// additionally enforces the admin security contract; for a valid admin block
// the two must agree so callers are never surprised by a difference.
func TestConfigJSONMethodEquivalence(t *testing.T) {
	cfg := &Config{
		Admin: &AdminConfig{
			Listen:  "127.0.0.1:2019",
			Origins: []string{"127.0.0.1"},
		},
	}
	viaMethod, err := cfg.JSON()
	if err != nil {
		t.Fatalf("Config.JSON() failed: %v", err)
	}
	viaStdlib, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}
	if string(viaMethod) != string(viaStdlib) {
		t.Fatalf("Config.JSON() and json.Marshal disagree:\n method: %s\n stdlib: %s", viaMethod, viaStdlib)
	}
}

// TestAdminConfigOriginsRequired is a documentation-as-test reminder that
// Origins should be an explicit allowlist. The struct itself doesn't enforce
// this (omitempty allows nil), but this test pins the convention: when Origins
// IS set, it must not contain "*".
func TestAdminConfigOriginsRequired(t *testing.T) {
	admin := &AdminConfig{
		Listen:  "127.0.0.1:2019",
		Origins: []string{"127.0.0.1", "::1"},
	}
	data, err := json.Marshal(admin)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}
	if strings.Contains(string(data), `"*"`) {
		t.Fatal("admin.origins must never contain \"*\"")
	}
}

// TestAdminConfigValidateRejectsNonLoopbackListen pins the security contract
// that AdminConfig.Validate() rejects binding the admin API to a non-loopback
// interface (the admin API has no authentication and must stay on localhost).
func TestAdminConfigValidateRejectsNonLoopbackListen(t *testing.T) {
	bad := []string{"0.0.0.0:2019", ":2019", "192.168.1.10:2019", "[::]:2019"}
	for _, listen := range bad {
		admin := &AdminConfig{Listen: listen, Origins: []string{"127.0.0.1"}}
		if err := admin.Validate(); err == nil {
			t.Errorf("Validate() accepted non-loopback listen %q", listen)
		}
	}

	good := []string{"127.0.0.1:2019", "localhost:2019", "[::1]:2019", ""}
	for _, listen := range good {
		admin := &AdminConfig{Listen: listen, Origins: []string{"127.0.0.1"}}
		if err := admin.Validate(); err != nil {
			t.Errorf("Validate() rejected loopback listen %q: %v", listen, err)
		}
	}

	// Wildcard origins must still be rejected even with a loopback listen.
	admin := &AdminConfig{Listen: "127.0.0.1:2019", Origins: []string{"*"}}
	if err := admin.Validate(); err == nil {
		t.Fatal("Validate() must still reject wildcard origins")
	}
}

// TestFileServerHandlerMarshal verifies the file_server handler serializes
// root and strip_path_prefix as flat Caddy fields — exactly the shape Caddy's
// file_server module expects (no nested Headers object). Mirrors the target
// shape vanblog emits for theme static assets.
func TestFileServerHandlerMarshal(t *testing.T) {
	fs := Handler{
		Handler:         "file_server",
		Root:            "/var/lib/vanblog/themes/base/dist/client",
		StripPathPrefix: "/themes/base",
	}
	data, err := json.Marshal(fs)
	if err != nil {
		t.Fatalf("marshal file_server: %v", err)
	}
	want := `{"handler":"file_server","root":"/var/lib/vanblog/themes/base/dist/client","strip_path_prefix":"/themes/base"}`
	if string(data) != want {
		t.Fatalf("file_server JSON mismatch:\n got: %s\nwant: %s", string(data), want)
	}
	if strings.Contains(string(data), "headers") {
		t.Fatalf("file_server must not emit a headers key: %s", string(data))
	}
}

// TestFileServerHandlerMarshalNoStrip verifies file_server with only root
// (admin static assets) omits strip_path_prefix entirely (omitempty).
func TestFileServerHandlerMarshalNoStrip(t *testing.T) {
	fs := Handler{
		Handler: "file_server",
		Root:    "/app/admin/dist/client",
	}
	data, err := json.Marshal(fs)
	if err != nil {
		t.Fatalf("marshal file_server: %v", err)
	}
	want := `{"handler":"file_server","root":"/app/admin/dist/client"}`
	if string(data) != want {
		t.Fatalf("file_server JSON mismatch:\n got: %s\nwant: %s", string(data), want)
	}
	if strings.Contains(string(data), "strip_path_prefix") {
		t.Fatalf("strip_path_prefix must be omitted when empty: %s", string(data))
	}
}

// TestFileServerHandlerUnmarshalJSONRoundTrip verifies a file_server handler
// round-trips through MarshalJSON/UnmarshalJSON without losing root or
// strip_path_prefix (mirrors TestHandlerUnmarshalJSONRoundTrip).
func TestFileServerHandlerUnmarshalJSONRoundTrip(t *testing.T) {
	fs := Handler{
		Handler:         "file_server",
		Root:            "/var/lib/vanblog/themes/base/dist/client",
		StripPathPrefix: "/themes/base",
	}
	data, err := json.Marshal(fs)
	if err != nil {
		t.Fatalf("marshal file_server: %v", err)
	}
	var back Handler
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatalf("unmarshal file_server: %v", err)
	}
	if back.Handler != "file_server" || back.Root != fs.Root || back.StripPathPrefix != fs.StripPathPrefix {
		t.Fatalf("file_server fields lost in round-trip: %+v", back)
	}
}

// TestFileServerRejectsHeaders pins the contract that file_server cannot carry
// a Headers policy: Caddy's file_server module has no `headers` field, so any
// shape (nested or flat) would be rejected by the admin API with HTTP 400.
// We fail fast instead of emitting config Caddy would reject.
func TestFileServerRejectsHeaders(t *testing.T) {
	fs := Handler{
		Handler: "file_server",
		Root:    "/app/admin/dist/client",
		Headers: &HeaderPolicy{
			Response: &HeaderOps{Set: map[string][]string{"X-Foo": {"bar"}}},
		},
	}
	if _, err := json.Marshal(fs); err == nil {
		t.Fatal("file_server with Headers must be rejected")
	}
}

// TestExistingHandlerTypesUnchanged pins the exact JSON output of the
// pre-existing handler kinds so future changes to MarshalJSON cannot silently
// alter their on-wire shape (regression guard for backward compatibility).
func TestExistingHandlerTypesUnchanged(t *testing.T) {
	cases := []struct {
		name string
		h    Handler
		want string
	}{
		{
			name: "reverse_proxy",
			h:    Handler{Handler: "reverse_proxy", Upstreams: []Upstream{{Dial: "127.0.0.1:8090"}}},
			want: `{"handler":"reverse_proxy","upstreams":[{"dial":"127.0.0.1:8090"}]}`,
		},
		{
			name: "static_response",
			h:    Handler{Handler: "static_response", StatusCode: 200, Body: "ok"},
			want: `{"handler":"static_response","status_code":200,"body":"ok"}`,
		},
		{
			name: "rewrite",
			h:    Handler{Handler: "rewrite", URI: "/foo"},
			want: `{"handler":"rewrite","uri":"/foo"}`,
		},
		{
			name: "subroute",
			h: Handler{
				Handler: "subroute",
				Routes:  []Route{{Handle: []Handler{{Handler: "static_response", StatusCode: 200, Body: "ok"}}}},
			},
			want: `{"handler":"subroute","routes":[{"handle":[{"handler":"static_response","status_code":200,"body":"ok"}]}]}`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data, err := json.Marshal(tc.h)
			if err != nil {
				t.Fatalf("marshal %s: %v", tc.name, err)
			}
			if string(data) != tc.want {
				t.Fatalf("%s JSON mismatch:\n got: %s\nwant: %s", tc.name, string(data), tc.want)
			}
		})
	}
}
