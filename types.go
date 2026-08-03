package caddyadmin

import (
	"encoding/json"
	"fmt"
	"maps"
	"net"
	"slices"
	"strings"
)

// Route represents a single Caddy route with optional @id for stable identification.
// See: https://caddyserver.com/docs/api#using-stable-ids
type Route struct {
	// ID is the stable identifier for the route, mapped to Caddy's "@id" field.
	// Used for AddRoute/RemoveRoute/GetRoutes by ID instead of array position.
	ID string `json:"@id,omitempty"`

	// Match defines the route matchers. A route matches if ANY matcher matches.
	Match []MatchRule `json:"match,omitempty"`

	// Handle defines the route handlers. Executed in order when the route matches.
	Handle []Handler `json:"handle,omitempty"`
}

// MatchRule defines a single Caddy matcher. We only use Path matching for now.
type MatchRule struct {
	// Path matches request paths using Caddy's fast path matcher.
	// Supports glob: ["/api/*", "/static/*"]
	Path []string `json:"path,omitempty"`

	// Host matches request hostnames. Wildcards supported: ["*.example.com"]
	Host []string `json:"host,omitempty"`

	// Header matches request headers.
	Header map[string][]string `json:"header,omitempty"`

	// Method matches HTTP methods: ["GET", "POST"]
	Method []string `json:"method,omitempty"`

	// RemoteIP matches when the client IP is (or is not) in the given CIDR
	// ranges. Maps to Caddy's `remote_ip` request matcher:
	//
	//	{"remote_ip": {"ranges": [...], "except": [...]}}
	//
	// Ranges are CIDR blocks to match; Except excludes specific IPs (negation).
	// Caddy has no bare `ip`/`not_ip` matcher modules — the old IP/NotIP fields
	// emitted keys Caddy rejects, so they were replaced with this shape.
	RemoteIP *RemoteIPMatch `json:"remote_ip,omitempty"`
}

// RemoteIPMatch is the value of Caddy's `remote_ip` request matcher.
// See: https://caddyserver.com/docs/json/apps/http/servers/routes/match/remote_ip
type RemoteIPMatch struct {
	Ranges []string `json:"ranges,omitempty"` // CIDR ranges to match (e.g. ["192.168.0.0/16"])
	Except []string `json:"except,omitempty"` // IPs to exclude (e.g. ["192.168.1.1"])
}

// Handler defines a single Caddy handler. Different handler types use different fields.
//
// Fields are validated against the handler schema at marshal time; setting a field
// that a handler doesn't support returns an error. To register fields for custom or
// third-party handler modules, use RegisterHandlerFields.
type Handler struct {
	// Handler is the module name: "reverse_proxy", "static_response", "rewrite", "subroute", "file_server", "headers", etc.
	// See: https://caddyserver.com/docs/json/apps/http/#servers/routes/handle/handler
	Handler string `json:"handler"`

	// --- reverse_proxy / static_response shared ---

	// Upstreams is the list of upstream backends (reverse_proxy).
	Upstreams []Upstream `json:"upstreams,omitempty"`

	// Headers is request/response header manipulation for reverse_proxy,
	// static_response, and the standalone `headers` handler.
	//
	// In-memory representation is always *HeaderPolicy, but the on-wire JSON
	// shape differs per handler (verified against Caddy 2.8 admin API):
	//   - reverse_proxy → nested at "headers" key ({request:{...}, response:{...}})
	//   - standalone `headers` handler → flattened at top level (request:/response:)
	//   - static_response → flat http.Header shape (map[string][]string); Caddy rejects
	//     the nested shape with HTTP 400
	//   - file_server → rejected entirely (Caddy's file_server has no headers field)
	Headers *HeaderPolicy `json:"headers,omitempty"`

	// --- static_response fields ---

	// StatusCode for static_response: 200, 301, 302, 403, 404, etc.
	StatusCode int `json:"status_code,omitempty"`

	// Body for static_response (inline content).
	Body string `json:"body,omitempty"`

	// --- rewrite fields ---

	// URI sets or rewrites the request URI (path + query).
	// Accepts placeholders: "/foo", "?{http.request.uri.query}&a=b", etc.
	// See: https://caddyserver.com/docs/json/apps/http/servers/routes/handle/rewrite
	URI string `json:"uri,omitempty"`

	// StripPathPrefix strips the given prefix from the beginning of the URI path.
	// Default comparison is in normalized (unescaped) space.
	// See: https://caddyserver.com/docs/json/apps/http/servers/routes/handle/rewrite
	StripPathPrefix string `json:"strip_path_prefix,omitempty"`

	// StripPathSuffix strips the given suffix from the end of the URI path.
	// See: https://caddyserver.com/docs/json/apps/http/servers/routes/handle/rewrite
	StripPathSuffix string `json:"strip_path_suffix,omitempty"`

	// Method changes the request's HTTP verb (rewrite).
	Method string `json:"method,omitempty"`

	// URISubstring performs substring replacements on the URI (rewrite).
	URISubstring []URISubst `json:"uri_substring,omitempty"`

	// --- file_server fields ---

	// Root is the directory file_server serves files from.
	// The request path is joined to this root after any upstream rewrite.
	// See: https://caddyserver.com/docs/json/apps/http/servers/routes/handle/file_server
	Root string `json:"root,omitempty"`

	// Hide is a list of files or folders to hide; file_server pretends they
	// don't exist. Accepts glob patterns like "*.ext" or "/foo/*/bar" and
	// placeholders. Uses filesystem paths, not request paths.
	Hide []string `json:"hide,omitempty"`

	// IndexNames is the list of index files to try when a directory is requested.
	// Default: index.html, index.txt.
	IndexNames []string `json:"index_names,omitempty"`

	// Browse enables directory listings when no index file exists.
	Browse *Browse `json:"browse,omitempty"`

	// --- general fields ---

	// Routes for subroute handler (nested routes).
	Routes []Route `json:"routes,omitempty"`
}

// Upstream defines a single upstream backend for reverse_proxy.
type Upstream struct {
	// Dial is the upstream address: "host:port" or unix socket.
	Dial string `json:"dial"`
}

// HeaderPolicy defines request/response header manipulation for reverse_proxy.
// See: https://caddyserver.com/docs/json/apps/http/#servers/routes/handle/header
type HeaderPolicy struct {
	Request  *HeaderOps `json:"request,omitempty"`
	Response *HeaderOps `json:"response,omitempty"`
}

// HeaderOps defines request and response header operations.
// See: https://caddyserver.com/docs/json/apps/http/servers/routes/handle/headers
type HeaderOps struct {
	Add    map[string][]string        `json:"add,omitempty"`    // Add headers; does not replace existing.
	Set    map[string][]string        `json:"set,omitempty"`    // Set headers; replaces existing values.
	Delete []string                   `json:"delete,omitempty"` // Delete header fields (wildcards supported).
	Replace map[string][]Replacement  `json:"replace,omitempty"` // In-situ substring replacements.
	// Response-only fields (ignored for request headers by Caddy):
	Require  *ResponseMatcher `json:"require,omitempty"` // Defer ops until response matches these criteria.
	Deferred bool             `json:"deferred,omitempty"` // Defer ops until response headers are written.
}

// Replacement describes a string replacement in header values.
type Replacement struct {
	Search       string `json:"search,omitempty"`        // Substring to find.
	SearchRegexp string `json:"search_regexp,omitempty"` // Regex to search with.
	Replace      string `json:"replace,omitempty"`       // Replacement string.
}

// ResponseMatcher conditions response header operations on status code and/or header values.
type ResponseMatcher struct {
	StatusCode []int               `json:"status_code,omitempty"` // Required status codes.
	Headers    map[string][]string `json:"headers,omitempty"`     // Required header values.
}

// Browse configures directory browsing for file_server.
type Browse struct {
	TemplateFile string   `json:"template_file,omitempty"`
	Sort         []string `json:"sort,omitempty"`
	FileLimit    int      `json:"file_limit,omitempty"`
}

// URISubst describes a substring replacement in the rewrite handler's URI.
type URISubst struct {
	Find    string `json:"find,omitempty"`    // Substring to find.
	Replace string `json:"replace,omitempty"` // Replacement string.
	Limit   int    `json:"limit,omitempty"`   // Max replacements (0 = unlimited).
}

// ============================================================
// Full Caddy config root structs
// ============================================================
//
// These structs allow expressing the *entire* Caddy config JSON (the document
// POSTed to POST /load) as Go values, eliminating all string-interpolated JSON.
// Reference: https://caddyserver.com/docs/api#post-/load
//
// Design notes:
//   - All fields use pointer + `omitempty` where it makes sense so the
//     marshaled JSON is clean (no empty objects/arrays leaking in).
//   - Existing Route / MatchRule / Handler / Upstream / HeaderPolicy /
//     HeaderOps structs above are reused by Server.Routes.

// Config is the root of a Caddy config JSON document.
type Config struct {
	Admin   *AdminConfig `json:"admin,omitempty"`
	Logs    *LogsConfig  `json:"logging,omitempty"`
	Storage *Storage     `json:"storage,omitempty"`
	Apps    *Apps        `json:"apps,omitempty"`
}

// JSON returns the canonical Caddy-compatible JSON encoding of the config.
// It validates the admin security contract first, then marshals. Unlike a
// bare json.Marshal, it refuses to serialize a config that would expose the
// unauthenticated admin API to the network (wildcard origins / non-loopback
// listen) — callers must run AdminConfig.Validate() or use Config.JSON().
func (c *Config) JSON() ([]byte, error) {
	if c.Admin != nil {
		if err := c.Admin.Validate(); err != nil {
			return nil, err
		}
	}
	return json.Marshal(c)
}

// AdminConfig corresponds to the top-level `admin` block.
type AdminConfig struct {
	Listen  string   `json:"listen"`            // e.g. "127.0.0.1:2019"
	Origins []string `json:"origins,omitempty"` // explicit allowlist; NEVER contain "*"
	Persist *bool    `json:"persist,omitempty"` // nil = Caddy default
}

// Validate checks for security-sensitive misconfigurations.
func (a *AdminConfig) Validate() error {
	if slices.Contains(a.Origins, "*") {
		return fmt.Errorf("caddyadmin: admin origin must not be wildcard '*' — exposes admin API to network")
	}
	return a.validateListen()
}

// validateListen rejects binding the admin API to a non-loopback interface.
// The admin API has no authentication (see README gotcha #6); exposing it to
// the network would let anyone read or replace the running Caddy config.
func (a *AdminConfig) validateListen() error {
	if a.Listen == "" {
		return nil
	}
	host, _, err := net.SplitHostPort(a.Listen)
	if err != nil {
		// Not a host:port address (e.g. a Unix socket); let Caddy resolve it.
		return nil
	}
	if host == "" || !isLoopbackHost(host) {
		return fmt.Errorf("caddyadmin: admin listen %q must bind to a loopback address (e.g. 127.0.0.1:2019) — the admin API has no auth and must not be exposed to the network", a.Listen)
	}
	return nil
}

// isLoopbackHost reports whether host is "localhost" or a loopback IP address.
func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// LogsConfig corresponds to the top-level `logging` block.
type LogsConfig struct {
	Logs map[string]LogEntry `json:"logs,omitempty"`
}

// LogEntry is one named logger (key is the logger name; the default logger
// uses the special key "default").
//
// Caddy's canonical logging JSON uses an object form for `writer`, e.g.:
//
//	"default": {
//	  "writer": {"output": "file", "filename": "/var/log/caddy.log"},
//	  "level":  "WARN"
//	}
//
// Level must be an uppercase zap level: DEBUG / INFO / WARN / ERROR / PANIC.
type LogEntry struct {
	Writer *LogWriter `json:"writer,omitempty"`
	Level  string     `json:"level,omitempty"`
}

// LogWriter is the writer configuration for a log entry.
// See: https://caddyserver.com/docs/json/logging/#logs
type LogWriter struct {
	Output   string `json:"output"`             // "file" / "stderr" / "stdout" / "net"
	Filename string `json:"filename,omitempty"` // for output="file"
}

// Storage corresponds to the top-level `storage` block. vanblog uses the
// file_system module exclusively.
type Storage struct {
	Module string `json:"module"` // "file_system"
	Root   string `json:"root"`   // e.g. "/data/caddy"
}

// Apps corresponds to the top-level `apps` block. We only model http + tls
// (the only apps vanblog configures explicitly).
type Apps struct {
	HTTP *HTTPApp `json:"http,omitempty"`
	TLS  *TLSApp  `json:"tls,omitempty"`
}

// HTTPApp corresponds to apps.http.
type HTTPApp struct {
	Servers map[string]*Server `json:"servers,omitempty"` // "srv0" -> ...
}

// Server corresponds to apps.http.servers.{name}. It is a named HTTP listener
// (e.g. "srv0" for :443, "srv1" for :80 redirect, "srv_mgmt" for :8080).
type Server struct {
	Listen           []string          `json:"listen,omitempty"` // [":443"], [":80"], [":8080"]
	Routes           []Route           `json:"routes,omitempty"`
	ListenerWrappers []ListenerWrapper `json:"listener_wrappers,omitempty"` // e.g. http_redirect
	Logs             *ServerLogs       `json:"logs,omitempty"`
	// TLS connection policies are intentionally NOT modeled here: under
	// automatic HTTPS, Caddy generates them itself. Declaring them manually
	// fights Caddy's automation and is a known foot-gun.
}

// ListenerWrapper is one entry under server.listener_wrappers. The only
// wrapper vanblog uses is "http_redirect" (HTTP→HTTPS redirect on the :80
// server).
type ListenerWrapper struct {
	Wrapper string `json:"wrapper"` // "http_redirect"
}

// ServerLogs corresponds to server.logs (per-server logger config).
type ServerLogs struct {
	DefaultLoggerName string `json:"default_logger_name,omitempty"`
}

// TLSApp corresponds to apps.tls.
type TLSApp struct {
	Automation *Automation `json:"automation,omitempty"`
	// certificates / get_certificate / session_tickets etc. are managed by
	// Caddy internally under automatic HTTPS and are intentionally not modeled.
}

// Automation corresponds to apps.tls.automation.
type Automation struct {
	Policies []AutomationPolicy `json:"policies,omitempty"`
	OnDemand *OnDemandTLS       `json:"on_demand,omitempty"`
}

// AutomationPolicy is one entry under tls.automation.policies.
//
// For vanblog's on-demand TLS model, there is typically a single policy with
// Subjects = the allowlisted domains and OnDemand = true. Caddy then calls
// the OnDemandTLS.Ask endpoint before issuing each certificate.
type AutomationPolicy struct {
	Subjects []string `json:"subjects,omitempty"`
	OnDemand bool     `json:"on_demand,omitempty"`
	Issuers  []Issuer `json:"issuers,omitempty"`
}

// OnDemandTLS corresponds to tls.automation.on_demand. The Ask endpoint is
// vanblog's own /api/hooks/caddy/ask, which returns 2xx for allowlisted
// domains and non-2xx otherwise — this is the core of vanblog's on-demand
// TLS allowlist.
type OnDemandTLS struct {
	Ask string `json:"ask,omitempty"`
}

// Issuer is one certificate issuer under an AutomationPolicy. vanblog lets
// Caddy use its default ACME issuer (Let's Encrypt) and only optionally sets
// the email; other ACME-specific fields are left to Caddy's defaults.
type Issuer struct {
	Module string `json:"module"` // "acme" / "zerossl" / "internal"
	Email  string `json:"email,omitempty"`
}

// ============================================================
// Handler field schema registry
// ============================================================
//
// Each handler module has a known set of valid top-level JSON fields.
// Caddy silently ignores unknown fields at the handler level (encoding/json),
// so emitting an invalid field (e.g. strip_path_prefix on file_server)
// is a silent misconfiguration. We reject unknown fields at marshal time.
//
// Call RegisterHandlerFields to extend this set for custom/third-party modules.

var knownHandlerFields = map[string]map[string]struct{}{
	"reverse_proxy": {
		"handler": {}, "upstreams": {}, "headers": {},
	},
	"static_response": {
		"handler": {}, "status_code": {}, "body": {}, "headers": {},
	},
	"rewrite": {
		"handler": {}, "uri": {}, "strip_path_prefix": {}, "strip_path_suffix": {},
		"uri_substring": {}, "path_regexp": {}, "method": {}, "query": {},
	},
	"subroute": {
		"handler": {}, "routes": {},
	},
	"file_server": {
		"handler": {}, "fs": {}, "root": {}, "hide": {}, "index_names": {},
		"browse": {}, "canonical_uris": {}, "status_code": {},
		"pass_thru": {}, "precompressed": {}, "precompressed_order": {},
		"etag_file_extensions": {},
	},
	"headers": {
		"handler": {}, "request": {}, "response": {},
	},
	"vars": {
		"handler": {},
	},
}

// RegisterHandlerFields registers (or extends) the known JSON field set for a
// handler module. Use this for custom Caddy builds with third-party modules
// whose fields are not in the built-in registry.
//
// The handler name should match the admin API module name (e.g. "cache").
// Fields is the list of valid top-level JSON keys for that module.
func RegisterHandlerFields(handler string, fields []string) {
	if _, ok := knownHandlerFields[handler]; !ok {
		knownHandlerFields[handler] = make(map[string]struct{}, len(fields))
	}
	for _, f := range fields {
		knownHandlerFields[handler][f] = struct{}{}
	}
}

// HandlerFieldSet returns the known JSON field set for a handler module.
// Returns nil if the handler is completely unknown (unregistered).
func HandlerFieldSet(handler string) map[string]struct{} {
	return knownHandlerFields[handler]
}

// Validate checks that all non-zero fields on this Handler are valid for its
// handler module. Returns an error for fields Caddy would silently ignore.
// MarshalJSON calls Validate automatically; call it explicitly to fail early
// before building large config trees.
func (h Handler) Validate() error {
	if h.Handler == "" {
		return fmt.Errorf("caddyadmin: Handler.Handler is required")
	}
	fields := HandlerFieldSet(h.Handler)
	if fields == nil {
		return fmt.Errorf("caddyadmin: unknown handler module %q — register fields with RegisterHandlerFields", h.Handler)
	}

	check := func(fieldName string, set bool) error {
		if set {
			if _, ok := fields[fieldName]; !ok {
				return fmt.Errorf("caddyadmin: handler %q has no field %q", h.Handler, fieldName)
			}
		}
		return nil
	}

	if err := check("upstreams", len(h.Upstreams) > 0); err != nil {
		return err
	}
	if err := check("status_code", h.StatusCode != 0); err != nil {
		return err
	}
	if err := check("body", h.Body != ""); err != nil {
		return err
	}
	if err := check("uri", h.URI != ""); err != nil {
		return err
	}
	if err := check("strip_path_prefix", h.StripPathPrefix != ""); err != nil {
		return err
	}
	if err := check("strip_path_suffix", h.StripPathSuffix != ""); err != nil {
		return err
	}
	if err := check("uri_substring", len(h.URISubstring) > 0); err != nil {
		return err
	}
	if err := check("method", h.Method != ""); err != nil {
		return err
	}
	if err := check("root", h.Root != ""); err != nil {
		return err
	}
	if err := check("hide", len(h.Hide) > 0); err != nil {
		return err
	}
	if err := check("index_names", len(h.IndexNames) > 0); err != nil {
		return err
	}
	if err := check("browse", h.Browse != nil); err != nil {
		return err
	}
	if err := check("routes", len(h.Routes) > 0); err != nil {
		return err
	}

	// Headers: validated separately per-handler in MarshalJSON
	if h.Headers != nil {
		switch h.Handler {
		case "file_server":
			return fmt.Errorf("caddyadmin: file_server handler does not support headers")
		case "headers":
			// ok — emitted flattened at top level
		default:
			if _, ok := fields["headers"]; !ok {
				return fmt.Errorf("caddyadmin: handler %q has no field %q", h.Handler, "headers")
			}
		}
	}

	return nil
}

// ============================================================
// Custom marshaling
// ============================================================

// handlerRaw is the default marshal output of Handler with the Headers field
// omitted. MarshalJSON fills Headers separately depending on Handler kind.
type handlerRaw struct {
	Handler         string      `json:"handler"`
	Upstreams       []Upstream  `json:"upstreams,omitempty"`
	StatusCode      int         `json:"status_code,omitempty"`
	Body            string      `json:"body,omitempty"`
	URI             string      `json:"uri,omitempty"`
	StripPathPrefix string      `json:"strip_path_prefix,omitempty"`
	StripPathSuffix string      `json:"strip_path_suffix,omitempty"`
	Method          string      `json:"method,omitempty"`
	URISubstring    []URISubst  `json:"uri_substring,omitempty"`
	Root            string      `json:"root,omitempty"`
	Hide            []string    `json:"hide,omitempty"`
	IndexNames      []string    `json:"index_names,omitempty"`
	Browse          *Browse     `json:"browse,omitempty"`
	Routes          []Route     `json:"routes,omitempty"`
}

// MarshalJSON serializes Handler. Fields are validated against the handler
// schema (Validate) before marshaling. Headers are emitted per-handler:
//   - reverse_proxy → nested at "headers" key ({request:{...}, response:{...}})
//   - standalone `headers` handler → flattened at top level (request:/response:)
//   - static_response → flat map[string][]string (http.Header shape)
//   - file_server → rejected entirely
func (h Handler) MarshalJSON() ([]byte, error) {
	if err := h.Validate(); err != nil {
		return nil, err
	}

	raw := handlerRaw{
		Handler:         h.Handler,
		Upstreams:       h.Upstreams,
		StatusCode:      h.StatusCode,
		Body:            h.Body,
		URI:             h.URI,
		StripPathPrefix: h.StripPathPrefix,
		StripPathSuffix: h.StripPathSuffix,
		Method:          h.Method,
		URISubstring:    h.URISubstring,
		Root:            h.Root,
		Hide:            h.Hide,
		IndexNames:      h.IndexNames,
		Browse:          h.Browse,
		Routes:          h.Routes,
	}

	if h.Headers == nil {
		return json.Marshal(raw)
	}

	if h.Handler == "file_server" {
		// Already validated above, but re-check for safety.
		return nil, fmt.Errorf("caddyadmin: file_server handler does not support headers")
	}

	if h.Handler == "static_response" {
		// Caddy's static_response only supports Response.Set as a flat map.
		if h.Headers.Response != nil && (len(h.Headers.Response.Add) > 0 || len(h.Headers.Response.Delete) > 0) {
			return nil, fmt.Errorf("caddyadmin: static_response handler does not support header Add/Delete operations")
		}
		if h.Headers.Request != nil {
			return nil, fmt.Errorf("caddyadmin: static_response handler does not support request headers")
		}
		flat := map[string][]string{}
		if h.Headers.Response != nil {
			maps.Copy(flat, h.Headers.Response.Set)
		}
		return marshalHandlerWithHeaders(raw, flat)
	}
	if h.Handler == "headers" {
		// The standalone `headers` directive carries request/response at the
		// handler top level, NOT under a `headers` field (unlike reverse_proxy,
		// whose HeaderPolicy lives at `headers`). Emit them flattened.
		m := map[string]any{"handler": "headers"}
		if h.Headers != nil {
			if h.Headers.Request != nil {
				m["request"] = h.Headers.Request
			}
			if h.Headers.Response != nil {
				m["response"] = h.Headers.Response
			}
		}
		return json.Marshal(m)
	}
	return marshalHandlerWithHeaders(raw, h.Headers)
}

// marshalHandlerWithHeaders builds the JSON by combining handlerRaw fields and
// headers into a single map, avoiding fragile byte-level JSON manipulation.
func marshalHandlerWithHeaders(raw handlerRaw, headers any) ([]byte, error) {
	m := map[string]any{
		"handler": raw.Handler,
		"headers": headers,
	}
	if raw.Upstreams != nil {
		m["upstreams"] = raw.Upstreams
	}
	if raw.StatusCode != 0 {
		m["status_code"] = raw.StatusCode
	}
	if raw.Body != "" {
		m["body"] = raw.Body
	}
	if raw.URI != "" {
		m["uri"] = raw.URI
	}
	if raw.StripPathPrefix != "" {
		m["strip_path_prefix"] = raw.StripPathPrefix
	}
	if raw.StripPathSuffix != "" {
		m["strip_path_suffix"] = raw.StripPathSuffix
	}
	if raw.Method != "" {
		m["method"] = raw.Method
	}
	if raw.URISubstring != nil {
		m["uri_substring"] = raw.URISubstring
	}
	if raw.Root != "" {
		m["root"] = raw.Root
	}
	if raw.Hide != nil {
		m["hide"] = raw.Hide
	}
	if raw.IndexNames != nil {
		m["index_names"] = raw.IndexNames
	}
	if raw.Browse != nil {
		m["browse"] = raw.Browse
	}
	if raw.Routes != nil {
		m["routes"] = raw.Routes
	}
	return json.Marshal(m)
}

// UnmarshalJSON decodes a Handler, mirroring MarshalJSON's per-handler
// Headers shape. static_response handlers carry a flat map[string][]string
// (http.Header shape); every other handler carries the nested HeaderPolicy
// shape. This makes round-tripping a live config (GET /config then edit)
// lossless instead of silently dropping static_response header manipulation.
func (h *Handler) UnmarshalJSON(data []byte) error {
	// Decode into a map first so we can dispatch on the handler name.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	decode := func(key string, out any) error {
		v, ok := raw[key]
		if !ok || len(v) == 0 || string(v) == "null" {
			return nil
		}
		return json.Unmarshal(v, out)
	}

	if err := decode("handler", &h.Handler); err != nil {
		return err
	}
	if err := decode("upstreams", &h.Upstreams); err != nil {
		return err
	}
	if err := decode("status_code", &h.StatusCode); err != nil {
		return err
	}
	if err := decode("body", &h.Body); err != nil {
		return err
	}
	if err := decode("uri", &h.URI); err != nil {
		return err
	}
	if err := decode("routes", &h.Routes); err != nil {
		return err
	}
	if err := decode("root", &h.Root); err != nil {
		return err
	}
	if err := decode("strip_path_prefix", &h.StripPathPrefix); err != nil {
		return err
	}
	if err := decode("strip_path_suffix", &h.StripPathSuffix); err != nil {
		return err
	}
	if err := decode("method", &h.Method); err != nil {
		return err
	}
	if err := decode("uri_substring", &h.URISubstring); err != nil {
		return err
	}
	if err := decode("hide", &h.Hide); err != nil {
		return err
	}
	if err := decode("index_names", &h.IndexNames); err != nil {
		return err
	}
	if err := decode("browse", &h.Browse); err != nil {
		return err
	}

	if h.Handler == "headers" {
		// The standalone `headers` directive carries request/response at the
		// handler top level (not under `headers`), mirroring MarshalJSON.
		hp := &HeaderPolicy{}
		if err := decode("request", &hp.Request); err != nil {
			return err
		}
		if err := decode("response", &hp.Response); err != nil {
			return err
		}
		h.Headers = hp
		return nil
	}

	hdr, ok := raw["headers"]
	if !ok || len(hdr) == 0 || string(hdr) == "null" {
		return nil
	}

	if h.Handler == "static_response" {
		// static_response headers are a flat http.Header map.
		var flat map[string][]string
		if err := json.Unmarshal(hdr, &flat); err != nil {
			return err
		}
		h.Headers = &HeaderPolicy{Response: &HeaderOps{Set: flat}}
		return nil
	}

	// All other handlers use the nested HeaderPolicy shape.
	var hp HeaderPolicy
	if err := json.Unmarshal(hdr, &hp); err != nil {
		return err
	}
	h.Headers = &hp
	return nil
}
