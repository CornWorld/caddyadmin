# caddyadmin

Caddy admin API wrapper for personal usage — pure Go, zero external dependencies.

Provides typed Go structs for the [Caddy](https://caddyserver.com/) JSON configuration model
and a minimal HTTP client to interact with the Caddy admin API endpoint.

```
go get github.com/CornWorld/caddyadmin
```

---

## Quick Start

```go
package main

import (
    "fmt"
    "log"

    "github.com/CornWorld/caddyadmin"
)

func main() {
    // Connect to Caddy admin API (default: http://127.0.0.1:2019)
    client := caddyadmin.NewClient("http://127.0.0.1:2019")

    // Fetch current configuration
    cfg, err := client.GetConfig()
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Current config: %s\n", cfg)

    // List routes for server "srv0"
    routes, err := client.GetRoutes("srv0")
    if err != nil {
        log.Fatal(err)
    }
    for _, r := range routes {
        fmt.Printf("Route %s: %+v\n", r.ID, r.Match)
    }
}
```

---

## API Client Reference

| Method | HTTP | Caddy Endpoint |
|---|---|---|
| `NewClient(baseURL string) *Client` | — | Constructor. Strips trailing `/`. Uses 10s timeout, HTTP/1.1 only, no compression. |
| `GetConfig() (json.RawMessage, error)` | GET | `/config` — full running config |
| `LoadConfig(config json.RawMessage) error` | POST | `/load` — replace entire config atomically |
| `ValidateConfig(config json.RawMessage) error` | POST | `/load?validate_only=true` — dry-run validation |
| `GetConfigPath(path string) (json.RawMessage, error)` | GET | `/config/{path}` — config subtree |
| `GetRoutes(serverName string) ([]Route, error)` | GET | `/config/apps/http/servers/{name}/routes` |
| `GetAutocertDomains() ([]string, error)` | GET | `/config/apps/tls/certificates/automate` |
| `AddRoute(serverName string, route *Route) error` | POST | `/config/apps/http/servers/{name}/routes` |
| `RemoveRouteByID(id string) error` | DELETE | `/id/{id}` — delete by stable `@id` |
| `Version() (map[string]any, error)` | GET | `/version` (falls back to `/config` for older Caddy) |

---

## Type Contracts

### Config — Root

```go
type Config struct {
    Admin   *AdminConfig `json:"admin,omitempty"`
    Logs    *LogsConfig  `json:"logging,omitempty"`
    Storage *Storage     `json:"storage,omitempty"`
    Apps    *Apps        `json:"apps,omitempty"`
}
```

### AdminConfig

```go
type AdminConfig struct {
    Listen  string   `json:"listen"`            // e.g. "127.0.0.1:2019"
    Origins []string `json:"origins,omitempty"`  // NEVER wildcard "*" (Validate() rejects it)
    Persist *bool    `json:"persist,omitempty"`  // nil = Caddy default
}
```

### Apps → HTTPApp + TLSApp

```go
type Apps struct {
    HTTP *HTTPApp `json:"http,omitempty"`
    TLS  *TLSApp  `json:"tls,omitempty"`
}

type HTTPApp struct {
    Servers map[string]*Server `json:"servers,omitempty"` // "srv0" → *Server
}

type TLSApp struct {
    Automation *Automation `json:"automation,omitempty"`
}
```

### Server

```go
type Server struct {
    Listen           []string          `json:"listen,omitempty"`
    Routes           []Route           `json:"routes,omitempty"`
    ListenerWrappers []ListenerWrapper `json:"listener_wrappers,omitempty"`
    Logs             *ServerLogs       `json:"logs,omitempty"`
}
```

### Route

```go
type Route struct {
    ID      string      `json:"@id,omitempty"`     // Stable identifier for CRUD
    Match   []MatchRule `json:"match,omitempty"`    // ANY rule matching = route matches
    Handle  []Handler   `json:"handle,omitempty"`   // Handler chain
}
```

### MatchRule

```go
type MatchRule struct {
    Path    []string            `json:"path,omitempty"`   // Glob ["/api/*"]
    Host    []string            `json:"host,omitempty"`   // ["*.example.com"]
    Header  map[string][]string `json:"header,omitempty"`
    Method  []string            `json:"method,omitempty"` // ["GET","POST"]
    NotIP   []string            `json:"not_ip,omitempty"`
    IP      []string            `json:"ip,omitempty"`
}
```

### Handler

```go
type Handler struct {
    Handler    string        `json:"handler"`             // "reverse_proxy" | "static_response" | "rewrite" | "subroute"
    Upstreams  []Upstream    `json:"upstreams,omitempty"`
    Headers    *HeaderPolicy `json:"headers,omitempty"`    // custom MarshalJSON (see Gotchas)
    StatusCode int           `json:"status_code,omitempty"`
    Body       string        `json:"body,omitempty"`
    URI        string        `json:"uri,omitempty"`
    Routes     []Route       `json:"routes,omitempty"`     // subroute nested routes
}
```

### HeaderPolicy

```go
type HeaderPolicy struct {
    Request  *HeaderOps `json:"request,omitempty"`
    Response *HeaderOps `json:"response,omitempty"`
}

type HeaderOps struct {
    Add    map[string][]string `json:"add,omitempty"`
    Set    map[string][]string `json:"set,omitempty"`
    Delete []string            `json:"delete,omitempty"`
}
```

### LogsConfig

```go
type LogsConfig struct {
    Logs map[string]LogEntry `json:"logs,omitempty"`
}

type LogEntry struct {
    Writer *LogWriter `json:"writer,omitempty"`
    Level  string     `json:"level,omitempty"` // DEBUG | INFO | WARN | ERROR | PANIC
}

type LogWriter struct {
    Output   string `json:"output"`            // "file" | "stderr" | "stdout" | "net"
    Filename string `json:"filename,omitempty"` // for output="file"
}
```

### Storage

```go
type Storage struct {
    Module string `json:"module"` // "file_system"
    Root   string `json:"root"`   // e.g. "/data/caddy"
}
```

### TLS

```go
type Automation struct {
    Policies []AutomationPolicy `json:"policies,omitempty"`
    OnDemand *OnDemandTLS       `json:"on_demand,omitempty"`
}

type AutomationPolicy struct {
    Subjects []string `json:"subjects,omitempty"`
    OnDemand bool     `json:"on_demand,omitempty"`
    Issuers  []Issuer `json:"issuers,omitempty"`
}

type OnDemandTLS struct {
    Ask string `json:"ask,omitempty"` // URL Caddy calls before issuing cert
}

type Issuer struct {
    Module string `json:"module"` // "acme" | "zerossl" | "internal"
    Email  string `json:"email,omitempty"`
}
```

---

## Key Gotchas

### 1. Caddy Admin Is HTTP/1.1 Only
The admin endpoint does not support HTTP/2. The client explicitly sets `ForceAttemptHTTP2: false`. Do not configure H2 on the admin listener.

### 2. Compression Disabled
`DisableCompression: true` — avoids gzip-related issues on the admin port. All responses are read as-is.

### 3. LoadConfig Retries Transient Errors
`LoadConfig` retries up to **3 times with 500ms delay** for:
- `io.EOF` / `io.ErrUnexpectedEOF`
- `syscall.ECONNRESET` (connection reset)
- `syscall.EPIPE` (broken pipe)
- HTTP 5xx responses

4xx errors are **never retried** — they indicate a client-side problem. This retry logic exists because Caddy's admin endpoint may reset the connection during config reloads.

### 4. Handler JSON Shape Changes by Module
The `Handler.Headers` field marshals differently depending on `Handler.Handler`:
- **`static_response`**: headers marshal as a flat `map[string][]string` (http.Header shape). Add/Delete/Request sub-fields are rejected with an error.
- **All other modules** (`reverse_proxy`, `rewrite`, etc.): headers marshal as the full nested `HeaderPolicy` object (`{request: ..., response: ...}`).

### 5. AdminConfig.Origins — Never Wildcard
`AdminConfig.Validate()` returns an error if `Origins` contains `"*"`. This is a deliberate security measure — the admin API should never be accessible from arbitrary origins. Use explicit origin values only.

### 6. No Authentication
Caddy's admin API has no built-in auth mechanism. It is designed to bind to localhost only (`127.0.0.1:2019`). Never expose it to a network interface without additional protection.

### 7. Routes Use @id for Stable Identification
Routes are identified by their `@id` field (JSON tag `@id`). This is used by `RemoveRouteByID()` which calls `DELETE /id/{id}`. Without a set `@id`, a route cannot be deleted or updated individually — you'd have to reload the entire config.

### 8. Base URL Trailing Slash Trimmed
`NewClient` strips any trailing `/` from the base URL. All paths are appended directly, so `http://127.0.0.1:2019/` and `http://127.0.0.1:2019` produce identical behavior.

### 9. Version() Fallback
`Version()` tries `GET /version` first. If that fails (older Caddy versions), it falls back to extracting version info from `GET /config`.

### 10. Zero External Dependencies
The entire library uses only the Go standard library:
`encoding/json`, `errors`, `fmt`, `io`, `net/http`, `os`, `strings`, `time`, `context`, `bytes`.

Easy to audit, vendor, and maintain.

---

## Testing

Unit tests use a mock HTTP server (`httptest.Server`) — run with:

```bash
go test -v -run 'TestMock|TestClientBaseURL|TestRouteJSON|TestConfig|TestAdminConfig'
```

Integration tests require a running Caddy instance (Docker container named `caddy-dev`) — opt in via:

```bash
CADDY_TEST=1 go test -v -run 'TestGetConfig|TestLoad|TestValidate'
```

---

## License

MIT
