// Package testapp provides a web application for testing the ATLogin OIDC flow.
// It can be embedded in other applications to provide verification and login testing.
package testapp

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Server represents a test app server instance.
type Server struct {
	clientID     string
	clientSecret string
	issuer       string

	mu       sync.Mutex
	sessions map[string]*session
}

type session struct {
	state       string
	nonce       string
	email       string
	createdAt   time.Time
	redirectURI string
}

type oidcConfig struct {
	Issuer                string   `json:"issuer"`
	AuthorizationEndpoint string   `json:"authorization_endpoint"`
	TokenEndpoint         string   `json:"token_endpoint"`
	UserinfoEndpoint      string   `json:"userinfo_endpoint"`
	JwksURI               string   `json:"jwks_uri"`
	ScopesSupported       []string `json:"scopes_supported"`
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	IDToken     string `json:"id_token"`
}

type userInfo struct {
	Sub   string `json:"sub"`
	Name  string `json:"name"`
	Email string `json:"email"`
}

type webFingerResponse struct {
	Subject string          `json:"subject"`
	Links   []webFingerLink `json:"links"`
}

type webFingerLink struct {
	Rel  string `json:"rel"`
	Href string `json:"href"`
}

type verificationResult struct {
	Domain         string
	Email          string
	ATProtoHandle  string
	HasDNS         bool
	HasHTTPS       bool
	HasWebFinger   bool
	WebFinger      *webFingerResponse
	Issuer         string
	ExpectedIssuer string
	Errors         []string
	Warnings       []string
}

// parseLoginHint extracts the ATProto handle and domain from a login hint.
//
// Format: user@domain
//
// ATProto handle rules:
// 1. Default: user@domain -> @user.domain (ATProto handle), domain (webfinger domain)
// 2. If "user." is a prefix of domain: user@user.example.com -> @user.example.com, user.example.com
// 3. Special case for at.apenwarr.ca and atlogin.net: user@at.apenwarr.ca -> @user, at.apenwarr.ca
//
// Examples:
//   - at@apenwarr.ca -> @at.apenwarr.ca (handle), apenwarr.ca (domain)
//   - apenwarr@apenwarr.ca -> @apenwarr.ca (handle), apenwarr.ca (domain)
//   - user@at.apenwarr.ca -> @user (handle), at.apenwarr.ca (domain) [backward compat]
//   - user@atlogin.net -> @user (handle), atlogin.net (domain)
//
// Returns: (atprotoHandle, webfingerDomain, error)
func parseLoginHint(loginHint string) (string, string, error) {
	parts := strings.SplitN(loginHint, "@", 2)
	if len(parts) != 2 {
		return "", "", fmt.Errorf("expected format: user@domain, got: %s", loginHint)
	}

	user := parts[0]
	domain := parts[1]

	if user == "" {
		return "", "", fmt.Errorf("user cannot be empty")
	}

	if domain == "" {
		return "", "", fmt.Errorf("domain cannot be empty")
	}

	// Special case for backward compatibility with at.apenwarr.ca and atlogin.net
	if domain == "at.apenwarr.ca" || domain == "atlogin.net" {
		return user, domain, nil
	}

	// Check if "user." is a prefix of domain
	prefix := user + "."
	if strings.HasPrefix(domain, prefix) {
		// user@user.example.com -> @user.example.com
		return domain, domain, nil
	}

	// Default case: user@domain -> @user.domain
	atprotoHandle := user + "." + domain
	return atprotoHandle, domain, nil
}

// NewServer creates a new test app server with the given credentials.
func NewServer(clientID, clientSecret, issuer string) *Server {
	return &Server{
		clientID:     clientID,
		clientSecret: clientSecret,
		issuer:       issuer,
		sessions:     make(map[string]*session),
	}
}

// RegisterHandlers registers all test app HTTP handlers on the given mux.
func (s *Server) RegisterHandlers(mux *http.ServeMux) {
	mux.HandleFunc("/{$}", s.serveHome)
	mux.HandleFunc("/verify", s.serveVerify)
	mux.HandleFunc("/login", s.serveLogin)
	mux.HandleFunc("/callback", s.serveCallback)
}

var homeTemplate = template.Must(template.New("home").Parse(`<!DOCTYPE html>
<html>
<head>
    <title>ATLogin - OIDC for ATProto/Bluesky</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            max-width: 700px;
            margin: 50px auto;
            padding: 20px;
            line-height: 1.6;
        }
        h1 {
            color: #1d4ed8;
            margin-bottom: 10px;
        }
        h2 {
            color: #333;
            margin-top: 40px;
            padding-top: 20px;
            border-top: 2px solid #e5e7eb;
        }
        .subtitle {
            color: #666;
            font-size: 18px;
            margin-bottom: 30px;
        }
        .intro {
            background-color: #eff6ff;
            border-left: 4px solid #1d4ed8;
            padding: 15px;
            margin-bottom: 30px;
        }
        .intro p {
            margin: 10px 0;
        }
        form {
            margin: 20px 0;
        }
        label {
            display: block;
            margin-bottom: 5px;
            font-weight: bold;
        }
        input[type="email"] {
            width: 100%;
            padding: 10px;
            border: 1px solid #ddd;
            border-radius: 4px;
            box-sizing: border-box;
            font-size: 16px;
        }
        button {
            margin-top: 10px;
            padding: 10px 20px;
            background-color: #007bff;
            color: white;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-size: 16px;
        }
        button:hover {
            background-color: #0056b3;
        }
        .help {
            color: #666;
            font-size: 14px;
            margin-top: 5px;
        }
        .preview {
            margin-top: 15px;
            padding: 12px;
            background-color: #f9fafb;
            border: 1px solid #d1d5db;
            border-radius: 4px;
            font-family: monospace;
            min-height: 24px;
        }
        .preview-label {
            font-size: 13px;
            font-weight: bold;
            color: #374151;
            margin-bottom: 5px;
        }
        .preview-handle {
            color: #1d4ed8;
            font-size: 16px;
        }
        .preview-error {
            color: #dc2626;
            font-size: 14px;
        }
        .features {
            background-color: #f0fdf4;
            border-left: 4px solid #10b981;
            padding: 15px;
            margin: 20px 0;
        }
        .features ul {
            margin: 10px 0;
            padding-left: 20px;
        }
    </style>
</head>
<body>
    <h1>ATLogin</h1>
    <div class="subtitle">OpenID Connect Identity Provider for ATProto (Bluesky) Accounts</div>

    <div class="intro">
        <p><strong>ATLogin</strong> lets you use your ATProto/Bluesky identity to log in to any application that supports OIDC.</p>
        <p>Use your Bluesky handle as your email address for seamless authentication across services.</p>
    </div>

    <div class="features">
        <strong>What you can do:</strong>
        <ul>
            <li>Log in to OIDC-compatible apps with your Bluesky identity</li>
            <li>Generate client credentials for your own applications</li>
            <li>Use any domain with ATProto handle verification</li>
        </ul>
    </div>

    <h2>Set Up ATProto Login for Your Domain</h2>
    <p>Test the ATLogin OIDC flow and verify your domain is configured correctly.</p>

    <form action="/verify" method="post">
        <label for="email">Email Address (Your ATProto Identity):</label>
        <input type="email" id="email" name="email" required
               placeholder="{{.ExampleEmail}}" oninput="updatePreview()">
        <div class="help">Format: handle@domain (e.g., {{.ExampleEmail}} or username@bsky.social)</div>

        <div class="preview-label">Your ATProto handle is:</div>
        <div class="preview" id="preview">
            <span class="preview-handle" id="preview-handle"></span>
            <span class="preview-error" id="preview-error"></span>
        </div>

        <button type="submit">Verify Domain & Test Login</button>
    </form>

    <script>
        function updatePreview() {
            const input = document.getElementById('email').value;
            const previewHandle = document.getElementById('preview-handle');
            const previewError = document.getElementById('preview-error');

            if (!input) {
                previewHandle.textContent = '';
                previewError.textContent = '';
                return;
            }

            const parts = input.split('@');
            if (parts.length !== 2) {
                previewHandle.textContent = '';
                previewError.textContent = 'Invalid format: use handle@domain';
                return;
            }

            const user = parts[0];
            const domain = parts[1];

            if (!user || !domain) {
                previewHandle.textContent = '';
                previewError.textContent = 'Both handle and domain are required';
                return;
            }

            let atprotoHandle;
            let error = '';

            // Special case for at.apenwarr.ca and atlogin.net (backward compatibility)
            if (domain === 'at.apenwarr.ca' || domain === 'atlogin.net') {
                atprotoHandle = '@' + user;
                if (!user.includes('.')) {
                    error = ' ⚠️ Warning: ATProto handles must contain a dot ';
                }
            }
            // Check if "user." is a prefix of domain
            else if (domain.startsWith(user + '.')) {
                atprotoHandle = '@' + domain;
            }
            // Default case: user@domain -> @user.domain
            else {
                atprotoHandle = '@' + user + '.' + domain;
            }

            // Validate that the handle contains a dot (unless it's the special case)
            if (domain !== 'at.apenwarr.ca' && domain !== 'atlogin.net' && !atprotoHandle.substring(1).includes('.')) {
                error = ' ⚠️ Invalid: ATProto handles must contain a dot';
            }

            previewHandle.textContent = atprotoHandle;
            previewError.textContent = error;
        }

        // Initialize preview on page load
        updatePreview();
    </script>
</body>
</html>
`))

var verifyTemplate = template.Must(template.New("verify").Parse(`<!DOCTYPE html>
<html>
<head>
    <title>Domain Verification - ATLogin Test</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            max-width: 800px;
            margin: 50px auto;
            padding: 20px;
        }
        h1 {
            color: #333;
        }
        .status {
            padding: 15px;
            border-radius: 4px;
            margin-bottom: 20px;
        }
        .success {
            background-color: #d4edda;
            border: 1px solid #c3e6cb;
            color: #155724;
        }
        .error {
            background-color: #f8d7da;
            border: 1px solid #f5c6cb;
            color: #721c24;
        }
        .warning {
            background-color: #fff3cd;
            border: 1px solid #ffeaa7;
            color: #856404;
        }
        .section {
            margin: 20px 0;
        }
        .section h2 {
            color: #555;
            border-bottom: 2px solid #ddd;
            padding-bottom: 5px;
        }
        pre {
            background-color: #f5f5f5;
            border: 1px solid #ddd;
            border-radius: 4px;
            padding: 15px;
            overflow-x: auto;
            white-space: pre-wrap;
            word-wrap: break-word;
        }
        .button {
            display: inline-block;
            margin-top: 10px;
            margin-right: 10px;
            padding: 10px 20px;
            background-color: #007bff;
            color: white;
            text-decoration: none;
            border-radius: 4px;
            border: none;
            cursor: pointer;
            font-size: 16px;
        }
        .button:hover {
            background-color: #0056b3;
        }
        .button-secondary {
            background-color: #6c757d;
        }
        .button-secondary:hover {
            background-color: #545b62;
        }
        ul {
            margin: 10px 0;
        }
        li {
            margin: 5px 0;
        }
        .check-item {
            margin: 10px 0;
        }
        .check-pass::before {
            content: "✓ ";
            color: #28a745;
            font-weight: bold;
        }
        .check-fail::before {
            content: "✗ ";
            color: #dc3545;
            font-weight: bold;
        }
    </style>
</head>
<body>
    <h1>Domain Verification</h1>

    {{if .Errors}}
    <div class="status error">
        <strong>Verification Failed</strong>
        <ul>
        {{range .Errors}}
            <li>{{.}}</li>
        {{end}}
        </ul>
    </div>
    {{else}}
    <div class="status success">
        <strong>Domain Verified!</strong> Your domain is properly configured for Tailscale ATLogin.
    </div>
    {{end}}

    {{if .Warnings}}
    <div class="status warning">
        <strong>Warnings:</strong>
        <ul>
        {{range .Warnings}}
            <li>{{.}}</li>
        {{end}}
        </ul>
    </div>
    {{end}}

    <div class="section">
        <h2>Verification Checks</h2>
        <div class="check-item">
            <strong>ATProto username:</strong> @{{.ATProtoHandle}}
        </div>
        <div class="check-item {{if .HasDNS}}check-pass{{else}}check-fail{{end}}">
            DNS resolution for {{.Domain}}
        </div>
        <div class="check-item {{if .HasHTTPS}}check-pass{{else}}check-fail{{end}}">
            HTTPS connectivity to {{.Domain}}
        </div>
        <div class="check-item {{if .HasWebFinger}}check-pass{{else}}check-fail{{end}}">
            WebFinger endpoint (/.well-known/webfinger)
        </div>
        {{if .HasWebFinger}}
        <div class="check-item {{if .Issuer}}check-pass{{else}}check-fail{{end}}">
            OIDC issuer link in WebFinger
        </div>
        {{end}}
    </div>

    {{if .WebFinger}}
    <div class="section">
        <h2>WebFinger Response</h2>
        <pre>{{.WebFingerJSON}}</pre>
    </div>
    {{end}}

    {{if .Issuer}}
    <div class="section">
        <h2>Detected OIDC Issuer</h2>
        <p><strong>{{.Issuer}}</strong></p>
    </div>
    {{end}}

    {{if .Errors}}
    <div class="section">
        <h2>How to Fix</h2>

        {{if not .HasDNS}}
        <h3>DNS Setup</h3>
        <p>The domain <strong>{{.Domain}}</strong> does not have a DNS entry. Add an A or CNAME record pointing to your server.</p>
        {{end}}

        {{if not .HasHTTPS}}
        <h3>HTTPS Setup</h3>
        <p>Could not connect to <strong>https://{{.Domain}}</strong>. Make sure:</p>
        <ul>
            <li>Your server is running and accessible on port 443</li>
            <li>You have a valid SSL/TLS certificate</li>
            <li>Firewall rules allow HTTPS traffic</li>
        </ul>
        {{end}}

        {{if not .HasWebFinger}}
        <h3>WebFinger Setup</h3>
        <p><strong>Important:</strong> The WebFinger endpoint must be <strong>dynamically generated</strong> to support all email addresses at your domain. It cannot be a static file.</p>

        <p>Your server needs to handle requests to <code>/.well-known/webfinger</code> and:</p>
        <ol>
            <li>Read the <code>resource</code> query parameter (e.g., <code>?resource=acct:user@{{.Domain}}</code>)</li>
            <li>Return JSON with that resource as the subject</li>
            <li>Include the OIDC issuer link pointing to {{.ExpectedIssuer}}</li>
        </ol>

        <p>Example for <code>{{.Email}}</code>:</p>
        <pre>{
  "subject": "acct:{{.Email}}",
  "links": [
    {
      "rel": "http://openid.net/specs/connect/1.0/issuer",
      "href": "{{.ExpectedIssuer}}"
    }
  ]
}</pre>

        <p><strong>Quick Solution (Recommended):</strong> Use a reverse proxy to forward WebFinger requests to the atlogin server:</p>

        <h4>Nginx Configuration:</h4>
        <pre>location /.well-known/webfinger {
    proxy_pass {{.ExpectedIssuer}}/helpers/webfinger;
    proxy_set_header Host $host;
}</pre>

        <h4>Apache Configuration:</h4>
        <pre>ProxyPass /.well-known/webfinger {{.ExpectedIssuer}}/helpers/webfinger
ProxyPassReverse /.well-known/webfinger {{.ExpectedIssuer}}/helpers/webfinger</pre>

        <h4>Caddy Configuration:</h4>
        <pre>reverse_proxy /.well-known/webfinger {{.ExpectedIssuer}}/helpers/webfinger</pre>

        <p>This forwards all WebFinger requests from <a href="https://{{.Domain}}/.well-known/webfinger?resource=acct:{{.Email}}">https://{{.Domain}}/.well-known/webfinger?resource=...</a> to <a href="{{.ExpectedIssuer}}/helpers/webfinger?resource=acct:{{.Email}}">{{.ExpectedIssuer}}/helpers/webfinger?resource=...</a></p>

        <p>Click these links to test your setup once configured.</p>

        <p>If implementing your own endpoint, serve it with <code>Content-Type: application/jrd+json</code></p>
        {{end}}

        {{if and .HasWebFinger (not .Issuer)}}
        <h3>OIDC Issuer Missing</h3>
        <p>Your WebFinger response is missing the OIDC issuer link. Make sure your WebFinger response includes:</p>
        <pre>{
  "links": [
    {
      "rel": "http://openid.net/specs/connect/1.0/issuer",
      "href": "{{.ExpectedIssuer}}"
    }
  ]
}</pre>
        {{end}}
    </div>
    {{end}}

    <div class="section">
        <form action="/login" method="post" style="display: inline;">
            <input type="hidden" name="email" value="{{.Email}}">
            {{if or .Errors .Warnings}}
            <button type="submit" class="button">Login anyway</button>
            {{else}}
            <button type="submit" class="button">Login</button>
            {{end}}
        </form>
        <a href="/" class="button button-secondary">Start Over</a>
    </div>
</body>
</html>
`))

var resultTemplate = template.Must(template.New("result").Parse(`<!DOCTYPE html>
<html>
<head>
    <title>ATLogin Test Results</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            max-width: 800px;
            margin: 50px auto;
            padding: 20px;
        }
        h1 {
            color: #333;
        }
        .success {
            background-color: #d4edda;
            border: 1px solid #c3e6cb;
            color: #155724;
            padding: 15px;
            border-radius: 4px;
            margin-bottom: 20px;
        }
        .section {
            margin: 20px 0;
        }
        .section h2 {
            color: #555;
            border-bottom: 2px solid #ddd;
            padding-bottom: 5px;
        }
        pre {
            background-color: #f5f5f5;
            border: 1px solid #ddd;
            border-radius: 4px;
            padding: 15px;
            overflow-x: auto;
        }
        .back-link {
            display: inline-block;
            margin-top: 20px;
            padding: 10px 20px;
            background-color: #007bff;
            color: white;
            text-decoration: none;
            border-radius: 4px;
        }
        .back-link:hover {
            background-color: #0056b3;
        }
        .generate-client-btn {
            display: inline-block;
            margin-top: 20px;
            margin-left: 10px;
            padding: 10px 20px;
            background-color: #28a745;
            color: white;
            text-decoration: none;
            border-radius: 4px;
        }
        .generate-client-btn:hover {
            background-color: #218838;
        }
        .client-section {
            margin-top: 30px;
            padding: 20px;
            background-color: #fff3cd;
            border: 1px solid #ffeaa7;
            border-radius: 4px;
        }
        .client-section h2 {
            margin-top: 0;
            color: #856404;
        }
    </style>
</head>
<body>
    <h1>Authentication Successful!</h1>

    <div class="success">
        Successfully authenticated via ATLogin OIDC flow
    </div>

    <div class="section">
        <h2>User Information</h2>
        <pre>{{.UserInfoJSON}}</pre>
    </div>

    <div class="section">
        <h2>ID Token (JWT)</h2>
        <pre>{{.IDToken}}</pre>
    </div>

    <div class="section">
        <h2>Access Token</h2>
        <pre>{{.AccessToken}}</pre>
    </div>

    <div class="section">
        <h2>Token Response</h2>
        <pre>{{.TokenResponseJSON}}</pre>
    </div>

    <div class="client-section">
        <h2>Generate OIDC Client Credentials</h2>
        <p>Now that you've verified your identity, you can generate client credentials for your applications.</p>
        <a href="/generate-client" class="generate-client-btn">Generate Client Credentials</a>
    </div>

    <a href="/" class="back-link">Test Again</a>
</body>
</html>
`))

func (s *Server) serveHome(w http.ResponseWriter, r *http.Request) {
	// Get the host from the request to generate an example email
	host := r.Host
	if host == "" {
		host = "example.com"
	}
	// Strip port if present
	if colonPos := strings.Index(host, ":"); colonPos >= 0 {
		host = host[:colonPos]
	}

	homeTemplate.Execute(w, map[string]any{
		"ExampleEmail": fmt.Sprintf("your-handle@%s", host),
	})
}

// getBaseURL constructs the base URL from the incoming request
func getBaseURL(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
		scheme = "https"
	}
	host := r.Host
	if host == "" {
		host = "localhost:8080"
	}
	return scheme + "://" + host
}

// getIssuerURL returns the issuer URL, using the request's host if the issuer is not explicitly set
func (s *Server) getIssuerURL(r *http.Request) string {
	if s.issuer != "" {
		return s.issuer
	}
	return getBaseURL(r)
}

func (s *Server) serveLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	email := r.FormValue("email")
	if email == "" {
		http.Error(w, "Email is required", http.StatusBadRequest)
		return
	}

	// Get base URL from request
	baseURL := getBaseURL(r)
	redirectURI := baseURL + "/callback"

	// Get issuer URL (use request host if not configured)
	issuerURL := s.getIssuerURL(r)

	// Discover OIDC configuration
	config, err := s.discoverOIDCConfig(r.Context(), issuerURL)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to discover OIDC config: %v", err), http.StatusInternalServerError)
		return
	}

	// Generate state and nonce
	state := randomString(32)
	nonce := randomString(32)

	// Store session
	s.mu.Lock()
	s.sessions[state] = &session{
		state:       state,
		nonce:       nonce,
		email:       email,
		createdAt:   time.Now(),
		redirectURI: redirectURI,
	}
	s.mu.Unlock()

	// Build authorization URL
	authURL, err := url.Parse(config.AuthorizationEndpoint)
	if err != nil {
		http.Error(w, fmt.Sprintf("Invalid authorization endpoint: %v", err), http.StatusInternalServerError)
		return
	}

	q := authURL.Query()
	q.Set("client_id", s.clientID)
	q.Set("response_type", "code")
	q.Set("scope", "openid profile email")
	q.Set("redirect_uri", redirectURI)
	q.Set("state", state)
	q.Set("nonce", nonce)
	q.Set("login_hint", email)
	authURL.RawQuery = q.Encode()

	http.Redirect(w, r, authURL.String(), http.StatusFound)
}

func (s *Server) serveCallback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Check for errors
	if errMsg := r.URL.Query().Get("error"); errMsg != "" {
		errDesc := r.URL.Query().Get("error_description")
		http.Error(w, fmt.Sprintf("Authentication error: %s - %s", errMsg, errDesc), http.StatusBadRequest)
		return
	}

	// Get state and code
	state := r.URL.Query().Get("state")
	code := r.URL.Query().Get("code")

	if state == "" || code == "" {
		http.Error(w, "Missing state or code parameter", http.StatusBadRequest)
		return
	}

	// Verify state and get session
	s.mu.Lock()
	sess, ok := s.sessions[state]
	if ok {
		delete(s.sessions, state)
	}
	s.mu.Unlock()

	if !ok {
		http.Error(w, "Invalid state parameter", http.StatusBadRequest)
		return
	}

	// Check session age (10 minutes max)
	if time.Since(sess.createdAt) > 10*time.Minute {
		http.Error(w, "Session expired", http.StatusBadRequest)
		return
	}

	// Get issuer URL (use request host if not configured)
	issuerURL := s.getIssuerURL(r)

	// Discover OIDC configuration
	config, err := s.discoverOIDCConfig(ctx, issuerURL)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to discover OIDC config: %v", err), http.StatusInternalServerError)
		return
	}

	// Exchange code for tokens
	tokenResp, err := s.exchangeCode(ctx, config.TokenEndpoint, code, sess.redirectURI)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to exchange code: %v", err), http.StatusInternalServerError)
		return
	}

	// Get user info
	userInfo, err := s.getUserInfo(ctx, config.UserinfoEndpoint, tokenResp.AccessToken)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to get user info: %v", err), http.StatusInternalServerError)
		return
	}

	// Create authenticated session for client generation
	if err = s.createAuthSession(ctx, issuerURL, tokenResp.AccessToken, w); err != nil {
		// Log but don't fail - user can still see their auth result
		// They just won't be able to generate clients without re-authenticating
		fmt.Fprintf(w, "<!-- Warning: Failed to create session: %v -->\n", err)
	}

	// Pretty-print JSON
	userInfoJSON, _ := json.MarshalIndent(userInfo, "", "  ")
	tokenRespJSON, _ := json.MarshalIndent(tokenResp, "", "  ")

	// Display results
	resultTemplate.Execute(w, map[string]any{
		"UserInfoJSON":      string(userInfoJSON),
		"IDToken":           tokenResp.IDToken,
		"AccessToken":       tokenResp.AccessToken,
		"TokenResponseJSON": string(tokenRespJSON),
	})
}

func (s *Server) discoverOIDCConfig(ctx context.Context, issuerURL string) (*oidcConfig, error) {
	configURL := strings.TrimSuffix(issuerURL, "/") + "/.well-known/openid-configuration"

	req, err := http.NewRequestWithContext(ctx, "GET", configURL, nil)
	if err != nil {
		return nil, err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, body)
	}

	var config oidcConfig
	if err := json.NewDecoder(resp.Body).Decode(&config); err != nil {
		return nil, err
	}

	return &config, nil
}

func (s *Server) exchangeCode(ctx context.Context, tokenEndpoint, code, redirectURI string) (*tokenResponse, error) {
	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", code)
	data.Set("redirect_uri", redirectURI)
	data.Set("client_id", s.clientID)
	data.Set("client_secret", s.clientSecret)

	req, err := http.NewRequestWithContext(ctx, "POST", tokenEndpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, body)
	}

	var tokenResp tokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, err
	}

	return &tokenResp, nil
}

func (s *Server) getUserInfo(ctx context.Context, userinfoEndpoint, accessToken string) (*userInfo, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", userinfoEndpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, body)
	}

	var info userInfo
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return nil, err
	}

	return &info, nil
}

func (s *Server) serveVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	email := r.FormValue("email")
	if email == "" {
		http.Error(w, "Email is required", http.StatusBadRequest)
		return
	}

	// Parse email to get ATProto handle and webfinger domain
	atprotoHandle, domain, err := parseLoginHint(email)
	if err != nil {
		http.Error(w, fmt.Sprintf("Invalid email format: %v", err), http.StatusBadRequest)
		return
	}

	// Get issuer URL (use request host if not configured)
	issuerURL := s.getIssuerURL(r)

	// Verify the domain
	result := s.verifyDomain(r.Context(), domain, email, atprotoHandle, issuerURL)

	// Pretty-print WebFinger JSON
	var webFingerJSON string
	if result.WebFinger != nil {
		data, _ := json.MarshalIndent(result.WebFinger, "", "  ")
		webFingerJSON = string(data)
	}

	// Render verification result
	verifyTemplate.Execute(w, map[string]any{
		"Domain":         result.Domain,
		"Email":          result.Email,
		"ATProtoHandle":  result.ATProtoHandle,
		"HasDNS":         result.HasDNS,
		"HasHTTPS":       result.HasHTTPS,
		"HasWebFinger":   result.HasWebFinger,
		"WebFinger":      result.WebFinger,
		"WebFingerJSON":  webFingerJSON,
		"Issuer":         result.Issuer,
		"ExpectedIssuer": result.ExpectedIssuer,
		"Errors":         result.Errors,
		"Warnings":       result.Warnings,
	})
}

func (s *Server) verifyDomain(ctx context.Context, domain, email, atprotoHandle, issuerURL string) *verificationResult {
	result := &verificationResult{
		Domain:         domain,
		Email:          email,
		ATProtoHandle:  atprotoHandle,
		ExpectedIssuer: issuerURL,
	}

	// Validate that ATProto handle contains a dot (unless it's the special at.apenwarr.ca/atlogin.net case)
	if !strings.Contains(atprotoHandle, ".") {
		result.Errors = append(result.Errors, "ATProto accounts must contain a dot")
		return result
	}

	// Check DNS resolution
	addrs, err := net.LookupHost(domain)
	if err != nil || len(addrs) == 0 {
		result.Errors = append(result.Errors, "DNS lookup failed: domain does not resolve")
		return result
	}
	result.HasDNS = true

	// Check HTTPS connectivity and WebFinger
	webfingerURL := fmt.Sprintf("https://%s/.well-known/webfinger?resource=acct:%s", domain, url.QueryEscape(email))

	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}

	req, err := http.NewRequestWithContext(ctx, "GET", webfingerURL, nil)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("Failed to create request: %v", err))
		return result
	}

	resp, err := client.Do(req)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("HTTPS connection failed: %v", err))
		return result
	}
	defer resp.Body.Close()

	result.HasHTTPS = true

	if resp.StatusCode != http.StatusOK {
		result.Errors = append(result.Errors, fmt.Sprintf("WebFinger endpoint returned status %d", resp.StatusCode))
		return result
	}

	// Parse WebFinger response
	var wf webFingerResponse
	if err := json.NewDecoder(resp.Body).Decode(&wf); err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("Failed to parse WebFinger response: %v", err))
		return result
	}

	result.HasWebFinger = true
	result.WebFinger = &wf

	// Look for OIDC issuer link
	for _, link := range wf.Links {
		if link.Rel == "http://openid.net/specs/connect/1.0/issuer" {
			result.Issuer = link.Href
			break
		}
	}

	if result.Issuer == "" {
		result.Errors = append(result.Errors, "WebFinger response is missing OIDC issuer link")
	} else if result.Issuer != result.ExpectedIssuer {
		result.Warnings = append(result.Warnings, fmt.Sprintf("OIDC issuer (%s) differs from expected issuer (%s)", result.Issuer, result.ExpectedIssuer))
	}

	return result
}

func (s *Server) createAuthSession(ctx context.Context, issuerURL, accessToken string, w http.ResponseWriter) error {
	sessionURL := strings.TrimSuffix(issuerURL, "/") + "/create-session"

	req, err := http.NewRequestWithContext(ctx, "POST", sessionURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("unexpected status %d: %s", resp.StatusCode, body)
	}

	// Copy session cookies from the response to the client
	for _, cookie := range resp.Cookies() {
		http.SetCookie(w, cookie)
	}

	return nil
}

func randomString(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}
