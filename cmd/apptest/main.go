// Command apptest is a simple web application for testing the ATLogin OIDC flow.
// It prompts the user for their email address, initiates the OIDC flow with ATLogin,
// and displays the resulting OIDC information after successful authentication.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

var (
	flagClientID     = flag.String("client-id", "", "OIDC client ID (required)")
	flagClientSecret = flag.String("client-secret", "", "OIDC client secret (required)")
	flagIssuer       = flag.String("issuer", "https://at.apenwarr.ca", "OIDC issuer URL")
	flagAddr         = flag.String("addr", ":8080", "address to listen on")
)

type server struct {
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

func main() {
	flag.Parse()

	if *flagClientID == "" {
		log.Fatal("--client-id is required")
	}
	if *flagClientSecret == "" {
		log.Fatal("--client-secret is required")
	}

	srv := &server{
		clientID:     *flagClientID,
		clientSecret: *flagClientSecret,
		issuer:       *flagIssuer,
		sessions:     make(map[string]*session),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/{$}", srv.serveHome)
	mux.HandleFunc("/login", srv.serveLogin)
	mux.HandleFunc("/callback", srv.serveCallback)

	log.Printf("Starting test app at %s", *flagAddr)
	log.Printf("Visit http://localhost%s to test the flow", *flagAddr)
	log.Fatal(http.ListenAndServe(*flagAddr, mux))
}

var homeTemplate = template.Must(template.New("home").Parse(`<!DOCTYPE html>
<html>
<head>
    <title>ATLogin Test App</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            max-width: 600px;
            margin: 50px auto;
            padding: 20px;
        }
        h1 {
            color: #333;
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
    </style>
</head>
<body>
    <h1>ATLogin Test App</h1>
    <p>Enter your desired email address to test the ATLogin OIDC flow.</p>

    <form action="/login" method="post">
        <label for="email">Email Address:</label>
        <input type="email" id="email" name="email" required
               placeholder="apenwarr.ca@at.apenwarr.ca">
        <div class="help">Format: handle@domain (e.g., apenwarr.ca@at.apenwarr.ca)</div>
        <button type="submit">Log In with ATLogin</button>
    </form>
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

    <a href="/" class="back-link">Test Again</a>
</body>
</html>
`))

func (s *server) serveHome(w http.ResponseWriter, r *http.Request) {
	homeTemplate.Execute(w, nil)
}

// getBaseURL constructs the base URL from the incoming request
func getBaseURL(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
		scheme = "https"
	}
	host := r.Host
	if host == "" {
		host = "localhost" + *flagAddr
	}
	return scheme + "://" + host
}

func (s *server) serveLogin(w http.ResponseWriter, r *http.Request) {
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

	// Discover OIDC configuration
	config, err := s.discoverOIDCConfig(r.Context())
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

func (s *server) serveCallback(w http.ResponseWriter, r *http.Request) {
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

	// Discover OIDC configuration
	config, err := s.discoverOIDCConfig(ctx)
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

func (s *server) discoverOIDCConfig(ctx context.Context) (*oidcConfig, error) {
	configURL := strings.TrimSuffix(s.issuer, "/") + "/.well-known/openid-configuration"

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

func (s *server) exchangeCode(ctx context.Context, tokenEndpoint, code, redirectURI string) (*tokenResponse, error) {
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

func (s *server) getUserInfo(ctx context.Context, userinfoEndpoint, accessToken string) (*userInfo, error) {
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

func randomString(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}
