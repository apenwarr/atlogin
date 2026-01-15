// Command atlogin is an OIDC Identity Provider that uses ATProto OAuth for authentication.
// Users authenticate using their ATProto handle with any domain (e.g., hello.example.com@any.domain),
// which initiates an OAuth flow with their PDS (Personal Data Server).
// The provider accepts any domain and authenticates the ATProto handle, returning the full email as provided.
package main

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"atlogin/testapp"
	"github.com/bluesky-social/indigo/atproto/auth/oauth"
	"github.com/bluesky-social/indigo/atproto/syntax"
	"github.com/tailscale/hujson"
	"gopkg.in/go-jose/go-jose.v2"
	"gopkg.in/go-jose/go-jose.v2/jwt"
)

var (
	flagStateDir  = flag.String("state-dir", "./state", "state directory")
	flagNewClient = flag.String("new-client", "", "add a new client ID and generate a secret for it")
	flagInit      = flag.Bool("init", false, "initialize state directory and all key files, then exit")
)

// Removed hardcoded user constants - now using ATProto OAuth for authentication

// Config represents the configuration file structure.
type Config struct {
	Addr       string            `json:"addr,omitempty"`
	Issuer     string            `json:"issuer,omitempty"`
	ClientName string            `json:"client_name,omitempty"`
	MasterKey  string            `json:"master_key,omitempty"`
	Secrets    map[string]string `json:"secrets"`
}

func main() {
	flag.Parse()

	stateDir := *flagStateDir

	if err := os.MkdirAll(stateDir, 0700); err != nil {
		log.Fatalf("cannot create state directory: %v", err)
	}

	configPath := filepath.Join(stateDir, "config.json")
	keyFile := filepath.Join(stateDir, "signing-key.json")

	// Write files from environment variables if set (for fly.io secrets)
	if err := writeFromEnv("ATLOGIN_CONFIG", configPath); err != nil {
		log.Fatalf("cannot write config from ATLOGIN_CONFIG: %v", err)
	}
	if err := writeFromEnv("ATLOGIN_SIGNING_KEY", keyFile); err != nil {
		log.Fatalf("cannot write signing key from ATLOGIN_SIGNING_KEY: %v", err)
	}

	// Handle -new-client flag
	if *flagNewClient != "" {
		if err := addNewClient(configPath, *flagNewClient); err != nil {
			log.Fatal(err)
		}
		return
	}

	// Always ensure signing key exists
	if err := ensureSigningKey(keyFile); err != nil {
		log.Fatalf("cannot initialize signing key: %v", err)
	}

	// Handle -init flag
	if *flagInit {
		// Ensure config file exists with empty secrets
		if err := ensureConfig(configPath); err != nil {
			log.Fatalf("cannot initialize config: %v", err)
		}
		log.Printf("Initialized state directory: %s", stateDir)
		return
	}

	config, err := loadConfig(configPath)
	if err != nil {
		log.Fatal(err)
	}

	// Ensure master_key exists, generate if empty
	if config.MasterKey == "" {
		config.MasterKey = randomHex(32)
		if err := saveConfig(configPath, config); err != nil {
			log.Fatalf("cannot save config with generated master_key: %v", err)
		}
		log.Printf("Generated and saved master_key to config")
	}

	if len(config.Secrets) == 0 {
		log.Fatal("config must have at least one client in secrets")
	}

	addr := config.Addr
	if addr == "" {
		addr = ":9411"
	}

	// issuer can be empty - it will be dynamically set from the Host header
	issuer := config.Issuer

	clientName := config.ClientName
	if clientName == "" {
		clientName = "ATLogin"
	}

	// Initialize custom auth store for ATProto OAuth
	store := newCustomAuthStore()

	srv := &idpServer{
		issuer:       issuer,
		clientName:   clientName,
		secrets:      config.Secrets,
		masterKey:    config.MasterKey,
		configPath:   configPath,
		keyFile:      keyFile,
		store:        store,
		codes:        make(map[string]*authRequest),
		accessTokens: make(map[string]*authRequest),
		oauthClients: make(map[string]*oauth.ClientApp),
	}

	// Create test app with the first client credentials from the config
	var testAppClientID, testAppClientSecret string
	for clientID, secret := range config.Secrets {
		testAppClientID = clientID
		testAppClientSecret = secret
		break
	}
	testApp := testapp.NewServer(testAppClientID, testAppClientSecret, "")

	mux := http.NewServeMux()

	// Register test app handlers (includes root handler)
	testApp.RegisterHandlers(mux)

	// Register IDP handlers
	mux.HandleFunc("/.well-known/webfinger", srv.serveWebFinger)
	mux.HandleFunc("/helpers/webfinger", srv.serveWebFinger) // Stable helper endpoint for reverse proxying
	mux.HandleFunc("/.well-known/openid-configuration", srv.serveOpenIDConfig)
	mux.HandleFunc("/.well-known/jwks.json", srv.serveJWKS)
	mux.HandleFunc("/authorize", srv.serveAuthorize)
	mux.HandleFunc("/token", srv.serveToken)
	mux.HandleFunc("/userinfo", srv.serveUserInfo)
	mux.HandleFunc("/atproto/callback", srv.serveATProtoCallback)
	mux.HandleFunc("/client-metadata.json", srv.serveClientMetadata)
	mux.HandleFunc("/create-session", srv.serveCreateSession)
	mux.HandleFunc("/generate-client", srv.serveGenerateClient)

	log.Printf("Starting OIDC server at %s (issuer: %s)", addr, issuer)
	log.Fatal(http.ListenAndServe(addr, mux))
}

func loadConfig(configPath string) (*Config, error) {
	configData, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("cannot read config file %s: %v", configPath, err)
	}

	// Parse hujson (JSON with comments and trailing commas)
	configData, err = hujson.Standardize(configData)
	if err != nil {
		return nil, fmt.Errorf("cannot parse config file %s: %v", configPath, err)
	}

	var config Config
	if err := json.Unmarshal(configData, &config); err != nil {
		return nil, fmt.Errorf("cannot parse config file %s: %v", configPath, err)
	}

	return &config, nil
}

func saveConfig(configPath string, config *Config) error {
	data, err := json.MarshalIndent(config, "", "\t")
	if err != nil {
		return fmt.Errorf("cannot marshal config: %v", err)
	}
	data = append(data, '\n')

	tmpFile := configPath + ".tmp"
	if err := os.WriteFile(tmpFile, data, 0600); err != nil {
		return fmt.Errorf("cannot write temp config file: %v", err)
	}
	if err := os.Rename(tmpFile, configPath); err != nil {
		os.Remove(tmpFile)
		return fmt.Errorf("cannot rename config file: %v", err)
	}
	return nil
}

func ensureConfig(configPath string) error {
	if _, err := os.Stat(configPath); err == nil {
		return nil // already exists
	}
	config := &Config{Secrets: make(map[string]string)}
	data, err := json.MarshalIndent(config, "", "\t")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return os.WriteFile(configPath, data, 0600)
}

// writeFromEnv writes the base64-decoded contents of an environment variable to a file.
// If the environment variable is not set, it does nothing.
func writeFromEnv(envVar, filePath string) error {
	value := os.Getenv(envVar)
	if value == "" {
		return nil
	}
	data, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return fmt.Errorf("invalid base64 in %s: %v", envVar, err)
	}
	return os.WriteFile(filePath, data, 0600)
}

func ensureSigningKey(keyFile string) error {
	if _, err := os.Stat(keyFile); err == nil {
		return nil // already exists
	}
	kid, k, err := genRSAKey(2048)
	if err != nil {
		return err
	}
	sk := &signingKey{k: k, kid: kid}
	data, err := sk.MarshalJSON()
	if err != nil {
		return err
	}
	return os.WriteFile(keyFile, data, 0600)
}

func addNewClient(configPath, clientID string) error {
	config, err := loadConfig(configPath)
	if err != nil {
		return err
	}

	if config.Secrets == nil {
		config.Secrets = make(map[string]string)
	}

	if _, exists := config.Secrets[clientID]; exists {
		return fmt.Errorf("client %q already exists", clientID)
	}

	secret := randomHex(32)
	config.Secrets[clientID] = secret

	// Write config atomically
	data, err := json.MarshalIndent(config, "", "\t")
	if err != nil {
		return fmt.Errorf("cannot marshal config: %v", err)
	}
	data = append(data, '\n')

	tmpFile := configPath + ".tmp"
	if err := os.WriteFile(tmpFile, data, 0600); err != nil {
		return fmt.Errorf("cannot write temp config file: %v", err)
	}
	if err := os.Rename(tmpFile, configPath); err != nil {
		os.Remove(tmpFile)
		return fmt.Errorf("cannot rename config file: %v", err)
	}

	// Print secret to stdout (only non-stderr output)
	fmt.Println(secret)
	return nil
}

type idpServer struct {
	issuer     string
	clientName string
	secrets    map[string]string // clientID -> clientSecret
	masterKey  string
	configPath string
	keyFile    string
	store      *customAuthStore

	mu           sync.Mutex
	signingKey   *signingKey
	codes        map[string]*authRequest
	accessTokens map[string]*authRequest
	oauthClients map[string]*oauth.ClientApp // issuerURL -> OAuth client (cached per host)
}

type authRequest struct {
	clientID     string
	nonce        string
	redirectURI  string
	validTill    time.Time
	atprotoState string // ATProto OAuth state parameter
}

type atprotoSession struct {
	handle      string
	did         string
	email       string
	domain      string // Original domain from login_hint (e.g., "any.domain")
	clientID    string
	redirectURI string
	nonce       string
	oidcState   string // Original OIDC state parameter from Tailscale
	createdAt   time.Time
}

// getIssuerURL returns the issuer URL, using the request's Host header if not configured
func (s *idpServer) getIssuerURL(r *http.Request) string {
	if s.issuer != "" {
		return s.issuer
	}
	// Dynamically construct from the request
	scheme := "https"
	if r.TLS == nil && r.Header.Get("X-Forwarded-Proto") != "https" {
		scheme = "http"
	}
	host := r.Host
	if host == "" {
		host = "localhost:9411"
	}
	return scheme + "://" + host
}

// getOrCreateOAuthClient returns an OAuth client for the given issuer URL,
// creating it if it doesn't exist yet. This allows dynamic OAuth client
// creation based on the request's Host header.
func (s *idpServer) getOAuthClient(issuerURL string) *oauth.ClientApp {
	s.mu.Lock()
	defer s.mu.Unlock()

	if client, ok := s.oauthClients[issuerURL]; ok {
		return client
	}

	// Create a new OAuth client for this issuer
	oauthConfig := oauth.NewPublicConfig(
		issuerURL+"/client-metadata.json",
		issuerURL+"/atproto/callback",
		[]string{"atproto"},
	)
	oauthApp := oauth.NewClientApp(&oauthConfig, s.store)
	s.oauthClients[issuerURL] = oauthApp
	log.Printf("Created ATProto OAuth client for issuer: %s", issuerURL)
	return oauthApp
}

type verifiedUser struct {
	did        string
	handle     string
	email      string
	verifiedAt time.Time
}

// customAuthStore implements oauth.ClientAuthStore with custom OIDC session tracking
type customAuthStore struct {
	mu       sync.Mutex
	sessions map[string]*oauth.ClientSessionData
	requests map[string]*oauth.AuthRequestData
	// Map ATProto state to OIDC session info
	oidcSessions map[string]*atprotoSession
	// Track verified users for client generation (DID -> user info)
	verifiedUsers map[string]*verifiedUser
	// Map session ID (from cookie) to user DID for authentication
	sessionIDToUser map[string]string // sessionID -> DID
	// Track the most recently created state for linking
	lastState string
}

func newCustomAuthStore() *customAuthStore {
	return &customAuthStore{
		sessions:        make(map[string]*oauth.ClientSessionData),
		requests:        make(map[string]*oauth.AuthRequestData),
		oidcSessions:    make(map[string]*atprotoSession),
		verifiedUsers:   make(map[string]*verifiedUser),
		sessionIDToUser: make(map[string]string),
	}
}

func (s *customAuthStore) GetSession(ctx context.Context, did syntax.DID, sessionID string) (*oauth.ClientSessionData, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := fmt.Sprintf("%s:%s", did, sessionID)
	sess, ok := s.sessions[key]
	if !ok {
		return nil, fmt.Errorf("session not found")
	}
	return sess, nil
}

func (s *customAuthStore) SaveSession(ctx context.Context, sess oauth.ClientSessionData) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := fmt.Sprintf("%s:%s", sess.AccountDID, sess.SessionID)
	s.sessions[key] = &sess
	return nil
}

func (s *customAuthStore) DeleteSession(ctx context.Context, did syntax.DID, sessionID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := fmt.Sprintf("%s:%s", did, sessionID)
	delete(s.sessions, key)
	return nil
}

func (s *customAuthStore) GetAuthRequestInfo(ctx context.Context, state string) (*oauth.AuthRequestData, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	req, ok := s.requests[state]
	if !ok {
		return nil, fmt.Errorf("auth request not found")
	}
	return req, nil
}

func (s *customAuthStore) SaveAuthRequestInfo(ctx context.Context, info oauth.AuthRequestData) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.requests[info.State] = &info
	s.lastState = info.State // Track the most recent state
	return nil
}

func (s *customAuthStore) DeleteAuthRequestInfo(ctx context.Context, state string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.requests, state)
	return nil
}

func (s *idpServer) getSigningKey() (*signingKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.signingKey != nil {
		return s.signingKey, nil
	}

	// Try to load from file
	if data, err := os.ReadFile(s.keyFile); err == nil {
		var sk signingKey
		if err := sk.UnmarshalJSON(data); err == nil {
			s.signingKey = &sk
			return s.signingKey, nil
		}
		log.Printf("Error unmarshaling key: %v, generating new one", err)
	}

	// Generate new key
	kid, k, err := genRSAKey(2048)
	if err != nil {
		return nil, err
	}
	sk := &signingKey{k: k, kid: kid}

	// Save to file
	data, err := sk.MarshalJSON()
	if err != nil {
		return nil, err
	}
	dir := filepath.Dir(s.keyFile)
	if dir != "" && dir != "." {
		os.MkdirAll(dir, 0700)
	}
	if err := os.WriteFile(s.keyFile, data, 0600); err != nil {
		log.Printf("Warning: could not save key file: %v", err)
	}

	s.signingKey = sk
	return s.signingKey, nil
}

func (s *idpServer) getSigner() (jose.Signer, error) {
	sk, err := s.getSigningKey()
	if err != nil {
		return nil, err
	}
	return jose.NewSigner(jose.SigningKey{
		Algorithm: jose.RS256,
		Key:       sk.k,
	}, &jose.SignerOptions{
		ExtraHeaders: map[jose.HeaderKey]any{
			jose.HeaderType: "JWT",
			"kid":           fmt.Sprint(sk.kid),
		},
	})
}

func (s *idpServer) serveWebFinger(w http.ResponseWriter, r *http.Request) {
	resource := r.URL.Query().Get("resource")
	if resource == "" {
		http.Error(w, "missing resource parameter", http.StatusBadRequest)
		return
	}

	issuerURL := s.getIssuerURL(r)

	w.Header().Set("Content-Type", "application/jrd+json")
	json.NewEncoder(w).Encode(map[string]any{
		"subject": resource,
		"links": []map[string]string{
			{
				"rel":  "http://openid.net/specs/connect/1.0/issuer",
				"href": issuerURL,
			},
		},
	})
}

func (s *idpServer) serveOpenIDConfig(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	if r.Method == "OPTIONS" {
		return
	}

	issuerURL := s.getIssuerURL(r)

	json.NewEncoder(w).Encode(map[string]any{
		"issuer":                                issuerURL,
		"authorization_endpoint":                issuerURL + "/authorize",
		"token_endpoint":                        issuerURL + "/token",
		"userinfo_endpoint":                     issuerURL + "/userinfo",
		"jwks_uri":                              issuerURL + "/.well-known/jwks.json",
		"scopes_supported":                      []string{"openid", "profile", "email"},
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"claims_supported":                      []string{"sub", "aud", "exp", "iat", "iss", "name", "email"},
	})
}

func (s *idpServer) serveJWKS(w http.ResponseWriter, r *http.Request) {
	sk, err := s.getSigningKey()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{
			{
				Key:       sk.k.Public(),
				Algorithm: string(jose.RS256),
				Use:       "sig",
				KeyID:     fmt.Sprint(sk.kid),
			},
		},
	})
}

func (s *idpServer) serveAuthorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	clientID := q.Get("client_id")
	if _, ok := s.secrets[clientID]; !ok {
		http.Error(w, "invalid client_id", http.StatusBadRequest)
		return
	}

	redirectURI := q.Get("redirect_uri")
	if redirectURI == "" {
		http.Error(w, "missing redirect_uri", http.StatusBadRequest)
		return
	}

	// Extract ATProto handle and domain from login_hint parameter
	// Expected format: hello.example.com@any.domain
	loginHint := q.Get("login_hint")
	if loginHint == "" {
		http.Error(w, "missing login_hint parameter (expected format: handle@domain)", http.StatusBadRequest)
		return
	}

	// Parse the login hint to extract the ATProto handle and domain
	handle, domain, err := parseLoginHint(loginHint)
	if err != nil {
		http.Error(w, fmt.Sprintf("invalid login_hint format: %v", err), http.StatusBadRequest)
		return
	}

	// Get issuer URL from request Host header
	issuerURL := s.getIssuerURL(r)

	// Get or create OAuth client for this issuer
	oauthApp := s.getOAuthClient(issuerURL)

	// Start the ATProto OAuth flow
	ctx := r.Context()
	log.Printf("Starting ATProto OAuth flow for handle: %q (from login_hint: %q, domain: %q, issuer: %q)", handle, loginHint, domain, issuerURL)
	atprotoRedirectURL, err := oauthApp.StartAuthFlow(ctx, handle)
	if err != nil {
		log.Printf("ATProto OAuth flow failed for handle %q: %v", handle, err)
		http.Error(w, fmt.Sprintf("failed to start ATProto OAuth flow for handle @%s: %v\n\nThis usually means the ATProto account doesn't exist or isn't resolvable. Make sure the account exists on the ATProto network (e.g., Bluesky).", handle, err), http.StatusBadRequest)
		return
	}

	// Get the state that was just saved by StartAuthFlow
	// The library calls SaveAuthRequestInfo internally, and we track the state there
	s.store.mu.Lock()
	atprotoState := s.store.lastState
	if atprotoState == "" {
		s.store.mu.Unlock()
		http.Error(w, "failed to get ATProto OAuth state", http.StatusInternalServerError)
		return
	}

	// Store the OIDC request info mapped to the ATProto state
	s.store.oidcSessions[atprotoState] = &atprotoSession{
		handle:      handle,
		domain:      domain, // Store the original domain from login_hint
		clientID:    clientID,
		redirectURI: redirectURI,
		nonce:       q.Get("nonce"),
		oidcState:   q.Get("state"), // Preserve the original OIDC state parameter
		createdAt:   time.Now(),
	}
	s.store.mu.Unlock()

	// Redirect the user to the ATProto OAuth authorization endpoint
	http.Redirect(w, r, atprotoRedirectURL, http.StatusFound)
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

func (s *idpServer) serveToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Validate client credentials
	clientID, clientSecret, ok := r.BasicAuth()
	if !ok {
		clientID = r.FormValue("client_id")
		clientSecret = r.FormValue("client_secret")
	}
	expectedSecret, ok := s.secrets[clientID]
	if !ok || clientSecret != expectedSecret {
		http.Error(w, "invalid client credentials", http.StatusUnauthorized)
		return
	}

	if r.FormValue("grant_type") != "authorization_code" {
		http.Error(w, "unsupported grant_type", http.StatusBadRequest)
		return
	}

	code := r.FormValue("code")
	s.mu.Lock()
	ar, ok := s.codes[code]
	if ok {
		delete(s.codes, code)
	}
	s.mu.Unlock()

	if !ok {
		http.Error(w, "invalid code", http.StatusBadRequest)
		return
	}

	if ar.clientID != clientID {
		http.Error(w, "client_id mismatch", http.StatusBadRequest)
		return
	}

	if ar.redirectURI != r.FormValue("redirect_uri") {
		http.Error(w, "redirect_uri mismatch", http.StatusBadRequest)
		return
	}

	signer, err := s.getSigner()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Get user info from ATProto session
	s.store.mu.Lock()
	var sess *atprotoSession
	if ar.atprotoState != "" {
		sess = s.store.oidcSessions[ar.atprotoState]
	}
	s.store.mu.Unlock()

	issuerURL := s.getIssuerURL(r)

	// Default values if no ATProto session
	userSub := "unknown"
	userName := "Unknown User"
	// Construct a default email using the request host
	host := r.Host
	if host == "" {
		host = "localhost"
	}
	// Strip port if present
	if colonPos := strings.Index(host, ":"); colonPos >= 0 {
		host = host[:colonPos]
	}
	userEmail := "unknown@" + host

	if sess != nil {
		userSub = sess.did
		userName = sess.handle
		userEmail = sess.email
	}

	now := time.Now()
	claims := map[string]any{
		"iss":   issuerURL,
		"sub":   userSub,
		"aud":   clientID,
		"exp":   now.Add(time.Hour).Unix(),
		"iat":   now.Unix(),
		"name":  userName,
		"email": userEmail,
	}
	if ar.nonce != "" {
		claims["nonce"] = ar.nonce
	}

	token, err := jwt.Signed(signer).Claims(claims).CompactSerialize()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	accessToken := randomHex(32)
	s.mu.Lock()
	s.accessTokens[accessToken] = &authRequest{
		validTill:    now.Add(time.Hour),
		atprotoState: ar.atprotoState,
	}
	s.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"access_token": accessToken,
		"token_type":   "Bearer",
		"expires_in":   3600,
		"id_token":     token,
	})
}

func (s *idpServer) serveUserInfo(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if len(auth) < 8 || auth[:7] != "Bearer " {
		http.Error(w, "invalid authorization header", http.StatusUnauthorized)
		return
	}
	token := auth[7:]

	s.mu.Lock()
	ar, ok := s.accessTokens[token]
	s.mu.Unlock()

	if !ok || ar.validTill.Before(time.Now()) {
		http.Error(w, "invalid or expired token", http.StatusUnauthorized)
		return
	}

	// Find the ATProto session associated with this token
	s.store.mu.Lock()
	var sess *atprotoSession
	if ar.atprotoState != "" {
		sess = s.store.oidcSessions[ar.atprotoState]
	}
	s.store.mu.Unlock()

	// If no ATProto session, return default values (for backwards compatibility)
	if sess == nil {
		// Construct a default email using the request host
		host := r.Host
		if host == "" {
			host = "localhost"
		}
		// Strip port if present
		if colonPos := strings.Index(host, ":"); colonPos >= 0 {
			host = host[:colonPos]
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"sub":   "unknown",
			"name":  "Unknown User",
			"email": "unknown@" + host,
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"sub":   sess.did,
		"name":  sess.handle,
		"email": sess.email,
	})
}

// resolveHandleToDID resolves an ATProto handle to its DID by querying the handle's identity
func resolveHandleToDID(ctx context.Context, handle string) (string, error) {
	// ATProto handle resolution: query com.atproto.identity.resolveHandle
	// We need to find the PDS for this handle first, or use a public resolver

	// Use the public bsky API endpoint for handle resolution
	resolveURL := fmt.Sprintf("https://public.api.bsky.app/xrpc/com.atproto.identity.resolveHandle?handle=%s", url.QueryEscape(handle))

	req, err := http.NewRequestWithContext(ctx, "GET", resolveURL, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create resolve request: %w", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to resolve handle: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("handle resolution failed with status %d", resp.StatusCode)
	}

	var result struct {
		DID string `json:"did"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("failed to decode resolution response: %w", err)
	}

	if result.DID == "" {
		return "", fmt.Errorf("no DID returned for handle %s", handle)
	}

	return result.DID, nil
}

func (s *idpServer) serveClientMetadata(w http.ResponseWriter, r *http.Request) {
	// Get issuer URL from request Host header
	issuerURL := s.getIssuerURL(r)

	// Get or create OAuth client for this issuer
	oauthApp := s.getOAuthClient(issuerURL)

	// Generate the OAuth client metadata document for ATProto OAuth
	metadata := oauthApp.Config.ClientMetadata()

	// Convert to map to add custom fields
	var metadataMap map[string]any
	data, err := json.Marshal(metadata)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := json.Unmarshal(data, &metadataMap); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Add custom client_name and client_uri
	metadataMap["client_name"] = s.clientName
	metadataMap["client_uri"] = issuerURL

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Cache-Control", "public, max-age=3600")

	if err := json.NewEncoder(w).Encode(metadataMap); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func (s *idpServer) serveATProtoCallback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// The ATProto OAuth library's state parameter is passed in the query
	// We need to extract it to find our corresponding OIDC session
	atprotoState := r.URL.Query().Get("state")
	if atprotoState == "" {
		http.Error(w, "missing state parameter", http.StatusBadRequest)
		return
	}

	// Find the corresponding OIDC session BEFORE processing callback
	s.store.mu.Lock()
	matchedSession, ok := s.store.oidcSessions[atprotoState]
	s.store.mu.Unlock()

	if !ok {
		http.Error(w, "no matching OIDC session found - session may have expired", http.StatusBadRequest)
		return
	}

	// Get issuer URL from request Host header
	issuerURL := s.getIssuerURL(r)

	// Get or create OAuth client for this issuer
	oauthApp := s.getOAuthClient(issuerURL)

	// Process the OAuth callback
	sessData, err := oauthApp.ProcessCallback(ctx, r.URL.Query())
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to process ATProto callback: %v", err), http.StatusInternalServerError)
		return
	}

	// SECURITY: Verify that the authenticated DID matches the handle we initiated the flow with
	// Resolve the handle to DID and compare
	authenticatedDID := string(sessData.AccountDID)
	expectedDID, err := resolveHandleToDID(ctx, matchedSession.handle)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to verify handle ownership: %v", err), http.StatusForbidden)
		return
	}
	if authenticatedDID != expectedDID {
		http.Error(w, fmt.Sprintf("security error: authenticated as %s but expected %s for handle %s",
			authenticatedDID, expectedDID, matchedSession.handle), http.StatusForbidden)
		return
	}

	// Update the session with the authenticated user's information
	s.store.mu.Lock()
	matchedSession.did = authenticatedDID

	// Construct email to match the original login_hint format
	// User logged in as "handle@domain", so we return "handle@domain"
	if matchedSession.email == "" {
		matchedSession.email = matchedSession.handle + "@" + matchedSession.domain
	}

	// Store the verified session for client generation (use DID as key)
	s.store.verifiedUsers[authenticatedDID] = &verifiedUser{
		did:       authenticatedDID,
		handle:    matchedSession.handle,
		email:     matchedSession.email,
		verifiedAt: time.Now(),
	}
	s.store.mu.Unlock()

	// Generate an authorization code for the OIDC flow
	code := randomHex(32)
	s.mu.Lock()
	s.codes[code] = &authRequest{
		clientID:     matchedSession.clientID,
		nonce:        matchedSession.nonce,
		redirectURI:  matchedSession.redirectURI,
		atprotoState: atprotoState,
	}
	s.mu.Unlock()

	// Redirect back to the original OIDC client
	u, _ := url.Parse(matchedSession.redirectURI)
	uq := u.Query()
	uq.Set("code", code)
	// CRITICAL: Pass back the original OIDC state parameter
	if matchedSession.oidcState != "" {
		uq.Set("state", matchedSession.oidcState)
	}
	u.RawQuery = uq.Encode()

	http.Redirect(w, r, u.String(), http.StatusFound)
}

func (s *idpServer) serveCreateSession(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Verify the request has a valid Bearer token from /userinfo
	auth := r.Header.Get("Authorization")
	if len(auth) < 8 || auth[:7] != "Bearer " {
		http.Error(w, "Missing or invalid authorization header", http.StatusUnauthorized)
		return
	}
	token := auth[7:]

	// Validate the access token and get the user info
	s.mu.Lock()
	ar, ok := s.accessTokens[token]
	s.mu.Unlock()

	if !ok || ar.validTill.Before(time.Now()) {
		http.Error(w, "Invalid or expired token", http.StatusUnauthorized)
		return
	}

	// Get the verified user from the ATProto session
	s.store.mu.Lock()
	var user *verifiedUser
	if ar.atprotoState != "" {
		sess := s.store.oidcSessions[ar.atprotoState]
		if sess != nil {
			user = s.store.verifiedUsers[sess.did]
		}
	}
	s.store.mu.Unlock()

	if user == nil {
		http.Error(w, "User not found or not verified", http.StatusUnauthorized)
		return
	}

	// Generate a session ID
	sessionID := randomHex(32)

	// Store the session
	s.store.mu.Lock()
	s.store.sessionIDToUser[sessionID] = user.did
	s.store.mu.Unlock()

	// Set a session cookie (valid for 1 hour)
	http.SetCookie(w, &http.Cookie{
		Name:     "atlogin_session",
		Value:    sessionID,
		Path:     "/",
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   3600, // 1 hour
	})

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Session created"))
}

func (s *idpServer) serveGenerateClient(w http.ResponseWriter, r *http.Request) {
	// Check for valid session cookie
	cookie, err := r.Cookie("atlogin_session")
	if err != nil {
		http.Error(w, "Unauthorized: Please log in first", http.StatusUnauthorized)
		return
	}

	// Validate session and get user
	s.store.mu.Lock()
	did, ok := s.store.sessionIDToUser[cookie.Value]
	var user *verifiedUser
	if ok {
		user = s.store.verifiedUsers[did]
	}
	s.store.mu.Unlock()

	if user == nil {
		http.Error(w, "Unauthorized: Invalid or expired session", http.StatusUnauthorized)
		return
	}

	if r.Method == "GET" {
		// Show the form
		html := `<!DOCTYPE html>
<html>
<head>
    <title>Generate OIDC Client</title>
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
        .info {
            background-color: #e7f3ff;
            border: 1px solid #b3d9ff;
            padding: 15px;
            border-radius: 4px;
            margin-bottom: 20px;
        }
        .form-group {
            margin: 20px 0;
        }
        label {
            display: block;
            margin-bottom: 5px;
            font-weight: bold;
        }
        input[type="text"] {
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
        .result {
            background-color: #d4edda;
            border: 1px solid #c3e6cb;
            color: #155724;
            padding: 20px;
            border-radius: 4px;
            margin-top: 20px;
        }
        .result h2 {
            margin-top: 0;
        }
        .credential {
            background-color: #f5f5f5;
            border: 1px solid #ddd;
            padding: 10px;
            margin: 10px 0;
            border-radius: 4px;
            font-family: monospace;
            word-break: break-all;
        }
        .label {
            font-weight: bold;
            color: #555;
        }
        .link {
            margin-top: 15px;
            padding: 10px;
            background-color: #fff3cd;
            border: 1px solid #ffeaa7;
            border-radius: 4px;
        }
        .link a {
            color: #856404;
            font-weight: bold;
        }
    </style>
</head>
<body>
    <h1>Generate OIDC Client Configuration</h1>
    <div class="info">
        After logging in and verifying your identity, you can generate OIDC client credentials to use with your applications.
    </div>
    <form method="POST">
        <div class="form-group">
            <label for="app_name">Application Name:</label>
            <input type="text" id="app_name" name="app_name" value="Tailscale" required>
        </div>
        <button type="submit">Generate Client Credentials</button>
    </form>
</body>
</html>`
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(html))
		return
	}

	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse form
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Failed to parse form", http.StatusBadRequest)
		return
	}

	appName := r.FormValue("app_name")
	if appName == "" {
		appName = "app"
	}

	// Use the user's email (which includes both handle and domain) as the identifier
	// This ensures different login methods (apenwarr.ca@atlogin.net vs apenwarr@apenwarr.ca)
	// produce different client_ids and therefore different secrets
	// Encoding scheme to avoid collisions:
	// - Replace "-" with "--" (escape existing hyphens first)
	// - Replace "@" with "-at-"
	// - Replace "." with "-"
	// This way "a-b@c" and "a.b@c" produce different results
	userID := user.email
	userID = strings.ReplaceAll(userID, "-", "--")  // Escape hyphens first
	userID = strings.ReplaceAll(userID, "@", "-at-")
	userID = strings.ReplaceAll(userID, ".", "-")

	// Generate client_id and client_secret
	// Format: <email-encoded>-<appname>-v1
	clientID := fmt.Sprintf("%s-%s-v1", userID, appName)
	clientSecret := s.generateClientSecret(clientID)

	// Add to config
	s.mu.Lock()
	s.secrets[clientID] = clientSecret
	s.mu.Unlock()

	// Save config to disk
	config, err := loadConfig(s.configPath)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to load config: %v", err), http.StatusInternalServerError)
		return
	}
	config.Secrets[clientID] = clientSecret
	if err := saveConfig(s.configPath, config); err != nil {
		http.Error(w, fmt.Sprintf("Failed to save config: %v", err), http.StatusInternalServerError)
		return
	}

	// Prepare result HTML
	issuerURL := s.getIssuerURL(r)
	resultHTML := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
    <title>OIDC Client Generated</title>
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
        .result {
            background-color: #d4edda;
            border: 1px solid #c3e6cb;
            color: #155724;
            padding: 20px;
            border-radius: 4px;
            margin-top: 20px;
        }
        .result h2 {
            margin-top: 0;
        }
        .credential {
            background-color: #f5f5f5;
            border: 1px solid #ddd;
            padding: 10px;
            margin: 10px 0;
            border-radius: 4px;
            font-family: monospace;
            word-break: break-all;
        }
        .label {
            font-weight: bold;
            color: #555;
            display: block;
            margin-bottom: 5px;
        }
        .link {
            margin-top: 15px;
            padding: 10px;
            background-color: #fff3cd;
            border: 1px solid #ffeaa7;
            border-radius: 4px;
        }
        .link a {
            color: #856404;
            font-weight: bold;
        }
        .instructions {
            margin-top: 20px;
            padding: 15px;
            background-color: #e7f3ff;
            border: 1px solid #b3d9ff;
            border-radius: 4px;
        }
    </style>
</head>
<body>
    <h1>OIDC Client Configuration Generated</h1>
    <div class="result">
        <h2>Client Credentials</h2>
        <p>Copy these credentials and paste them into your application:</p>

        <div class="credential">
            <span class="label">App Name:</span>
            %s
        </div>

        <div class="credential">
            <span class="label">Client ID:</span>
            %s
        </div>

        <div class="credential">
            <span class="label">Client Secret:</span>
            %s
        </div>

        <div class="credential">
            <span class="label">Issuer URL:</span>
            %s
        </div>
    </div>`, appName, clientID, clientSecret, issuerURL)

	// Add Tailscale link if app name is Tailscale
	if appName == "Tailscale" {
		resultHTML += `
    <div class="link">
        <strong>Tailscale Setup:</strong><br>
        Configure your custom OIDC provider at: <a href="https://login.tailscale.com/start/oidc" target="_blank">https://login.tailscale.com/start/oidc</a>
    </div>`
	}

	resultHTML += `
    <div class="instructions">
        <h3>Next Steps:</h3>
        <ol>
            <li>Copy the Client ID and Client Secret above</li>
            <li>Configure your application with these credentials</li>
            <li>Set the Issuer URL to: <code>` + issuerURL + `</code></li>
            <li>When users log in, they should use the format: <code>handle@domain</code></li>
        </ol>
    </div>
</body>
</html>`

	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(resultHTML))
}

func (s *idpServer) generateClientSecret(clientID string) string {
	// Generate client_secret using HMAC-SHA256 of client_id with master_key
	h := hmac.New(sha256.New, []byte(s.masterKey))
	h.Write([]byte(clientID))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// Signing key helpers

type signingKey struct {
	k   *rsa.PrivateKey
	kid uint64
}

type signingKeyJSON struct {
	Key string `json:"key"`
	ID  uint64 `json:"id"`
}

func (sk *signingKey) MarshalJSON() ([]byte, error) {
	b := pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(sk.k),
	}
	return json.Marshal(signingKeyJSON{
		Key: base64.URLEncoding.EncodeToString(pem.EncodeToMemory(&b)),
		ID:  sk.kid,
	})
}

func (sk *signingKey) UnmarshalJSON(data []byte) error {
	var j signingKeyJSON
	if err := json.Unmarshal(data, &j); err != nil {
		return err
	}
	decoded, err := base64.URLEncoding.DecodeString(j.Key)
	if err != nil {
		return err
	}
	block, _ := pem.Decode(decoded)
	if block == nil {
		return fmt.Errorf("no PEM block found")
	}
	k, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return err
	}
	sk.k = k
	sk.kid = j.ID
	return nil
}

func genRSAKey(bits int) (uint64, *rsa.PrivateKey, error) {
	kid, err := readUint64(rand.Reader)
	if err != nil {
		return 0, nil, err
	}
	k, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return 0, nil, err
	}
	return kid, k, nil
}

func readUint64(r io.Reader) (uint64, error) {
	var b [8]byte
	for {
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return 0, err
		}
		if v := binary.BigEndian.Uint64(b[:]); v != 0 {
			return v, nil
		}
	}
}

func randomHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
}
