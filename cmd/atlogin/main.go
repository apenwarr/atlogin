// Command atlogin is an OIDC Identity Provider that uses ATProto OAuth for authentication.
// Users authenticate using their ATProto handle with any domain (e.g., hello.example.com@any.domain),
// which initiates an OAuth flow with their PDS (Personal Data Server).
// The provider accepts any domain and authenticates the ATProto handle, returning the full email as provided.
package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
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
	Addr    string            `json:"addr,omitempty"`
	Issuer  string            `json:"issuer,omitempty"`
	Secrets map[string]string `json:"secrets"`
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

	if len(config.Secrets) == 0 {
		log.Fatal("config must have at least one client in secrets")
	}

	addr := config.Addr
	if addr == "" {
		addr = ":9411"
	}

	issuer := config.Issuer
	if issuer == "" {
		issuer = "https://at.apenwarr.ca"
	}

	// Initialize custom auth store for ATProto OAuth
	store := newCustomAuthStore()

	// Initialize ATProto OAuth client
	// Use NewPublicConfig for production deployment with proper client metadata
	oauthConfig := oauth.NewPublicConfig(
		issuer+"/client-metadata.json",
		issuer+"/atproto/callback",
		[]string{"atproto"},
	)
	oauthApp := oauth.NewClientApp(&oauthConfig, store)

	srv := &idpServer{
		issuer:       issuer,
		secrets:      config.Secrets,
		keyFile:      keyFile,
		oauthApp:     oauthApp,
		oauthHost:    issuer,
		store:        store,
		codes:        make(map[string]*authRequest),
		accessTokens: make(map[string]*authRequest),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/{$}", serveRoot)
	mux.HandleFunc("/.well-known/webfinger", srv.serveWebFinger)
	mux.HandleFunc("/.well-known/openid-configuration", srv.serveOpenIDConfig)
	mux.HandleFunc("/.well-known/jwks.json", srv.serveJWKS)
	mux.HandleFunc("/authorize", srv.serveAuthorize)
	mux.HandleFunc("/token", srv.serveToken)
	mux.HandleFunc("/userinfo", srv.serveUserInfo)
	mux.HandleFunc("/atproto/callback", srv.serveATProtoCallback)
	mux.HandleFunc("/client-metadata.json", srv.serveClientMetadata)

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

func serveRoot(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	io.WriteString(w, "Hello, this is the atlogin server.\n")
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
	issuer    string
	secrets   map[string]string // clientID -> clientSecret
	keyFile   string
	oauthApp  *oauth.ClientApp
	oauthHost string // host for OAuth callback URL
	store     *customAuthStore

	mu           sync.Mutex
	signingKey   *signingKey
	codes        map[string]*authRequest
	accessTokens map[string]*authRequest
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

// customAuthStore implements oauth.ClientAuthStore with custom OIDC session tracking
type customAuthStore struct {
	mu       sync.Mutex
	sessions map[string]*oauth.ClientSessionData
	requests map[string]*oauth.AuthRequestData
	// Map ATProto state to OIDC session info
	oidcSessions map[string]*atprotoSession
	// Track the most recently created state for linking
	lastState string
}

func newCustomAuthStore() *customAuthStore {
	return &customAuthStore{
		sessions:     make(map[string]*oauth.ClientSessionData),
		requests:     make(map[string]*oauth.AuthRequestData),
		oidcSessions: make(map[string]*atprotoSession),
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

	w.Header().Set("Content-Type", "application/jrd+json")
	json.NewEncoder(w).Encode(map[string]any{
		"subject": resource,
		"links": []map[string]string{
			{
				"rel":  "http://openid.net/specs/connect/1.0/issuer",
				"href": s.issuer,
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

	json.NewEncoder(w).Encode(map[string]any{
		"issuer":                                s.issuer,
		"authorization_endpoint":                s.issuer + "/authorize",
		"token_endpoint":                        s.issuer + "/token",
		"userinfo_endpoint":                     s.issuer + "/userinfo",
		"jwks_uri":                              s.issuer + "/.well-known/jwks.json",
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

	// Start the ATProto OAuth flow
	ctx := r.Context()
	atprotoRedirectURL, err := s.oauthApp.StartAuthFlow(ctx, handle)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to start ATProto OAuth flow: %v", err), http.StatusInternalServerError)
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

// parseLoginHint extracts the ATProto handle and domain from a login hint in the format:
// handle@any.domain -> (handle, any.domain)
// We accept any domain and will service it as an authoritative login provider.
func parseLoginHint(loginHint string) (string, string, error) {
	parts := strings.SplitN(loginHint, "@", 2)
	if len(parts) != 2 {
		return "", "", fmt.Errorf("expected format: handle@domain, got: %s", loginHint)
	}

	handle := parts[0]
	domain := parts[1]

	if handle == "" {
		return "", "", fmt.Errorf("handle cannot be empty")
	}

	if domain == "" {
		return "", "", fmt.Errorf("domain cannot be empty")
	}

	return handle, domain, nil
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

	// Default values if no ATProto session
	userSub := "unknown"
	userName := "Unknown User"
	userEmail := "unknown@at.apenwarr.ca"

	if sess != nil {
		userSub = sess.did
		userName = sess.handle
		userEmail = sess.email
	}

	now := time.Now()
	claims := map[string]any{
		"iss":   s.issuer,
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
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"sub":   "unknown",
			"name":  "Unknown User",
			"email": "unknown@at.apenwarr.ca",
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
	// Generate the OAuth client metadata document for ATProto OAuth
	metadata := s.oauthApp.Config.ClientMetadata()

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	if err := json.NewEncoder(w).Encode(metadata); err != nil {
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

	// Process the OAuth callback
	sessData, err := s.oauthApp.ProcessCallback(ctx, r.URL.Query())
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
