// Command atlogin is a minimal OIDC Identity Provider that always authenticates
// as admin@at.apenwarr.ca.
package main

import (
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
	"sync"
	"time"

	"github.com/tailscale/hujson"
	"gopkg.in/go-jose/go-jose.v2"
	"gopkg.in/go-jose/go-jose.v2/jwt"
)

var (
	flagStateDir  = flag.String("state-dir", "./state", "state directory")
	flagNewClient = flag.String("new-client", "", "add a new client ID and generate a secret for it")
	flagInit      = flag.Bool("init", false, "initialize state directory and all key files, then exit")
)

const (
	userEmail = "admin@at.apenwarr.ca"
	userName  = "Administrator"
	userSub   = "admin"
)

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

	srv := &idpServer{
		issuer:       issuer,
		secrets:      config.Secrets,
		keyFile:      keyFile,
		codes:        make(map[string]*authRequest),
		accessTokens: make(map[string]*authRequest),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/webfinger", srv.serveWebFinger)
	mux.HandleFunc("/.well-known/openid-configuration", srv.serveOpenIDConfig)
	mux.HandleFunc("/.well-known/jwks.json", srv.serveJWKS)
	mux.HandleFunc("/authorize", srv.serveAuthorize)
	mux.HandleFunc("/token", srv.serveToken)
	mux.HandleFunc("/userinfo", srv.serveUserInfo)

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
	issuer  string
	secrets map[string]string // clientID -> clientSecret
	keyFile string

	mu           sync.Mutex
	signingKey   *signingKey
	codes        map[string]*authRequest
	accessTokens map[string]*authRequest
}

type authRequest struct {
	clientID    string
	nonce       string
	redirectURI string
	validTill   time.Time
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

	code := randomHex(32)
	s.mu.Lock()
	s.codes[code] = &authRequest{
		clientID:    clientID,
		nonce:       q.Get("nonce"),
		redirectURI: redirectURI,
	}
	s.mu.Unlock()

	u, _ := url.Parse(redirectURI)
	uq := u.Query()
	uq.Set("code", code)
	if state := q.Get("state"); state != "" {
		uq.Set("state", state)
	}
	u.RawQuery = uq.Encode()

	http.Redirect(w, r, u.String(), http.StatusFound)
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
		validTill: now.Add(time.Hour),
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

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"sub":   userSub,
		"name":  userName,
		"email": userEmail,
	})
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
