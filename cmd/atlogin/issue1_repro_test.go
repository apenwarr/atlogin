package main

// Reproducer/regression tests for #1: go test ./cmd/atlogin -run TestIssue1 -v
// Only the completed ATProto login is seeded; handlers and config I/O are real.
import (
	"encoding/base64"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestIssue1(t *testing.T) {
	const clientID = "alice-bsky-social-at-atlogin-net-test-v1"
	configPath := filepath.Join(t.TempDir(), "config.json")
	config := `{"master_key":"test-key","secrets":{"seed+client%":"s+e/c="}}`
	t.Setenv("ATLOGIN_CONFIG", base64.StdEncoding.EncodeToString([]byte(config)))
	boot := func(t *testing.T) *idpServer {
		t.Helper()
		// The same config overwrite/load performed by main() on each Fly start.
		if err := writeFromEnv("ATLOGIN_CONFIG", configPath); err != nil {
			t.Fatal(err)
		}
		c, err := loadConfig(configPath)
		if err != nil {
			t.Fatal(err)
		}
		return &idpServer{secrets: c.Secrets, masterKey: c.MasterKey,
			configPath: configPath, store: newCustomAuthStore()}
	}
	s := boot(t)
	s.store.verifiedUsers["did:plc:test"] = &verifiedUser{
		email: "alice.bsky.social@atlogin.net", verifiedAt: time.Now(),
	}
	s.store.sessionIDToUser["session"] = "did:plc:test"
	r := httptest.NewRequest("POST", "/generate-client", strings.NewReader("app_name=test"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.AddCookie(&http.Cookie{Name: "atlogin_session", Value: "session"})
	w := httptest.NewRecorder()
	s.serveGenerateClient(w, r)
	secret := s.secrets[clientID]
	if w.Code != http.StatusOK || secret == "" {
		t.Fatalf("generate client: %d %s", w.Code, w.Body)
	}

	q := url.Values{
		"client_id": {clientID}, "redirect_uri": {"https://keycloak.example/cb?a=1&b=2"},
		"response_type": {"code"}, "scope": {"openid"},
		"state": {`kc-state"<>&`}, "nonce": {"kc-nonce"},
		"resource": {"one", "two"},
	}
	authorize := func(s *idpServer, id string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", "/authorize?"+q.Encode(), nil)
		params := r.URL.Query()
		params.Set("client_id", id)
		r.URL.RawQuery = params.Encode()
		w := httptest.NewRecorder()
		s.serveAuthorize(w, r)
		return w
	}
	token := func(s *idpServer, id, pass string, basic bool) *httptest.ResponseRecorder {
		form := url.Values{"grant_type": {"authorization_code"}}
		if !basic {
			form.Set("client_id", id)
			form.Set("client_secret", pass)
		}
		r := httptest.NewRequest("POST", "/token", strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if basic {
			r.SetBasicAuth(id, pass)
		}
		w := httptest.NewRecorder()
		s.serveToken(w, r)
		return w
	}
	checkClientAuth := func(t *testing.T, w *httptest.ResponseRecorder) {
		t.Helper()
		// Deliberately omit the code: reaching code validation proves client auth
		// succeeded, without inventing an ATProto session or signing OIDC tokens.
		if w.Code != http.StatusBadRequest || strings.TrimSpace(w.Body.String()) != "invalid code" {
			t.Fatalf("client authentication: %d %s; want 400 invalid code", w.Code, w.Body)
		}
	}

	t.Run("restart", func(t *testing.T) {
		restarted := boot(t)
		if w := authorize(restarted, clientID); strings.TrimSpace(w.Body.String()) == "invalid client_id" {
			t.Errorf("/authorize rejected a generated client after restart")
		}
		checkClientAuth(t, token(restarted, clientID, secret, false))
	})
	t.Run("missing_login_hint", func(t *testing.T) {
		w := authorize(s, clientID)
		if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `name="login_hint"`) {
			t.Fatalf("/authorize: %d %s; want login form", w.Code, w.Body)
		}
		for key, values := range q {
			for _, value := range values {
				want := `name="` + key + `" value="` + html.EscapeString(value) + `"`
				if !strings.Contains(w.Body.String(), want) {
					t.Errorf("login form lost parameter %s=%q", key, value)
				}
			}
		}
	})
	for _, tc := range []struct {
		name, id, secret string
		basic            bool
	}{
		{"basic_encoded", url.QueryEscape(clientID), url.QueryEscape(secret), true},
		{"basic_raw", clientID, secret, true},
		{"post", clientID, secret, false},
		{"configured_encoded", "seed%2Bclient%25", "s%2Be%2Fc%3D", true},
		{"configured_raw", "seed+client%", "s+e/c=", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			checkClientAuth(t, token(s, tc.id, tc.secret, tc.basic))
		})
	}
	t.Run("invalid_credentials", func(t *testing.T) {
		if w := authorize(s, "unknown"); w.Code != http.StatusBadRequest || strings.TrimSpace(w.Body.String()) != "invalid client_id" {
			t.Errorf("unknown client: %d %s", w.Code, w.Body)
		}
		for _, id := range []string{clientID, "unknown"} {
			if w := token(s, id, "wrong-secret", true); w.Code != http.StatusUnauthorized {
				t.Errorf("bad credentials for %q: %d %s", id, w.Code, w.Body)
			}
		}
	})
}
