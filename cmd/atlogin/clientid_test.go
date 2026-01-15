package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"
)

// TestClientIDUniqueness verifies that different login methods produce different client_ids
func TestClientIDUniqueness(t *testing.T) {
	appName := "Tailscale"

	testCases := []struct {
		name     string
		email    string
		expected string
	}{
		{
			name:     "atlogin.net direct",
			email:    "apenwarr.ca@atlogin.net",
			expected: "apenwarr-ca-at-atlogin-net-Tailscale-v1",
		},
		{
			name:     "own domain",
			email:    "apenwarr@apenwarr.ca",
			expected: "apenwarr-at-apenwarr-ca-Tailscale-v1",
		},
		{
			name:     "subdomain",
			email:    "apenwarr@ca",
			expected: "apenwarr-at-ca-Tailscale-v1",
		},
		{
			name:     "bsky.social",
			email:    "alice@alice.bsky.social",
			expected: "alice-at-alice-bsky-social-Tailscale-v1",
		},
		{
			name:     "bsky.social via atlogin.net",
			email:    "alice.bsky.social@atlogin.net",
			expected: "alice-bsky-social-at-atlogin-net-Tailscale-v1",
		},
	}

	clientIDs := make(map[string]string)

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Generate client_id using the same logic as serveGenerateClient
			userID := tc.email
			userID = strings.ReplaceAll(userID, "-", "--")  // Escape hyphens first
			userID = strings.ReplaceAll(userID, "@", "-at-")
			userID = strings.ReplaceAll(userID, ".", "-")
			clientID := userID + "-" + appName + "-v1"

			if clientID != tc.expected {
				t.Errorf("Expected client_id %q, got %q", tc.expected, clientID)
			}

			// Check for collisions
			if existingEmail, exists := clientIDs[clientID]; exists {
				t.Errorf("Collision! client_id %q generated for both %q and %q",
					clientID, existingEmail, tc.email)
			}
			clientIDs[clientID] = tc.email
		})
	}

	// Verify all client_ids are unique
	if len(clientIDs) != len(testCases) {
		t.Errorf("Expected %d unique client_ids, got %d", len(testCases), len(clientIDs))
	}
}

// TestClientSecretDeterministic verifies that the same client_id always produces the same secret
func TestClientSecretDeterministic(t *testing.T) {
	masterKey := "test-master-key-12345"
	clientID := "apenwarr-ca-at-atlogin-net-Tailscale-v1"

	// Generate secret twice
	secret1 := generateClientSecretTest(clientID, masterKey)
	secret2 := generateClientSecretTest(clientID, masterKey)

	if secret1 != secret2 {
		t.Errorf("Client secret is not deterministic: %q != %q", secret1, secret2)
	}
}

// TestClientSecretUnique verifies that different client_ids produce different secrets
func TestClientSecretUnique(t *testing.T) {
	masterKey := "test-master-key-12345"

	testCases := []struct {
		email string
	}{
		{"apenwarr.ca@atlogin.net"},
		{"apenwarr@apenwarr.ca"},
		{"apenwarr@ca"},
	}

	secrets := make(map[string]string)

	for _, tc := range testCases {
		userID := tc.email
		userID = strings.ReplaceAll(userID, "-", "--")
		userID = strings.ReplaceAll(userID, "@", "-at-")
		userID = strings.ReplaceAll(userID, ".", "-")
		clientID := userID + "-Tailscale-v1"
		secret := generateClientSecretTest(clientID, masterKey)

		if existingEmail, exists := secrets[secret]; exists {
			t.Errorf("Secret collision! Same secret for %q and %q", tc.email, existingEmail)
		}
		secrets[secret] = tc.email
	}

	if len(secrets) != len(testCases) {
		t.Errorf("Expected %d unique secrets, got %d", len(testCases), len(secrets))
	}
}

// TestClientIDDecoding verifies that we can decode enough information from the client_id
func TestClientIDDecoding(t *testing.T) {
	testCases := []struct {
		name          string
		email         string
		appName       string
		expectedParts []string
	}{
		{
			name:          "standard format",
			email:         "apenwarr.ca@atlogin.net",
			appName:       "Tailscale",
			expectedParts: []string{"apenwarr-ca", "at", "atlogin-net", "Tailscale", "v1"},
		},
		{
			name:          "own domain",
			email:         "apenwarr@apenwarr.ca",
			appName:       "GitLab",
			expectedParts: []string{"apenwarr", "at", "apenwarr-ca", "GitLab", "v1"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			userID := tc.email
			userID = strings.ReplaceAll(userID, "-", "--")
			userID = strings.ReplaceAll(userID, "@", "-at-")
			userID = strings.ReplaceAll(userID, ".", "-")
			clientID := userID + "-" + tc.appName + "-v1"

			// Verify the client_id contains identifiable parts
			parts := strings.Split(clientID, "-")
			if len(parts) < 3 {
				t.Errorf("client_id %q has too few parts (expected at least 3)", clientID)
			}

			// Verify it contains the app name
			if !strings.Contains(clientID, tc.appName) {
				t.Errorf("client_id %q doesn't contain app name %q", clientID, tc.appName)
			}

			// Verify it contains version
			if !strings.HasSuffix(clientID, "-v1") {
				t.Errorf("client_id %q doesn't end with -v1", clientID)
			}

			// Verify it contains the email in encoded form
			for _, part := range tc.expectedParts {
				if !strings.Contains(clientID, part) {
					t.Errorf("client_id %q missing expected part %q", clientID, part)
				}
			}
		})
	}
}

// TestClientIDRoundTrip verifies we can reconstruct the email from client_id
func TestClientIDRoundTrip(t *testing.T) {
	testCases := []struct {
		email string
	}{
		{"apenwarr.ca@atlogin.net"},
		{"apenwarr@apenwarr.ca"},
		{"alice.bsky.social@atlogin.net"},
		{"test@example.com"},
	}

	for _, tc := range testCases {
		t.Run(tc.email, func(t *testing.T) {
			// Encode
			userID := tc.email
			userID = strings.ReplaceAll(userID, "-", "--")
			userID = strings.ReplaceAll(userID, "@", "-at-")
			userID = strings.ReplaceAll(userID, ".", "-")
			clientID := userID + "-Tailscale-v1"

			// Decode
			// Remove suffix "-Tailscale-v1"
			withoutSuffix := strings.TrimSuffix(clientID, "-Tailscale-v1")

			// Convert back (reverse order):
			// 1. Replace "-at-" with "@"
			// 2. Replace single "-" with "."
			// 3. Replace "--" with "-"
			decoded := strings.ReplaceAll(withoutSuffix, "-at-", "@")
			decoded = strings.ReplaceAll(decoded, "--", "\x00") // Temp marker
			decoded = strings.ReplaceAll(decoded, "-", ".")
			decoded = strings.ReplaceAll(decoded, "\x00", "-")

			if decoded != tc.email {
				t.Errorf("Round trip failed: %q -> %q -> %q", tc.email, clientID, decoded)
			}
		})
	}
}

// TestClientIDNoCollisions tests that similar emails don't collide
func TestClientIDNoCollisions(t *testing.T) {
	// These should all be different
	testEmails := []string{
		"a@b.c",
		"a.b@c",
		"a-b@c",
		"a@b-c",
		"ab@c",
		"a@bc",
	}

	clientIDs := make(map[string]string)
	appName := "test"

	for _, email := range testEmails {
		userID := email
		userID = strings.ReplaceAll(userID, "-", "--")
		userID = strings.ReplaceAll(userID, "@", "-at-")
		userID = strings.ReplaceAll(userID, ".", "-")
		clientID := userID + "-" + appName + "-v1"

		if existingEmail, exists := clientIDs[clientID]; exists {
			t.Errorf("Collision between %q and %q -> both produce %q",
				email, existingEmail, clientID)
		}
		clientIDs[clientID] = email
	}
}

// Helper function to generate client secret (mimics generateClientSecret method)
func generateClientSecretTest(clientID, masterKey string) string {
	h := hmac.New(sha256.New, []byte(masterKey))
	h.Write([]byte(clientID))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}
