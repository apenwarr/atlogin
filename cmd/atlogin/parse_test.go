package main

import "testing"

func TestParseLoginHint(t *testing.T) {
	tests := []struct {
		name           string
		loginHint      string
		wantHandle     string
		wantDomain     string
		wantErr        bool
	}{
		{
			name:       "at@apenwarr.ca -> @at.apenwarr.ca",
			loginHint:  "at@apenwarr.ca",
			wantHandle: "at.apenwarr.ca",
			wantDomain: "apenwarr.ca",
		},
		{
			name:       "apenwarr@apenwarr.ca -> @apenwarr.ca",
			loginHint:  "apenwarr@apenwarr.ca",
			wantHandle: "apenwarr.ca",
			wantDomain: "apenwarr.ca",
		},
		{
			name:       "user@at.apenwarr.ca -> @user (backward compat)",
			loginHint:  "user@at.apenwarr.ca",
			wantHandle: "user",
			wantDomain: "at.apenwarr.ca",
		},
		{
			name:       "alice@example.com -> @alice.example.com",
			loginHint:  "alice@example.com",
			wantHandle: "alice.example.com",
			wantDomain: "example.com",
		},
		{
			name:       "john@john.doe.com -> @john.doe.com (prefix match)",
			loginHint:  "john@john.doe.com",
			wantHandle: "john.doe.com",
			wantDomain: "john.doe.com",
		},
		{
			name:       "hello@hello.example.com -> @hello.example.com (prefix match)",
			loginHint:  "hello@hello.example.com",
			wantHandle: "hello.example.com",
			wantDomain: "hello.example.com",
		},
		{
			name:      "empty user",
			loginHint: "@example.com",
			wantErr:   true,
		},
		{
			name:      "no @ sign",
			loginHint: "invalid",
			wantErr:   true,
		},
		{
			name:      "empty domain",
			loginHint: "user@",
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotHandle, gotDomain, err := parseLoginHint(tt.loginHint)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseLoginHint() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil {
				return
			}
			if gotHandle != tt.wantHandle {
				t.Errorf("parseLoginHint() handle = %v, want %v", gotHandle, tt.wantHandle)
			}
			if gotDomain != tt.wantDomain {
				t.Errorf("parseLoginHint() domain = %v, want %v", gotDomain, tt.wantDomain)
			}
		})
	}
}
