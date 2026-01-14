// Command apptest is a simple web application for testing the ATLogin OIDC flow.
// It prompts the user for their email address, initiates the OIDC flow with ATLogin,
// and displays the resulting OIDC information after successful authentication.
package main

import (
	"flag"
	"log"
	"net/http"

	"atlogin/testapp"
)

var (
	flagClientID     = flag.String("client-id", "", "OIDC client ID (required)")
	flagClientSecret = flag.String("client-secret", "", "OIDC client secret (required)")
	flagIssuer       = flag.String("issuer", "", "OIDC issuer URL (uses request Host if not specified)")
	flagAddr         = flag.String("addr", ":8080", "address to listen on")
)

func main() {
	flag.Parse()

	if *flagClientID == "" {
		log.Fatal("--client-id is required")
	}
	if *flagClientSecret == "" {
		log.Fatal("--client-secret is required")
	}

	srv := testapp.NewServer(*flagClientID, *flagClientSecret, *flagIssuer)

	mux := http.NewServeMux()
	srv.RegisterHandlers(mux)

	log.Printf("Starting test app at %s", *flagAddr)
	log.Printf("Visit http://localhost%s to test the flow", *flagAddr)
	log.Fatal(http.ListenAndServe(*flagAddr, mux))
}
