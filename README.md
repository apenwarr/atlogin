# ATLogin

**OpenID Connect Identity Provider for ATProto (Bluesky) Accounts**

ATLogin lets you use your ATProto/Bluesky identity to log in to any application that supports OIDC (OpenID Connect). Think of it as "Sign in with Bluesky" for the web.

⚠️ **Security Notice**: This project is vibe-coded and has **never been security reviewed**. Use at your own risk, especially for production systems.

## How It Works

### The Basic Idea

Your ATProto identity has two parts:
- **User**: `alice.example.com`
- **Domain**: where you prove ownership (via WebFinger)

ATLogin bridges these into standard OIDC login:

1. Register `https://example.com` as your OIDC provider in your app (Tailscale, etc.)
2. Log in as `alice@example.com`
3. ATLogin authenticates you via ATProto OAuth as `@alice.example.com`
4. Your app receives standard OIDC tokens

### Email-to-Handle Conversion Rules

ATLogin converts email-style logins to ATProto handles using these rules:

| Login Format | ATProto Handle | Rule |
|-------------|----------------|------|
| `alice@example.com` | `@alice.example.com` | Default: user@domain → @user.domain |
| `alice@alice.bsky.social` | `@alice.bsky.social` | Prefix match: user@user.X → @user.X |
| `alice.bsky.social@atlogin.net` | `@alice.bsky.social` | Special: direct handle passthrough |
| `alice.bsky.social@at.apenwarr.ca` | `@alice.bsky.social` | Legacy: same as atlogin.net |

The **prefix match rule** is clever: if the username is a prefix of the domain (like `alice@alice.bsky.social`), we assume the full domain IS your handle.

### Special Case: atlogin.net (Like @gmail.com)

Instead of setting up WebFinger on your own domain, you can use:

```
alice.bsky.social@atlogin.net
```

This works just like `@gmail.com` - a hosted service that handles the OIDC side for you. No need to:
- Configure WebFinger on your domain
- Set up reverse proxies
- Manage DNS records

Just use `atlogin.net` as your OIDC issuer and log in with your Bluesky handle as the email prefix.

## Setup Options

### Option 1: Use Your Own Domain

**Requirements:**
- Control over `example.com`
- HTTPS server
- WebFinger endpoint at `/.well-known/webfinger`

**Steps:**
1. Set up WebFinger to point to ATLogin (see deployment docs)
2. Register `https://example.com` in your OIDC app
3. Log in as `alice@example.com`

**Pros:**
- Your own branded domain
- Full control

**Cons:**
- Requires technical setup
- Need to maintain infrastructure

### Option 2: Use atlogin.net (Hosted)

**Requirements:**
- Just a Bluesky account

**Steps:**
1. Register `https://atlogin.net` in your OIDC app
2. Log in as `alice.bsky.social@atlogin.net`

**Pros:**
- Zero configuration
- Works immediately
- No infrastructure to maintain

**Cons:**
- Dependent on atlogin.net service
- Not your own domain

## Example: Tailscale Setup

1. **Generate Client Credentials**
   - Visit your ATLogin instance
   - Log in with your Bluesky account
   - Click "Generate Client Credentials"
   - Use app name: "Tailscale"

2. **Configure Tailscale**
   - Go to https://login.tailscale.com/start/oidc
   - Enter your client ID and secret
   - Set issuer: `https://atlogin.net` (or your domain)

3. **Log In**
   - Use email: `alice.bsky.social@atlogin.net`
   - Or with your domain: `alice@example.com`

## Future: bsky.social Native Support

If Bluesky decides to support this natively, they could:

1. **Publish WebFinger** at `bsky.social/.well-known/webfinger`
2. **Host their own ATLogin instance**

Then users could log in as:
```
alice@bsky.social  →  authenticates as @alice.bsky.social
```

This would make "Sign in with Bluesky" native to any OIDC app, no third-party needed.

## Installation

### Requirements

- Go 1.21+
- An ATProto/Bluesky account for testing

### Quick Start

```bash
# Clone the repository
git clone https://github.com/yourusername/atlogin.git
cd atlogin

# Initialize state directory and keys
./atlogin -init

# Add a test client
./atlogin -new-client testclient
# (saves the secret to config.json and prints it)

# Start the server
./atlogin

# Visit http://localhost:9411
```

### Configuration

Create `state/config.json`:

```json
{
  "addr": ":9411",
  "issuer": "https://your-domain.com",
  "client_name": "Your ATLogin Instance",
  "master_key": "auto-generated-on-first-run",
  "secrets": {
    "client-id": "client-secret"
  }
}
```

**Fields:**
- `addr`: Listen address (default: `:9411`)
- `issuer`: Your public OIDC issuer URL (optional, auto-detected from Host header)
- `client_name`: Display name shown during OAuth
- `master_key`: Auto-generated HMAC key for deterministic secrets
- `secrets`: Map of client_id → client_secret

### Deployment

See deployment examples in `docs/`:
- Nginx reverse proxy config
- Apache config
- Caddy config
- Docker deployment
- Fly.io deployment

## WebFinger Setup

For your own domain to work, you need WebFinger at:

```
https://example.com/.well-known/webfinger?resource=acct:alice@example.com
```

**Response:**
```json
{
  "subject": "acct:alice@example.com",
  "links": [
    {
      "rel": "http://openid.net/specs/connect/1.0/issuer",
      "href": "https://example.com"
    }
  ]
}
```

ATLogin provides a helper endpoint you can reverse proxy to:
```
https://your-atlogin.com/helpers/webfinger
```

## Client Credential Generation

After logging in, users can generate OIDC client credentials:

1. **Automatic on Login**: Session cookie set after ATProto authentication
2. **Visit `/generate-client`**: Protected endpoint (requires valid session)
3. **Enter App Name**: e.g., "Tailscale"
4. **Get Credentials**:
   - `client_id`: `<user-handle>-<app-name>-v1`
   - `client_secret`: `base64(HMAC-SHA256(client_id, master_key))`

Secrets are deterministic (same client_id always produces same secret) and automatically saved to config.

## Architecture

```
User Browser
    ↓
[1] Login: alice@example.com
    ↓
OIDC App (Tailscale, etc.)
    ↓
[2] Redirect to: https://example.com/authorize
    ↓
ATLogin IDP
    ↓
[3] Initiate ATProto OAuth
    ↓
ATProto Network (Bluesky)
    ↓
[4] User authorizes via their PDS
    ↓
ATLogin IDP
    ↓
[5] Verify handle ownership (DID check)
    ↓
[6] Return OIDC tokens to app
    ↓
User is logged in!
```

**Security Features:**
- ATProto OAuth for authentication
- Handle-to-DID verification (prevents spoofing)
- HTTP-only session cookies
- HMAC-based deterministic secrets
- Token expiration (1 hour)

## API Endpoints

### OIDC Standard Endpoints

- `GET /.well-known/openid-configuration` - OIDC discovery
- `GET /.well-known/jwks.json` - Public keys
- `GET /authorize` - OAuth authorization
- `POST /token` - Token exchange
- `GET /userinfo` - User information

### ATLogin Specific

- `GET /.well-known/webfinger` - WebFinger discovery
- `GET /helpers/webfinger` - WebFinger helper (for reverse proxy)
- `GET /atproto/callback` - ATProto OAuth callback
- `POST /create-session` - Create authenticated session
- `GET/POST /generate-client` - Generate OIDC client credentials

### Test App

- `GET /` - Home page with demo/setup tool
- `POST /verify` - Domain verification
- `POST /login` - Initiate OIDC flow
- `GET /callback` - OIDC callback

## Development

```bash
# Run tests
go test ./...

# Run specific test
go test ./cmd/atlogin -run TestParseLoginHint

# Build
go build -o atlogin ./cmd/atlogin

# Run with debug logging
./atlogin -state-dir ./state
```

## Contributing

Contributions welcome! This is an experimental project exploring how ATProto can work with OIDC.

**Areas that need work:**
- Security review (please!)
- Better session management
- Persistent storage option
- Rate limiting
- Logging improvements
- More tests

## License

MIT License - see LICENSE file

## Credits

Built with:
- [indigo](https://github.com/bluesky-social/indigo) - ATProto Go library
- [go-jose](https://github.com/go-jose/go-jose) - JWT/JOSE library

Inspired by the need to use Bluesky identities everywhere.

## FAQ

**Q: Is this secure?**
A: This is experimental code that hasn't been security reviewed. Don't use it for critical systems without proper audit.

**Q: Why not just use email?**
A: ATProto provides decentralized identity with cryptographic verification. Plus, you already have a Bluesky account!

**Q: Can I use this in production?**
A: You can, but you're taking on the risk. Get a security review first.

**Q: What if atlogin.net goes down?**
A: Use your own domain instead! That's the beauty of the design.

**Q: Does this work with any OIDC app?**
A: Yes! Tailscale, GitLab, Grafana, anything that supports custom OIDC providers.

**Q: Can I self-host?**
A: Absolutely! That's the recommended approach for production.

**Q: What about multi-user?**
A: Each user generates their own client credentials after logging in. The IDP supports unlimited users.

**Q: Why the weird email format rules?**
A: We need to map `user@domain` to `@handle` while supporting different domain patterns. The rules handle common cases cleanly.

## Support

- File issues on GitHub
- Check out the examples in `/docs`
- Join the discussion on Bluesky

---

**Remember:** This is experimental software. Use responsibly! 🚀
