# SUNET Auth Server

A production-ready [GNAP (Grant Negotiation and Authorization Protocol)](https://datatracker.ietf.org/doc/html/rfc9635) authentication server implementation, part of the eduID IAM suite.

[![CodeQL](https://github.com/SUNET/sunet-auth-server/actions/workflows/codeql-analysis.yml/badge.svg)](https://github.com/SUNET/sunet-auth-server/actions/workflows/codeql-analysis.yml)
[![License](https://img.shields.io/badge/License-BSD_2--Clause-blue.svg)](https://opensource.org/licenses/BSD-2-Clause)

## Overview

SUNET Auth Server is an authentication server that implements the GNAP protocol (RFC 9635), allowing users to request JWT access tokens using various authentication methods including mutual TLS, JWKs, and SAML2. It supports both dynamic and static client configuration.

### Key Features

- **GNAP Protocol**: Full implementation targeting RFC 9635
- **Multiple Authentication Methods**:
  - Mutual TLS (mTLS) with certificate validation
  - JWK-based authentication (JWS, detached JWS and HTTP Message Signatures `httpsig`)
  - SAML2 Service Provider integration
  - Certificate Authority (CA) trust validation
- **Trust Frameworks**:
  - TLS-FED (TLS Federation) metadata support
  - SAML metadata trust (MDQ - Metadata Query Protocol)
  - Custom CA certificate chains
- **User Interaction**: Redirect and user code start modes, with an explicit resource owner consent step bound
  to the browser that started the interaction
- **Flexible Configuration**: Support for both static and dynamic client registration
- **Production-Ready**: Built with FastAPI, includes health checks, comprehensive logging, and Docker support

## Quick Start

### Prerequisites

- Python 3.13+
- MongoDB (for transaction state storage)
- Docker (optional, for containerized deployment)

### Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/SUNET/sunet-auth-server.git
   cd sunet-auth-server
   ```

2. **Install dependencies using uv**:
   ```bash
   uv pip sync requirements.txt
   ```

   Or using pip:
   ```bash
   pip install -r requirements.txt
   ```

3. **Configure the server**:
   Create a configuration file (YAML or environment variables). See [Configuration](#configuration) section.

4. **Run the server**:
   ```bash
   uvicorn auth_server.run:app --host 0.0.0.0 --port 8080
   ```

### Docker Deployment

```bash
# Build the image
docker build -t sunet-auth-server .

# Run the container
docker run -p 8080:8080 \
  -e app_name=auth-server \
  -e app_entrypoint=auth_server.run:app \
  -e AUTH_TOKEN_ISSUER=https://your-domain.com \
  -e MONGO_URI=mongodb://mongo:27017/auth_server \
  sunet-auth-server
```

## Configuration

The server is configured using environment variables or a YAML configuration file. Key configuration options include:

### Essential Settings

| Variable | Description | Default |
|----------|-------------|---------|
| `AUTH_TOKEN_ISSUER` | JWT token issuer identifier (required) | - |
| `AUTH_TOKEN_AUDIENCE` | JWT token audience | None |
| `AUTH_TOKEN_EXPIRES_IN` | Token expiration time | 10 hours |
| `MONGO_URI` | MongoDB connection string | None |
| `KEYSTORE_PATH` | Path to JWKS keystore file | `keystore.jwks` |
| `SIGNING_KEY_ID` | Key ID for signing tokens | `default` |

### Authentication Flows

Enable specific authentication flows using the `AUTH_FLOWS` configuration:

```yaml
auth_flows:
  - ConfigFlow      # Static client configuration
  - CAFlow          # Certificate Authority validation
  - MDQFlow         # SAML metadata query
  - TLSFEDFlow      # TLS Federation metadata
  - InteractionFlow # User interaction (SAML2 SP)
  - TestFlow        # Testing purposes only
```

### SAML2 Configuration

For SAML2 Service Provider functionality:

```yaml
pysaml2_config_path: /path/to/saml2_config.py
saml2_discovery_service_url: https://ds.example.com
saml2_single_idp: https://idp.example.com/metadata  # Optional: skip discovery
```

### TLS-FED Metadata

Configure TLS Federation metadata sources:

```yaml
tls_fed_metadata:
  - remote: https://metadata.tls-fed.org/federation.json
    jwks: /path/to/trust/jwks.json
    strict: true
  - local: /path/to/local/metadata.json
    jwks: /path/to/trust/jwks.json
```

#### TLS federation metadata caching

Metadata is refreshed in the background once it passes its `renew_at` time (the metadata's `cache_ttl`, or
`tls_fed_metadata_cache_ttl` as default). Failed refreshes are retried with exponential backoff starting at
`tls_fed_metadata_retry_interval`, never longer than `tls_fed_metadata_cache_ttl` or `tls_fed_metadata_stale_grace`.
While refreshes fail, the last good metadata is served for at most `tls_fed_metadata_stale_grace` after `renew_at`
(default 5 minutes). After that the source is dropped and its entities are rejected (fail closed), even if the
metadata has not reached its `exp` yet. `tls_fed_metadata_stale_grace` must be at least
`tls_fed_metadata_retry_interval`, and the retry interval and cache ttl must be greater than zero. Requests only wait
for a metadata source that has never loaded successfully, bounded by `http_client_timeout`.

### Static Client Configuration

Configure pre-registered clients:

```yaml
client_keys:
  client-id-1:
    proof:
      method: mtls
    cert: "-----BEGIN CERTIFICATE-----\n..."
    claims:
      scope: "example.org"
      custom_claim: "value"
```

### Key Proofs (httpsig, jws and jwsd)

#### httpsig

`httpsig` (RFC 9635 7.3.1, RFC 9421 and RFC 9530) is supported for keys sent by value (public JWK) and for keys
in `client_keys`. The proof is given either as a string or as an object:

```json
"proof": "httpsig"
"proof": {"method": "httpsig", "alg": "ecdsa-p256-sha256", "content-digest-alg": "sha-512"}
```

- String form: the algorithm comes from the `alg` (a JWS name) of the JWK, which is then required. Supported:
  `ES256` (ecdsa-p256-sha256), `ES384` (ecdsa-p384-sha384), `RS256` (rsa-v1_5-sha256), `PS512` (rsa-pss-sha512)
  and `EdDSA` (ed25519, an `OKP` JWK with `crv` `Ed25519`). The Content-Digest algorithm is `sha-256`.
- Object form: `alg` is required and must match the key (and the JWK `alg` if there is one).
  `content-digest-alg` is `sha-256` (default) or `sha-512`.
- The JWK needs a `kid`, it must be the `keyid` of the signature. Private keys (`d` etc.) sent by value are
  rejected. HMAC (`oct` keys) is not supported. The algorithm is never taken from the message, an explicit `alg`
  signature parameter is rejected.
- Signature parameters: `tag` must be `gnap`, `created` is required and must be at most
  `proof_httpsig_max_age` old (and not more than `proof_httpsig_clock_skew` in the future), `expires` must not
  have passed. A signed `nonce` is required by default and can only be used once per key.
- Covered components: `@method` and `@target-uri` always, `content-digest` when the request has a body and
  `authorization` for requests carrying an access token (continuation and token management requests).
- Several signatures can be sent. The request is accepted if one of them is valid.
- Requests to `/continue` and `/token` must be signed with the key of the grant request.

Nonces are stored in MongoDB (`proof_nonces`, expiring). Without `mongo_uri` they are only remembered by the
running process, which does not protect a deployment with several workers or instances.

| Variable | Description | Default |
|----------|-------------|---------|
| `PROOF_HTTPSIG_MAX_AGE` | How old a signature's `created` may be | 5 minutes |
| `PROOF_HTTPSIG_CLOCK_SKEW` | Accepted clock difference between client and server | 30 seconds |
| `PROOF_HTTPSIG_REQUIRE_CONTENT_TYPE` | Require `content-type` to be signed when there is a body | `false` |
| `PROOF_HTTPSIG_NONCE_REQUIRED` | Require a signed `nonce`. Disabling it leaves requests replayable until `proof_httpsig_max_age` expires | `true` |
| `PROOF_EXTERNAL_BASE_URL` | Scheme and authority clients sign, see below | None |

#### Running behind a proxy

`@target-uri` (httpsig) and `uri` (jws and jwsd) must match the URL the client used. A proxy that terminates TLS or
rewrites host or port makes the server see another URL than the client signed. Either set
`proof_external_base_url` to the public base URL (scheme, host and port only, no credentials, path, query or
fragment, for example `https://auth.example.com`), which is the recommended option, or run uvicorn/gunicorn with proxy
headers support (`--proxy-headers --forwarded-allow-ips=<proxy address>`) so the scheme and host are restored.
Forwarded headers are never read by the auth server itself. The path and query must be the same after the proxy as
they were for the client.

If you use `--forwarded-allow-ips`, list only the proxy address. Any address in that list can set the scheme and host
the server reconstructs, so a broad list (such as `*` or client-routable space) lets a client sign a forged authority
and the URI binding loses its meaning.

## API Endpoints

### Grant Request (GNAP Transaction)

**POST** `/transaction`

Initiate a GNAP transaction to request access tokens.

#### mtls
```bash
curl -X POST https://auth.example.com/transaction \
  -H "Content-Type: application/json" \
  -d '{
    "access_token": [{
      "flags": ["bearer"],
      "access": [{"type": "example-api", "scope": "example.org"}]
    }],
    "client": {
      "key": {
        "proof": "mtls",
        "cert#S256": "HTOXGzzHrtiq_Art..."
      }
    }
  }'
```
#### Preconfigured keys in config
```bash
curl -X POST https://auth.example.com/transaction \
  -H "Content-Type: application/json" \
  -d '{
    "access_token": [{
      "flags": ["bearer"],
      "access": [{"type": "example-api", "scope": "example.org"}]
    }],
    "client": {
      "key": "configured_key_name"
    }
  }'
```

#### Expecting an interaction
```bash
curl -X POST https://auth.example.com/transaction \
  -H "Content-Type: application/json" \
  -d '{
    "access_token": [{
      "flags": ["bearer"],
      "access": [{"type": "example-api", "scope": "example.org"}]
    }],
    "client": {
      "key": {
        "proof": "mtls",
        "cert#S256": "HTOXGzzHrtiq_Art..."
      }
    },
    "interact": {
      "start": ["user_code_uri"]
    }
  }'
```
### Continue Transaction

**POST** `/continue/{continue_reference}`

Continue an in-progress GNAP transaction.

### User Interaction

**GET** `/interaction/redirect/{transaction_id}`

Start the interaction. The first browser to arrive is bound to the transaction: the server stores an
interaction session id and a CSRF token and sets an `httponly` per-transaction session cookie. Later
requests from any other browser are rejected with `403`.

If the user is not authenticated yet, this redirects to the SAML2 SP (`/saml2/sp/authn/{transaction_id}`).
Once authentication is done, the same URL renders the consent screen listing the requested access and the
subject information the client asked for.

**POST** `/interaction/consent/{transaction_id}`

Submit the resource owner's decision from the consent screen. Form fields: `decision` (`approve`, anything
else counts as a denial) and `csrf_token`. Requires the interaction session cookie set by the redirect
endpoint. Approval sets the transaction to `approved`, denial sets it to `denied`; either way the agreed
`finish` method (redirect or push) is triggered.

Continuing a denied transaction fails with `403` and the GNAP error code `user_denied`.

**GET** / **POST** `/interaction/code`

Show and submit the user code for the `user_code` / `user_code_uri` interaction start modes. A valid code
redirects to `/interaction/redirect/{transaction_id}`.

### Health Check

**GET** `/status/healthy`

Returns server health status.

```bash
curl http://localhost:8080/status/healthy
```

## Authentication Flows

### 1. ConfigFlow (Static Configuration)

Pre-configured clients with static credentials and claims.
- Loads client keys and claims from configuration

### 2. CAFlow (Certificate Authority)

Validates client certificates against a trusted CA bundle.

- Loads CA certificates from `ca_certs_path`
- Validates certificate chain and validity period
- Extracts organization ID from certificate (optional)
- Supports revocation checking

### 3. MDQFlow (SAML Metadata Query)

Retrieves and validates certificates from SAML metadata.

- Queries MDQ server for entity metadata
- Validates certificates from SAML metadata

### 4. TLSFEDFlow (TLS Federation)

Uses TLS-FED metadata for certificate validation.

- Loads and validates TLS-FED metadata
- Supports both remote and local metadata sources
- Validates entity issuer certificate from metadata
- Caches metadata with configurable TTL

### 5. InteractionFlow (User Authentication)

Integrates SAML2 SP for user authentication flows.

- Redirects user to SAML IdP
- Processes SAML assertions
- Asks the resource owner to approve or deny the request on a consent screen before the transaction is
  approved — authentication alone is not approval
- Binds the interaction to the browser that started it, so an interaction URL handed to someone else can
  not be used to approve the transaction
- Issues access tokens based on authentication
- Supports discovery service for IdP selection

The consent screen does not name the client: `InteractionFlow` clients are anonymous and `client.display` is
self-asserted (RFC 9635 2.3), so showing it would be misleading.

### 6. TestFlow

For development and testing purposes only. **Do not use in production** — it issues access tokens to anyone
who asks, with no key proof at all.

Enable it in the configuration:

```yaml
auth_flows:
  - TestFlow
```

Or as an environment variable (the value is a JSON list):

```bash
AUTH_FLOWS='["TestFlow"]'
```

Then send a grant request with the `test` proof method and no key material:

```bash
curl -X POST http://localhost:8080/transaction \
  -H "Content-Type: application/json" \
  -d '{
    "access_token": [{
      "flags": ["bearer"],
      "access": [{"type": "example-api", "scope": "example.org"}]
    }],
    "client": {
      "key": {
        "proof": "test"
      }
    }
  }'
```

The response contains a signed access token right away, with `auth_source: test` and `source: test mode` in
the claims. The `bearer` flag is still required — see [Known Limitations](#known-limitations).

TestFlow also accepts the real proof methods (`mtls`, `jws`, `jwsd`): if `proof` is anything but `test`, the
proof is verified as usual, only the client key is not looked up in any trust source. This is how the test
suite exercises proof verification without an MDQ server or a CA bundle.

Flows are tried in the order they are configured, and `TestFlow` never rejects a request whose proof verifies
against the key in the request itself, so a configured `TestFlow` short circuits every flow after it. Leave it
out of any deployment that serves real clients.

## Development

### Setup Development Environment

```bash
# Install development dependencies
uv pip sync dev_requirements.txt

# Run tests
make test

# Type checking
make typecheck

# Code formatting
make reformat
```

### Code Quality

The project uses:
- **ruff** for linting and formatting
- **mypy** for static type checking
- **pytest** for testing

### Running Tests

```bash
pytest --log-cli-level DEBUG
```

## Utility Scripts

The `scripts/` directory contains helpful utilities:

- **`gen_jwks.py`**: Generate JWKS keystore
- **`gen_cert.py`**: Generate test certificates
- **`token_info.py`**: Decode and inspect JWT tokens
- **`inspect_tls_fed_metadata.py`**: Inspect TLS-FED metadata
- **`pem2fingerprint_rfc8705.py`**: Get cert#S256 value from pem cert
- **`validate_tls_fed_metadata.py`**: Validate TLS-FED metadata signatures

## Architecture

```
src/auth_server/
├── api.py              # FastAPI application setup
├── flows.py            # Authentication flow implementations
├── config.py           # Configuration management
├── models/             # Pydantic models for GNAP, JOSE, etc.
│   ├── gnap.py        # GNAP protocol models
│   ├── jose.py        # JWK, JWS models
│   └── claims.py      # JWT claims models
├── routers/            # FastAPI route handlers
│   ├── root.py        # Grant request endpoints
│   ├── interaction.py # User interaction and consent endpoints
│   ├── saml2_sp.py    # SAML2 SP endpoints
│   ├── status.py      # Health check endpoints
│   └── templates/     # Consent, user code and result pages (Jinja2)
├── proof/              # Proof verification (mTLS, JWS, etc.)
├── db/                 # Database models and operations
└── tests/              # Test suite
```

## Known Limitations

The following GNAP features are not yet implemented:

- **HTTPSIG** key rotation (`gnap-rotate` signatures) and HMAC algorithms (asymmetric keys only)
- **Key-bound** access tokens — grant requests must include the `bearer` access token flag; requests without it are rejected with `invalid_request`
- **Multiple access token requests** (array of token requests in a single grant)
- **Client/user by reference**
- Access token **rotation** (`POST /token/{ref}` returns `invalid_rotation`)
- Access token **introspection** (RFC 9767)
- **App** interaction start mode
- Subject **`sub_ids`**

Note: revoking an access token (`DELETE /token/{ref}`) removes AS-side state only — the JWT remains valid to offline validators until it expires.

These features may be added in future releases based on demand and use cases.

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes with tests
4. Run `make reformat` and `make typecheck`
5. Submit a pull request

## License

This project is licensed under the BSD 2-Clause License. See [LICENSE](LICENSE) file for details.

## Support

- **Documentation**: [https://github.com/sunet/sunet-auth-server](https://github.com/sunet/sunet-auth-server)
- **API Documentation**: [https://auth.sunet.se/docs](https://auth.sunet.se/docs)
- **Issues**: [GitHub Issues](https://github.com/SUNET/sunet-auth-server/issues)

## Acknowledgments

Developed and maintained by [SUNET](https://www.sunet.se/) (Swedish University Computer Network) as part of the eduID identity and access management infrastructure.

## References

- [RFC 9635 - Grant Negotiation and Authorization Protocol (GNAP)](https://datatracker.ietf.org/doc/html/rfc9635)
- [GNAP Working Group](https://datatracker.ietf.org/wg/gnap/about/)
- [TLS-FED](https://github.com/dotse/tls-fed-auth)
- [SAML2 MDQ](https://tools.ietf.org/html/draft-young-md-query)
