# CI / Service Accounts

For CI pipelines and machine-to-machine authentication, use your OIDC provider's
service accounts with API tokens. The examples below use kanidm — the recommended IdP.

## Creating a Service Account (kanidm)

Service accounts are created in kanidm:

```bash
# Create the service account
kanidm service-account create ci-bot --display-name "CI Bot"

# Generate an API token
kanidm service-account api-token generate ci-bot --label "orb-chrysa-ci"
```

The API token is a JWS (JSON Web Signature) bearer token. Use it as the `docker login`
password:

```bash
echo "<api-token>" | docker login localhost:5050 --username ci-bot --password-stdin
```

## How It Works

1. CI pipeline authenticates with the IdP access token
2. Orb Chrysa's `/v2/token` endpoint validates the token via the JWKS endpoint
3. IdP groups are mapped to OCI scopes through the config's `[[auth.permissions]]`
4. A short-lived OCI bearer token is issued for the session

## Token Validation

IdP access tokens are validated locally using the cached JWKS — no per-request
call to the IdP. The JWKS is refreshed periodically (default: every 300 seconds).

## Client Credentials Grant

Service accounts configured as OAuth2 resource servers can also use the
`client_credentials` grant:

```bash
# Exchange client credentials for an access token
curl -X POST https://idp:8443/oauth2/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -u "ci-bot:<client-secret>" \
  -d "grant_type=client_credentials&scope=oci_push oci_pull"

# Use the access token with docker login
echo "<access_token>" | docker login localhost:5050 --username ci-bot --password-stdin
```

## Best Practices

- Rotate API tokens regularly
- Use short-lived tokens with appropriate scopes
- Store tokens in CI secret management (GitHub Actions secrets, etc.)
- Use separate service accounts for different pipelines
