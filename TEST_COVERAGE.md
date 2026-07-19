# Test coverage

The project uses Python's standard-library `unittest` runner:

```sh
python3 -m unittest discover -s tests
```

## Grok authentication

`tests/test_headroom.py` covers:

- parsing Grok CLI credentials and RFC 3339 bearer expiry;
- selecting only the official xAI OIDC entry from mixed-scope credentials
  before usage reads and refreshes;
- refreshing an expiring Headroom-owned home through the OAuth token endpoint;
- preserving identity metadata while rotating access and refresh tokens;
- sending the official client and optional principal fields in the refresh
  grant;
- deriving a missing OIDC client ID from the documented xAI auth scope key;
- refusing non-xAI OIDC issuers before sending a refresh token over the network;
- deriving expiry from the access-token JWT when `expires_in` is omitted;
- rejecting non-finite or out-of-range raw usage percentages before rounding;
- refusing network and file writes for adopted homes;
- accepting a symlinked Headroom root while rejecting slot symlinks that escape
  the owned homes directory;
- requiring the canonical `homes/<slot-name>` path rather than any descendant;
- rejecting `auth.json` symlinks that escape to adopted credentials;
- rejecting hard-linked credentials shared with an adopted home;
- validating the slot's expected identity before any refresh mutation;
- retaining local identity diagnostics when expected-email validation holds;
- revalidating the seat fingerprint from the credential read under lock;
- failing closed without network when the auth lock is busy;
- refreshing before snapshot credential-digest binding;
- retaining fail-closed behavior for expired or rejected credentials.
- accepting and rendering Grok's weekly capacity when 5h is intentionally
  missing in all Übersicht copies, while retaining strict validation for other
  providers.

The HTTP tests use fake openers and never contact xAI or mutate a live Grok
credential.
