# xmip-core-authorize-scope

Scope authorization: the scopes a token carries against the scope an action on an artifact needs, as OAuth 2.0 states them; a transport-layer policy. A technology of [xmip-core-authorize](https://github.com/IlleNilsson/xmip-core-authorize).

It is a constraint, never a grant: a token missing a required scope is
denied, and one carrying every required scope is answered with no opinion, so
the gate opens only where another policy grants.

## Verification

The included workflow is manual-only and calls the versioned shared workflow at
`IlleNilsson/.github@v1`.
