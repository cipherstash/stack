---
'@cipherstash/auth': patch
---

Access-key and device-session tokens are now refreshed before they expire,
in the background. In Node, such a strategy refreshes its token between 90
seconds and two minutes before it expires, on a task of its own, so
`getToken` returns the current token at once while it still works. Before, the
first call in the last 90 seconds started the refresh and waited for it. The
refresh runs only while the strategy is in use, so an idle process stops
asking the token service.

`OidcFederationStrategy` has no background task: each user's token is still
refreshed by that user's calls, in the last 90 seconds before it expires.

After a refresh fails, the next attempt waits about a second, doubling up to
30 seconds. Meanwhile a call whose token still works gets it, and a call whose
token has expired fails at once with that refresh's error, rather than every
call asking the token service again. This backoff applies to the WASM build
too, which has no background task and still refreshes in the last 90 seconds.

The JavaScript API is unchanged.
