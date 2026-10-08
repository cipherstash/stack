---
"@cipherstash/auth": patch
---

Auth failures carry more help, and their messages never quote a credential or another library's text. A failure's `type` (`NOT_AUTHENTICATED`, `INVALID_CRN`, ...) is unchanged.

- `REQUEST_ERROR`'s message no longer repeats the transport's own error, which can carry a URL with its query string. It gains `help` saying what to check.
- `INVALID_TOKEN` for a token whose claims do not decode no longer quotes the decoder's message, which could carry a byte or a claim of the token.
- A failed device binding reports ZeroKMS's status, not its response body.
- `SERVER_ERROR` for a refused token exchange names the HTTP status and the auth server's `error_description`, not the response body, which from the edge in front of it is an HTML page and can echo the access key. A body that is not JSON is reported by where it broke, not by the parser's message.
- A profile file that is not valid JSON is reported by error kind, line and column, not by the parser's message, which could quote the file.
- `INVALID_GRANT`, `INVALID_WORKSPACE_ID` and `ALREADY_CONSUMED` gain `help`, and `NOT_AUTHENTICATED`'s help names `stash auth login`.
- A `STORE_ERROR` carries the help of the profile failure underneath it, such as logging in again when the profile file is missing.
