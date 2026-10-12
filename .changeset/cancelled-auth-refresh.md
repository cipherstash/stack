---
'@cipherstash/auth': patch
---

Keep native token refreshes running when their caller is cancelled, so rotated device-session credentials are saved and subsequent requests can still authenticate. Close a refresh-waiter notification race and avoid returning a token that expired during refresh.
