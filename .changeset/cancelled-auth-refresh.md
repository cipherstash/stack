---
'@cipherstash/auth': patch
---

Keep native token refreshes running when their caller is cancelled, so rotated device-session credentials are saved and subsequent requests can still authenticate. Close a refresh-waiter notification race, and give the caller that started a refresh the new token rather than the expiring one it replaced.
