---
'@cipherstash/auth': patch
---

A key router now holds ZeroKMS and at most one key vendor backend by its type. The ZeroKMS side of a router must be a ZeroKMS key source, and a router is not one, so a router that holds a second router does not compile. No runtime behaviour changes.
