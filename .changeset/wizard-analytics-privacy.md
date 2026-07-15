---
'@cipherstash/wizard': patch
---

Align the wizard's analytics with the `stash` CLI's telemetry privacy contract.
The wizard now honors `DO_NOT_TRACK`, `STASH_TELEMETRY_DISABLED`, and CI
auto-detection; uses a random per-session identifier instead of one derived
from username@hostname; disables IP→geo resolution; and reports error events as
fixed labels / error class names instead of raw messages (which could embed
schema names or connection details). Analytics remain dormant unless a PostHog
key is configured at build time.
