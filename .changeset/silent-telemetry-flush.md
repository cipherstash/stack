---
'stash': patch
---

Fix telemetry stack traces printing to the terminal when the telemetry endpoint is unreachable or returns an error. The PostHog SDK logs flush failures to the console internally (bypassing the CLI's own error swallowing), so a machine with telemetry enabled and a failing network printed two full stack-trace blocks per command. The CLI now supplies the SDK with a fetch wrapper that absorbs network and HTTP errors, so a failed send is silently dropped — matching the documented fire-and-forget behaviour. Command output, including `stash manifest --json` stdout, was never corrupted; the noise went to stderr.
