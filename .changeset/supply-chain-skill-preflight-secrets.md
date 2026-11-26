---
"stash": patch
---

The `stash-supply-chain-security` skill now describes the secrets of the FFI release pre-flight workflow correctly. It said that the workflow passes no secrets to its build. The workflow now passes exactly two, by name: `DOCKER_HUB_USERNAME` and `DOCKER_HUB_PASSWORD`. The musl build uses them to log in to Docker Hub before it pulls Alpine. They cannot authenticate an npm publish, so the workflow still cannot publish.
