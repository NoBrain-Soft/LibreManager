# VM-based end-to-end tests

`make e2e` runs `test/e2e/run.sh`, which uses Incus to start one central VM and three agent VMs
(Debian 13, Ubuntu 24.04, Rocky 9), installs the central node with `install-central.sh`,
enrolls the agents with the generated command and checks: hosts connected, metrics present,
inventory stored, a security-only upgrade job succeeds, a shell session opens and is recorded.

Prerequisites: `incus` with VM support, ~16 GB RAM, the server image and agent packages built
(`make image packages`). Not run in CI (needs nested virtualization).
