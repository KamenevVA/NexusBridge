# Roadmap to NexusBridge 1.0

Acceptance is evidence-based, not a percentage estimate.

| Gate | Scope | State |
|---|---|---|
| G0-L | Restricted ordinary ChatGPT Desktop integration, protected file/hash | Passed in owner environment |
| G1 | Native files, restricted terminal, local guard, negative tests | Passed in owner environment, v0.1.0 |
| G0-R | Independent remote Chat integration | Passed in owner environment (mobile out of scope) |
| G2 | Stable authenticated relay, pairing, replay, reconnect, VPN/reboot | Next |
| G3 | Console, onboarding, tray, installer/uninstall | Pending |
| G4 | Workspaces, Git, deterministic jobs and recovery | Pending |
| G5 | Desktop vision and UI automation | Pending |
| G6 | Multi-device infrastructure, authorized SSH/ADB/WOL | Pending |
| G7 | Security review, SBOM, 72h soak, production release | Pending |

Local G1 acceptance includes native handle-relative I/O, pin-race and interrupted-write recovery, dedicated nonadmin AppContainer and child/core separation, bounded Job Objects, exact owner approval, emergency stop, audit anchor and retention. Remote Chat proof accepted; durable relay is the next prerequisite. No date or platform capability is promised without verification.
