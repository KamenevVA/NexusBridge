# Security policy

NexusBridge is a development alpha. Do not expose it to untrusted networks or grant it access to personal or production data.

## Supported versions

Only the current development snapshot is maintained; no production security support guarantee is provided.

## Reporting

Use GitHub's private vulnerability reporting if available, or contact the repository owner privately. Do not include credentials, private paths, tokens, screenshots or exploit details in public issues. If private reporting is unavailable, request a private contact channel without disclosing the vulnerability.

## Current boundaries

The stdio runner creates a fresh synthetic workspace. Read-only is the default. File checks and an audit hash chain are defense-in-depth, not a complete OS sandbox or a signature. A same-user hostile external writer, Windows reparse/TOCTOU hazards, descendant process isolation, audit truncation across restarts and full local approval enforcement remain open engineering work. Do not run as administrator or use a public tunnel.

Never commit runtime data, secrets or private integration evidence.

Alpha.5 adds a native process lifetime boundary, pinned-handle transfer, exact one-time local approval and an experimental dedicated non-admin profile. These are not a full network or filesystem sandbox. Remaining risks include native read/write/create/list TOCTOU, child access to core audit/checkpoints, network isolation and audit retention/anchoring. Do not deploy the profile or runner as a production service.
