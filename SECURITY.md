# Security policy

NexusBridge v0.1.0 is a local MVP, not production-ready. No untrusted network exposure or personal/production data in the disposable test runner.

## Reporting

Use GitHub private vulnerability reporting if available or contact the owner privately. Never post credentials, private paths, tokens, screenshots or exploit details publicly.

## Local boundaries

The default stdio runner is read-only and synthetic. An owner-provisioned dedicated non-admin profile adds protected ACLs, AppContainer zero capabilities and loopback-exemption checks, a creation-time Job Object with process/CPU/memory caps, and exact one-use approvals. Native file operations verify pinned handle-relative paths, reject reparse points, ADS, hardlinks and conflicting hashes. Protected checkpoints permit explicit recovery after interrupted replacement; the owner maintains an offline audit anchor, verified archive and retention policy.

The tested AppContainer denied external TCP and protected file access while ordinary baseline TCP succeeded. This is bounded evidence, not proof against all protocols, all attacks, privileged owner/admin or OS compromise. No general content DLP, signed installer, remote security or production certification. Job-only disposable runner is not an OS sandbox for arbitrary commands. The owner must provision and protect roots, keep sensitive data out of selected workspace/output, and maintain audit archives. Never deploy a public G1 endpoint.

See [local runbook](docs/G1-LOCAL.md) for precise limits. Never commit runtime data, secrets or private integration evidence.
