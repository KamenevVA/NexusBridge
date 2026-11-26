# G1 local MVP runbook (Windows x64)

Version 0.1.0. No listener or remote relay. Do not expose stdio through a tunnel.

## Disposable local self-test

Install Node.js 24.x, Git and use the Windows x64 .NET Framework compiler already present on supported test host. Run as a standard user:

    npm ci --ignore-scripts
    npm run typecheck
    npm test
    node src/mvp-stdio.ts

The default MCP tool set is read-only. The runner creates a fresh synthetic directory, prints its session name to stderr, and uses stdin/stdout for MCP. Explicit --sandbox-write and --sandbox-exec enable disposable test capabilities. The only command template is a synthetic self-test. A local owner terminal may list, approve or stop using scripts/guard-local.mts and the printed alpha-SESSION identifier. Never use the Job-only disposable runner for untrusted arbitrary commands or personal directories.

## Dedicated local profile (advanced owner provisioning)

Provisioning is a local administrator operation, not an MCP command. Runtime must be a dedicated standard Windows account, not the owner, SYSTEM, LocalService, NetworkService or an administrator. Copy the reviewed app/source, locked dependencies and three locally built native helpers into an owner-controlled read-only application root. The dedicated account must be able to read/execute these files, but not change them, dependencies, application directories or control policy. Configure separate canonical absolute local roots for workspace, checkpoints, audit, pending requests and control. None may overlap each other or the app root. Workspace/checkpoint roots must be on the same volume. Do not grant the account access to owner-only files. Checkpoint/audit/pending directories must be writable to the dedicated core, not the AppContainer child. Control is writable only to the owner.

For exec, choose a fresh NexusBridgeExec followed by 32 lowercase hexadecimal characters. Derive its SID using the native AppContainer helper --derive NAME. Grant that SID read/traverse to the required parent and reviewed executable/application, and modify only to the selected workspace. Apply the low-integrity label to the workspace only. Do not grant access to control, checkpoints, audit or pending; do not grant capabilities or loopback exemptions. Create the profile under the dedicated account with the helper --create NAME; remove with --delete NAME after shutdown. The core verifies the SID, zero capabilities, no loopback exemption and Job membership before child resume. Do not change global firewall or VPN.

Owner writes a JSON profile under the protected control root. Shape (placeholder strings must be replaced with actual canonical paths/IDs):

    {
      "v": 1,
      "sessionId": "00000000-0000-4000-8000-000000000001",
      "executorSid": "S-1-5-21-1-2-3-1001",
      "expiresAt": 0,
      "workspaceRoot": "E:\\NB-Local\\workspace",
      "checkpointRoot": "E:\\NB-Local\\checkpoints",
      "auditRoot": "E:\\NB-Local\\audit",
      "controlRoot": "E:\\NB-Local\\control",
      "pendingRoot": "E:\\NB-Local\\pending",
      "scopes": {"read":true,"write":false,"exec":false},
      "auditRetentionDays":30,
      "commands": {}
    }

expiresAt is a future Unix timestamp in milliseconds, at most one hour from launch. Use the actual dedicated principal SID and a fresh UUID. For exec, set exec=true, add appContainerProfile and up to eight owner-defined templates: name -> {exe, cwd, args, timeoutMs, input}. Executable is an absolute protected .exe; cwd inside selected workspace. Arguments and executable SHA-256 are part of exact approvals. Timeout 100..60000 ms. No model-supplied shell or new template. Start node src/g1-profile.ts <absolute-profile.json> as dedicated standard user with a local MCP stdio client; use a separate owner terminal for the following commands.

    node scripts/guard-local.mts list <absolute-profile.json>
    node scripts/guard-local.mts approve <absolute-profile.json> <approval-uuid>
    node scripts/guard-local.mts stop <absolute-profile.json>

The owner reviews the exact request and enters the displayed digest interactively. Stop is latched. New work requires new authorized session. No automatic owner approval for real actions.

## Recovery and journal

If a write returns unknown outcome, inspect checkpoint with get_checkpoint_info and current file hash. Explicitly approve restore_file if needed; never blind-retry. Replacement can leave protected backup and temporary files after interruption. Restore preserves bytes, not original file metadata. Inspect orphan files locally; do not delete unknown files automatically.

After clean shutdown, owner can use scripts/audit-local.mts inspect|anchor|archive|prune <absolute-profile.json> [archive-directory or archive-file]. Existing journal restart requires an owner-protected anchor; truncation before anchor is refused. Anchor and prune require interactive digest confirmation. Prune requires elapsed retention and a byte-identical verified external archive. New journal after retirement needs new session ID. Do not remove stale lease without checking that the old core is stopped.

G1 does not provide a production installer, stable remote transport or general DLP. Those are later gates. The synthetic provisioning harness is internal test evidence, never a production launcher.
