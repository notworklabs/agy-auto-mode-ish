# Workspace Guardrails Policy (`agy-auto-mode-ish`)

This workspace is protected by the `agy-auto-mode-ish` PreToolUse hook plugin:

1. **Workspace Autonomy (`auto_approve`)**: You have full permission to read, create, edit, and replace project files inside the active workspace root, and to run configured project test, lint, build, and read-only Git commands.
2. **Strict Workspace Boundary (`deny`)**: Never write or edit files outside the active workspace root (except your conversation artifact/scratch directory), never set `Cwd` outside the workspace root, and never read or modify `.env` secrets (`.env.example` is allowed).
3. **Destructive & Host Actions Require Confirmation (`force_ask`)**:
   - Deleting or removing files (`rm`, `rmdir`, `unlink`, `find -delete`, `git clean`, `git reset --hard`, `git restore`, `git checkout --`) will always prompt the user. Prefer editing or replacing file content over deleting files unless deletion is necessary.
   - Host system changes outside containers (`sudo`, `apt`, `systemctl`, `chmod`, `chown`, `mount`, global package installs) and modifying `.agents/` guardrail files always prompt the user.
