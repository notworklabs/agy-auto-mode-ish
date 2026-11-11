---
name: guardrails-init
description: Inspects the current repository and generates or updates `.agents/guardrails.json` and matching `/permissions` rules for the `agy-auto-mode-ish` plugin. Activate when the user asks to set up, customize, or audit workspace guardrails for a project.
---

# Guardrails Initialization & Customization Skill (`guardrails-init`)

Use this skill when the user wants to configure or update the `agy-auto-mode-ish` plugin for a repository.

## Workflow

1. **Inspect Repository Structure**:
   - Check `README.md`, `AGENTS.md`, `package.json`, `pyproject.toml`, `Makefile`, and `docker-compose.yml` to identify:
     - Sensitive data directories or secret files that must be added to `deny_paths` (e.g., `secrets/`, `backups/`, `data/`).
     - Destructive project-specific commands that must be added to `deny_commands` (e.g., `docker compose down -v`).
     - Deployment or live service commands that should require confirmation in `ask_commands` (e.g., `docker compose up/down/restart`, deployment scripts).
     - Standard test, linter, and build commands to auto-approve in `allow_commands` (e.g., `pytest`, `ruff`, `npm test`, `npm run build`, `npx playwright test`, `cargo test`, `go test`).

2. **Create or Update `.agents/guardrails.json`**:
   Write a clean `.agents/guardrails.json` file in the project root following `defaults/guardrails.schema.json`:
   ```json
   {
     "$schema": "./plugins/agy-auto-mode-ish/defaults/guardrails.schema.json",
     "description": "Project-specific guardrails layered on top of agy-auto-mode-ish defaults.",
     "deny_paths": ["secrets/"],
     "ask_write_paths": [".agents/"],
     "deny_commands": [
       {
         "pattern": "<regex>",
         "reason": "<explanation shown when blocked>"
       }
     ],
     "ask_commands": [
       {
         "pattern": "<regex>",
         "reason": "<explanation shown when prompting>"
       }
     ],
     "allow_commands": [
       "^<regex-for-safe-test-or-build-command>"
     ]
   }
   ```

3. **Verify with `--self-test`**:
   Run the plugin's built-in verification suite:
   ```bash
   python3 <path-to-plugin>/scripts/permission_gate.py --self-test
   ```
