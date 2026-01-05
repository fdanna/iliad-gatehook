# Repository Guidelines

## Project Structure & Module Organization
- `docker-compose.yml` defines the runtime stack (baresip container and any helper services).
- `baresip/` is the mounted runtime config directory (e.g., `config`, `accounts`, `contacts`).
- `scripts/` holds automation scripts (see `scripts/gate_open.sh`) and ad-hoc logs.
- `gatehook/` and `modules/` contain a small C module build layout (`gatehook/gatehook.c`, `modules/modules.mk`).

## Build, Test, and Development Commands
- `docker compose up -d` starts the stack in detached mode.
- `docker compose restart baresip` restarts baresip after config changes.
- `docker compose logs -f baresip` tails baresip runtime logs for troubleshooting.
- `docker compose logs -f gatehook` tails gatehook logs if the service is enabled.

## Coding Style & Naming Conventions
- Bash: follow `scripts/gate_open.sh` conventions (`#!/usr/bin/env bash`, `set -euo pipefail`).
- C: match existing K&R-style formatting in `gatehook/gatehook.c`; prefer lowercase snake_case.
- Config: keep one directive per line in `baresip/config`, avoid inline comments unless needed.
- Names: use descriptive, lowercase filenames (e.g., `gate_open.sh`, `gatehook.c`).

## Testing Guidelines
- No automated test framework is present.
- Validate manually: start the stack, place a call, and confirm expected logs in `docker compose logs -f`.
- Keep changes small and verify by editing `baresip/config` and restarting the service.

## Commit & Pull Request Guidelines
- This repository does not include Git history, so no local conventions are discoverable.
- Use clear, imperative subjects (e.g., "Add gatehook service") and explain why the change is needed.
- If you introduce new services or scripts, include setup notes in the PR description.

## Security & Configuration Tips
- Treat `baresip/accounts` and related files as sensitive; avoid committing credentials or tokens.
- Keep device IPs and endpoints configurable where possible, and document defaults in the README.
