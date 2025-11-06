# Copilot / AI agent instructions for this repository

Purpose
- Help AI coding agents become productive quickly in this repository by describing where to look, what to infer, and how to validate assumptions. This file is intentionally concise and actionable.

If this repository already has a more detailed agent doc
- Merge this file with the existing content. Prefer preserving explicit commands, CI references, and project-specific notes.

Quick discovery checklist (what to run first)
- Search for these files to infer language, build system, and workflows: `package.json`, `pyproject.toml`, `requirements.txt`, `Pipfile`, `setup.py`, `poetry.lock`, `pom.xml`, `build.gradle`, `Cargo.toml`, `go.mod`, `Dockerfile`, `.github/workflows`, `Makefile`, `src/`, `tests/`, `scripts/`.
- If no matches, consult `README.md` at repository root.

How to infer the "big picture" architecture
- Look for top-level directories: `api`, `services`, `web`, `frontend`, `backend`, `cmd`, `pkg`, `libs`. These often indicate service boundaries.
- Check `Dockerfile` and `.github/workflows` for deployment flow and CI commands. Examples: `docker build` steps, `kubectl`, cloud provider CLIs, or container image names.
- Read `src/` or `lib/` entrypoints (e.g., `index.js`, `main.py`, `cmd/*`) to understand runtime startup, config loading, and dependencies.
- Locate configuration files (`config/*`, `*.yaml`, `*.toml`, `settings.py`, `env.example`) to discover runtime flags, environment variables, and secrets handling.

Project-specific conventions to capture
- Test layout: Are tests under `tests/`, alongside modules, or under `<module>/tests/`? Use that pattern when adding tests.
- Naming conventions: scan for common symbol names (e.g., `create_app`, `app.py`, `server.js`, `cli.py`) and follow them.
- DB migrations and ORM: look for `migrations/`, `alembic.ini`, `prisma/`, or `schema.rb` to infer how schema changes are applied.

Common agent tasks and precise commands to run (verify before use)
- Use repository search first to find exact script names before running commands. Example patterns:
  - Node: inspect `package.json` then run `npm run <script>` or `pnpm`/`yarn` equivalents.
  - Python: prefer `poetry run`, `pipenv run`, or `python -m venv .venv && .venv/bin/pip install -r requirements.txt` depending on lockfiles.
  - Go/Rust/Java: run the conventional build commands from detected manifest files (`go build`, `cargo build`, `mvn -q -B package`).
- CI-aware checks: If `.github/workflows` exists, copy the workflow job steps to reproduce locally (e.g., `setup-node`, `setup-python`, `cache`, `run tests`).

How to add small fixes or tests
- Follow the repo's test layout and test command script. Add a single focused unit test near the code under `tests/` or next to the module if that pattern exists.
- Run only the minimal failing test locally, iterate until green, and then update the test command in `package.json`/CI file only if necessary.

Integration points and external dependencies
- Note references to external services in code or config: `AWS`, `GCP`, `Azure`, `DATABASE_URL`, `REDIS_URL`, `SENTRY_DSN`, `AUTH0`, etc. Document how the repo expects credentials (env vars, secrets manager, `.env` files).
- If third-party SDKs are used (e.g., `boto3`, `aws-sdk`, `stripe`), search for initializing code to identify required credentials and minimal mock strategies for tests.

When merging with an existing `.github/copilot-instructions.md`
- Preserve any explicit run commands, CI job names, environment variable lists, or security notes.
- Replace outdated commands only after verifying the repo still uses that toolchain (by searching manifest files).

If the repository appears empty or minimal (current state)
- This file will act as a discovery template. Agents should perform the Quick discovery checklist and then update this file with concrete commands and examples found in the repo.
- Ask the human maintainer for missing details: preferred test runner, target Node/Python versions, and any secret handling rules.

Examples (fill from repo when discovered)
- Example Node script: if `package.json` has `"start": "node server.js"`, include: `Run: npm install && npm run start`.
- Example Python entry: if `app.py` defines `create_app()`, include: `Run tests: python -m pytest tests/ --maxfail=1 -q`.

Finish and feedback
- After making repo-specific edits, ask: "Which CI job or script should the agent prefer as canonical for local testing?" to finalize instructions.

— End of file —
