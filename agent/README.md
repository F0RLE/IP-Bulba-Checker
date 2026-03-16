# Agent Memory

Shared project memory for AI assistants working on Bulbascan.

Use this folder as the neutral home for project-specific instructions instead of provider-specific top-level folders.

Files:
- `shared.md` — canonical project context and workflow for all assistants
- `gemini.md` — Gemini-facing wrapper
- `claude.md` — Claude-facing wrapper
- `codex.md` — Codex-facing wrapper

Rule:
- Keep cross-agent guidance in `shared.md`
- Keep assistant-specific files thin and mostly referential
- When workflow changes, update `shared.md` first
