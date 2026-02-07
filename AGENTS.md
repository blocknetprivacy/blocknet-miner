# AGENTS
This file describes project-specific conventions for humans and coding agents.

## Project overview
`blocknet-miner` is a desktop-friendly launcher for the `blocknet` daemon.
It serves a local-only web UI and reverse-proxies the daemon API so the browser never needs the daemon Bearer token.

Key paths:
- `cmd/blocknet-miner/main.go`: HTTP server, reverse proxy, daemon process lifecycle
- `cmd/blocknet-miner/ui/index.html`: UI layout
- `cmd/blocknet-miner/ui/app.js`: UI logic (polling + rendering)
- `cmd/blocknet-miner/ui/style.css`: UI styling

## Commands
Build:
- `make build`

Run (from `dist/` bundle):
- `make dist`
- `./dist/blocknet-miner`

Tests / sanity checks:
- `go test ./...`
- `gofmt -w cmd/blocknet-miner/*.go`

## UX conventions
- Prefer small, readable key/value tables over raw JSON blobs.
- Buttons must be explicit about scope (e.g. “start daemon” vs “start mining”).
- Disable controls when the action is not valid (e.g. can’t “stop” when stopped).

## Wallet / seed safety
- Treat recovery seed/mnemonic as highly sensitive.
- Do not log seed phrases.
- Do not persist seed phrases in UI state.
- Any future “show seed” UX should be opt-in, require explicit confirmation, and be displayed only on-demand.

## Git conventions
- Do not commit build outputs or binaries. Keep `.gitignore` updated (e.g. `dist/`, built executables).
- Do not add any automated co-author lines to commit messages.
