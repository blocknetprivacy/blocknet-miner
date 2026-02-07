# blocknet-miner
A desktop-friendly launcher for the Blocknet daemon.

Goal (MVP): solo mining + wallet visibility without using a terminal.

## How it works
- `blocknet-miner` starts a bundled daemon binary in the background.
- It serves a local web UI (default `127.0.0.1:8088`).
- The UI talks to the daemon through a local reverse proxy (`/daemon/...`) so the browser never needs the daemon Bearer token.

## Storage model (portable by default)
This launcher supports two storage locations:
- **Portable** (recommended for new installs): stored next to the launcher binary.
  - Creates `blocknet-miner-data/` alongside the executable.
  - Contains the chain data dir (`data/`) and your wallet file.
- **System**: stored in your OS user config directory.

The UI includes a **Storage** section that lets you:
- switch between portable/system storage (when the daemon is stopped)
- choose an existing wallet file and existing data directory
- create a new wallet file with a custom name (Save As)

## Wallet recovery seed
- Use **wallet → show recovery seed** to reveal the 12-word BIP39 seed.
- This is opt-in and requires password confirmation.
- The seed is not persisted in UI state.

Note: this requires a daemon build that includes the private endpoint `POST /api/wallet/seed`.

## Import seed (recover wallet)
Use **Storage → create wallet file…** (pick a new filename/path), then **Storage → import seed…**.
This runs the daemon in `--recover` mode and creates a new wallet file at the selected path.

## Mining
- Use **mining → start mining / stop mining**.
- Change the thread count in the input and click **apply threads**.
  - Thread changes take effect on the next block attempt.

## Quit
Use **quit app** to stop the daemon and exit the launcher.

## Help
See `HELP.md`. If anything is confusing or broken, please open an issue.

## Build
```sh
make build
```

## Bundle (dist folder)
This creates `dist/blocknet-miner` and bundles the daemon as `dist/blocknetd`.

```sh
make dist
# or
make dist BLOCKNET_BIN=/path/to/blocknet
# (common local dev setup)
make dist BLOCKNET_BIN=../blocknet/blocknet
```

## Run
```sh
./dist/blocknet-miner
```
Then open the printed URL.

## Tests / sanity checks
```sh
go test ./...
```

## Status
This repo is a prototype, but it is now usable for basic mining + wallet management.
