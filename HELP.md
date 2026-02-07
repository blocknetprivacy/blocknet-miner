# blocknet-miner help
This app is local-only and does not include telemetry.

The UI reverse-proxies the daemon API via `/daemon/...` so the browser never needs the daemon Bearer token.

## Quick start
1. (Optional) Pick your storage under **Storage** *before* starting the daemon.
2. Enter a wallet password and click **start daemon**.
3. Click **start mining** to begin solo mining.
4. Back up your wallet seed (see below).

## Storage
You can keep everything portable (next to the app) or use system config directories.

Storage paths can only be changed while the daemon is stopped.

Actions:
- **use portable**: store chain + wallet next to the executable (creates `blocknet-miner-data/`).
- **use system**: store chain + wallet under your OS config directory.
- **create wallet file…**: Save As dialog to choose a *new* wallet filename/path.
- **choose wallet file**: pick an existing wallet file.
- **choose data dir**: pick an existing chain/data directory.

Notes:
- On Linux, the app uses `zenity` (or falls back to `kdialog`) for file dialogs.
- On macOS it uses `osascript`.
- On Windows it uses PowerShell + WinForms dialogs.

## Wallet backup (recovery seed)
Your recovery seed controls all funds.

- Anyone with this seed can steal your coins.
- Never share it.
- Never enter it online.
- Store it offline.

To reveal the seed:
1. Open the **wallet** card.
2. Click **show recovery seed**.
3. Confirm, re-enter your wallet password, and write the 12 words down.

## Import seed (wallet recovery)
Recovering from seed creates a new encrypted wallet file at the currently selected wallet path.

Recommended flow:
1. Storage → **create wallet file…** (pick a new filename/path).
2. (Optional) Storage → **choose data dir** if you want to reuse existing chain data.
3. Storage → **import seed…** → enter seed and set a new password → **recover + start**.

Safety notes:
- For safety, the app refuses to recover into an existing wallet file.
- If you need to recover alongside an existing wallet, use a different filename.

## Mining
- Start/stop: use **start mining** / **stop mining**.
- Threads: change the number and click **apply threads**.

Note: Argon2id PoW uses ~2GB RAM per thread.

## Quit
Use **quit app** to stop the daemon and close the launcher.

## Troubleshooting
- If the daemon won’t start, check the **daemon** card details for the last error.
- If controls are disabled, stop the daemon first (some actions are only valid when stopped).
- If the UI doesn’t prompt again, clear Local Storage for this UI origin.

## Still stuck?
If you still have questions or hit a bug, please open an issue and include:
- your OS + version
- what you clicked / expected
- the **last error** shown in the daemon panel (if any)
- whether you’re using portable or system storage
