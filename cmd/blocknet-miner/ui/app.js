async function jfetch(path, opts = {}) {
  const res = await fetch(path, {
    headers: { "Content-Type": "application/json" },
    ...opts,
  });
  const text = await res.text();
  let data = null;
  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    data = { raw: text };
  }
  if (!res.ok) {
    const msg = (data && (data.error || data.message)) || res.statusText;
    throw new Error(msg);
  }
  return data;
}

function humanKey(k) {
  return String(k)
    .replace(/_/g, " ")
    .replace(/\s+/g, " ")
    .trim()
    .replace(/^\w/, (c) => c.toUpperCase());
}

function atomicToBNT(n) {
  const v = Number(n);
  if (!Number.isFinite(v)) return null;
  return (v / 1e8).toFixed(8);
}

function timeAgo(dateStr) {
  const then = new Date(dateStr);
  if (isNaN(then)) return null;
  const seconds = Math.floor((Date.now() - then) / 1000);
  if (seconds < 5) return "just now";
  if (seconds < 60) return `${seconds}s ago`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ${minutes % 60}m ago`;
  const days = Math.floor(hours / 24);
  return `${days}d ${hours % 24}h ago`;
}

function formatValue(key, val) {
  // Known atomic-unit fields.
  if (key === "spendable" || key === "pending" || key === "total" || key === "amount") {
    const bnt = atomicToBNT(val);
    if (bnt != null) {
      return { main: `${bnt} BNT`, sub: `${val} atomic` };
    }
  }

  if (key === "hashrate" && typeof val === "number") {
    return { main: `${val.toFixed(4)} H/s` };
  }

  if (key === "started_at" && typeof val === "string") {
    const ago = timeAgo(val);
    if (ago) return { main: ago, title: val };
  }

  if (val == null) return { main: "-" };
  if (typeof val === "boolean") return { main: val ? "true" : "false" };
  if (typeof val === "number") return { main: String(val) };
  if (typeof val === "string") return { main: val };

  // Arrays / objects: keep compact so the table stays readable.
  try {
    return { main: JSON.stringify(val) };
  } catch {
    return { main: String(val) };
  }
}

function renderKV(el, obj, { order = [] } = {}) {
  if (!el) return;

  el.replaceChildren();

  if (!obj || typeof obj !== "object") {
    el.textContent = obj == null ? "-" : String(obj);
    return;
  }

  const keys = Object.keys(obj);
  const ordered = [];
  const seen = new Set();

  for (const k of order) {
    if (k in obj) {
      ordered.push(k);
      seen.add(k);
    }
  }
  for (const k of keys.sort()) {
    if (!seen.has(k)) ordered.push(k);
  }

  const table = document.createElement("table");
  const tbody = document.createElement("tbody");

  for (const k of ordered) {
    const tr = document.createElement("tr");

    const th = document.createElement("th");
    th.textContent = humanKey(k);

    const td = document.createElement("td");
    const formatted = formatValue(k, obj[k]);

    const main = document.createElement("span");
    main.textContent = formatted.main;
    if (formatted.title) td.title = formatted.title;
    td.appendChild(main);

    if (formatted.sub) {
      const sub = document.createElement("span");
      sub.className = "sub";
      sub.textContent = formatted.sub;
      td.appendChild(sub);
    }

    tr.appendChild(th);
    tr.appendChild(td);
    tbody.appendChild(tr);
  }

  table.appendChild(tbody);
  el.appendChild(table);
}

function setBoxText(el, text) {
  el.replaceChildren();
  const div = document.createElement("div");
  div.className = "kvText";
  div.textContent = text;
  el.appendChild(div);
}

function renderSeed(el, { mnemonic, words }) {
  el.replaceChildren();

  if (!mnemonic) {
    const msg = document.createElement("div");
    msg.className = "kvText";
    msg.textContent = "(no seed returned)";
    el.appendChild(msg);
    return;
  }

  const m = document.createElement("div");
  m.className = "seedMnemonic";
  m.textContent = mnemonic;
  el.appendChild(m);

  const ws = Array.isArray(words) && words.length ? words : String(mnemonic).split(/\s+/).filter(Boolean);
  const grid = document.createElement("div");
  grid.className = "seedWords";

  for (let i = 0; i < ws.length; i++) {
    const item = document.createElement("div");
    item.className = "seedWord";
    item.textContent = `${i + 1}. ${ws[i]}`;
    grid.appendChild(item);
  }

  el.appendChild(grid);
}

const STORAGE_PROMPT_KEY = "blocknetMinerStoragePrompted";
let autoPromptingStorage = false;
let daemonConnectedOnce = false;
let daemonStartedAt = 0;
const CONNECTING_GRACE_MS = 15000;

async function maybePromptStorageSetup(state) {
  if (autoPromptingStorage) return false;
  if (state.started) return false;

  // Existing install heuristic: system-config wallet exists but portable wallet doesn't.
  if (!state.config_wallet_exists || state.portable_wallet_exists) return false;

  if (localStorage.getItem(STORAGE_PROMPT_KEY) === "1") return false;

  autoPromptingStorage = true;
  localStorage.setItem(STORAGE_PROMPT_KEY, "1");

  const ok = confirm(
    "Existing wallet detected in the system config directory.\n\n" +
      "Do you want to select your existing wallet file and chain/data directory now?\n" +
      "(You can change this later under Storage.)"
  );

  if (ok) {
    try {
      await jfetch("/local/pick-wallet", { method: "POST" });
      await jfetch("/local/pick-data", { method: "POST" });
    } catch (e) {
      alert(e.message);
    }

    // Re-render soon with updated state.
    setTimeout(() => refresh().catch(() => {}), 0);
  }

  autoPromptingStorage = false;
  return ok;
}

async function refresh() {
  const state = await jfetch("/local/state");

  // If we triggered the prompt, let the next refresh render the updated paths.
  if (await maybePromptStorageSetup(state)) return;

  const line = document.getElementById("stateLine");
  const details = document.getElementById("daemonDetails");

  const startBtn = document.getElementById("startBtn");
  const stopBtn = document.getElementById("stopBtn");
  const mineStartBtn = document.getElementById("mineStartBtn");
  const mineStopBtn = document.getElementById("mineStopBtn");
  const seedBtn = document.getElementById("seedBtn");
  const applyThreadsBtn = document.getElementById("applyThreadsBtn");

  const portableBtn = document.getElementById("portableBtn");
  const configBtn = document.getElementById("configBtn");
  const saveWalletBtn = document.getElementById("saveWalletBtn");
  const pickWalletBtn = document.getElementById("pickWalletBtn");
  const pickDataBtn = document.getElementById("pickDataBtn");
  const recoverBtn = document.getElementById("recoverBtn");
  const storageDetails = document.getElementById("storageDetails");

  const statusEl = document.getElementById("statusOut");
  const walletEl = document.getElementById("walletOut");
  const miningEl = document.getElementById("miningOut");
  const walletHint = document.getElementById("walletHint");

  startBtn.disabled = !!state.started;
  stopBtn.disabled = !state.started;
  if (seedBtn) seedBtn.disabled = !state.started;
  if (applyThreadsBtn) applyThreadsBtn.disabled = !state.started;

  if (portableBtn) portableBtn.disabled = !!state.started;
  if (configBtn) configBtn.disabled = !!state.started;
  if (saveWalletBtn) saveWalletBtn.disabled = !!state.started;
  if (pickWalletBtn) pickWalletBtn.disabled = !!state.started;
  if (pickDataBtn) pickDataBtn.disabled = !!state.started;
  if (recoverBtn) recoverBtn.disabled = !!state.started;

  line.textContent = state.started
    ? `Daemon running (api=${state.daemon_api})`
    : "Daemon stopped";

  details.textContent = `wallet=${state.wallet_file}\ndata=${state.data_dir}` +
    (state.last_error ? `\nerror=${state.last_error}` : "");

  if (storageDetails) {
    storageDetails.textContent =
      `current:\n  wallet=${state.wallet_file} (${state.wallet_exists ? "exists" : "missing"})\n  data=${state.data_dir}` +
      `\n\nportable:\n  wallet=${state.portable_wallet_file} (${state.portable_wallet_exists ? "exists" : "missing"})\n  data=${state.portable_data_dir}` +
      `\n\nsystem:\n  wallet=${state.config_wallet_file} (${state.config_wallet_exists ? "exists" : "missing"})\n  data=${state.config_data_dir}`;
  }

  if (walletHint) {
    if (!state.wallet_exists) {
      walletHint.textContent = "No wallet found yet. Starting the daemon will create a new wallet. Back up your recovery seed after it starts.";
    } else {
      walletHint.textContent = "Back up: use “show recovery seed” and store it offline. Also copy the wallet file somewhere safe.";
    }
  }

  const walletActions = document.getElementById("walletActions");
  const miningActions = document.getElementById("miningActions");

  if (!state.started) {
    mineStartBtn.disabled = true;
    mineStopBtn.disabled = true;
    daemonConnectedOnce = false;
    daemonStartedAt = 0;

    walletActions.classList.add("hidden");
    miningActions.classList.add("hidden");

    setBoxText(statusEl, "(not connected)");
    setBoxText(walletEl, "(not connected)");
    setBoxText(miningEl, "(not connected)");
    return;
  }

  if (!daemonStartedAt) daemonStartedAt = Date.now();
  const connecting = !daemonConnectedOnce && (Date.now() - daemonStartedAt) < CONNECTING_GRACE_MS;

  try {
    const status = await jfetch("/daemon/api/status");
    daemonConnectedOnce = true;
    walletActions.classList.remove("hidden");
    miningActions.classList.remove("hidden");
    renderKV(statusEl, status, {
      order: [
        "chain_height",
        "peers",
        "syncing",
        "peer_id",
        "best_hash",
        "mempool_size",
        "mempool_bytes",
        "total_work",
        "identity_age",
      ],
    });
  } catch (e) {
    setBoxText(statusEl, connecting ? "connecting…" : `error: ${e.message}`);
  }

  try {
    const walletAddr = await jfetch("/daemon/api/wallet/address");
    const bal = await jfetch("/daemon/api/wallet/balance");
    const combined = { ...walletAddr, ...bal };

    renderKV(walletEl, combined, {
      order: [
        "address",
        "view_only",
        "spendable",
        "pending",
        "total",
        "outputs_unspent",
        "outputs_total",
        "chain_height",
      ],
    });
  } catch (e) {
    setBoxText(walletEl, connecting ? "connecting…" : `error: ${e.message}`);
  }

  try {
    const mining = await jfetch("/daemon/api/mining");
    renderKV(miningEl, mining, {
      order: ["running", "threads", "hashrate", "hash_count", "blocks_found", "started_at"],
    });

    // Make mining controls self-explanatory.
    mineStartBtn.disabled = !!mining.running;
    mineStopBtn.disabled = !mining.running;
  } catch (e) {
    setBoxText(miningEl, connecting ? "connecting…" : `error: ${e.message}`);
  }
}

async function onStart() {
  const passwordEl = document.getElementById("password");
  const password = passwordEl.value;
  const threads = Number(document.getElementById("threads").value || "1");
  await jfetch("/local/start", {
    method: "POST",
    body: JSON.stringify({ password, threads }),
  });

  // Don't keep the wallet password sitting in the DOM.
  passwordEl.value = "";

  await refresh();
}

async function onStop() {
  await jfetch("/local/stop", { method: "POST" });
  await refresh();
}

async function mineStart() {
  await jfetch("/daemon/api/mining/start", { method: "POST" });
  await refresh();
}

async function mineStop() {
  await jfetch("/daemon/api/mining/stop", { method: "POST" });
  await refresh();
}

async function applyThreads() {
  const threads = Number(document.getElementById("threads").value || "1");
  if (!Number.isFinite(threads) || threads < 1) throw new Error("threads must be >= 1");
  await jfetch("/daemon/api/mining/threads", {
    method: "POST",
    body: JSON.stringify({ threads }),
  });
  await refresh();
}

async function usePortable() {
  await jfetch("/local/use-portable", { method: "POST" });
  await refresh();
}

async function useConfig() {
  await jfetch("/local/use-config", { method: "POST" });
  await refresh();
}

async function saveWallet() {
  await jfetch("/local/save-wallet", { method: "POST" });
  await refresh();
}

async function pickWallet() {
  await jfetch("/local/pick-wallet", { method: "POST" });
  await refresh();
}

async function pickData() {
  await jfetch("/local/pick-data", { method: "POST" });
  await refresh();
}

async function quitApp() {
  const ok = confirm("Quit blocknet miner?\n\nThis will stop the daemon.");
  if (!ok) return;

  try {
    // The server may shut down before replying; treat errors as ok.
    await jfetch("/local/quit", { method: "POST" });
  } catch {
    // ignore
  }
}

const seedModal = document.getElementById("seedModal");
const seedPassword = document.getElementById("seedPassword");
const seedOut = document.getElementById("seedOut");

function openSeedModal() {
  if (!seedModal) return;
  seedOut.replaceChildren();
  seedPassword.value = "";
  seedModal.classList.remove("hidden");
  seedPassword.focus();
}

function closeSeedModal() {
  if (!seedModal) return;
  seedModal.classList.add("hidden");
  seedOut.replaceChildren();
  seedPassword.value = "";
}

const recoverModal = document.getElementById("recoverModal");
const recoverMnemonic = document.getElementById("recoverMnemonic");
const recoverPassword = document.getElementById("recoverPassword");
const recoverPassword2 = document.getElementById("recoverPassword2");

function openRecoverModal() {
  if (!recoverModal) return;
  recoverMnemonic.value = "";
  recoverPassword.value = "";
  recoverPassword2.value = "";
  recoverModal.classList.remove("hidden");
  recoverMnemonic.focus();
}

function closeRecoverModal() {
  if (!recoverModal) return;
  recoverModal.classList.add("hidden");
  recoverMnemonic.value = "";
  recoverPassword.value = "";
  recoverPassword2.value = "";
}

async function runRecover() {
  const mnemonic = recoverMnemonic.value;
  const p1 = recoverPassword.value;
  const p2 = recoverPassword2.value;
  if (!mnemonic || !mnemonic.trim()) throw new Error("seed required");
  if (!p1 || !p1.trim()) throw new Error("password required");
  if (p1 !== p2) throw new Error("passwords do not match");

  const threads = Number(document.getElementById("threads").value || "1");

  const ok = confirm(
    "Recover wallet from seed now?\n\n" +
      "This will create a new wallet file at the selected wallet path.\n" +
      "Make sure you are not overwriting an existing wallet."
  );
  if (!ok) return;

  await jfetch("/local/recover", {
    method: "POST",
    body: JSON.stringify({ mnemonic, password: p1, threads }),
  });

  closeRecoverModal();
  await refresh();
}

async function revealSeed() {
  const password = seedPassword.value;
  if (!password || !password.trim()) throw new Error("password required");

  const ok = confirm(
    "Show recovery seed now?\n\nAnyone with this seed can steal your coins. Write it down and store it offline."
  );
  if (!ok) return;

  const data = await jfetch("/daemon/api/wallet/seed", {
    method: "POST",
    body: JSON.stringify({ password }),
  });

  renderSeed(seedOut, data);
  seedPassword.value = "";
}

document.getElementById("startBtn").addEventListener("click", () => onStart().catch(alert));
document.getElementById("password").addEventListener("keydown", (e) => {
  if (e.key === "Enter") onStart().catch(alert);
});
document.getElementById("stopBtn").addEventListener("click", () => onStop().catch(alert));
document.getElementById("mineStartBtn").addEventListener("click", () => mineStart().catch(alert));
document.getElementById("mineStopBtn").addEventListener("click", () => mineStop().catch(alert));
document.getElementById("applyThreadsBtn").addEventListener("click", () => applyThreads().catch(alert));
document.getElementById("quitBtn").addEventListener("click", () => quitApp().catch(alert));

document.getElementById("seedBtn").addEventListener("click", () => openSeedModal());
document.getElementById("seedCancelBtn").addEventListener("click", () => closeSeedModal());
document.getElementById("seedRevealBtn").addEventListener("click", () => revealSeed().catch(alert));

document.getElementById("portableBtn").addEventListener("click", () => usePortable().catch(alert));
document.getElementById("configBtn").addEventListener("click", () => useConfig().catch(alert));
document.getElementById("saveWalletBtn").addEventListener("click", () => saveWallet().catch(alert));
document.getElementById("pickWalletBtn").addEventListener("click", () => pickWallet().catch(alert));
document.getElementById("pickDataBtn").addEventListener("click", () => pickData().catch(alert));
document.getElementById("recoverBtn").addEventListener("click", () => openRecoverModal());
document.getElementById("recoverCancelBtn").addEventListener("click", () => closeRecoverModal());
document.getElementById("recoverRunBtn").addEventListener("click", () => runRecover().catch(alert));

// Close modals when clicking backdrop.
seedModal.addEventListener("click", (e) => {
  if (e.target === seedModal) closeSeedModal();
});
recoverModal.addEventListener("click", (e) => {
  if (e.target === recoverModal) closeRecoverModal();
});

document.addEventListener("keydown", (e) => {
  if (e.key !== "Escape") return;
  closeSeedModal();
  closeRecoverModal();
});

refresh().catch(() => {});
setInterval(() => refresh().catch(() => {}), 1500);
