package main

import (
	"bufio"
	"context"
	"embed"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

//go:embed ui/*
var uiFS embed.FS

type appState struct {
	mu sync.RWMutex

	started bool
	pid     int

	uiAddr     string
	daemonAPI  string
	dataDir    string
	walletFile string
	listenAddr string

	// Suggested/default storage locations.
	portableDataDir    string
	portableWalletFile string
	configDataDir      string
	configWalletFile   string

	lastError string

	cmd   *exec.Cmd
	token string
}

func (s *appState) snapshot() map[string]any {
	s.mu.RLock()
	started := s.started
	pid := s.pid
	uiAddr := s.uiAddr
	daemonAPI := s.daemonAPI
	dataDir := s.dataDir
	walletFile := s.walletFile
	listenAddr := s.listenAddr
	lastError := s.lastError

	portableDataDir := s.portableDataDir
	portableWalletFile := s.portableWalletFile
	configDataDir := s.configDataDir
	configWalletFile := s.configWalletFile
	s.mu.RUnlock()

	return map[string]any{
		"started":       started,
		"pid":           pid,
		"ui_addr":       uiAddr,
		"daemon_api":    daemonAPI,
		"data_dir":      dataDir,
		"wallet_file":   walletFile,
		"wallet_exists": fileExists(walletFile),
		"listen_addr":   listenAddr,
		"last_error":    lastError,

		"portable_data_dir":      portableDataDir,
		"portable_wallet_file":   portableWalletFile,
		"portable_wallet_exists": fileExists(portableWalletFile),
		"config_data_dir":        configDataDir,
		"config_wallet_file":     configWalletFile,
		"config_wallet_exists":   fileExists(configWalletFile),
	}
}

func (s *appState) setError(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err == nil {
		s.lastError = ""
		return
	}
	s.lastError = err.Error()
}

func (s *appState) setPaths(dataDir, walletFile string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.started {
		return fmt.Errorf("daemon is running")
	}
	s.dataDir = dataDir
	s.walletFile = walletFile
	return nil
}

func main() {
	uiAddr := flag.String("ui", "127.0.0.1:8088", "UI listen address")
	daemonAPI := flag.String("daemon-api", "127.0.0.1:8332", "Daemon API address")
	listenAddr := flag.String("listen", "/ip4/0.0.0.0/tcp/28080", "P2P listen address passed to daemon")

	dataDir := flag.String("data", "", "Data dir (default: auto)")
	walletFile := flag.String("wallet", "", "Wallet file path (default: auto)")

	noBrowser := flag.Bool("no-browser", false, "Do not auto-open the browser")
	flag.Parse()

	exe, err := os.Executable()
	if err != nil {
		exe = "."
	}
	exeDir := filepath.Dir(exe)

	cfgDir, err := os.UserConfigDir()
	if err != nil {
		cfgDir = "."
	}

	// Portable storage lives alongside the binaries (for the dist/ bundle).
	// NOTE: can't use "blocknet" here because that collides with the bundled daemon binary name.
	portableBase := filepath.Join(exeDir, "blocknet-miner-data")
	portableDataDir := filepath.Join(portableBase, "data")
	portableWalletFile := filepath.Join(portableBase, "wallet.dat")

	// Config storage lives under the OS user config dir.
	configBase := filepath.Join(cfgDir, "blocknet")
	configDataDir := filepath.Join(configBase, "data")
	configWalletFile := filepath.Join(configBase, "wallet.dat")

	// Auto defaulting:
	// - If a config wallet exists, assume this is an existing install and use config paths.
	// - Otherwise, default to portable paths (so new installs are portable by default).
	if *dataDir == "" && *walletFile == "" {
		if fileExists(configWalletFile) {
			*dataDir = configDataDir
			*walletFile = configWalletFile
		} else {
			*dataDir = portableDataDir
			*walletFile = portableWalletFile
		}
	} else {
		// Backwards compatible behavior for partial overrides.
		if *dataDir == "" {
			*dataDir = configDataDir
		}
		if *walletFile == "" {
			*walletFile = configWalletFile
		}
	}

	st := &appState{
		uiAddr:     *uiAddr,
		daemonAPI:  *daemonAPI,
		dataDir:    *dataDir,
		walletFile: *walletFile,
		listenAddr: *listenAddr,

		portableDataDir:    portableDataDir,
		portableWalletFile: portableWalletFile,
		configDataDir:      configDataDir,
		configWalletFile:   configWalletFile,
	}

	mux := http.NewServeMux()

	// UI assets
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) { serveUIFile(w, r, "ui/index.html") })
	mux.HandleFunc("GET /app.js", func(w http.ResponseWriter, r *http.Request) { serveUIFile(w, r, "ui/app.js") })
	mux.HandleFunc("GET /style.css", func(w http.ResponseWriter, r *http.Request) { serveUIFile(w, r, "ui/style.css") })
	mux.HandleFunc("GET /favicon.ico", func(w http.ResponseWriter, r *http.Request) { serveUIFile(w, r, "ui/favicon.ico") })
	mux.HandleFunc("GET /favicon-16.png", func(w http.ResponseWriter, r *http.Request) { serveUIFile(w, r, "ui/favicon-16.png") })
	mux.HandleFunc("GET /favicon-32.png", func(w http.ResponseWriter, r *http.Request) { serveUIFile(w, r, "ui/favicon-32.png") })
	mux.HandleFunc("GET /apple-touch-icon.png", func(w http.ResponseWriter, r *http.Request) { serveUIFile(w, r, "ui/apple-touch-icon.png") })
	mux.HandleFunc("GET /blocknet.png", func(w http.ResponseWriter, r *http.Request) { serveUIFile(w, r, "ui/blocknet.png") })

	// Local control
	mux.HandleFunc("GET /local/state", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, st.snapshot())
	})
	mux.HandleFunc("POST /local/start", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Password string `json:"password"`
			Threads  int    `json:"threads"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeErr(w, http.StatusBadRequest, "invalid JSON")
			return
		}
		if strings.TrimSpace(req.Password) == "" {
			writeErr(w, http.StatusBadRequest, "password required")
			return
		}
		if req.Threads < 1 {
			req.Threads = 1
		}

		if err := st.startDaemon(req.Password, req.Threads); err != nil {
			st.setError(err)
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		st.setError(nil)
		writeJSON(w, http.StatusOK, st.snapshot())
	})

	mux.HandleFunc("POST /local/recover", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Mnemonic string `json:"mnemonic"`
			Password string `json:"password"`
			Threads  int    `json:"threads"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeErr(w, http.StatusBadRequest, "invalid JSON")
			return
		}

		mnemonic := strings.Join(strings.Fields(req.Mnemonic), " ")
		if mnemonic == "" {
			writeErr(w, http.StatusBadRequest, "mnemonic required")
			return
		}
		if strings.TrimSpace(req.Password) == "" {
			writeErr(w, http.StatusBadRequest, "password required")
			return
		}
		if req.Threads < 1 {
			req.Threads = 1
		}

		if err := st.recoverWallet(mnemonic, req.Password, req.Threads); err != nil {
			st.setError(err)
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		st.setError(nil)
		writeJSON(w, http.StatusOK, st.snapshot())
	})

	mux.HandleFunc("POST /local/save-wallet", func(w http.ResponseWriter, r *http.Request) {
		st.mu.RLock()
		defaultWallet := st.walletFile
		defaultDataDir := st.dataDir
		st.mu.RUnlock()

		path, err := pickSaveFile("Create wallet file", defaultWallet)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		if strings.TrimSpace(path) == "" {
			writeJSON(w, http.StatusOK, st.snapshot())
			return
		}
		if fileExists(path) {
			writeErr(w, http.StatusConflict, "wallet file already exists (use choose wallet file instead)")
			return
		}

		if err := st.setPaths(defaultDataDir, path); err != nil {
			writeErr(w, http.StatusConflict, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, st.snapshot())
	})
	mux.HandleFunc("POST /local/stop", func(w http.ResponseWriter, r *http.Request) {
		if err := st.stopDaemon(); err != nil {
			st.setError(err)
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		st.setError(nil)
		writeJSON(w, http.StatusOK, st.snapshot())
	})

	mux.HandleFunc("POST /local/use-portable", func(w http.ResponseWriter, r *http.Request) {
		if err := st.setPaths(st.portableDataDir, st.portableWalletFile); err != nil {
			writeErr(w, http.StatusConflict, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, st.snapshot())
	})

	mux.HandleFunc("POST /local/use-config", func(w http.ResponseWriter, r *http.Request) {
		if err := st.setPaths(st.configDataDir, st.configWalletFile); err != nil {
			writeErr(w, http.StatusConflict, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, st.snapshot())
	})

	mux.HandleFunc("POST /local/pick-wallet", func(w http.ResponseWriter, r *http.Request) {
		st.mu.RLock()
		defaultWallet := st.walletFile
		defaultDataDir := st.dataDir
		st.mu.RUnlock()

		path, err := pickFile("Select wallet.dat", defaultWallet)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		if strings.TrimSpace(path) == "" {
			// User cancelled.
			writeJSON(w, http.StatusOK, st.snapshot())
			return
		}

		if err := st.setPaths(defaultDataDir, path); err != nil {
			writeErr(w, http.StatusConflict, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, st.snapshot())
	})

	mux.HandleFunc("POST /local/pick-data", func(w http.ResponseWriter, r *http.Request) {
		st.mu.RLock()
		defaultDataDir := st.dataDir
		defaultWallet := st.walletFile
		st.mu.RUnlock()

		path, err := pickDir("Select chain/data directory", defaultDataDir)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		if strings.TrimSpace(path) == "" {
			// User cancelled.
			writeJSON(w, http.StatusOK, st.snapshot())
			return
		}

		if err := st.setPaths(path, defaultWallet); err != nil {
			writeErr(w, http.StatusConflict, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, st.snapshot())
	})

	// Reverse proxy to daemon API (injects bearer token)
	proxy := st.daemonProxy()
	daemon := http.StripPrefix("/daemon", proxy)
	// Go's ServeMux treats a path-only pattern ("/daemon/") as matching *all* methods.
	// That conflicts with method-specific catch-alls like "GET /".
	mux.Handle("GET /daemon/", daemon)
	mux.Handle("POST /daemon/", daemon)

	srv := &http.Server{
		Addr:         st.uiAddr,
		Handler:      withNoCache(mux),
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	var shutdownOnce sync.Once
	shutdown := func() {
		shutdownOnce.Do(func() {
			_ = st.stopDaemon()

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = srv.Shutdown(ctx)
		})
	}

	mux.HandleFunc("POST /local/quit", func(w http.ResponseWriter, r *http.Request) {
		// Respond first, then shut down shortly after so the browser can receive the reply.
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
		go func() {
			time.Sleep(100 * time.Millisecond)
			shutdown()
		}()
	})

	registerShutdown(shutdown)

	fmt.Printf("blocknet-miner listening on http://%s\n", st.uiAddr)
	fmt.Printf("data dir: %s\n", st.dataDir)
	fmt.Printf("wallet:   %s\n", st.walletFile)
	fmt.Println("open the URL above in your browser")

	if !*noBrowser {
		go openBrowser("http://" + st.uiAddr)
	}

	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		fmt.Fprintf(os.Stderr, "server error: %v\n", err)
		os.Exit(1)
	}
}

func serveUIFile(w http.ResponseWriter, r *http.Request, name string) {
	b, err := uiFS.ReadFile(name)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if strings.HasSuffix(name, ".css") {
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
	}
	if strings.HasSuffix(name, ".js") {
		w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	}
	if strings.HasSuffix(name, ".html") {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
	}
	_, _ = w.Write(b)
}

func (s *appState) daemonProxy() http.Handler {
	target := &url.URL{Scheme: "http", Host: s.daemonAPI}
	proxy := httputil.NewSingleHostReverseProxy(target)

	proxy.Director = func(r *http.Request) {
		r.URL.Scheme = target.Scheme
		r.URL.Host = target.Host
		r.Host = target.Host

		s.mu.RLock()
		tok := s.token
		s.mu.RUnlock()
		if tok != "" {
			r.Header.Set("Authorization", "Bearer "+tok)
		}
	}

	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		writeErr(w, http.StatusBadGateway, "daemon unavailable")
	}

	return proxy
}

func (s *appState) startDaemon(password string, threads int) error {
	return s.startDaemonInternal("", password, threads)
}

func (s *appState) recoverWallet(mnemonic, password string, threads int) error {
	// First, create/recover the wallet file using the CLI-style flow.
	// This mirrors `blocknet --recover` behavior without changing the daemon.
	if err := s.runRecoveryCLI(mnemonic, password); err != nil {
		return err
	}

	// Then start the daemon in headless API mode and load the recovered wallet.
	return s.startDaemonInternal("", password, threads)
}

func (s *appState) startDaemonInternal(mnemonic, password string, threads int) error {
	s.mu.Lock()
	if s.started {
		s.mu.Unlock()
		return nil
	}
	s.mu.Unlock()

	if err := os.MkdirAll(s.dataDir, 0o700); err != nil {
		return fmt.Errorf("create data dir: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(s.walletFile), 0o700); err != nil {
		return fmt.Errorf("create wallet dir: %w", err)
	}

	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("find executable: %w", err)
	}
	exeDir := filepath.Dir(exe)

	daemonBin, err := findBundledDaemon(exeDir)
	if err != nil {
		return err
	}

	cookiePath := filepath.Join(s.dataDir, "api.cookie")
	_ = os.Remove(cookiePath)

	args := []string{
		"--daemon",
		"--data", s.dataDir,
		"--wallet", s.walletFile,
		"--listen", s.listenAddr,
		"--api", s.daemonAPI,
	}

	cmd := exec.Command(daemonBin, args...)
	stdout, _ := cmd.StdoutPipe()
	stderr, _ := cmd.StderrPipe()

	setProcAttrs(cmd)

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start daemon: %w", err)
	}

	// Consume output so the daemon can't block if it gets chatty.
	go drain("daemon-stdout", stdout)
	go drain("daemon-stderr", stderr)

	s.mu.Lock()
	s.cmd = cmd
	s.started = true
	s.pid = cmd.Process.Pid
	s.token = ""
	s.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := s.waitForCookie(ctx, cookiePath); err != nil {
		_ = s.stopDaemon()
		return err
	}

	tokBytes, err := os.ReadFile(cookiePath)
	if err != nil {
		_ = s.stopDaemon()
		return fmt.Errorf("read api cookie: %w", err)
	}
	tok := strings.TrimSpace(string(tokBytes))
	if tok == "" {
		_ = s.stopDaemon()
		return fmt.Errorf("api cookie empty")
	}

	s.mu.Lock()
	s.token = tok
	s.mu.Unlock()

	// Load (or create+load) the wallet via the authenticated API.
	if err := s.loadWalletViaAPI(ctx, password); err != nil {
		_ = s.stopDaemon()
		return err
	}

	// Apply thread count immediately.
	_ = s.setMiningThreads(ctx, threads)

	return nil
}

func (s *appState) waitForCookie(ctx context.Context, path string) error {
	t := time.NewTicker(150 * time.Millisecond)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("daemon did not become ready (api.cookie not found)")
		case <-t.C:
			if fi, err := os.Stat(path); err == nil && fi.Size() > 0 {
				return nil
			}
		}
	}
}

func (s *appState) setMiningThreads(ctx context.Context, threads int) error {
	s.mu.RLock()
	tok := s.token
	api := s.daemonAPI
	s.mu.RUnlock()
	if tok == "" {
		return fmt.Errorf("no api token")
	}

	body := strings.NewReader(fmt.Sprintf(`{"threads": %d}`, threads))
	req, _ := http.NewRequestWithContext(ctx, "POST", "http://"+api+"/api/mining/threads", body)
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("set threads failed: %s", strings.TrimSpace(string(b)))
	}
	return nil
}

// loadWalletViaAPI calls the daemon's authenticated /api/wallet/load endpoint.
// This replaces the old stdin-based password prompts in daemon mode.
func (s *appState) loadWalletViaAPI(ctx context.Context, password string) error {
	password = strings.TrimSpace(password)
	if password == "" {
		return fmt.Errorf("password required")
	}

	s.mu.RLock()
	api := s.daemonAPI
	tok := s.token
	s.mu.RUnlock()

	if tok == "" {
		return fmt.Errorf("no api token")
	}

	body := strings.NewReader(fmt.Sprintf(`{"password": %q}`, password))
	req, _ := http.NewRequestWithContext(ctx, "POST", "http://"+api+"/api/wallet/load", body)
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("load wallet: %w", err)
	}
	defer resp.Body.Close()

	// 409 = wallet already loaded – treat as success for idempotency / older daemons.
	if resp.StatusCode == http.StatusConflict {
		return nil
	}

	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("load wallet failed: %s", strings.TrimSpace(string(b)))
	}

	return nil
}

func (s *appState) stopDaemon() error {
	s.mu.Lock()
	cmd := s.cmd
	started := s.started
	s.mu.Unlock()
	if !started || cmd == nil || cmd.Process == nil {
		return nil
	}

	// Try graceful shutdown.
	_ = interruptProcess(cmd)

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	select {
	case <-time.After(5 * time.Second):
		_ = killProcess(cmd)
		<-done
	case <-done:
	}

	s.mu.Lock()
	s.cmd = nil
	s.started = false
	s.pid = 0
	s.token = ""
	s.mu.Unlock()
	return nil
}

// runRecoveryCLI mirrors `blocknet --recover` by running the bundled daemon
// in interactive recovery mode to create a wallet file from a mnemonic.
// Once the wallet file exists, the main daemon process can be started in
// headless API mode and the wallet loaded via /api/wallet/load.
func (s *appState) runRecoveryCLI(mnemonic, password string) error {
	mnemonic = strings.Join(strings.Fields(mnemonic), " ")
	if mnemonic == "" {
		return fmt.Errorf("mnemonic required")
	}
	password = strings.TrimSpace(password)
	if password == "" {
		return fmt.Errorf("password required")
	}

	// Snapshot paths under lock.
	s.mu.RLock()
	dataDir := s.dataDir
	walletFile := s.walletFile
	listenAddr := s.listenAddr
	s.mu.RUnlock()

	if fileExists(walletFile) {
		return fmt.Errorf("wallet already exists at %s", walletFile)
	}

	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return fmt.Errorf("create data dir: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(walletFile), 0o700); err != nil {
		return fmt.Errorf("create wallet dir: %w", err)
	}

	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("find executable: %w", err)
	}
	exeDir := filepath.Dir(exe)

	daemonBin, err := findBundledDaemon(exeDir)
	if err != nil {
		return err
	}

	args := []string{
		"--wallet", walletFile,
		"--data", dataDir,
		"--listen", listenAddr,
		"--recover",
	}

	cmd := exec.Command(daemonBin, args...)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("stdin pipe (recover): %w", err)
	}
	stdout, _ := cmd.StdoutPipe()
	stderr, _ := cmd.StderrPipe()

	setProcAttrs(cmd)

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start recover process: %w", err)
	}

	// Feed mnemonic + password prompts just like the interactive CLI.
	go func() {
		defer stdin.Close()
		_, _ = io.WriteString(stdin, mnemonic+"\n"+password+"\n"+password+"\n")
	}()

	// Drain output so the process can't block.
	go drain("recover-stdout", stdout)
	go drain("recover-stderr", stderr)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	t := time.NewTicker(250 * time.Millisecond)
	defer t.Stop()

	for {
		select {
		case err := <-done:
			if err != nil {
				return fmt.Errorf("wallet recovery failed: %w", err)
			}
			if !fileExists(walletFile) {
				return fmt.Errorf("wallet recovery exited but wallet not found at %s", walletFile)
			}
			return nil

		case <-t.C:
			if fi, err := os.Stat(walletFile); err == nil && fi.Size() > 0 {
				// Wallet file exists and is non-empty – we can stop the helper process.
				_ = interruptProcess(cmd)
				return nil
			}

		case <-ctx.Done():
			_ = killProcess(cmd)
			return fmt.Errorf("wallet recovery timed out")
		}
	}
}

func drain(name string, r io.Reader) {
	if r == nil {
		return
	}
	s := bufio.NewScanner(r)
	for s.Scan() {
		_ = name
		// Intentionally discard. (Later: wire into UI log panel.)
	}
}

func withNoCache(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func openBrowser(urlStr string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", urlStr)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", urlStr)
	default:
		cmd = exec.Command("xdg-open", urlStr)
	}
	_ = cmd.Start()
}

func findBundledDaemon(dir string) (string, error) {
	candidates := []string{"blocknetd", "blocknet"}
	for _, name := range candidates {
		path := filepath.Join(dir, name)
		if runtime.GOOS == "windows" {
			path += ".exe"
		}
		if _, err := os.Stat(path); err == nil {
			return path, nil
		}
	}

	return "", fmt.Errorf("bundled daemon binary not found next to launcher (expected blocknetd or blocknet in %s)", dir)
}

func pickFile(title, initialPath string) (string, error) {
	switch runtime.GOOS {
	case "linux":
		if _, err := exec.LookPath("zenity"); err == nil {
			args := []string{"--file-selection", "--title=" + title}
			if strings.TrimSpace(initialPath) != "" {
				args = append(args, "--filename="+initialPath)
			}
			out, err := exec.Command("zenity", args...).Output()
			if err != nil {
				return "", nil // cancelled
			}
			return strings.TrimSpace(string(out)), nil
		}

		if _, err := exec.LookPath("kdialog"); err == nil {
			// kdialog --getopenfilename [startDir]
			start := ""
			if strings.TrimSpace(initialPath) != "" {
				start = filepath.Dir(initialPath)
			}
			args := []string{"--title", title, "--getopenfilename"}
			if start != "" {
				args = append(args, start)
			}
			out, err := exec.Command("kdialog", args...).Output()
			if err != nil {
				return "", nil // cancelled
			}
			return strings.TrimSpace(string(out)), nil
		}

		return "", fmt.Errorf("no file picker found (install zenity or kdialog, or set --wallet/--data manually)")

	case "darwin":
		if _, err := exec.LookPath("osascript"); err != nil {
			return "", fmt.Errorf("osascript not found")
		}

		dir := ""
		if strings.TrimSpace(initialPath) != "" {
			dir = filepath.Dir(initialPath)
		}
		script := "POSIX path of (choose file with prompt \"" + strings.ReplaceAll(title, "\"", "\\\"") + "\""
		if dir != "" {
			script += " default location (POSIX file \"" + strings.ReplaceAll(dir, "\"", "\\\"") + "\")"
		}
		script += ")"

		out, err := exec.Command("osascript", "-e", script).Output()
		if err != nil {
			return "", nil // cancelled
		}
		return strings.TrimSpace(string(out)), nil

	case "windows":
		// Use PowerShell + WinForms dialogs.
		ps := "powershell"
		if _, err := exec.LookPath(ps); err != nil {
			return "", fmt.Errorf("powershell not found")
		}

		q := func(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }
		script := `Add-Type -AssemblyName System.Windows.Forms; ` +
			`$dlg = New-Object System.Windows.Forms.OpenFileDialog; ` +
			`$dlg.Title = ` + q(title) + `; ` +
			`$dlg.Filter = 'Wallet files|*.dat|All files|*.*'; ` +
			`$init = ` + q(initialPath) + `; ` +
			`if ($init -ne '') { ` +
			`  $dlg.InitialDirectory = [System.IO.Path]::GetDirectoryName($init); ` +
			`  $dlg.FileName = [System.IO.Path]::GetFileName($init); ` +
			`} else { $dlg.FileName = 'wallet.dat' }; ` +
			`if ($dlg.ShowDialog() -eq 'OK') { Write-Output $dlg.FileName }`

		out, err := exec.Command(ps, "-NoProfile", "-Command", script).Output()
		if err != nil {
			return "", nil // cancelled
		}
		return strings.TrimSpace(string(out)), nil
	}

	return "", fmt.Errorf("file picker not supported on this OS")
}

func pickDir(title, initialDir string) (string, error) {
	switch runtime.GOOS {
	case "linux":
		if _, err := exec.LookPath("zenity"); err == nil {
			args := []string{"--file-selection", "--directory", "--title=" + title}
			if strings.TrimSpace(initialDir) != "" {
				args = append(args, "--filename="+initialDir+string(os.PathSeparator))
			}
			out, err := exec.Command("zenity", args...).Output()
			if err != nil {
				return "", nil // cancelled
			}
			return strings.TrimSpace(string(out)), nil
		}

		if _, err := exec.LookPath("kdialog"); err == nil {
			args := []string{"--title", title, "--getexistingdirectory"}
			if strings.TrimSpace(initialDir) != "" {
				args = append(args, initialDir)
			}
			out, err := exec.Command("kdialog", args...).Output()
			if err != nil {
				return "", nil
			}
			return strings.TrimSpace(string(out)), nil
		}

		return "", fmt.Errorf("no directory picker found (install zenity or kdialog, or set --wallet/--data manually)")

	case "darwin":
		if _, err := exec.LookPath("osascript"); err != nil {
			return "", fmt.Errorf("osascript not found")
		}

		script := "POSIX path of (choose folder with prompt \"" + strings.ReplaceAll(title, "\"", "\\\"") + "\""
		if strings.TrimSpace(initialDir) != "" {
			script += " default location (POSIX file \"" + strings.ReplaceAll(initialDir, "\"", "\\\"") + "\")"
		}
		script += ")"

		out, err := exec.Command("osascript", "-e", script).Output()
		if err != nil {
			return "", nil
		}
		return strings.TrimSpace(string(out)), nil

	case "windows":
		ps := "powershell"
		if _, err := exec.LookPath(ps); err != nil {
			return "", fmt.Errorf("powershell not found")
		}

		q := func(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }
		script := `Add-Type -AssemblyName System.Windows.Forms; ` +
			`$dlg = New-Object System.Windows.Forms.FolderBrowserDialog; ` +
			`$dlg.Description = ` + q(title) + `; ` +
			`$init = ` + q(initialDir) + `; ` +
			`if ($init -ne '') { $dlg.SelectedPath = $init }; ` +
			`if ($dlg.ShowDialog() -eq 'OK') { Write-Output $dlg.SelectedPath }`

		out, err := exec.Command(ps, "-NoProfile", "-Command", script).Output()
		if err != nil {
			return "", nil
		}
		return strings.TrimSpace(string(out)), nil
	}

	return "", fmt.Errorf("directory picker not supported on this OS")
}

func pickSaveFile(title, initialPath string) (string, error) {
	switch runtime.GOOS {
	case "linux":
		if _, err := exec.LookPath("zenity"); err == nil {
			args := []string{"--file-selection", "--save", "--confirm-overwrite", "--title=" + title}
			if strings.TrimSpace(initialPath) != "" {
				args = append(args, "--filename="+initialPath)
			}
			out, err := exec.Command("zenity", args...).Output()
			if err != nil {
				return "", nil
			}
			return strings.TrimSpace(string(out)), nil
		}

		if _, err := exec.LookPath("kdialog"); err == nil {
			start := initialPath
			if strings.TrimSpace(start) == "" {
				start = "wallet.dat"
			}
			out, err := exec.Command("kdialog", "--title", title, "--getsavefilename", start).Output()
			if err != nil {
				return "", nil
			}
			return strings.TrimSpace(string(out)), nil
		}

		return "", fmt.Errorf("no save-file picker found (install zenity or kdialog, or set --wallet manually)")

	case "darwin":
		if _, err := exec.LookPath("osascript"); err != nil {
			return "", fmt.Errorf("osascript not found")
		}

		dir := ""
		name := "wallet.dat"
		if strings.TrimSpace(initialPath) != "" {
			dir = filepath.Dir(initialPath)
			name = filepath.Base(initialPath)
		}

		script := "POSIX path of (choose file name with prompt \"" + strings.ReplaceAll(title, "\"", "\\\"") + "\" default name \"" + strings.ReplaceAll(name, "\"", "\\\"") + "\""
		if strings.TrimSpace(dir) != "" {
			script += " default location (POSIX file \"" + strings.ReplaceAll(dir, "\"", "\\\"") + "\")"
		}
		script += ")"

		out, err := exec.Command("osascript", "-e", script).Output()
		if err != nil {
			return "", nil
		}
		return strings.TrimSpace(string(out)), nil

	case "windows":
		ps := "powershell"
		if _, err := exec.LookPath(ps); err != nil {
			return "", fmt.Errorf("powershell not found")
		}

		q := func(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }
		script := `Add-Type -AssemblyName System.Windows.Forms; ` +
			`$dlg = New-Object System.Windows.Forms.SaveFileDialog; ` +
			`$dlg.Title = ` + q(title) + `; ` +
			`$dlg.OverwritePrompt = $true; ` +
			`$dlg.Filter = 'Wallet files|*.dat|All files|*.*'; ` +
			`$init = ` + q(initialPath) + `; ` +
			`if ($init -ne '') { ` +
			`  $dlg.InitialDirectory = [System.IO.Path]::GetDirectoryName($init); ` +
			`  $dlg.FileName = [System.IO.Path]::GetFileName($init); ` +
			`} else { $dlg.FileName = 'wallet.dat' }; ` +
			`if ($dlg.ShowDialog() -eq 'OK') { Write-Output $dlg.FileName }`

		out, err := exec.Command(ps, "-NoProfile", "-Command", script).Output()
		if err != nil {
			return "", nil
		}
		return strings.TrimSpace(string(out)), nil
	}

	return "", fmt.Errorf("save-file picker not supported on this OS")
}
