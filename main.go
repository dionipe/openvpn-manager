package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// ---------------------------------------------------------------------------
// Configuration (env file → TOON file → built-in defaults)
// ---------------------------------------------------------------------------

// configFile is the TOON-format configuration file.
const configFile = "/etc/openvpn/manager.toon"

// envFile is an optional KEY=VALUE file that sets env vars before everything
// else is read. Useful for per-server overrides without touching manager.toon.
const envFile = "/etc/openvpn/manager.env"

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// loadEnvFile parses a shell-style KEY=VALUE file and calls os.Setenv for
// each entry — but only when the variable is not already set in the real
// environment (real env vars always win). Blank lines and # comments ignored.
func loadEnvFile(path string) {
	f, err := os.Open(path)
	if err != nil {
		return // file is optional — silently skip
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		idx := strings.IndexByte(line, '=')
		if idx <= 0 {
			continue
		}
		key := strings.TrimSpace(line[:idx])
		val := strings.TrimSpace(line[idx+1:])
		// Strip surrounding single or double quotes
		if len(val) >= 2 {
			if (val[0] == '"' && val[len(val)-1] == '"') ||
				(val[0] == '\'' && val[len(val)-1] == '\'') {
				val = val[1 : len(val)-1]
			}
		}
		// Strip inline # comments (must be preceded by whitespace, e.g. "value  # comment")
		if i := strings.Index(val, " #"); i >= 0 {
			val = strings.TrimSpace(val[:i])
		} else if i := strings.Index(val, "\t#"); i >= 0 {
			val = strings.TrimSpace(val[:i])
		}
		// Only set if not already present in the real environment
		if os.Getenv(key) == "" {
			os.Setenv(key, val)
		}
	}
	log.Printf("[config] Loaded env overrides from %s", path)
}

// detectPublicIP queries ipify.org to discover the server's outbound public IP.
// Returns empty string on any failure (no network, timeout, unexpected body).
func detectPublicIP() string {
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get("https://api.ipify.org")
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64))
	if err != nil {
		return ""
	}
	ip := strings.TrimSpace(string(body))
	// Sanity-check: only digits, dots and colons (IPv4/IPv6)
	for _, c := range ip {
		if !((c >= '0' && c <= '9') || c == '.' || c == ':') {
			return ""
		}
	}
	return ip
}

var (
	adminUser      = getEnv("OVPN_USER", "admin")
	adminPass      = getEnv("OVPN_PASS", "changeme")
	ovpnService    = getEnv("OVPN_SERVICE", "openvpn-server@server")
	serverPublicIP = getEnv("OVPN_PUBLIC_IP", "") // empty = auto-detect at startup
	sessionTTL     = 24 * time.Hour
	listenPort     = getEnv("OVPN_PORT", ":8080")
)

// Paths start with built-in defaults; loadConfig may override them.
var (
	easyRSADir  = "/etc/openvpn/easy-rsa"
	clientsDir  = "/etc/openvpn/clients"
	serverCerts = "/etc/openvpn/server"
)

// ---------------------------------------------------------------------------
// TOON config loader
// ---------------------------------------------------------------------------

// unquoteTOON strips outer double-quotes and resolves TOON escape sequences.
func unquoteTOON(s string) string {
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		inner := s[1 : len(s)-1]
		inner = strings.ReplaceAll(inner, `\"`, `"`)
		inner = strings.ReplaceAll(inner, `\\`, `\`)
		inner = strings.ReplaceAll(inner, `\n`, "\n")
		inner = strings.ReplaceAll(inner, `\r`, "\r")
		inner = strings.ReplaceAll(inner, `\t`, "\t")
		return inner
	}
	return s
}

// parseTOON parses a minimal TOON document into flat key-value pairs and
// one-level nested sections (e.g. the [paths] group).
func parseTOON(data string) (flat map[string]string, sections map[string]map[string]string) {
	flat = map[string]string{}
	sections = map[string]map[string]string{}
	currentSection := ""

	for _, raw := range strings.Split(data, "\n") {
		// strip inline comment (only if outside a quoted value — simple heuristic)
		line := raw
		if idx := strings.Index(line, " # "); idx > 0 {
			line = line[:idx]
		}

		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		// Indented sub-key (belongs to current section)
		if (strings.HasPrefix(line, "  ") || strings.HasPrefix(line, "\t")) && currentSection != "" {
			idx := strings.Index(trimmed, ": ")
			if idx < 0 {
				continue
			}
			sections[currentSection][trimmed[:idx]] = unquoteTOON(strings.TrimSpace(trimmed[idx+2:]))
			continue
		}

		// Section header: "key:" with nothing after the colon
		if strings.HasSuffix(strings.TrimRight(line, " \t"), ":") && !strings.Contains(line, ": ") {
			currentSection = strings.TrimSuffix(trimmed, ":")
			sections[currentSection] = map[string]string{}
			continue
		}

		// Flat key: value
		currentSection = ""
		idx := strings.Index(trimmed, ": ")
		if idx < 0 {
			continue
		}
		flat[trimmed[:idx]] = unquoteTOON(strings.TrimSpace(trimmed[idx+2:]))
	}
	return
}

// loadConfig reads /etc/openvpn/manager.toon and applies values.
// Environment variables always take precedence over the file.
func loadConfig() {
	data, err := os.ReadFile(configFile)
	if err != nil {
		log.Printf("[config] %s not found — using defaults/env vars", configFile)
		return
	}

	flat, sections := parseTOON(string(data))

	if v, ok := flat["admin_user"]; ok && os.Getenv("OVPN_USER") == "" {
		adminUser = v
	}
	if v, ok := flat["admin_pass"]; ok && os.Getenv("OVPN_PASS") == "" {
		adminPass = v
	}
	if v, ok := flat["ovpn_service"]; ok && os.Getenv("OVPN_SERVICE") == "" {
		ovpnService = v
	}
	if v, ok := flat["public_ip"]; ok && os.Getenv("OVPN_PUBLIC_IP") == "" {
		serverPublicIP = v
	}
	if v, ok := flat["listen_port"]; ok && os.Getenv("OVPN_PORT") == "" {
		listenPort = v
	}
	if v, ok := flat["session_ttl"]; ok {
		if d, err2 := time.ParseDuration(v); err2 == nil {
			sessionTTL = d
		}
	}
	if paths, ok := sections["paths"]; ok {
		if v, ok := paths["easy_rsa"]; ok {
			easyRSADir = v
		}
		if v, ok := paths["clients"]; ok {
			clientsDir = v
		}
		if v, ok := paths["server_certs"]; ok {
			serverCerts = v
		}
	}
	log.Printf("[config] Loaded from %s", configFile)
}

// checkPassword verifies a plain-text password against a stored value that is
// either a bcrypt hash ("$2a$"/"$2b$"/"$2y$" prefix) or a plain-text fallback.
func checkPassword(plain, stored string) bool {
	if strings.HasPrefix(stored, "$2a$") || strings.HasPrefix(stored, "$2b$") || strings.HasPrefix(stored, "$2y$") {
		return bcrypt.CompareHashAndPassword([]byte(stored), []byte(plain)) == nil
	}
	// plain-text fallback (env var or unhashed config)
	return subtle.ConstantTimeCompare([]byte(plain), []byte(stored)) == 1
}

// ---------------------------------------------------------------------------
// Session store
// ---------------------------------------------------------------------------

var (
	sessionsMu sync.RWMutex
	sessions   = map[string]time.Time{} // token -> expiry
)

func newSessionToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func isValidSession(token string) bool {
	if token == "" {
		return false
	}
	sessionsMu.RLock()
	expiry, ok := sessions[token]
	sessionsMu.RUnlock()
	if !ok {
		return false
	}
	if time.Now().After(expiry) {
		sessionsMu.Lock()
		delete(sessions, token)
		sessionsMu.Unlock()
		return false
	}
	return true
}

// startSessionCleanup removes expired sessions once per hour.
func startSessionCleanup() {
	ticker := time.NewTicker(time.Hour)
	go func() {
		for range ticker.C {
			now := time.Now()
			sessionsMu.Lock()
			for token, expiry := range sessions {
				if now.After(expiry) {
					delete(sessions, token)
				}
			}
			sessionsMu.Unlock()
		}
	}()
}

// ---------------------------------------------------------------------------
// Auth middleware
// ---------------------------------------------------------------------------

// publicPaths are accessible without a valid session.
var publicPaths = map[string]bool{
	"/login.html": true,
	"/api/login":  true,
	"/api/logout": true,
}

func authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if publicPaths[r.URL.Path] {
			next.ServeHTTP(w, r)
			return
		}

		cookie, err := r.Cookie("session")
		if err != nil || !isValidSession(cookie.Value) {
			if strings.HasPrefix(r.URL.Path, "/api/") {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
			} else {
				http.Redirect(w, r, "/login.html", http.StatusFound)
			}
			return
		}

		next.ServeHTTP(w, r)
	})
}

// ---------------------------------------------------------------------------
// Data types
// ---------------------------------------------------------------------------

type StatusResponse struct {
	Active     bool   `json:"active"`
	Status     string `json:"status"`
	Installed  bool   `json:"installed"`
	UnitExists bool   `json:"unit_exists"`
	Message    string `json:"message,omitempty"`
}

type ActionRequest struct {
	Action string `json:"action"` // start, stop, restart
}

type Client struct {
	Name           string `json:"name"`
	RealAddress    string `json:"real_address"`
	BytesReceived  string `json:"bytes_received"`
	BytesSent      string `json:"bytes_sent"`
	ConnectedSince string `json:"connected_since"`
}

// ---------------------------------------------------------------------------
// OpenVPN helpers
// ---------------------------------------------------------------------------

// isOpenVPNInstalled checks known binary paths directly, avoiding PATH issues.
func isOpenVPNInstalled() bool {
	for _, p := range []string{"/usr/sbin/openvpn", "/usr/bin/openvpn", "/sbin/openvpn"} {
		if _, err := os.Stat(p); err == nil {
			return true
		}
	}
	return false
}

// serviceUnitExists checks whether a usable systemd unit template is present.
func serviceUnitExists() bool {
	paths := []string{
		"/lib/systemd/system/openvpn@.service",
		"/lib/systemd/system/openvpn-server@.service",
		"/usr/lib/systemd/system/openvpn@.service",
		"/usr/lib/systemd/system/openvpn-server@.service",
		"/etc/systemd/system/openvpn@server.service",
		"/etc/systemd/system/openvpn-server@server.service",
	}
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

func main() {
	// --hash-pass <password>: print a bcrypt hash and exit (for manager.toon)
	if len(os.Args) == 3 && os.Args[1] == "--hash-pass" {
		hash, err := bcrypt.GenerateFromPassword([]byte(os.Args[2]), 12)
		if err != nil {
			log.Fatalf("bcrypt error: %v", err)
		}
		fmt.Println(string(hash))
		os.Exit(0)
	}

	loadEnvFile(envFile) // load manager.env FIRST so env vars are set before anything else
	loadConfig()
	loadGroups()
	loadWGPeers()

	// Re-read env vars that may have been set by loadEnvFile after package init
	if v := os.Getenv("OVPN_USER"); v != "" {
		adminUser = v
	}
	if v := os.Getenv("OVPN_PASS"); v != "" {
		adminPass = v
	}
	if v := os.Getenv("OVPN_SERVICE"); v != "" {
		ovpnService = v
	}
	if v := os.Getenv("OVPN_PUBLIC_IP"); v != "" {
		serverPublicIP = v
	}
	if v := os.Getenv("OVPN_PORT"); v != "" {
		listenPort = v
	}

	// WireGuard env overrides
	if v := os.Getenv("WG_INTERFACE"); v != "" {
		wgInterface = v
		wgService = "wg-quick@" + v
		wgConfigFile = "/etc/wireguard/" + v + ".conf"
	}
	if v := os.Getenv("WG_CONFIG"); v != "" {
		wgConfigFile = v
	}
	if v := os.Getenv("WG_CLIENTS_DIR"); v != "" {
		wgClientsDir = v
	}
	if v := os.Getenv("WG_SERVICE"); v != "" {
		wgService = v
	}
	if v := os.Getenv("WG_ENDPOINT"); v != "" {
		wgEndpoint = v
	}
	if v := os.Getenv("WG_DNS"); v != "" {
		wgDNS = v
	}
	if v := os.Getenv("WG_ALLOWED_IPS"); v != "" {
		wgAllowedIPs = v
	}

	// Auto-detect public IP if still empty after all config sources
	if serverPublicIP == "" {
		log.Println("[config] OVPN_PUBLIC_IP not set — auto-detecting public IP...")
		if ip := detectPublicIP(); ip != "" {
			serverPublicIP = ip
			log.Printf("[config] Auto-detected public IP: %s", serverPublicIP)
		} else {
			log.Println("[config] WARNING: could not detect public IP; generated .ovpn files may be incorrect")
		}
	}

	// Normalise listenPort: ensure it starts with ":"
	if listenPort != "" && listenPort[0] != ':' {
		listenPort = ":" + listenPort
	}
	if listenPort == "" {
		listenPort = ":8080"
	}

	if !strings.HasPrefix(adminPass, "$2a$") && !strings.HasPrefix(adminPass, "$2b$") && adminPass == "changeme" {
		log.Println("WARNING: Using default plain-text password. Run './openvpn-manager --hash-pass <password>' and set admin_pass in", configFile)
	}

	startSessionCleanup()

	mux := http.NewServeMux()

	// Serve static files
	fs := http.FileServer(http.Dir("./public"))
	mux.Handle("/", fs)

	// Auth endpoints (no middleware — handled in authMiddleware public path exemption)
	mux.HandleFunc("/api/login", handleLogin)
	mux.HandleFunc("/api/logout", handleLogout)

	// Protected API routes
	mux.HandleFunc("/api/status", handleStatus)
	mux.HandleFunc("/api/action", handleAction)
	mux.HandleFunc("/api/clients", handleClients)
	mux.HandleFunc("/api/install", handleInstall)
	mux.HandleFunc("/api/logs", handleLogs)
	mux.HandleFunc("/api/clients/create", handleCreateClient)
	mux.HandleFunc("/api/clients/list", handleListClients)
	mux.HandleFunc("/api/clients/download", handleDownloadClient)
	mux.HandleFunc("/api/clients/revoke", handleRevokeClient)
	mux.HandleFunc("/api/change-password", handleChangePassword)
	mux.HandleFunc("/api/sysinfo", handleSysInfo)
	mux.HandleFunc("/api/groups", handleGroups)
	mux.HandleFunc("/api/groups/", func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/api/groups/")
		parts := strings.SplitN(path, "/", 3)
		switch {
		case len(parts) == 1:
			handleGroup(w, r)
		case len(parts) >= 2 && parts[1] == "members":
			handleGroupMembers(w, r)
		case len(parts) >= 2 && parts[1] == "rules":
			handleGroupRules(w, r)
		default:
			http.Error(w, "Not found", http.StatusNotFound)
		}
	})

	// WireGuard routes
	mux.HandleFunc("/api/wg/status", handleWGStatus)
	mux.HandleFunc("/api/wg/action", handleWGAction)
	mux.HandleFunc("/api/wg/install", handleWGInstall)
	mux.HandleFunc("/api/wg/clients", handleWGConnectedClients)
	mux.HandleFunc("/api/wg/logs", handleWGLogs)
	mux.HandleFunc("/api/wg/peers/create", handleWGClientCreate)
	mux.HandleFunc("/api/wg/peers/list", handleWGClientList)
	mux.HandleFunc("/api/wg/peers/download", handleWGClientDownload)
	mux.HandleFunc("/api/wg/peers/revoke", handleWGClientRevoke)

	fmt.Printf("Server starting on http://localhost%s\n", listenPort)
	log.Printf("[config] public_ip=%s  service=%s  port=%s", serverPublicIP, ovpnService, listenPort)
	if err := http.ListenAndServe(listenPort, authMiddleware(mux)); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Auth handlers
// ---------------------------------------------------------------------------

func handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var creds struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	// Constant-time comparison for username; bcrypt-aware check for password
	userOK := subtle.ConstantTimeCompare([]byte(creds.Username), []byte(adminUser)) == 1
	passOK := checkPassword(creds.Password, adminPass)

	if !userOK || !passOK {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	token, err := newSessionToken()
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	sessionsMu.Lock()
	sessions[token] = time.Now().Add(sessionTTL)
	sessionsMu.Unlock()

	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(sessionTTL.Seconds()),
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "Login successful"})
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if cookie, err := r.Cookie("session"); err == nil {
		sessionsMu.Lock()
		delete(sessions, cookie.Value)
		sessionsMu.Unlock()
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		MaxAge:   -1,
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "Logged out"})
}

// handleChangePassword verifies the current password then replaces it with a
// new bcrypt hash, updating both the in-memory value and manager.toon.
func handleChangePassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
		ConfirmPassword string `json:"confirm_password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	if !checkPassword(req.CurrentPassword, adminPass) {
		// Use 403 so the UI can distinguish "wrong current password" from 401 session expiry
		http.Error(w, "Current password is incorrect.", http.StatusForbidden)
		return
	}
	if len(req.NewPassword) < 8 {
		http.Error(w, "New password must be at least 8 characters.", http.StatusBadRequest)
		return
	}
	if req.NewPassword != req.ConfirmPassword {
		http.Error(w, "New password and confirmation do not match.", http.StatusBadRequest)
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), 12)
	if err != nil {
		http.Error(w, "Failed to hash password.", http.StatusInternalServerError)
		return
	}
	newHash := string(hash)

	// Persist to manager.toon
	if err := updateTOONPassword(newHash); err != nil {
		http.Error(w, fmt.Sprintf("Password changed in memory but failed to save: %v", err), http.StatusInternalServerError)
		return
	}

	// Update in-memory value atomically
	adminPass = newHash

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "Password changed successfully."})
}

// ---------------------------------------------------------------------------
// System Info
// ---------------------------------------------------------------------------

type SysInfo struct {
	CPUPercent  float64 `json:"cpu_percent"`
	MemTotal    uint64  `json:"mem_total"`
	MemUsed     uint64  `json:"mem_used"`
	MemPercent  float64 `json:"mem_percent"`
	DiskTotal   uint64  `json:"disk_total"`
	DiskUsed    uint64  `json:"disk_used"`
	DiskPercent float64 `json:"disk_percent"`
	Uptime      uint64  `json:"uptime_seconds"`
	Hostname    string  `json:"hostname"`
	Kernel      string  `json:"kernel"`
}

func readCPUPercent() float64 {
	readStat := func() (idle, total uint64) {
		data, err := os.ReadFile("/proc/stat")
		if err != nil {
			return
		}
		for _, line := range strings.Split(string(data), "\n") {
			if !strings.HasPrefix(line, "cpu ") {
				continue
			}
			fields := strings.Fields(line)[1:]
			var vals [10]uint64
			for i, f := range fields {
				if i >= 10 {
					break
				}
				fmt.Sscanf(f, "%d", &vals[i])
			}
			for _, v := range vals {
				total += v
			}
			idle = vals[3] + vals[4]
			return
		}
		return
	}
	idle1, total1 := readStat()
	time.Sleep(200 * time.Millisecond)
	idle2, total2 := readStat()
	deltaTotal := total2 - total1
	if deltaTotal > 0 {
		deltaBusy := float64(deltaTotal - (idle2 - idle1))
		return deltaBusy / float64(deltaTotal) * 100
	}
	return 0
}

func readMemInfo() (total, used uint64, pct float64) {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return
	}
	var memTotal, memFree, buffers, cached, sReclaimable, shmem uint64
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		var v uint64
		fmt.Sscanf(fields[1], "%d", &v)
		switch fields[0] {
		case "MemTotal:":
			memTotal = v * 1024
		case "MemFree:":
			memFree = v * 1024
		case "Buffers:":
			buffers = v * 1024
		case "Cached:":
			cached = v * 1024
		case "SReclaimable:":
			sReclaimable = v * 1024
		case "Shmem:":
			shmem = v * 1024
		}
	}
	total = memTotal
	avail := memFree + buffers + cached + sReclaimable - shmem
	if avail > total {
		avail = 0
	}
	used = total - avail
	if total > 0 {
		pct = float64(used) / float64(total) * 100
	}
	return
}

func readDiskInfo(path string) (total, used uint64, pct float64) {
	out, err := exec.Command("df", "-B1", "--output=size,used", path).Output()
	if err != nil {
		return
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) < 2 {
		return
	}
	fields := strings.Fields(lines[1])
	if len(fields) < 2 {
		return
	}
	fmt.Sscanf(fields[0], "%d", &total)
	fmt.Sscanf(fields[1], "%d", &used)
	if total > 0 {
		pct = float64(used) / float64(total) * 100
	}
	return
}

func readUptime() uint64 {
	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0
	}
	var secs float64
	fmt.Sscanf(strings.Fields(string(data))[0], "%f", &secs)
	return uint64(secs)
}

func handleSysInfo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	cpu := readCPUPercent()
	memTotal, memUsed, memPct := readMemInfo()
	diskTotal, diskUsed, diskPct := readDiskInfo("/")
	uptime := readUptime()
	hostname, _ := os.Hostname()
	kernelBytes, _ := exec.Command("uname", "-r").Output()
	kernel := strings.TrimSpace(string(kernelBytes))

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(SysInfo{
		CPUPercent:  math.Round(cpu*10) / 10,
		MemTotal:    memTotal,
		MemUsed:     memUsed,
		MemPercent:  math.Round(memPct*10) / 10,
		DiskTotal:   diskTotal,
		DiskUsed:    diskUsed,
		DiskPercent: math.Round(diskPct*10) / 10,
		Uptime:      uptime,
		Hostname:    hostname,
		Kernel:      kernel,
	})
}

// updateTOONPassword rewrites the admin_pass line in manager.toon.
func updateTOONPassword(newHash string) error {
	data, err := os.ReadFile(configFile)
	if err != nil {
		// File doesn't exist yet — create it with minimal content
		content := fmt.Sprintf("admin_user: %s\nadmin_pass: %s\n", adminUser, newHash)
		return os.WriteFile(configFile, []byte(content), 0640)
	}

	lines := strings.Split(string(data), "\n")
	found := false
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "admin_pass:") {
			lines[i] = "admin_pass: " + newHash
			found = true
			break
		}
	}
	if !found {
		// Append the key if it wasn't present
		lines = append(lines, "admin_pass: "+newHash)
	}

	return os.WriteFile(configFile, []byte(strings.Join(lines, "\n")), 0640)
}

// ---------------------------------------------------------------------------
// API handlers
// ---------------------------------------------------------------------------

func handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	installed := isOpenVPNInstalled()
	unitExists := serviceUnitExists()

	resp := StatusResponse{
		Installed:  installed,
		UnitExists: unitExists,
	}

	if !installed {
		resp.Active = false
		resp.Status = "not_installed"
		resp.Message = "OpenVPN is not installed on this system."
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
		return
	}

	if !unitExists {
		resp.Active = false
		resp.Status = "no_unit"
		resp.Message = "OpenVPN is installed but no systemd service unit found. A server config may be missing."
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
		return
	}

	cmd := exec.Command("systemctl", "is-active", ovpnService)
	err := cmd.Run()

	resp.Active = err == nil
	if resp.Active {
		resp.Status = "active"
	} else {
		statusCmd := exec.Command("systemctl", "is-failed", ovpnService)
		if statusCmd.Run() == nil {
			resp.Status = "failed"
			resp.Message = fmt.Sprintf("The %s service has failed. Check logs for details.", ovpnService)
		} else {
			resp.Status = "inactive"
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func handleAction(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req ActionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	if req.Action != "start" && req.Action != "stop" && req.Action != "restart" {
		http.Error(w, "Invalid action", http.StatusBadRequest)
		return
	}

	if !isOpenVPNInstalled() {
		http.Error(w, "OpenVPN is not installed. Please install it first.", http.StatusServiceUnavailable)
		return
	}

	if !serviceUnitExists() {
		http.Error(w, "No systemd service unit found. Ensure a server.conf exists in /etc/openvpn/.", http.StatusServiceUnavailable)
		return
	}

	cmd := exec.Command("sudo", "systemctl", req.Action, ovpnService)
	output, err := cmd.CombinedOutput()
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to execute action: %v\n%s", err, string(output)), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "Action executed successfully"})
}

func handleClients(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	logPaths := []string{
		"/run/openvpn-server/status-server.log",
		"/var/log/openvpn/openvpn-status.log",
		"/etc/openvpn/openvpn-status.log",
		"/tmp/openvpn-status.log",
	}

	var data []byte
	var readErr error
	for _, p := range logPaths {
		data, readErr = os.ReadFile(p)
		if readErr == nil {
			break
		}
	}

	if readErr != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]Client{})
		return
	}

	clients := parseOpenVPNStatus(string(data))
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(clients)
}

func handleInstall(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if isOpenVPNInstalled() {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"message": "OpenVPN is already installed."})
		return
	}

	cmd := exec.Command("sudo", "apt-get", "install", "-y", "openvpn")
	output, err := cmd.CombinedOutput()
	if err != nil {
		http.Error(w, fmt.Sprintf("Installation failed: %v\n%s", err, string(output)), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "OpenVPN installed successfully."})
}

func handleLogs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	lines := r.URL.Query().Get("lines")
	if lines == "" {
		lines = "50"
	}

	for _, c := range lines {
		if c < '0' || c > '9' {
			http.Error(w, "Invalid lines parameter", http.StatusBadRequest)
			return
		}
	}

	var output []byte
	var err error

	if isOpenVPNInstalled() && serviceUnitExists() {
		cmd := exec.Command("journalctl", "-u", ovpnService, "-n", lines, "--no-pager", "--output=short-iso")
		output, err = cmd.CombinedOutput()
	} else if isOpenVPNInstalled() {
		cmd := exec.Command("dpkg", "-l", "openvpn")
		output, err = cmd.CombinedOutput()
	} else {
		output = []byte("OpenVPN is not installed. Use the Install button to install it.")
	}

	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"logs": string(output)})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"logs": string(output)})
}

// ---------------------------------------------------------------------------
// OpenVPN status parser
// ---------------------------------------------------------------------------

func parseOpenVPNStatus(logData string) []Client {
	var clients []Client
	lines := strings.Split(logData, "\n")
	inClientList := false

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Version 2/3 format: CLIENT_LIST,<name>,<real>,<virt>,<virt6>,<rx>,<tx>,<since>,...
		if strings.HasPrefix(line, "CLIENT_LIST,") {
			parts := strings.Split(line, ",")
			if len(parts) >= 8 && parts[1] != "Common Name" {
				clients = append(clients, Client{
					Name:           parts[1],
					RealAddress:    parts[2],
					BytesReceived:  parts[5],
					BytesSent:      parts[6],
					ConnectedSince: parts[7],
				})
			}
			continue
		}

		// Version 1 format
		if strings.HasPrefix(line, "Common Name,Real Address") {
			inClientList = true
			continue
		}
		if line == "ROUTING TABLE" {
			inClientList = false
		}
		if inClientList {
			parts := strings.Split(line, ",")
			if len(parts) >= 5 {
				clients = append(clients, Client{
					Name:           parts[0],
					RealAddress:    parts[1],
					BytesReceived:  parts[2],
					BytesSent:      parts[3],
					ConnectedSince: parts[4],
				})
			}
		}
	}
	return clients
}

// ---------------------------------------------------------------------------
// Client Management
// ---------------------------------------------------------------------------

// isValidClientName ensures the name is safe for filesystem and shell use.
func isValidClientName(name string) bool {
	if len(name) == 0 || len(name) > 64 {
		return false
	}
	for _, c := range name {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

// ClientProfile represents a provisioned .ovpn file entry.
type ClientProfile struct {
	Name          string `json:"name"`
	Created       string `json:"created"`
	HasPassphrase bool   `json:"has_passphrase"`
}

// handleCreateClient generates a PKI certificate + inline .ovpn profile.
func handleCreateClient(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Name       string `json:"name"`
		Passphrase string `json:"passphrase"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	name := strings.TrimSpace(req.Name)
	if !isValidClientName(name) {
		http.Error(w, "Invalid client name. Use only letters, numbers, dash, or underscore (max 64 chars).", http.StatusBadRequest)
		return
	}

	passphrase := req.Passphrase
	if passphrase != "" && len(passphrase) < 8 {
		http.Error(w, "Passphrase must be at least 8 characters.", http.StatusBadRequest)
		return
	}

	ovpnPath := fmt.Sprintf("%s/%s.ovpn", clientsDir, name)
	if _, err := os.Stat(ovpnPath); err == nil {
		http.Error(w, fmt.Sprintf("Client '%s' already exists.", name), http.StatusConflict)
		return
	}

	if err := os.MkdirAll(clientsDir, 0750); err != nil {
		http.Error(w, "Failed to create clients directory", http.StatusInternalServerError)
		return
	}

	easyrsa := fmt.Sprintf("%s/easyrsa", easyRSADir)

	genReq := exec.Command(easyrsa, "--batch", "gen-req", name, "nopass")
	genReq.Dir = easyRSADir
	if out, err := genReq.CombinedOutput(); err != nil {
		http.Error(w, fmt.Sprintf("gen-req failed: %v\n%s", err, string(out)), http.StatusInternalServerError)
		return
	}

	signReq := exec.Command(easyrsa, "--batch", "sign-req", "client", name)
	signReq.Dir = easyRSADir
	if out, err := signReq.CombinedOutput(); err != nil {
		http.Error(w, fmt.Sprintf("sign-req failed: %v\n%s", err, string(out)), http.StatusInternalServerError)
		return
	}

	if err := buildOVPNProfile(name, ovpnPath, passphrase); err != nil {
		http.Error(w, fmt.Sprintf("Failed to build .ovpn profile: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"message": fmt.Sprintf("Client '%s' created successfully.", name),
		"name":    name,
	})
}

// buildOVPNProfile assembles an inline .ovpn config and writes it to outPath.
// If passphrase is non-empty, the embedded private key is encrypted with AES-256-CBC.
func buildOVPNProfile(name, outPath, passphrase string) error {
	pkiDir := fmt.Sprintf("%s/pki", easyRSADir)

	ca, err := os.ReadFile(fmt.Sprintf("%s/ca.crt", serverCerts))
	if err != nil {
		return fmt.Errorf("read ca.crt: %w", err)
	}
	rawCert, err := os.ReadFile(fmt.Sprintf("%s/issued/%s.crt", pkiDir, name))
	if err != nil {
		return fmt.Errorf("read client cert: %w", err)
	}
	key, err := os.ReadFile(fmt.Sprintf("%s/private/%s.key", pkiDir, name))
	if err != nil {
		return fmt.Errorf("read client key: %w", err)
	}
	ta, err := os.ReadFile(fmt.Sprintf("%s/ta.key", serverCerts))
	if err != nil {
		return fmt.Errorf("read ta.key: %w", err)
	}

	keyPEM := string(key)
	if passphrase != "" {
		encrypted, err := encryptPrivateKey(key, passphrase)
		if err != nil {
			return fmt.Errorf("encrypt private key: %w", err)
		}
		keyPEM = string(encrypted)
	}

	profile := fmt.Sprintf(
		"client\ndev tun\nproto udp\nremote %s 1194\nresolv-retry infinite\nnobind\n"+
			"persist-key\npersist-tun\nremote-cert-tls server\nkey-direction 1\n"+
			"cipher AES-256-GCM\ndata-ciphers AES-256-GCM:AES-128-GCM:AES-256-CBC\n"+
			"compress stub-v2\nverb 3\n\n"+
			"<ca>\n%s</ca>\n<cert>\n%s</cert>\n<key>\n%s</key>\n<tls-auth>\n%s</tls-auth>\n",
		serverPublicIP,
		string(ca),
		extractCertBlock(string(rawCert)),
		keyPEM,
		string(ta),
	)

	return os.WriteFile(outPath, []byte(profile), 0640)
}

// encryptPrivateKey encrypts a PEM private key with AES-256-CBC.
// The passphrase is passed via environment variable to avoid exposure in ps listings.
func encryptPrivateKey(keyPEM []byte, passphrase string) ([]byte, error) {
	cmd := exec.Command("openssl", "pkey", "-aes-256-cbc", "-passout", "env:OVPN_KEY_PASS")
	cmd.Env = append(append([]string{}, os.Environ()...), "OVPN_KEY_PASS="+passphrase)
	cmd.Stdin = bytes.NewReader(keyPEM)
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("openssl pkey: %w", err)
	}
	return out, nil
}

// extractCertBlock returns only the -----BEGIN/END CERTIFICATE----- section.
func extractCertBlock(raw string) string {
	const begin = "-----BEGIN CERTIFICATE-----"
	const end = "-----END CERTIFICATE-----"
	start := strings.Index(raw, begin)
	if start == -1 {
		return raw
	}
	stop := strings.Index(raw[start:], end)
	if stop == -1 {
		return raw[start:]
	}
	return raw[start:start+stop+len(end)] + "\n"
}

// handleListClients returns all provisioned client .ovpn profiles.
func handleListClients(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	entries, err := os.ReadDir(clientsDir)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]ClientProfile{})
		return
	}

	profiles := []ClientProfile{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".ovpn") {
			continue
		}
		info, _ := e.Info()
		created := ""
		if info != nil {
			created = info.ModTime().UTC().Format(time.RFC3339)
		}
		ovpnData, _ := os.ReadFile(fmt.Sprintf("%s/%s", clientsDir, e.Name()))
		hasPassphrase := bytes.Contains(ovpnData, []byte("ENCRYPTED PRIVATE KEY"))
		profiles = append(profiles, ClientProfile{
			Name:          strings.TrimSuffix(e.Name(), ".ovpn"),
			Created:       created,
			HasPassphrase: hasPassphrase,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(profiles)
}

// handleDownloadClient serves the .ovpn file as a download attachment.
func handleDownloadClient(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	name := r.URL.Query().Get("name")
	if !isValidClientName(name) {
		http.Error(w, "Invalid client name", http.StatusBadRequest)
		return
	}

	ovpnPath := fmt.Sprintf("%s/%s.ovpn", clientsDir, name)
	data, err := os.ReadFile(ovpnPath)
	if err != nil {
		http.Error(w, "Client not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/x-openvpn-profile")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.ovpn"`, name))
	w.Write(data)
}

// ---------------------------------------------------------------------------
// Group Management
// ---------------------------------------------------------------------------

// groupsFile is where group definitions are persisted.
const groupsFile = "/etc/openvpn/manager-groups.json"

// ---------------------------------------------------------------------------
// WireGuard
// ---------------------------------------------------------------------------

// wgPeersFile persists the list of provisioned WireGuard peers.
const wgPeersFile = "/etc/wireguard/manager-peers.json"

var (
	wgInterface  = getEnv("WG_INTERFACE", "wg0")
	wgConfigFile = getEnv("WG_CONFIG", "/etc/wireguard/wg0.conf")
	wgClientsDir = getEnv("WG_CLIENTS_DIR", "/etc/wireguard/clients")
	wgService    = getEnv("WG_SERVICE", "wg-quick@wg0")
	wgEndpoint   = getEnv("WG_ENDPOINT", "")    // host:port, e.g. "1.2.3.4:51820"
	wgDNS        = getEnv("WG_DNS", "1.1.1.1")  // DNS for peer configs
	wgAllowedIPs = getEnv("WG_ALLOWED_IPS", "0.0.0.0/0, ::/0")
)

// WGPeer is metadata for a provisioned WireGuard peer (stored in the peers JSON file).
type WGPeer struct {
	Name      string `json:"name"`
	PublicKey string `json:"public_key"`
	IP        string `json:"ip"`   // assigned VPN IP, e.g. "10.8.1.2/32"
	Created   string `json:"created"`
}

var (
	wgPeersMu sync.RWMutex
	wgPeers   []WGPeer
)

func loadWGPeers() {
	wgPeersMu.Lock()
	defer wgPeersMu.Unlock()
	data, err := os.ReadFile(wgPeersFile)
	if err != nil {
		wgPeers = []WGPeer{}
		return
	}
	if err := json.Unmarshal(data, &wgPeers); err != nil {
		wgPeers = []WGPeer{}
	}
}

func saveWGPeers() error {
	data, err := json.MarshalIndent(wgPeers, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll("/etc/wireguard", 0750); err != nil {
		return err
	}
	return os.WriteFile(wgPeersFile, data, 0640)
}

// isWireGuardInstalled checks for wg and wg-quick binaries.
func isWireGuardInstalled() bool {
	for _, p := range []string{"/usr/bin/wg", "/usr/sbin/wg", "/bin/wg"} {
		if _, err := os.Stat(p); err == nil {
			return true
		}
	}
	return false
}

// handleWGStatus returns the WireGuard service status alongside install state.
func handleWGStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	type WGStatus struct {
		Active    bool   `json:"active"`
		Status    string `json:"status"`
		Installed bool   `json:"installed"`
		Message   string `json:"message,omitempty"`
	}

	installed := isWireGuardInstalled()
	resp := WGStatus{Installed: installed}

	if !installed {
		resp.Active = false
		resp.Status = "not_installed"
		resp.Message = "WireGuard is not installed on this system."
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
		return
	}

	cmd := exec.Command("systemctl", "is-active", wgService)
	if err := cmd.Run(); err == nil {
		resp.Active = true
		resp.Status = "active"
	} else {
		checkFailed := exec.Command("systemctl", "is-failed", wgService)
		if checkFailed.Run() == nil {
			resp.Status = "failed"
			resp.Message = fmt.Sprintf("The %s service has failed. Check logs for details.", wgService)
		} else {
			resp.Status = "inactive"
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// handleWGAction performs start/stop/restart on the wg-quick service.
func handleWGAction(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req ActionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}
	if req.Action != "start" && req.Action != "stop" && req.Action != "restart" {
		http.Error(w, "Invalid action", http.StatusBadRequest)
		return
	}
	if !isWireGuardInstalled() {
		http.Error(w, "WireGuard is not installed.", http.StatusServiceUnavailable)
		return
	}

	cmd := exec.Command("sudo", "systemctl", req.Action, wgService)
	out, err := cmd.CombinedOutput()
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to execute action: %v\n%s", err, string(out)), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "Action executed successfully"})
}

// handleWGInstall installs wireguard via apt-get.
func handleWGInstall(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if isWireGuardInstalled() {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"message": "WireGuard is already installed."})
		return
	}
	cmd := exec.Command("sudo", "apt-get", "install", "-y", "wireguard")
	out, err := cmd.CombinedOutput()
	if err != nil {
		http.Error(w, fmt.Sprintf("Installation failed: %v\n%s", err, string(out)), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "WireGuard installed successfully."})
}

// handleWGConnectedClients lists currently connected peers via `wg show`.
func handleWGConnectedClients(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	type WGConnected struct {
		PublicKey       string `json:"public_key"`
		Endpoint        string `json:"endpoint"`
		AllowedIPs      string `json:"allowed_ips"`
		LatestHandshake string `json:"latest_handshake"`
		BytesReceived   string `json:"bytes_received"`
		BytesSent       string `json:"bytes_sent"`
		Name            string `json:"name"`
	}

	out, err := exec.Command("sudo", "wg", "show", wgInterface, "dump").Output()
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]WGConnected{})
		return
	}

	// Build a map public_key -> peer name from persisted metadata
	wgPeersMu.RLock()
	nameByKey := map[string]string{}
	for _, p := range wgPeers {
		nameByKey[p.PublicKey] = p.Name
	}
	wgPeersMu.RUnlock()

	var connected []WGConnected
	for i, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if i == 0 {
			continue // first line is the server (interface) itself
		}
		fields := strings.Fields(line)
		if len(fields) < 7 {
			continue
		}
		pubKey := fields[0]
		c := WGConnected{
			PublicKey:       pubKey,
			Endpoint:        fields[2],
			AllowedIPs:      fields[3],
			LatestHandshake: fields[4],
			BytesReceived:   fields[5],
			BytesSent:       fields[6],
			Name:            nameByKey[pubKey],
		}
		connected = append(connected, c)
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(connected)
}

// nextWGIP finds the next unused /32 peer IP in the 10.8.1.0/24 range
// (or whatever subnet the server is using), starting at .2.
func nextWGIP() (string, error) {
	wgPeersMu.RLock()
	used := map[string]bool{}
	for _, p := range wgPeers {
		used[strings.TrimSuffix(p.IP, "/32")] = true
	}
	wgPeersMu.RUnlock()

	for i := 2; i <= 254; i++ {
		ip := fmt.Sprintf("10.8.1.%d", i)
		if !used[ip] {
			return ip + "/32", nil
		}
	}
	return "", fmt.Errorf("no free IP addresses in 10.8.1.0/24")
}

// runWGCmd runs a wg sub-command and returns combined output.
func runWGCmd(args ...string) ([]byte, error) {
	cmd := exec.Command("sudo", append([]string{"wg"}, args...)...)
	return cmd.CombinedOutput()
}

// handleWGClientCreate generates a new WireGuard peer key-pair, assigns an IP,
// adds the peer to the live interface (wg set) and appends it to the server
// config file, then returns a client .conf file for download.
func handleWGClientCreate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	name := strings.TrimSpace(req.Name)
	if !isValidClientName(name) {
		http.Error(w, "Invalid peer name. Use only letters, numbers, dash, or underscore (max 64 chars).", http.StatusBadRequest)
		return
	}

	// Ensure client dir exists
	if err := os.MkdirAll(wgClientsDir, 0750); err != nil {
		http.Error(w, "Failed to create WireGuard clients directory", http.StatusInternalServerError)
		return
	}

	outPath := fmt.Sprintf("%s/%s.conf", wgClientsDir, name)
	if _, err := os.Stat(outPath); err == nil {
		http.Error(w, fmt.Sprintf("Peer '%s' already exists.", name), http.StatusConflict)
		return
	}

	// Generate peer private + public key
	privOut, err := exec.Command("sudo", "bash", "-c", "wg genkey").Output()
	if err != nil {
		http.Error(w, fmt.Sprintf("wg genkey failed: %v", err), http.StatusInternalServerError)
		return
	}
	privKey := strings.TrimSpace(string(privOut))

	pubCmd := exec.Command("sudo", "bash", "-c", fmt.Sprintf("echo '%s' | wg pubkey", privKey))
	pubOut, err := pubCmd.Output()
	if err != nil {
		http.Error(w, fmt.Sprintf("wg pubkey failed: %v", err), http.StatusInternalServerError)
		return
	}
	pubKey := strings.TrimSpace(string(pubOut))

	// Assign IP
	peerIP, err := nextWGIP()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Determine endpoint for the client config
	endpoint := wgEndpoint
	if endpoint == "" {
		endpoint = serverPublicIP + ":51820"
	}

	// Get the server public key from the running interface (most reliable).
	serverPubKey := ""
	if out, e := exec.Command("sudo", "wg", "show", wgInterface, "public-key").Output(); e == nil {
		serverPubKey = strings.TrimSpace(string(out))
	}
	// Fallback: derive from the PrivateKey in [Interface] section of wg0.conf.
	// Only scan lines before the first [Peer] block to avoid picking up a peer's PublicKey.
	if serverPubKey == "" {
		if confData, err2 := os.ReadFile(wgConfigFile); err2 == nil {
			for _, line := range strings.Split(string(confData), "\n") {
				line = strings.TrimSpace(line)
				if strings.HasPrefix(line, "[Peer]") {
					break // stop — do not read peer sections
				}
				if strings.HasPrefix(line, "PrivateKey") {
					parts := strings.SplitN(line, "=", 2)
					if len(parts) == 2 {
						sPriv := strings.TrimSpace(parts[1])
						pcmd := exec.Command("sudo", "bash", "-c", fmt.Sprintf("echo '%s' | wg pubkey", sPriv))
						if po, e := pcmd.Output(); e == nil {
							serverPubKey = strings.TrimSpace(string(po))
						}
					}
					break
				}
			}
		}
	}

	// Build client .conf content
	clientConf := fmt.Sprintf("[Interface]\nPrivateKey = %s\nAddress = %s\nDNS = %s\n\n[Peer]\nPublicKey = %s\nAllowedIPs = %s\nEndpoint = %s\nPersistentKeepalive = 25\n",
		privKey,
		peerIP,
		wgDNS,
		serverPubKey,
		wgAllowedIPs,
		endpoint,
	)

	if err := os.WriteFile(outPath, []byte(clientConf), 0640); err != nil {
		http.Error(w, fmt.Sprintf("Failed to write client config: %v", err), http.StatusInternalServerError)
		return
	}

	// Add peer to the running WireGuard interface
	peerIPHost := strings.TrimSuffix(peerIP, "/32") + "/32"
	addCmd := exec.Command("sudo", "wg", "set", wgInterface, "peer", pubKey, "allowed-ips", peerIPHost)
	if out, err2 := addCmd.CombinedOutput(); err2 != nil {
		log.Printf("[wg] wg set peer failed (interface may be down): %v\n%s", err2, string(out))
		// Non-fatal — peer saved in config, will be active after next wg-quick up
	}

	// Append [Peer] block to server wg0.conf
	peerBlock := fmt.Sprintf("\n# Peer: %s\n[Peer]\nPublicKey = %s\nAllowedIPs = %s\n", name, pubKey, peerIPHost)
	f, err := os.OpenFile(wgConfigFile, os.O_APPEND|os.O_WRONLY, 0640)
	if err != nil {
		log.Printf("[wg] failed to append peer to %s: %v", wgConfigFile, err)
	} else {
		f.WriteString(peerBlock)
		f.Close()
	}

	// Persist metadata
	wgPeersMu.Lock()
	wgPeers = append(wgPeers, WGPeer{
		Name:      name,
		PublicKey: pubKey,
		IP:        peerIP,
		Created:   time.Now().UTC().Format(time.RFC3339),
	})
	saveWGPeers()
	wgPeersMu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"message": fmt.Sprintf("Peer '%s' created successfully.", name),
		"name":    name,
	})
}

// handleWGClientList returns all provisioned WireGuard peers (metadata).
func handleWGClientList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	wgPeersMu.RLock()
	defer wgPeersMu.RUnlock()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(wgPeers)
}

// handleWGClientDownload serves the peer .conf file as a download.
func handleWGClientDownload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	name := r.URL.Query().Get("name")
	if !isValidClientName(name) {
		http.Error(w, "Invalid peer name", http.StatusBadRequest)
		return
	}
	confPath := fmt.Sprintf("%s/%s.conf", wgClientsDir, name)
	data, err := os.ReadFile(confPath)
	if err != nil {
		http.Error(w, "Peer not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.conf"`, name))
	w.Write(data)
}

// handleWGClientRevoke removes a peer from the server config and the running interface.
func handleWGClientRevoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}
	name := strings.TrimSpace(req.Name)
	if !isValidClientName(name) {
		http.Error(w, "Invalid peer name", http.StatusBadRequest)
		return
	}

	// Find public key
	wgPeersMu.Lock()
	defer wgPeersMu.Unlock()

	peerIdx := -1
	for i, p := range wgPeers {
		if p.Name == name {
			peerIdx = i
			break
		}
	}
	if peerIdx == -1 {
		http.Error(w, "Peer not found", http.StatusNotFound)
		return
	}
	pubKey := wgPeers[peerIdx].PublicKey

	// Remove from running interface (best-effort)
	rmCmd := exec.Command("sudo", "wg", "set", wgInterface, "peer", pubKey, "remove")
	if out, err := rmCmd.CombinedOutput(); err != nil {
		log.Printf("[wg] wg set peer remove failed: %v\n%s", err, string(out))
	}

	// Remove [Peer] block from server config file
	if data, err := os.ReadFile(wgConfigFile); err == nil {
		updated := removeWGPeerBlock(string(data), pubKey)
		os.WriteFile(wgConfigFile, []byte(updated), 0640)
	}

	// Remove client .conf file
	os.Remove(fmt.Sprintf("%s/%s.conf", wgClientsDir, name))

	// Remove from metadata
	wgPeers = append(wgPeers[:peerIdx], wgPeers[peerIdx+1:]...)
	saveWGPeers()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"message": fmt.Sprintf("Peer '%s' revoked successfully.", name),
	})
}

// removeWGPeerBlock strips the [Peer] section with the given public key from
// a WireGuard config string, including the preceding "# Peer: …" comment.
func removeWGPeerBlock(conf, pubKey string) string {
	lines := strings.Split(conf, "\n")
	result := []string{}
	skip := false
	for i := 0; i < len(lines); i++ {
		line := lines[i]
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "[Peer]") {
			// Peek ahead to see if this block's PublicKey matches
			found := false
			for j := i + 1; j < len(lines) && j < i+10; j++ {
				t := strings.TrimSpace(lines[j])
				if strings.HasPrefix(t, "[") && t != "[Peer]" {
					break
				}
				if strings.HasPrefix(t, "PublicKey") {
					parts := strings.SplitN(t, "=", 2)
					if len(parts) == 2 && strings.TrimSpace(parts[1]) == pubKey {
						found = true
						break
					}
				}
			}
			if found {
				// Also remove the preceding "# Peer: …" comment if present
				if len(result) > 0 && strings.HasPrefix(strings.TrimSpace(result[len(result)-1]), "# Peer:") {
					result = result[:len(result)-1]
				}
				skip = true
			} else {
				skip = false
			}
		}
		if skip && strings.HasPrefix(trimmed, "[") && trimmed != "[Peer]" {
			skip = false
		}
		if !skip {
			result = append(result, line)
		}
	}
	return strings.TrimRight(strings.Join(result, "\n"), "\n") + "\n"
}

// handleWGLogs returns WireGuard journal entries.
func handleWGLogs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	lines := r.URL.Query().Get("lines")
	if lines == "" {
		lines = "50"
	}
	for _, c := range lines {
		if c < '0' || c > '9' {
			http.Error(w, "Invalid lines parameter", http.StatusBadRequest)
			return
		}
	}

	var output []byte
	var err error
	if isWireGuardInstalled() {
		cmd := exec.Command("journalctl", "-u", wgService, "-n", lines, "--no-pager", "--output=short-iso")
		output, err = cmd.CombinedOutput()
	} else {
		output = []byte("WireGuard is not installed.")
	}
	if err != nil && len(output) == 0 {
		output = []byte(fmt.Sprintf("journalctl error: %v", err))
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"logs": string(output)})
}

// Rule represents an iptables-style network rule for a group.
type Rule struct {
	ID       string `json:"id"`        // random hex ID
	Proto    string `json:"proto"`     // tcp | udp | icmp | all
	Dest     string `json:"dest"`      // CIDR or IP, e.g. "0.0.0.0/0" or "192.168.1.0/24"
	DestPort string `json:"dest_port"` // port or range, e.g. "80" / "8000:9000" / "" (all)
	Action   string `json:"action"`    // ACCEPT | DROP
	Comment  string `json:"comment"`
}

// Group holds a named collection of VPN clients and their access rules.
type Group struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	Members []string `json:"members"` // client names
	Rules   []Rule   `json:"rules"`
}

var (
	groupsMu sync.RWMutex
	groups   []Group
)

// loadGroups reads groups from disk; silently initialises empty list on error.
func loadGroups() {
	groupsMu.Lock()
	defer groupsMu.Unlock()
	data, err := os.ReadFile(groupsFile)
	if err != nil {
		groups = []Group{}
		return
	}
	if err := json.Unmarshal(data, &groups); err != nil {
		groups = []Group{}
	}
}

// saveGroups writes groups to disk (caller must hold groupsMu.Lock).
func saveGroups() error {
	data, err := json.MarshalIndent(groups, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(groupsFile, data, 0640)
}

func newID() string {
	b := make([]byte, 6)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// isValidGroupName allows letters, numbers, space, dash, underscore (max 64).
func isValidGroupName(name string) bool {
	name = strings.TrimSpace(name)
	if len(name) == 0 || len(name) > 64 {
		return false
	}
	for _, c := range name {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '-' || c == '_' || c == ' ') {
			return false
		}
	}
	return true
}

// isValidProto validates allowed protocol values.
func isValidProto(p string) bool {
	return p == "tcp" || p == "udp" || p == "icmp" || p == "all"
}

// isValidAction validates iptables action values.
func isValidAction(a string) bool {
	return a == "ACCEPT" || a == "DROP"
}

// isValidCIDR does a very lightweight check on an IP/CIDR value.
func isValidCIDR(s string) bool {
	if s == "" {
		return false
	}
	// allow "0.0.0.0/0" wildcard and simple IPs/CIDRs
	for _, c := range s {
		if !((c >= '0' && c <= '9') || c == '.' || c == '/' || c == ':') {
			return false
		}
	}
	return true
}

// isValidPort ensures port/range is numeric or empty.
func isValidPort(p string) bool {
	if p == "" {
		return true
	}
	for _, c := range p {
		if !((c >= '0' && c <= '9') || c == ':') {
			return false
		}
	}
	return true
}

// handleGroups handles GET (list all) and POST (create new group).
func handleGroups(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		groupsMu.RLock()
		defer groupsMu.RUnlock()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(groups)

	case http.MethodPost:
		var req struct {
			Name string `json:"name"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Bad request", http.StatusBadRequest)
			return
		}
		name := strings.TrimSpace(req.Name)
		if !isValidGroupName(name) {
			http.Error(w, "Invalid group name. Use letters, numbers, space, dash or underscore (max 64).", http.StatusBadRequest)
			return
		}
		groupsMu.Lock()
		defer groupsMu.Unlock()
		for _, g := range groups {
			if strings.EqualFold(g.Name, name) {
				http.Error(w, "A group with that name already exists.", http.StatusConflict)
				return
			}
		}
		g := Group{ID: newID(), Name: name, Members: []string{}, Rules: []Rule{}}
		groups = append(groups, g)
		if err := saveGroups(); err != nil {
			http.Error(w, "Failed to save group", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(g)

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleGroup handles operations on a single group (DELETE).
func handleGroup(w http.ResponseWriter, r *http.Request) {
	// Extract ID from path: /api/groups/<id>
	id := strings.TrimPrefix(r.URL.Path, "/api/groups/")
	id = strings.Split(id, "/")[0]
	if id == "" {
		http.Error(w, "Missing group ID", http.StatusBadRequest)
		return
	}

	switch r.Method {
	case http.MethodDelete:
		groupsMu.Lock()
		defer groupsMu.Unlock()
		idx := -1
		for i, g := range groups {
			if g.ID == id {
				idx = i
				break
			}
		}
		if idx == -1 {
			http.Error(w, "Group not found", http.StatusNotFound)
			return
		}
		groups = append(groups[:idx], groups[idx+1:]...)
		if err := saveGroups(); err != nil {
			http.Error(w, "Failed to save", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"message": "Group deleted."})

	case http.MethodPut:
		// Rename group
		var req struct {
			Name string `json:"name"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Bad request", http.StatusBadRequest)
			return
		}
		name := strings.TrimSpace(req.Name)
		if !isValidGroupName(name) {
			http.Error(w, "Invalid group name.", http.StatusBadRequest)
			return
		}
		groupsMu.Lock()
		defer groupsMu.Unlock()
		for i, g := range groups {
			if g.ID == id {
				groups[i].Name = name
				saveGroups()
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(groups[i])
				return
			}
		}
		http.Error(w, "Group not found", http.StatusNotFound)

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleGroupMembers handles GET (list members) and PUT (replace member list).
func handleGroupMembers(w http.ResponseWriter, r *http.Request) {
	// path: /api/groups/<id>/members
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/groups/"), "/")
	if len(parts) < 2 {
		http.Error(w, "Missing group ID", http.StatusBadRequest)
		return
	}
	id := parts[0]

	switch r.Method {
	case http.MethodGet:
		groupsMu.RLock()
		defer groupsMu.RUnlock()
		for _, g := range groups {
			if g.ID == id {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(g.Members)
				return
			}
		}
		http.Error(w, "Group not found", http.StatusNotFound)

	case http.MethodPut:
		var req struct {
			Members []string `json:"members"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Bad request", http.StatusBadRequest)
			return
		}
		// Validate each member name
		seen := map[string]bool{}
		clean := []string{}
		for _, m := range req.Members {
			m = strings.TrimSpace(m)
			if !isValidClientName(m) {
				http.Error(w, "Invalid client name: "+m, http.StatusBadRequest)
				return
			}
			if seen[m] {
				continue
			}
			seen[m] = true
			clean = append(clean, m)
		}
		groupsMu.Lock()
		defer groupsMu.Unlock()
		for i, g := range groups {
			if g.ID == id {
				groups[i].Members = clean
				saveGroups()
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(groups[i])
				return
			}
		}
		http.Error(w, "Group not found", http.StatusNotFound)

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleGroupRules handles GET (list rules), POST (add rule), DELETE (remove rule).
func handleGroupRules(w http.ResponseWriter, r *http.Request) {
	// path: /api/groups/<id>/rules  or  /api/groups/<id>/rules/<ruleID>
	path := strings.TrimPrefix(r.URL.Path, "/api/groups/")
	parts := strings.SplitN(path, "/", 3) // [groupID, "rules", ruleID?]
	if len(parts) < 2 {
		http.Error(w, "Missing group ID", http.StatusBadRequest)
		return
	}
	groupID := parts[0]
	ruleID := ""
	if len(parts) == 3 {
		ruleID = parts[2]
	}

	switch r.Method {
	case http.MethodGet:
		groupsMu.RLock()
		defer groupsMu.RUnlock()
		for _, g := range groups {
			if g.ID == groupID {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(g.Rules)
				return
			}
		}
		http.Error(w, "Group not found", http.StatusNotFound)

	case http.MethodPost:
		var req Rule
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Bad request", http.StatusBadRequest)
			return
		}
		// Validate fields
		if !isValidProto(req.Proto) {
			http.Error(w, "Invalid proto. Use: tcp, udp, icmp, all", http.StatusBadRequest)
			return
		}
		if !isValidCIDR(req.Dest) {
			http.Error(w, "Invalid destination CIDR/IP.", http.StatusBadRequest)
			return
		}
		if !isValidPort(req.DestPort) {
			http.Error(w, "Invalid port/range.", http.StatusBadRequest)
			return
		}
		if !isValidAction(req.Action) {
			http.Error(w, "Invalid action. Use: ACCEPT or DROP", http.StatusBadRequest)
			return
		}
		// Sanitise comment (strip control chars)
		comment := strings.Map(func(r rune) rune {
			if r < 32 {
				return -1
			}
			return r
		}, req.Comment)
		if len(comment) > 128 {
			comment = comment[:128]
		}

		rule := Rule{
			ID:       newID(),
			Proto:    req.Proto,
			Dest:     req.Dest,
			DestPort: req.DestPort,
			Action:   req.Action,
			Comment:  comment,
		}
		groupsMu.Lock()
		defer groupsMu.Unlock()
		for i, g := range groups {
			if g.ID == groupID {
				groups[i].Rules = append(groups[i].Rules, rule)
				saveGroups()
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusCreated)
				json.NewEncoder(w).Encode(rule)
				return
			}
		}
		http.Error(w, "Group not found", http.StatusNotFound)

	case http.MethodDelete:
		if ruleID == "" {
			http.Error(w, "Missing rule ID", http.StatusBadRequest)
			return
		}
		groupsMu.Lock()
		defer groupsMu.Unlock()
		for i, g := range groups {
			if g.ID == groupID {
				newRules := []Rule{}
				found := false
				for _, ru := range g.Rules {
					if ru.ID == ruleID {
						found = true
						continue
					}
					newRules = append(newRules, ru)
				}
				if !found {
					http.Error(w, "Rule not found", http.StatusNotFound)
					return
				}
				groups[i].Rules = newRules
				saveGroups()
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]string{"message": "Rule deleted."})
				return
			}
		}
		http.Error(w, "Group not found", http.StatusNotFound)

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleRevokeClient revokes a client certificate and removes its .ovpn profile.
func handleRevokeClient(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	name := strings.TrimSpace(req.Name)
	if !isValidClientName(name) {
		http.Error(w, "Invalid client name", http.StatusBadRequest)
		return
	}

	easyrsa := fmt.Sprintf("%s/easyrsa", easyRSADir)

	revoke := exec.Command(easyrsa, "--batch", "revoke", name)
	revoke.Dir = easyRSADir
	if out, err := revoke.CombinedOutput(); err != nil {
		http.Error(w, fmt.Sprintf("Revoke failed: %v\n%s", err, string(out)), http.StatusInternalServerError)
		return
	}

	genCRL := exec.Command(easyrsa, "--batch", "gen-crl")
	genCRL.Dir = easyRSADir
	if out, err := genCRL.CombinedOutput(); err != nil {
		http.Error(w, fmt.Sprintf("gen-crl failed: %v\n%s", err, string(out)), http.StatusInternalServerError)
		return
	}

	// Deploy updated CRL to server directory
	crlData, err := os.ReadFile(fmt.Sprintf("%s/pki/crl.pem", easyRSADir))
	if err == nil {
		os.WriteFile(fmt.Sprintf("%s/crl.pem", serverCerts), crlData, 0644)
	}

	os.Remove(fmt.Sprintf("%s/%s.ovpn", clientsDir, name))

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"message": fmt.Sprintf("Client '%s' revoked successfully.", name),
	})
}

