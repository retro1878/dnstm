package transport

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/net2share/dnstm/internal/binary"
	"github.com/net2share/dnstm/internal/config"
	"github.com/net2share/dnstm/internal/service"
	"github.com/net2share/dnstm/internal/system"
)

const (
	ConfigDir = "/etc/dnstm"
)

// Binary path getters using the binary manager.
// These return the path based on the current environment (test vs production).
var (
	binManager *binary.Manager
)

func getBinManager() *binary.Manager {
	if binManager == nil {
		binManager = binary.NewDefaultManager()
	}
	return binManager
}

// SlipstreamBinaryPath returns the path to slipstream-server.
func SlipstreamBinaryPath() string {
	path, _ := getBinManager().GetPath(binary.BinarySlipstreamServer)
	return path
}

// DNSTTBinaryPath returns the path to dnstt-server.
func DNSTTBinaryPath() string {
	path, _ := getBinManager().GetPath(binary.BinaryDNSTTServer)
	return path
}

// SSServerBinaryPath returns the path to ssserver.
func SSServerBinaryPath() string {
	path, _ := getBinManager().GetPath(binary.BinarySSServer)
	return path
}

// SSHTunUserBinaryPath returns the path to sshtun-user.
func SSHTunUserBinaryPath() string {
	path, _ := getBinManager().GetPath(binary.BinarySSHTunUser)
	return path
}

// VayDNSBinaryPath returns the path to vaydns-server.
func VayDNSBinaryPath() string {
	path, _ := getBinManager().GetPath(binary.BinaryVayDNSServer)
	return path
}

// MasterDNSVPNBinaryPath returns the path to masterdnsvpn-server.
func MasterDNSVPNBinaryPath() string {
	path, _ := getBinManager().GetPath(binary.BinaryMasterDNSVPNServer)
	return path
}

// BuildOptions configures how the transport should bind.
type BuildOptions struct {
	BindHost string // "127.0.0.1" for multi mode, or external IP for single mode
	BindPort int    // 53 for single mode, cfg.Port for multi mode
}

// Builder builds command lines for transport instances.
type Builder struct{}

// NewBuilder creates a new transport builder.
func NewBuilder() *Builder {
	return &Builder{}
}

// TunnelBuildResult contains the result of building a tunnel service.
type TunnelBuildResult struct {
	ExecStart    string
	ConfigDir    string
	ReadPaths    []string
	WritePaths   []string
	BindToPort53 bool
}

// CreateService creates a systemd service for the tunnel.
func (r *TunnelBuildResult) CreateService(serviceName string) error {
	cfg := &service.ServiceConfig{
		Name:             serviceName,
		Description:      fmt.Sprintf("dnstm tunnel: %s", serviceName),
		User:             system.DnstmUser,
		Group:            system.DnstmUser,
		ExecStart:        r.ExecStart,
		ReadOnlyPaths:    r.ReadPaths,
		ReadWritePaths:   r.WritePaths,
		BindToPrivileged: r.BindToPort53,
	}
	return service.CreateGenericService(cfg)
}

// BuildTunnelService builds the service configuration for a tunnel with the new config types.
// This bridges between the new config types and the existing builder logic.
func (b *Builder) BuildTunnelService(tunnel *config.TunnelConfig, backend *config.BackendConfig, opts *BuildOptions) (*TunnelBuildResult, error) {
	if opts == nil {
		opts = &BuildOptions{
			BindHost: "127.0.0.1",
			BindPort: tunnel.Port,
		}
	}

	result := &TunnelBuildResult{
		BindToPort53: opts.BindPort == 53,
	}

	// Create tunnel config directory
	configDir := filepath.Join(ConfigDir, "tunnels", tunnel.Tag)
	if err := os.MkdirAll(configDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create config directory: %w", err)
	}
	if err := system.ChownDirToDnstm(configDir); err != nil {
		return nil, fmt.Errorf("failed to set config directory ownership: %w", err)
	}
	result.ConfigDir = configDir

	// MasterDnsVPN has no backend; dispatch before the backend address lookup.
	if tunnel.Transport == config.TransportMasterDNSVPN {
		return b.buildMasterDNSVPNTunnel(tunnel, opts, result)
	}

	// Get target address from backend
	targetAddr := backend.Address
	if targetAddr == "" {
		// Default addresses based on backend type
		switch backend.Type {
		case config.BackendSOCKS:
			targetAddr = "127.0.0.1:1080"
		case config.BackendSSH:
			targetAddr = "127.0.0.1:22"
		}
	}

	switch tunnel.Transport {
	case config.TransportSlipstream:
		return b.buildSlipstreamTunnel(tunnel, backend, targetAddr, opts, result)
	case config.TransportDNSTT:
		return b.buildDNSTTTunnel(tunnel, backend, targetAddr, opts, result)
	case config.TransportVayDNS:
		return b.buildVayDNSTunnel(tunnel, backend, targetAddr, opts, result)
	default:
		return nil, fmt.Errorf("unknown transport type: %s", tunnel.Transport)
	}
}

// buildSlipstreamTunnel builds a Slipstream-based tunnel service.
func (b *Builder) buildSlipstreamTunnel(tunnel *config.TunnelConfig, backend *config.BackendConfig, targetAddr string, opts *BuildOptions, result *TunnelBuildResult) (*TunnelBuildResult, error) {
	// Read cert/key paths from tunnel config (already set before builder is called)
	if tunnel.Slipstream == nil || tunnel.Slipstream.Cert == "" || tunnel.Slipstream.Key == "" {
		return nil, fmt.Errorf("slipstream cert/key paths not set for tunnel %s", tunnel.Tag)
	}

	certPath := tunnel.Slipstream.Cert
	keyPath := tunnel.Slipstream.Key

	result.ReadPaths = append(result.ReadPaths, certPath, keyPath)

	// Slipstream + Shadowsocks uses ssserver with slipstream as plugin (SIP003)
	if backend.Type == config.BackendShadowsocks {
		return b.buildSlipstreamShadowsocksTunnel(tunnel, backend, certPath, keyPath, opts, result)
	}

	// Slipstream standalone mode (SOCKS, SSH, or custom target)
	args := []string{
		"--dns-listen-host", opts.BindHost,
		"--domain", tunnel.Domain,
		"--dns-listen-port", fmt.Sprintf("%d", opts.BindPort),
		"--target-address", targetAddr,
		"--cert", certPath,
		"--key", keyPath,
	}

	result.ExecStart = fmt.Sprintf("%s %s", SlipstreamBinaryPath(), strings.Join(args, " "))
	return result, nil
}

// buildSlipstreamShadowsocksTunnel builds a Slipstream+Shadowsocks tunnel using SIP003 plugin mode.
func (b *Builder) buildSlipstreamShadowsocksTunnel(tunnel *config.TunnelConfig, backend *config.BackendConfig, certPath, keyPath string, opts *BuildOptions, result *TunnelBuildResult) (*TunnelBuildResult, error) {
	if backend.Shadowsocks == nil {
		return nil, fmt.Errorf("shadowsocks backend missing configuration")
	}

	method := backend.Shadowsocks.Method
	if method == "" {
		method = "aes-256-gcm"
	}

	// Build plugin options
	pluginOpts := fmt.Sprintf("domain=%s;dns-listen-host=%s;dns-listen-port=%d;cert=%s;key=%s",
		tunnel.Domain, opts.BindHost, opts.BindPort, certPath, keyPath)

	// Write Shadowsocks config file
	ssConfig := map[string]interface{}{
		"server":      opts.BindHost,
		"server_port": opts.BindPort,
		"password":    backend.Shadowsocks.Password,
		"method":      method,
		"mode":        "tcp_only",
		"plugin":      SlipstreamBinaryPath(),
		"plugin_opts": pluginOpts,
		"plugin_mode": "tcp_only",
	}

	configPath := filepath.Join(result.ConfigDir, "config.json")
	data, err := json.MarshalIndent(ssConfig, "", "    ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := os.WriteFile(configPath, data, 0644); err != nil {
		return nil, fmt.Errorf("failed to write config: %w", err)
	}
	if err := system.ChownToDnstm(configPath); err != nil {
		return nil, fmt.Errorf("failed to set config file ownership: %w", err)
	}

	result.ExecStart = fmt.Sprintf("%s -c %s", SSServerBinaryPath(), configPath)
	result.ReadPaths = append(result.ReadPaths, configPath)

	return result, nil
}

// buildDNSTTTunnel builds a DNSTT-based tunnel service.
func (b *Builder) buildDNSTTTunnel(tunnel *config.TunnelConfig, backend *config.BackendConfig, targetAddr string, opts *BuildOptions, result *TunnelBuildResult) (*TunnelBuildResult, error) {
	// DNSTT doesn't support Shadowsocks
	if backend.Type == config.BackendShadowsocks {
		return nil, fmt.Errorf("DNSTT transport does not support Shadowsocks backend")
	}

	// Read key path from tunnel config (already set before builder is called)
	if tunnel.DNSTT == nil || tunnel.DNSTT.PrivateKey == "" {
		return nil, fmt.Errorf("dnstt private key path not set for tunnel %s", tunnel.Tag)
	}

	privKeyPath := tunnel.DNSTT.PrivateKey
	result.ReadPaths = append(result.ReadPaths, privKeyPath)

	mtu := "1232"
	if tunnel.DNSTT.MTU > 0 {
		mtu = fmt.Sprintf("%d", tunnel.DNSTT.MTU)
	}

	// Build dnstt-server command
	args := []string{
		"-udp", fmt.Sprintf("%s:%d", opts.BindHost, opts.BindPort),
		"-privkey-file", privKeyPath,
		"-mtu", mtu,
		tunnel.Domain,
		targetAddr,
	}

	result.ExecStart = fmt.Sprintf("%s %s", DNSTTBinaryPath(), strings.Join(args, " "))
	return result, nil
}

// buildVayDNSTunnel builds a VayDNS-based tunnel service.
func (b *Builder) buildVayDNSTunnel(tunnel *config.TunnelConfig, backend *config.BackendConfig, targetAddr string, opts *BuildOptions, result *TunnelBuildResult) (*TunnelBuildResult, error) {
	if backend.Type == config.BackendShadowsocks {
		return nil, fmt.Errorf("VayDNS transport does not support Shadowsocks backend")
	}

	if tunnel.VayDNS == nil || tunnel.VayDNS.PrivateKey == "" {
		return nil, fmt.Errorf("vaydns private key path not set for tunnel %s", tunnel.Tag)
	}

	privKeyPath := tunnel.VayDNS.PrivateKey
	result.ReadPaths = append(result.ReadPaths, privKeyPath)

	mtu := "1232"
	if tunnel.VayDNS.MTU > 0 {
		mtu = fmt.Sprintf("%d", tunnel.VayDNS.MTU)
	}

	args := []string{
		"-udp", fmt.Sprintf("%s:%d", opts.BindHost, opts.BindPort),
		"-privkey-file", privKeyPath,
		"-mtu", mtu,
		"-domain", tunnel.Domain,
		"-upstream", targetAddr,
		"-idle-timeout", tunnel.VayDNS.ResolvedVayDNSIdleTimeout(),
		"-keepalive", tunnel.VayDNS.ResolvedVayDNSKeepAlive(),
	}

	if tunnel.VayDNS.Fallback != "" {
		args = append(args, "-fallback", tunnel.VayDNS.Fallback)
	}
	if tunnel.VayDNS.DnsttCompat {
		args = append(args, "-dnstt-compat")
	}
	if n := tunnel.VayDNS.VayDNSClientIDSizeForFlag(); n > 0 {
		args = append(args, "-clientid-size", strconv.Itoa(n))
	}
	if tunnel.VayDNS.QueueSize > 0 && tunnel.VayDNS.QueueSize != 512 {
		args = append(args, "-queue-size", strconv.Itoa(tunnel.VayDNS.QueueSize))
	}
	if tunnel.VayDNS.KCPWindowSize > 0 {
		args = append(args, "-kcp-window-size", strconv.Itoa(tunnel.VayDNS.KCPWindowSize))
	}
	if tunnel.VayDNS.QueueOverflow != "" && tunnel.VayDNS.QueueOverflow != "drop" {
		args = append(args, "-queue-overflow", tunnel.VayDNS.QueueOverflow)
	}
	if tunnel.VayDNS.LogLevel != "" && tunnel.VayDNS.LogLevel != "info" {
		args = append(args, "-log-level", tunnel.VayDNS.LogLevel)
	}
	if tunnel.VayDNS.RecordType != "" && tunnel.VayDNS.RecordType != "txt" {
		args = append(args, "-record-type", tunnel.VayDNS.RecordType)
	}

	result.ExecStart = fmt.Sprintf("%s %s", VayDNSBinaryPath(), strings.Join(args, " "))
	return result, nil
}

// buildMasterDNSVPNTunnel builds a MasterDnsVPN-based tunnel service.
// MasterDnsVPN manages its own SOCKS5 proxy and does not forward to a DNSTM backend.
// The server_config.toml is generated by SetupMasterDNSVPN during tunnel creation;
// this method keeps UDP_HOST and UDP_PORT in sync with the current bind options so that
// mode switches (single ↔ multi) are reflected correctly.
func (b *Builder) buildMasterDNSVPNTunnel(tunnel *config.TunnelConfig, opts *BuildOptions, result *TunnelBuildResult) (*TunnelBuildResult, error) {
	if tunnel.MasterDNSVPN == nil || tunnel.MasterDNSVPN.ConfigFile == "" {
		return nil, fmt.Errorf("masterdnsvpn config_file not set for tunnel %s", tunnel.Tag)
	}

	configFile := tunnel.MasterDNSVPN.ConfigFile
	keyFile := filepath.Join(result.ConfigDir, "encrypt_key.txt")

	// Use the tunnel-local binary when set; fall back to the shared binary for
	// tunnels created before per-tunnel isolation was introduced.
	binaryPath := tunnel.MasterDNSVPN.BinaryPath
	if binaryPath == "" {
		binaryPath = MasterDNSVPNBinaryPath()
	}
	if binaryPath == "" {
		return nil, fmt.Errorf("masterdnsvpn-server binary not found for tunnel %s", tunnel.Tag)
	}

	// Sync UDP_HOST and UDP_PORT to match current bind options.
	// This handles mode switches where the port changes from 53 (single) to an
	// internal port (multi) without clobbering user customisations to other fields.
	if err := updateMasterDNSVPNBindConfig(configFile, opts.BindHost, opts.BindPort); err != nil {
		return nil, fmt.Errorf("failed to update masterdnsvpn config bind options: %w", err)
	}

	result.ReadPaths = append(result.ReadPaths, configFile, keyFile)
	result.ExecStart = fmt.Sprintf("%s -config %s -nowait", binaryPath, configFile)

	return result, nil
}

// updateMasterDNSVPNBindConfig updates only the UDP_HOST and UDP_PORT lines in an existing
// server_config.toml, preserving all other user-configured fields.
func updateMasterDNSVPNBindConfig(configFile, bindHost string, bindPort int) error {
	data, err := os.ReadFile(configFile)
	if err != nil {
		return fmt.Errorf("failed to read config file: %w", err)
	}

	lines := strings.Split(string(data), "\n")
	for i, line := range lines {
		switch {
		case strings.HasPrefix(line, "UDP_HOST"):
			lines[i] = fmt.Sprintf("UDP_HOST = \"%s\"", bindHost)
		case strings.HasPrefix(line, "UDP_PORT"):
			lines[i] = fmt.Sprintf("UDP_PORT = %d", bindPort)
		}
	}

	return os.WriteFile(configFile, []byte(strings.Join(lines, "\n")), 0640)
}

// applyMasterDNSVPNSetupConfig patches the four site-specific required fields in a
// MasterDnsVPN server_config.toml template, leaving all other settings at their release
// defaults.  It handles both single-line and multi-line DOMAIN arrays.
func applyMasterDNSVPNSetupConfig(content, domain, bindHost string, bindPort int, keyFilePath string) string {
	lines := strings.Split(content, "\n")
	out := make([]string, 0, len(lines))
	skipUntilClosingBracket := false

	for _, line := range lines {
		// When the DOMAIN array spans multiple lines, skip inner lines until "]".
		if skipUntilClosingBracket {
			if strings.Contains(line, "]") {
				skipUntilClosingBracket = false
			}
			continue
		}
		switch {
		case strings.HasPrefix(line, "DOMAIN"):
			out = append(out, fmt.Sprintf(`DOMAIN = ["%s"]`, domain))
			// If the original DOMAIN value doesn't close on this line it's multi-line.
			if !strings.Contains(line, "]") {
				skipUntilClosingBracket = true
			}
		case strings.HasPrefix(line, "UDP_HOST"):
			out = append(out, fmt.Sprintf(`UDP_HOST = "%s"`, bindHost))
		case strings.HasPrefix(line, "UDP_PORT"):
			out = append(out, fmt.Sprintf("UDP_PORT = %d", bindPort))
		case strings.HasPrefix(line, "ENCRYPTION_KEY_FILE"):
			out = append(out, fmt.Sprintf(`ENCRYPTION_KEY_FILE = "%s"`, keyFilePath))
		default:
			out = append(out, line)
		}
	}
	return strings.Join(out, "\n")
}

// minimalMasterDNSVPNConfig returns the minimal hardcoded server_config.toml content
// that is known to work for both -genkey and normal operation.
func minimalMasterDNSVPNConfig(domain, bindHost string, bindPort int, keyFilePath string) string {
	return fmt.Sprintf(
		"DOMAIN = [\"%s\"]\nPROTOCOL_TYPE = \"SOCKS5\"\nUDP_HOST = \"%s\"\nUDP_PORT = %d\nDATA_ENCRYPTION_METHOD = 1\nENCRYPTION_KEY_FILE = \"%s\"\nDNS_UPSTREAM_SERVERS = [\"1.1.1.1:53\", \"1.0.0.1:53\"]\nLOG_LEVEL = \"INFO\"\nCONFIG_VERSION = \"12\"\n",
		domain, bindHost, bindPort, keyFilePath,
	)
}

// SetupMasterDNSVPN generates an encryption key and a server_config.toml for a new
// MasterDnsVPN tunnel. It also copies the shared masterdnsvpn-server binary into tunnelDir
// so that each tunnel has an independent binary that can be versioned separately.
//
// Key generation always uses a minimal known-good config so the release template cannot
// affect genkey behaviour (e.g. by triggering network connections or extended init).
// The final runtime config is then written from the release template (if available) so
// that all upstream defaults are included.
//
// The caller must ensure the shared binary is installed (via EnsureMasterDNSVPNInstalled*)
// before calling this function.
//
// Returns the encryption key content (to show to the user), the config file path, and the
// path to the tunnel-local binary.
func SetupMasterDNSVPN(tunnelDir, domain, bindHost string, bindPort int) (encryptionKey, configFilePath, binaryPath string, err error) {
	// Copy the shared binary into the tunnel directory for per-tunnel isolation.
	tunnelBinaryPath, copyErr := CopyMasterDNSVPNBinaryToDir(tunnelDir)
	if copyErr != nil {
		return "", "", "", fmt.Errorf("masterdnsvpn-server binary not available: %w", copyErr)
	}
	_ = system.ChownToDnstm(tunnelBinaryPath) // best-effort

	keyFilePath := filepath.Join(tunnelDir, "encrypt_key.txt")
	configFilePath = filepath.Join(tunnelDir, "server_config.toml")

	// Step 1: Write the minimal known-good config for key generation.
	// Using a minimal config here avoids any compatibility issues the release template
	// might introduce (different field formats, extra network init, etc.).
	genkeyConfig := minimalMasterDNSVPNConfig(domain, bindHost, bindPort, keyFilePath)
	if writeErr := os.WriteFile(configFilePath, []byte(genkeyConfig), 0640); writeErr != nil {
		return "", "", "", fmt.Errorf("failed to write server config: %w", writeErr)
	}
	_ = system.ChownToDnstm(configFilePath) // best-effort

	// Step 2: Run -genkey with a 30-second timeout so the caller never hangs indefinitely.
	genkeyCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(genkeyCtx, tunnelBinaryPath, "-genkey", "-nowait")
	cmd.Dir = tunnelDir
	if out, cmdErr := cmd.CombinedOutput(); cmdErr != nil {
		return "", "", "", fmt.Errorf("failed to generate key: %w\nOutput: %s", cmdErr, out)
	}

	keyData, readErr := os.ReadFile(keyFilePath)
	if readErr != nil {
		return "", "", "", fmt.Errorf("failed to read generated key: %w", readErr)
	}
	_ = system.ChownToDnstm(keyFilePath) // best-effort

	// Step 3: Write the runtime config. Prefer the release-bundled template so that
	// all upstream defaults are included; fall back to the minimal config if unavailable.
	var runtimeConfig string
	if defaultCfgData, rErr := os.ReadFile(DefaultMasterDNSVPNConfigPath()); rErr == nil && len(defaultCfgData) > 0 {
		runtimeConfig = applyMasterDNSVPNSetupConfig(string(defaultCfgData), domain, bindHost, bindPort, keyFilePath)
	} else {
		runtimeConfig = genkeyConfig // minimal config already has correct values
	}
	if writeErr := os.WriteFile(configFilePath, []byte(runtimeConfig), 0640); writeErr != nil {
		return "", "", "", fmt.Errorf("failed to write runtime server config: %w", writeErr)
	}
	_ = system.ChownToDnstm(configFilePath) // best-effort

	return strings.TrimSpace(string(keyData)), configFilePath, tunnelBinaryPath, nil
}

// RegenerateTunnelService regenerates a tunnel's systemd service with new bind options.
// This is used when switching active tunnels in single mode.
func (b *Builder) RegenerateTunnelService(tunnel *config.TunnelConfig, backend *config.BackendConfig, opts *BuildOptions) error {
	serviceName := fmt.Sprintf("dnstm-%s", tunnel.Tag)

	// Stop the service if it's running
	if service.IsServiceActive(serviceName) {
		if err := service.StopService(serviceName); err != nil {
			return fmt.Errorf("failed to stop service: %w", err)
		}
	}

	// Remove the old service
	if service.IsServiceInstalled(serviceName) {
		if err := service.RemoveService(serviceName); err != nil {
			return fmt.Errorf("failed to remove old service: %w", err)
		}
	}

	// Build and create the new service
	result, err := b.BuildTunnelService(tunnel, backend, opts)
	if err != nil {
		return fmt.Errorf("failed to build service: %w", err)
	}

	if err := result.CreateService(serviceName); err != nil {
		return fmt.Errorf("failed to create service: %w", err)
	}

	return nil
}
