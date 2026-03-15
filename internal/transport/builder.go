package transport

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

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

// MasterDNSBinaryPath returns the path to masterdns-server.
func MasterDNSBinaryPath() string {
	path, _ := getBinManager().GetPath(binary.BinaryMasterDNSServer)
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
	ExecStart                  string
	ConfigDir                  string
	ReadPaths                  []string
	WritePaths                 []string
	BindToPort53               bool
	WorkingDirectory           string // Optional working directory for the service process
	SkipMemoryDenyWriteExecute bool   // Disable MemoryDenyWriteExecute (for PyInstaller binaries)
}

// CreateService creates a systemd service for the tunnel.
func (r *TunnelBuildResult) CreateService(serviceName string) error {
	cfg := &service.ServiceConfig{
		Name:                      serviceName,
		Description:               fmt.Sprintf("dnstm tunnel: %s", serviceName),
		User:                      system.DnstmUser,
		Group:                     system.DnstmUser,
		ExecStart:                 r.ExecStart,
		WorkingDirectory:          r.WorkingDirectory,
		ReadOnlyPaths:             r.ReadPaths,
		ReadWritePaths:            r.WritePaths,
		BindToPrivileged:          r.BindToPort53,
		SkipMemoryDenyWriteExecute: r.SkipMemoryDenyWriteExecute,
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
	case config.TransportMasterDNS:
		return b.buildMasterDNSTunnel(tunnel, backend, targetAddr, opts, result)
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

// buildMasterDNSTunnel builds a MasterDnsVPN-based tunnel service.
// MasterDNS is config-file based: it reads server_config.toml from its working directory.
func (b *Builder) buildMasterDNSTunnel(tunnel *config.TunnelConfig, backend *config.BackendConfig, targetAddr string, opts *BuildOptions, result *TunnelBuildResult) (*TunnelBuildResult, error) {
	if backend.Type == config.BackendShadowsocks {
		return nil, fmt.Errorf("MasterDNS transport does not support Shadowsocks backend")
	}

	if tunnel.MasterDNS == nil {
		return nil, fmt.Errorf("masterdns config not set for tunnel %s", tunnel.Tag)
	}

	// Determine protocol type and forwarding based on backend
	protocolType := "SOCKS5"
	useExternalSocks5 := false
	socks5Auth := false
	socks5User := ""
	socks5Pass := ""
	forwardIP := "127.0.0.1"
	forwardPort := 1080

	switch backend.Type {
	case config.BackendSOCKS:
		// Forward to the external SOCKS5 proxy (e.g., microsocks)
		useExternalSocks5 = true
		if host, portStr, err := net.SplitHostPort(targetAddr); err == nil {
			forwardIP = host
			if p, err := strconv.Atoi(portStr); err == nil {
				forwardPort = p
			}
		}
		if backend.HasSocksAuth() {
			socks5Auth = true
			socks5User = backend.Socks.User
			socks5Pass = backend.Socks.Password
		}
	case config.BackendSSH, config.BackendCustom:
		// TCP forwarding directly to the target
		protocolType = "TCP"
		if host, portStr, err := net.SplitHostPort(targetAddr); err == nil {
			forwardIP = host
			if p, err := strconv.Atoi(portStr); err == nil {
				forwardPort = p
			}
		}
	}

	encryptionMethod := tunnel.MasterDNS.EncryptionMethod
	if encryptionMethod == 0 {
		encryptionMethod = 1 // Default: XOR
	}

	// Write server_config.toml into the tunnel config directory
	configPath := filepath.Join(result.ConfigDir, "server_config.toml")
	configContent := fmt.Sprintf(`# MasterDnsVPN server configuration - managed by dnstm
# DO NOT EDIT MANUALLY

UDP_HOST = "%s"
UDP_PORT = %d

DOMAIN = ["%s"]

PROTOCOL_TYPE = "%s"

USE_EXTERNAL_SOCKS5 = %v

FORWARD_IP = "%s"
FORWARD_PORT = %d

SOCKS5_AUTH = %v
SOCKS5_USER = "%s"
SOCKS5_PASS = "%s"

SOCKS_HANDSHAKE_TIMEOUT = 120.0

DATA_ENCRYPTION_METHOD = %d

SUPPORTED_UPLOAD_COMPRESSION_TYPES = [0, 1, 2, 3]
SUPPORTED_DOWNLOAD_COMPRESSION_TYPES = [0, 1, 2, 3]

ARQ_WINDOW_SIZE = 256
ARQ_INITIAL_RTO = 0.5
ARQ_MAX_RTO = 1.5

ARQ_CONTROL_INITIAL_RTO = 0.5
ARQ_CONTROL_MAX_RTO = 1.5
ARQ_CONTROL_MAX_RETRIES = 180

SESSION_TIMEOUT = 300
SESSION_CLEANUP_INTERVAL = 30
MAX_SESSIONS = 255

MAX_CONCURRENT_REQUESTS = 500
CPU_WORKER_THREADS = 0
MAX_PACKETS_PER_BATCH = 1000
SOCKET_BUFFER_SIZE = 8388608

LOG_LEVEL = "INFO"

CONFIG_VERSION = 3.0
`,
		opts.BindHost,
		opts.BindPort,
		tunnel.Domain,
		protocolType,
		useExternalSocks5,
		forwardIP,
		forwardPort,
		socks5Auth,
		socks5User,
		socks5Pass,
		encryptionMethod,
	)

	if err := os.WriteFile(configPath, []byte(configContent), 0640); err != nil {
		return nil, fmt.Errorf("failed to write masterdns config: %w", err)
	}
	if err := system.ChownToDnstm(configPath); err != nil {
		return nil, fmt.Errorf("failed to set config file ownership: %w", err)
	}

	// The binary reads server_config.toml from its working directory
	result.ExecStart = MasterDNSBinaryPath()
	result.ReadPaths = append(result.ReadPaths, configPath)
	// encrypt_key.txt is generated at runtime in the config dir
	result.WritePaths = append(result.WritePaths, result.ConfigDir)

	// MasterDNS is a PyInstaller binary: needs WorkingDirectory and no MemoryDenyWriteExecute
	result.WorkingDirectory = result.ConfigDir
	result.SkipMemoryDenyWriteExecute = true

	return result, nil
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
