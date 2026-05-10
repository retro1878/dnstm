package transport

import (
	"archive/zip"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/net2share/dnstm/internal/binary"
	"github.com/net2share/dnstm/internal/config"
	"github.com/net2share/dnstm/internal/log"
)

// StatusFunc is a callback for reporting installation status messages.
type StatusFunc func(message string)

// EnsureTransportBinariesInstalled checks and installs required binaries for a transport type.
// This function accepts the new config.TransportType.
func EnsureTransportBinariesInstalled(transport config.TransportType) error {
	switch transport {
	case config.TransportSlipstream:
		return EnsureSlipstreamInstalled()
	case config.TransportDNSTT:
		return EnsureDnsttInstalled()
	case config.TransportVayDNS:
		return EnsureVayDNSInstalled()
	case config.TransportMasterDNSVPN:
		return EnsureMasterDNSVPNInstalled()
	default:
		return nil
	}
}

// EnsureBackendBinariesInstalled checks and installs required binaries for a backend type.
func EnsureBackendBinariesInstalled(backend config.BackendType) error {
	switch backend {
	case config.BackendShadowsocks:
		return EnsureShadowsocksInstalled()
	default:
		return nil
	}
}

// EnsureDnsttInstalled installs dnstt-server if not present.
func EnsureDnsttInstalled() error {
	return EnsureDnsttInstalledWithStatus(nil)
}

// EnsureDnsttInstalledWithStatus installs dnstt-server with status callback.
func EnsureDnsttInstalledWithStatus(statusFn StatusFunc) error {
	return ensureBinaryInstalled(binary.BinaryDNSTTServer, "dnstt-server", statusFn)
}

// EnsureSlipstreamInstalled installs slipstream-server if not present.
func EnsureSlipstreamInstalled() error {
	return EnsureSlipstreamInstalledWithStatus(nil)
}

// EnsureSlipstreamInstalledWithStatus installs slipstream-server with status callback.
func EnsureSlipstreamInstalledWithStatus(statusFn StatusFunc) error {
	return ensureBinaryInstalled(binary.BinarySlipstreamServer, "slipstream-server", statusFn)
}

// EnsureShadowsocksInstalled installs ssserver if not present.
func EnsureShadowsocksInstalled() error {
	return EnsureShadowsocksInstalledWithStatus(nil)
}

// EnsureShadowsocksInstalledWithStatus installs ssserver with status callback.
func EnsureShadowsocksInstalledWithStatus(statusFn StatusFunc) error {
	return ensureBinaryInstalled(binary.BinarySSServer, "ssserver", statusFn)
}

// EnsureVayDNSInstalled installs vaydns-server if not present.
func EnsureVayDNSInstalled() error {
	return EnsureVayDNSInstalledWithStatus(nil)
}

// EnsureVayDNSInstalledWithStatus installs vaydns-server with status callback.
func EnsureVayDNSInstalledWithStatus(statusFn StatusFunc) error {
	return ensureBinaryInstalled(binary.BinaryVayDNSServer, "vaydns-server", statusFn)
}

// EnsureSSHTunUserInstalled installs sshtun-user if not present.
func EnsureSSHTunUserInstalled() error {
	return EnsureSSHTunUserInstalledWithStatus(nil)
}

// EnsureSSHTunUserInstalledWithStatus installs sshtun-user with status callback.
func EnsureSSHTunUserInstalledWithStatus(statusFn StatusFunc) error {
	return ensureBinaryInstalled(binary.BinarySSHTunUser, "sshtun-user", statusFn)
}

// IsSSHTunUserInstalled checks if sshtun-user binary is installed.
func IsSSHTunUserInstalled() bool {
	mgr := binary.NewDefaultManager()
	_, err := mgr.GetPath(binary.BinarySSHTunUser)
	return err == nil
}

// EnsureMasterDNSVPNInstalled installs masterdnsvpn-server if not present.
func EnsureMasterDNSVPNInstalled() error {
	return EnsureMasterDNSVPNInstalledWithStatus(nil)
}

// EnsureMasterDNSVPNInstalledWithStatus installs the latest masterdnsvpn-server with a status callback.
func EnsureMasterDNSVPNInstalledWithStatus(statusFn StatusFunc) error {
	return EnsureMasterDNSVPNInstalledVersion("", statusFn)
}

// EnsureMasterDNSVPNInstalledVersion installs masterdnsvpn-server at the requested version tag.
// Pass "" to install the latest release. If the requested version is already installed the call
// is a no-op. When a specific version is requested but a different version is already present,
// the binary is re-downloaded and replaced.
func EnsureMasterDNSVPNInstalledVersion(version string, statusFn StatusFunc) error {
	mgr := binary.NewDefaultManager()

	_, alreadyInstalled := mgr.GetPath(binary.BinaryMasterDNSVPNServer)
	installed := alreadyInstalled == nil

	if installed {
		if version == "" {
			// No specific version requested — skip if any version is present.
			log.Debug("masterdnsvpn-server: already installed")
			if statusFn != nil {
				statusFn("masterdnsvpn-server already installed")
			}
			return nil
		}
		// Specific version requested — skip only if the installed version matches.
		installedVersion := ReadInstalledMasterDNSVPNVersion()
		if installedVersion == version {
			log.Debug("masterdnsvpn-server: version %s already installed", version)
			if statusFn != nil {
				statusFn(fmt.Sprintf("masterdnsvpn-server %s already installed", version))
			}
			return nil
		}
		if statusFn != nil {
			if installedVersion != "" {
				statusFn(fmt.Sprintf("Updating masterdnsvpn-server %s → %s...", installedVersion, version))
			} else {
				statusFn(fmt.Sprintf("Installing masterdnsvpn-server %s...", version))
			}
		}
	} else {
		if statusFn != nil {
			if version != "" {
				statusFn(fmt.Sprintf("Downloading masterdnsvpn-server %s...", version))
			} else {
				statusFn("Downloading masterdnsvpn-server...")
			}
		}
	}

	destPath, installedVersion, err := downloadAndInstallMasterDNSVPN(mgr.BinDir(), version)
	if err != nil {
		return err
	}

	// Persist the installed version so future calls can skip re-downloading.
	writeInstalledMasterDNSVPNVersion(installedVersion)

	log.Debug("masterdnsvpn-server installed at %s (version %s)", destPath, installedVersion)
	if statusFn != nil {
		statusFn(fmt.Sprintf("masterdnsvpn-server %s installed", installedVersion))
	}
	return nil
}

// downloadAndInstallMasterDNSVPN downloads the MasterDnsVPN server ZIP for the given release
// tag (pass "" for the latest release), extracts the versioned binary, installs it as
// "masterdnsvpn-server" in binDir, and returns the destination path and extracted version tag.
func downloadAndInstallMasterDNSVPN(binDir, versionTag string) (destPath, installedVersion string, err error) {
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		return "", "", fmt.Errorf("masterdnsvpn-server auto-install is only supported on linux/amd64; set DNSTM_MASTERDNSVPN_SERVER_PATH to provide the binary manually")
	}

	downloadURL := masterDNSVPNZipURL(versionTag)

	// Download ZIP to a temporary file.
	tmpZip, err := os.CreateTemp("", "masterdnsvpn-*.zip")
	if err != nil {
		return "", "", fmt.Errorf("failed to create temp file: %w", err)
	}
	tmpZipPath := tmpZip.Name()
	tmpZip.Close()
	defer os.Remove(tmpZipPath)

	resp, err := http.Get(downloadURL) //nolint:gosec // URL is constructed from validated constants/tags
	if err != nil {
		return "", "", fmt.Errorf("failed to download masterdnsvpn-server: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("failed to download masterdnsvpn-server: HTTP %d", resp.StatusCode)
	}

	f, err := os.OpenFile(tmpZipPath, os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return "", "", fmt.Errorf("failed to open temp file for writing: %w", err)
	}
	if _, err := io.Copy(f, resp.Body); err != nil {
		f.Close()
		return "", "", fmt.Errorf("failed to write download: %w", err)
	}
	f.Close()

	// Extract the binary. The binary inside the ZIP has a versioned filename such as
	// "MasterDnsVPN_Server_Linux_AMD64_v2026.04.07.233605-b5a4474", so we match by prefix.
	// Also extracts the bundled server_config.toml when present.
	tmpBin, extractedVersion, defaultConfig, err := extractMasterDNSVPNFromZip(tmpZipPath)
	if err != nil {
		return "", "", err
	}
	defer os.Remove(tmpBin)

	// Install to binDir as a fixed name so the binary manager can resolve it.
	if err := os.MkdirAll(binDir, 0750); err != nil {
		return "", "", fmt.Errorf("failed to create bin directory: %w", err)
	}
	destPath = filepath.Join(binDir, "masterdnsvpn-server")

	// Write to a temp file in the same directory, then rename atomically.
	// This avoids "text file busy" when an existing binary is held open by a running service.
	tmpDest := destPath + ".tmp"
	data, err := os.ReadFile(tmpBin)
	if err != nil {
		return "", "", fmt.Errorf("failed to read extracted binary: %w", err)
	}
	if err := os.WriteFile(tmpDest, data, 0755); err != nil {
		return "", "", fmt.Errorf("failed to stage masterdnsvpn-server: %w", err)
	}
	if err := os.Rename(tmpDest, destPath); err != nil {
		os.Remove(tmpDest)
		return "", "", fmt.Errorf("failed to install masterdnsvpn-server: %w", err)
	}

	// Cache the bundled default config so SetupMasterDNSVPN can use it as a template
	// for new tunnels rather than writing a minimal hardcoded config.
	if len(defaultConfig) > 0 {
		defaultConfigPath := filepath.Join(binDir, "masterdnsvpn-server_config.default.toml")
		_ = os.WriteFile(defaultConfigPath, defaultConfig, 0640) // best-effort; not fatal
	}

	return destPath, extractedVersion, nil
}

// DefaultMasterDNSVPNConfigPath returns the path where the default server_config.toml
// bundled with the release is cached on disk (next to the shared binary).
func DefaultMasterDNSVPNConfigPath() string {
	return filepath.Join(binary.NewDefaultManager().BinDir(), "masterdnsvpn-server_config.default.toml")
}

// extractMasterDNSVPNFromZip extracts the MasterDnsVPN server binary and, if present, the
// bundled server_config.toml from a ZIP archive.
// It matches the binary by the well-known filename prefix used in all releases and returns
// the temp file path, the version tag extracted from the filename
// (e.g. "v2026.04.07.233605-b5a4474"), and the raw bytes of server_config.toml (nil if absent).
func extractMasterDNSVPNFromZip(zipPath string) (tmpPath string, version string, defaultConfig []byte, err error) {
	r, err := zip.OpenReader(zipPath)
	if err != nil {
		return "", "", nil, fmt.Errorf("failed to open zip: %w", err)
	}
	defer r.Close()

	const binaryPrefix = "MasterDnsVPN_Server_Linux_AMD64_v"
	const configFileName = "server_config.toml"

	// Locate binary and config entries in a single pass.
	var binEntry, cfgEntry *zip.File
	for _, f := range r.File {
		if f.FileInfo().IsDir() {
			continue
		}
		name := filepath.Base(f.Name)
		if binEntry == nil && strings.HasPrefix(name, binaryPrefix) {
			binEntry = f
		}
		if cfgEntry == nil && name == configFileName {
			cfgEntry = f
		}
	}

	if binEntry == nil {
		return "", "", nil, fmt.Errorf("MasterDnsVPN server binary not found in zip (expected prefix: %s)", binaryPrefix)
	}

	// Re-attach the leading "v" so the version matches the GitHub release tag format.
	extractedVersion := "v" + strings.TrimPrefix(filepath.Base(binEntry.Name), binaryPrefix)

	// Extract binary to a temp file.
	rc, err := binEntry.Open()
	if err != nil {
		return "", "", nil, fmt.Errorf("failed to open zip entry: %w", err)
	}
	defer rc.Close()

	tmpFile, err := os.CreateTemp("", "masterdnsvpn-extracted-*")
	if err != nil {
		return "", "", nil, fmt.Errorf("failed to create temp file: %w", err)
	}
	if _, err := io.Copy(tmpFile, rc); err != nil {
		tmpFile.Close()
		os.Remove(tmpFile.Name())
		return "", "", nil, fmt.Errorf("failed to extract binary: %w", err)
	}
	tmpFile.Close()

	// Extract bundled server_config.toml (optional — not an error if absent).
	if cfgEntry != nil {
		if cfgRC, cfgErr := cfgEntry.Open(); cfgErr == nil {
			defaultConfig, _ = io.ReadAll(cfgRC)
			cfgRC.Close()
		}
	}

	return tmpFile.Name(), extractedVersion, defaultConfig, nil
}

// CopyMasterDNSVPNBinaryToDir copies the shared masterdnsvpn-server binary into destDir,
// creating it if necessary, and returns the path of the installed copy.
// The shared binary must already be installed (call EnsureMasterDNSVPNInstalled* first).
func CopyMasterDNSVPNBinaryToDir(destDir string) (string, error) {
	mgr := binary.NewDefaultManager()
	srcPath, err := mgr.GetPath(binary.BinaryMasterDNSVPNServer)
	if err != nil {
		return "", fmt.Errorf("shared masterdnsvpn-server binary not installed: %w", err)
	}

	if err := os.MkdirAll(destDir, 0750); err != nil {
		return "", fmt.Errorf("failed to create dir: %w", err)
	}

	destPath := filepath.Join(destDir, "masterdnsvpn-server")

	// Write to a temp file first, then rename atomically to avoid "text file busy"
	// when the destination binary is held open by a running tunnel service.
	tmpDest := destPath + ".tmp"
	src, err := os.Open(srcPath)
	if err != nil {
		return "", fmt.Errorf("failed to open shared binary: %w", err)
	}
	defer src.Close()

	dst, err := os.OpenFile(tmpDest, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0755)
	if err != nil {
		return "", fmt.Errorf("failed to create tunnel binary: %w", err)
	}
	if _, err := io.Copy(dst, src); err != nil {
		dst.Close()
		os.Remove(tmpDest)
		return "", fmt.Errorf("failed to copy binary: %w", err)
	}
	dst.Close()

	if err := os.Rename(tmpDest, destPath); err != nil {
		os.Remove(tmpDest)
		return "", fmt.Errorf("failed to install tunnel binary: %w", err)
	}

	return destPath, nil
}

// ensureBinaryInstalled uses the binary manager to ensure a binary is available.
func ensureBinaryInstalled(binType binary.BinaryType, displayName string, statusFn StatusFunc) error {
	mgr := binary.NewDefaultManager()

	// EnsureInstalled downloads if needed
	path, err := mgr.EnsureInstalled(binType)
	if err != nil {
		return fmt.Errorf("failed to install %s: %w", displayName, err)
	}

	log.Debug("%s installed at %s", displayName, path)

	if statusFn != nil {
		statusFn(fmt.Sprintf("%s installed", displayName))
	}
	return nil
}
