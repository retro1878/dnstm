package handlers

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/net2share/dnstm/internal/actions"
	"github.com/net2share/dnstm/internal/binary"
	"github.com/net2share/dnstm/internal/config"
	"github.com/net2share/dnstm/internal/dnsrouter"
	"github.com/net2share/dnstm/internal/network"
	"github.com/net2share/dnstm/internal/proxy"
	"github.com/net2share/dnstm/internal/router"
	"github.com/net2share/dnstm/internal/service"
	"github.com/net2share/dnstm/internal/system"
	"github.com/net2share/dnstm/internal/transport"
	"github.com/net2share/dnstm/internal/updater"
	"github.com/net2share/go-corelib/tui"
)

const installPath = "/usr/local/bin/dnstm"

// mdnsVersionLatest is the sentinel passed to EnsureMasterDNSVPNInstalledVersion for "latest".
const mdnsVersionLatest = ""

// mdnsVersionSkip is the sentinel returned by chooseMasterDNSVPNVersion to mean "skip install".
const mdnsVersionSkip = "__skip__"

func init() {
	actions.SetSystemHandler(actions.ActionInstall, HandleInstall)
}

// chooseMasterDNSVPNVersion prompts the user (interactive) or reads the CLI flag (non-interactive)
// to decide which MasterDnsVPN version to install.
// Returns "" (mdnsVersionLatest) for latest, a specific tag (e.g. "v2026.04.07.233605-b5a4474")
// for a pinned release, or mdnsVersionSkip to skip installation altogether.
func chooseMasterDNSVPNVersion(ctx *actions.Context) (string, error) {
	if !ctx.IsInteractive {
		v := ctx.GetString("masterdnsvpn-version")
		if v == "skip" {
			return mdnsVersionSkip, nil
		}
		// "" or any tag value is used as-is ("" → latest via masterDNSVPNZipURL).
		return v, nil
	}

	// Build menu options: Skip, Latest, then specific release tags.
	options := []tui.MenuOption{
		{Label: "Skip (install later when needed)", Value: mdnsVersionSkip},
		{Label: "Latest", Value: mdnsVersionLatest},
	}

	releases, fetchErr := transport.FetchMasterDNSVPNReleases()
	if fetchErr != nil {
		ctx.Output.Warning("Could not fetch MasterDnsVPN releases: " + fetchErr.Error())
	}
	for _, tag := range releases {
		options = append(options, tui.MenuOption{Label: tag, Value: tag})
	}

	choice, err := tui.RunMenu(tui.MenuConfig{
		Title:   "MasterDnsVPN Version",
		Options: options,
	})
	if err != nil {
		return mdnsVersionSkip, err
	}
	// Empty string from RunMenu means the user pressed Escape/cancelled → skip.
	if choice == "" {
		return mdnsVersionSkip, nil
	}
	return choice, nil
}

// HandleInstall performs system installation.
func HandleInstall(ctx *actions.Context) error {
	force := ctx.GetBool("force")

	// Check if already installed
	if router.IsInitialized() && !force {
		// If binaries are missing, install just the missing ones
		missing := transport.GetMissingBinaries()

		// When --masterdnsvpn-version is explicitly given, always include masterdnsvpn
		// in the work list so that propagation to existing tunnel directories runs even
		// when the shared binary is already at the requested version.  This makes the
		// command idempotent and handles interrupted installs cleanly.
		requestedMDNSVersion := ctx.GetString("masterdnsvpn-version")
		if requestedMDNSVersion != "" && requestedMDNSVersion != "skip" {
			alreadyInList := false
			for _, m := range missing {
				if m == string(binary.BinaryMasterDNSVPNServer) {
					alreadyInList = true
					break
				}
			}
			if !alreadyInList {
				missing = append(missing, string(binary.BinaryMasterDNSVPNServer))
			}
		}

		if len(missing) > 0 {
			return installMissingBinaries(ctx, missing)
		}
		return fmt.Errorf("dnstm is already installed. Use --force to reinstall")
	}

	modeStr := ctx.GetString("mode")

	// Preserve the existing mode when reinstalling without explicitly specifying --mode,
	// so that --force doesn't silently reset a multi-mode setup back to single.
	if modeStr == "" && router.IsInitialized() {
		if existingCfg, loadErr := config.Load(); loadErr == nil {
			modeStr = existingCfg.Route.Mode
		}
	}
	// Default to single mode for a fresh install.
	if modeStr == "" {
		modeStr = "single"
	}
	if modeStr != "single" && modeStr != "multi" {
		return fmt.Errorf("invalid mode: %s (must be 'single' or 'multi')", modeStr)
	}

	// Prompt for MasterDnsVPN version BEFORE entering progress mode so the TUI menu
	// and any network fetch can run without conflicting with the progress display.
	mdnsVersion, err := chooseMasterDNSVPNVersion(ctx)
	if err != nil {
		return fmt.Errorf("failed to select MasterDnsVPN version: %w", err)
	}

	if ctx.IsInteractive {
		ctx.Output.BeginProgress("Install dnstm")
	} else {
		ctx.Output.Println()
	}

	ctx.Output.Info("Installing dnstm components...")

	// Step 0: Ensure dnstm binary is installed at the standard path
	if err := ensureDnstmInstalled(ctx); err != nil {
		return fmt.Errorf("failed to install dnstm binary: %w", err)
	}

	// Step 1: Create dnstm user
	ctx.Output.Info("Creating dnstm user...")
	if err := system.CreateDnstmUser(); err != nil {
		return fmt.Errorf("failed to create dnstm user: %w", err)
	}
	ctx.Output.Status("dnstm user ready")

	// Step 2: Initialize router
	ctx.Output.Info("Initializing router...")
	if err := router.Initialize(); err != nil {
		return fmt.Errorf("failed to initialize router: %w", err)
	}
	ctx.Output.Status("Router initialized")

	// Step 3: Set operating mode and ensure built-in backends
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}
	cfg.Route.Mode = modeStr
	cfg.EnsureBuiltinBackends()
	if err := cfg.Save(); err != nil {
		return fmt.Errorf("failed to save config: %w", err)
	}
	ctx.Output.Status(fmt.Sprintf("Mode set to %s", GetModeDisplayName(cfg.Route.Mode)))

	// Step 4: Create DNS router service
	svc := dnsrouter.NewService()
	if err := svc.CreateService(); err != nil {
		ctx.Output.Warning("DNS router service: " + err.Error())
	} else {
		ctx.Output.Status("DNS router service created")
	}

	// Step 5: Install binaries
	ctx.Output.Println()
	ctx.Output.Info("Installing transport binaries...")

	// Status callback routes output through the context
	statusFn := func(msg string) { ctx.Output.Status(msg) }

	if err := transport.EnsureDnsttInstalledWithStatus(statusFn); err != nil {
		return fmt.Errorf("failed to install dnstt-server: %w", err)
	}

	if err := transport.EnsureSlipstreamInstalledWithStatus(statusFn); err != nil {
		return fmt.Errorf("failed to install slipstream-server: %w", err)
	}

	if err := transport.EnsureShadowsocksInstalledWithStatus(statusFn); err != nil {
		return fmt.Errorf("failed to install ssserver: %w", err)
	}

	if err := transport.EnsureVayDNSInstalledWithStatus(statusFn); err != nil {
		return fmt.Errorf("failed to install vaydns-server: %w", err)
	}

	if err := transport.EnsureSSHTunUserInstalledWithStatus(statusFn); err != nil {
		ctx.Output.Warning("sshtun-user: " + err.Error())
	}

	if mdnsVersion != mdnsVersionSkip {
		versionTag := mdnsVersion // "" = latest, or a specific tag
		if err := transport.EnsureMasterDNSVPNInstalledVersion(versionTag, statusFn); err != nil {
			return fmt.Errorf("failed to install masterdnsvpn-server: %w", err)
		}
		// Propagate to existing tunnel directories (relevant for --force reinstalls).
		if err := propagateMasterDNSVPNBinary(ctx, statusFn); err != nil {
			ctx.Output.Warning("masterdnsvpn-server propagation: " + err.Error())
		}
	}

	if !proxy.IsMicrosocksInstalled() {
		ctx.Output.Info("Installing microsocks...")
		if err := proxy.InstallMicrosocks(nil); err != nil {
			return fmt.Errorf("failed to install microsocks: %w", err)
		}
	}
	// Ensure microsocks service is configured and running
	if !proxy.IsMicrosocksRunning() {
		ctx.Output.Info("Configuring microsocks service...")
		port, err := proxy.FindAvailablePort()
		if err != nil {
			ctx.Output.Warning("Could not find available port: " + err.Error())
		} else {
			cfg.Proxy.Port = port
			cfg.UpdateSocksBackendPort(port)
			if err := cfg.Save(); err != nil {
				ctx.Output.Warning("Failed to save proxy port: " + err.Error())
			}
			// Preserve existing auth config on reinstall
			var socksUser, socksPass string
			if socksBackend := cfg.GetBackendByTag("socks"); socksBackend != nil && socksBackend.HasSocksAuth() {
				socksUser = socksBackend.Socks.User
				socksPass = socksBackend.Socks.Password
			}
			if err := proxy.ConfigureMicrosocksWithAuth(port, socksUser, socksPass); err != nil {
				ctx.Output.Warning("microsocks service config: " + err.Error())
			} else {
				if err := proxy.StartMicrosocks(); err != nil {
					ctx.Output.Warning("microsocks service start: " + err.Error())
				} else {
					ctx.Output.Status(fmt.Sprintf("microsocks installed and running on port %d", port))
				}
			}
		}
	} else {
		ctx.Output.Status("microsocks already running")
	}

	// Step 6: Configure firewall
	ctx.Output.Println()
	ctx.Output.Info("Configuring firewall...")
	network.ClearNATOnly()
	if err := network.AllowPort53(); err != nil {
		ctx.Output.Warning("Firewall configuration: " + err.Error())
	} else {
		ctx.Output.Status("Firewall configured (port 53 UDP/TCP)")
	}

	// Step 7: Create version manifest
	if err := createVersionManifest(ctx); err != nil {
		ctx.Output.Warning("Failed to create version manifest: " + err.Error())
	}

	ctx.Output.Success("Installation complete!")

	// Show next steps (different for CLI vs interactive)
	if ctx.IsInteractive {
		ctx.Output.Println()
		ctx.Output.Info("Next: Select 'Backends' > 'Add' for custom backends (optional)")
		ctx.Output.Info("Next: Select 'Tunnels' > 'Add' to create a tunnel")
		ctx.Output.EndProgress()
	} else {
		ctx.Output.Println()
		ctx.Output.Info("Next steps:")
		ctx.Output.Println("  1. Add backend (optional): dnstm backend add")
		ctx.Output.Println("  2. Add tunnel: dnstm tunnel add")
		ctx.Output.Println()
	}

	return nil
}

// ensureDnstmInstalled copies the current binary to /usr/local/bin/dnstm if needed.
// This ensures services always use the correct binary path.
func ensureDnstmInstalled(ctx *actions.Context) error {
	currentExe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get current executable: %w", err)
	}

	// If already running from install path, nothing to do
	if currentExe == installPath {
		ctx.Output.Status("dnstm binary already at " + installPath)
		return nil
	}

	// Check if install path exists and is the same file
	destInfo, err := os.Stat(installPath)
	if err == nil {
		srcInfo, err := os.Stat(currentExe)
		if err == nil && os.SameFile(srcInfo, destInfo) {
			ctx.Output.Status("dnstm binary already at " + installPath)
			return nil
		}
	}

	// Copy current binary to install path
	ctx.Output.Info("Installing dnstm binary to " + installPath + "...")

	src, err := os.Open(currentExe)
	if err != nil {
		return fmt.Errorf("failed to open source binary: %w", err)
	}
	defer src.Close()

	// Create temp file first, then rename (atomic)
	tmpPath := installPath + ".tmp"
	dst, err := os.OpenFile(tmpPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0755)
	if err != nil {
		return fmt.Errorf("failed to create destination: %w", err)
	}

	if _, err := io.Copy(dst, src); err != nil {
		dst.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("failed to copy binary: %w", err)
	}
	dst.Close()

	// Rename temp to final (atomic on same filesystem)
	if err := os.Rename(tmpPath, installPath); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("failed to install binary: %w", err)
	}

	ctx.Output.Status("dnstm binary installed to " + installPath)
	return nil
}

// installMissingBinaries installs only the binaries that are missing.
// This handles the upgrade case where a new dnstm version adds a new transport binary.
func installMissingBinaries(ctx *actions.Context, missing []string) error {
	// If MasterDnsVPN is among the missing binaries, prompt for the desired version
	// BEFORE entering progress mode (the TUI menu must not run inside the progress UI).
	mdnsVersion := mdnsVersionLatest
	for _, name := range missing {
		if binary.BinaryType(name) == binary.BinaryMasterDNSVPNServer {
			var err error
			mdnsVersion, err = chooseMasterDNSVPNVersion(ctx)
			if err != nil {
				return fmt.Errorf("failed to select MasterDnsVPN version: %w", err)
			}
			break
		}
	}

	if ctx.IsInteractive {
		ctx.Output.BeginProgress("Install Missing Binaries")
	}

	ctx.Output.Info("Installing missing transport binaries...")
	statusFn := func(msg string) { ctx.Output.Status(msg) }

	for _, name := range missing {
		binType := binary.BinaryType(name)
		switch binType {
		case binary.BinaryDNSTTServer:
			if err := transport.EnsureDnsttInstalledWithStatus(statusFn); err != nil {
				return fmt.Errorf("failed to install %s: %w", name, err)
			}
		case binary.BinarySlipstreamServer:
			if err := transport.EnsureSlipstreamInstalledWithStatus(statusFn); err != nil {
				return fmt.Errorf("failed to install %s: %w", name, err)
			}
		case binary.BinarySSServer:
			if err := transport.EnsureShadowsocksInstalledWithStatus(statusFn); err != nil {
				return fmt.Errorf("failed to install %s: %w", name, err)
			}
		case binary.BinaryVayDNSServer:
			if err := transport.EnsureVayDNSInstalledWithStatus(statusFn); err != nil {
				return fmt.Errorf("failed to install %s: %w", name, err)
			}
		case binary.BinaryMasterDNSVPNServer:
			if mdnsVersion != mdnsVersionSkip {
				if err := transport.EnsureMasterDNSVPNInstalledVersion(mdnsVersion, statusFn); err != nil {
					ctx.Output.Warning("masterdnsvpn-server: " + err.Error())
					break
				}
				// Propagate the updated binary to all existing MasterDnsVPN tunnel
				// directories and regenerate their systemd services so the new version
				// takes effect without manual intervention.
				if err := propagateMasterDNSVPNBinary(ctx, statusFn); err != nil {
					ctx.Output.Warning("masterdnsvpn-server propagation: " + err.Error())
				}
			} else {
				ctx.Output.Status("masterdnsvpn-server: skipped")
			}
		case binary.BinarySSHTunUser:
			if err := transport.EnsureSSHTunUserInstalledWithStatus(statusFn); err != nil {
				ctx.Output.Warning("sshtun-user: " + err.Error())
			}
		default:
			ctx.Output.Warning(fmt.Sprintf("Unknown binary: %s", name))
		}
	}

	// Update version manifest with installed versions
	manifest, err := updater.LoadManifest()
	if err != nil {
		manifest = updater.NewManifest()
	}
	for _, name := range missing {
		def, ok := binary.GetDef(binary.BinaryType(name))
		if ok && def.PinnedVersion != "" {
			manifest.SetVersion(name, def.PinnedVersion)
		}
	}
	if err := manifest.Save(); err != nil {
		ctx.Output.Warning("Failed to update version manifest: " + err.Error())
	}

	ctx.Output.Success("Missing binaries installed!")

	if ctx.IsInteractive {
		ctx.Output.EndProgress()
	}

	return nil
}

// propagateMasterDNSVPNBinary copies the (already-updated) shared masterdnsvpn-server
// binary to every existing MasterDnsVPN tunnel directory and regenerates each tunnel's
// systemd service so the new binary version takes effect.  Running tunnels are restarted
// automatically.
func propagateMasterDNSVPNBinary(ctx *actions.Context, statusFn transport.StatusFunc) error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	sg := router.NewServiceGenerator()
	builder := transport.NewBuilder()

	updated := 0
	for i := range cfg.Tunnels {
		tunnelCfg := &cfg.Tunnels[i]
		if tunnelCfg.Transport != config.TransportMasterDNSVPN {
			continue
		}

		tunnelDir := filepath.Join(transport.ConfigDir, "tunnels", tunnelCfg.Tag)
		serviceName := router.GetServiceName(tunnelCfg.Tag)
		wasRunning := service.IsServiceActive(serviceName)

		// Copy the updated shared binary into the tunnel directory.
		newBinaryPath, copyErr := transport.CopyMasterDNSVPNBinaryToDir(tunnelDir)
		if copyErr != nil {
			ctx.Output.Warning(fmt.Sprintf("  %s: failed to copy binary: %v", tunnelCfg.Tag, copyErr))
			continue
		}
		_ = system.ChownToDnstm(newBinaryPath) // best-effort

		// Update the binary path stored in the config.
		if tunnelCfg.MasterDNSVPN == nil {
			tunnelCfg.MasterDNSVPN = &config.MasterDNSVPNConfig{}
		}
		tunnelCfg.MasterDNSVPN.BinaryPath = newBinaryPath

		// Determine the correct bind options: the active tunnel in single mode binds to
		// EXTERNAL_IP:53; all other tunnels (including every tunnel in multi mode) bind
		// to 127.0.0.1:port.
		var svcMode router.ServiceMode
		if cfg.IsSingleMode() && cfg.Route.Active == tunnelCfg.Tag {
			svcMode = router.ServiceModeSingle
		} else {
			svcMode = router.ServiceModeMulti
		}

		bindOpts, bindErr := sg.GetBindOptions(tunnelCfg, svcMode)
		if bindErr != nil {
			ctx.Output.Warning(fmt.Sprintf("  %s: failed to get bind options: %v", tunnelCfg.Tag, bindErr))
			continue
		}

		// Regenerate the systemd service (stops old service, removes it, creates new one).
		// MasterDnsVPN has no DNSTM backend — pass nil for the backend parameter.
		if regenErr := builder.RegenerateTunnelService(tunnelCfg, nil, bindOpts); regenErr != nil {
			ctx.Output.Warning(fmt.Sprintf("  %s: failed to regenerate service: %v", tunnelCfg.Tag, regenErr))
			continue
		}

		// Restart the tunnel if it was running before we regenerated the service.
		if wasRunning {
			if startErr := service.StartService(serviceName); startErr != nil {
				ctx.Output.Warning(fmt.Sprintf("  %s: failed to restart: %v", tunnelCfg.Tag, startErr))
			}
		}

		updated++
		if statusFn != nil {
			statusFn(fmt.Sprintf("masterdnsvpn-server propagated to tunnel %s", tunnelCfg.Tag))
		}
	}

	if updated > 0 {
		if saveErr := cfg.Save(); saveErr != nil {
			return fmt.Errorf("failed to save config: %w", saveErr)
		}
		ctx.Output.Status(fmt.Sprintf("Updated binary in %d MasterDnsVPN tunnel(s)", updated))
	}

	return nil
}

// createVersionManifest creates the initial version manifest after installation.
// Uses pinned versions from binary definitions as the source of truth.
func createVersionManifest(ctx *actions.Context) error {
	manifest := updater.NewManifest()

	for _, def := range binary.ServerBinaries() {
		if def.SkipUpdate || def.PinnedVersion == "" {
			continue
		}
		manifest.SetVersion(string(def.Type), def.PinnedVersion)
	}

	return manifest.Save()
}
