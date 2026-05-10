package handlers

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/net2share/dnstm/internal/actions"
	"github.com/net2share/dnstm/internal/certs"
	"github.com/net2share/dnstm/internal/config"
	"github.com/net2share/dnstm/internal/keys"
	"github.com/net2share/dnstm/internal/router"
	"github.com/net2share/dnstm/internal/transport"
	"github.com/net2share/go-corelib/tui"
)

func init() {
	actions.SetTunnelHandler(actions.ActionTunnelConvert, HandleTunnelConvert)
	actions.SetTunnelHandler(actions.ActionTunnelConvertAll, HandleTunnelConvertAll)
}

// HandleTunnelConvert converts a tunnel to a different transport type,
// preserving the tag, domain, and port.
func HandleTunnelConvert(ctx *actions.Context) error {
	cfg, err := RequireConfig(ctx)
	if err != nil {
		return err
	}

	tag, err := RequireTag(ctx, "tunnel")
	if err != nil {
		return err
	}

	tunnelCfg := cfg.GetTunnelByTag(tag)
	if tunnelCfg == nil {
		return actions.TunnelNotFoundError(tag)
	}

	if ctx.IsInteractive {
		return convertTunnelInteractive(ctx, cfg, tunnelCfg)
	}
	return convertTunnelNonInteractive(ctx, cfg, tunnelCfg)
}

func convertTunnelInteractive(ctx *actions.Context, cfg *config.Config, tunnelCfg *config.TunnelConfig) error {
	fromTransport := tunnelCfg.Transport

	// Build transport options excluding current transport
	var transportOptions []tui.MenuOption
	for _, t := range []struct {
		label string
		value config.TransportType
	}{
		{"VayDNS", config.TransportVayDNS},
		{"DNSTT", config.TransportDNSTT},
		{"Slipstream", config.TransportSlipstream},
		{"MasterDnsVPN", config.TransportMasterDNSVPN},
	} {
		if t.value != fromTransport {
			transportOptions = append(transportOptions, tui.MenuOption{
				Label: t.label,
				Value: string(t.value),
			})
		}
	}

	toTransportStr, err := tui.RunMenu(tui.MenuConfig{
		Title:   fmt.Sprintf("Convert '%s' (%s) to", tunnelCfg.Tag, config.GetTransportTypeDisplayName(fromTransport)),
		Options: transportOptions,
	})
	if err != nil {
		return err
	}
	if toTransportStr == "" {
		return nil
	}
	toTransport := config.TransportType(toTransportStr)

	// Select backend if target transport requires one
	var backendTag string
	if toTransport != config.TransportMasterDNSVPN {
		backendOptions := buildBackendOptions(cfg, toTransport)
		if len(backendOptions) == 0 {
			return actions.NewActionError(
				"no compatible backends available",
				"Add a backend first with 'dnstm backend add'",
			)
		}
		backendTag, err = tui.RunMenu(tui.MenuConfig{
			Title:   "Backend",
			Options: backendOptions,
		})
		if err != nil {
			return err
		}
		if backendTag == "" {
			return nil
		}
	}

	return doConvertTunnel(ctx, cfg, tunnelCfg, toTransport, backendTag)
}

func convertTunnelNonInteractive(ctx *actions.Context, cfg *config.Config, tunnelCfg *config.TunnelConfig) error {
	toTransportStr := ctx.GetString("to")
	if toTransportStr == "" {
		return fmt.Errorf("--to flag is required\n\nUsage: dnstm tunnel convert -t TAG --to TRANSPORT [-b BACKEND]")
	}

	toTransport := config.TransportType(toTransportStr)
	switch toTransport {
	case config.TransportSlipstream, config.TransportDNSTT, config.TransportVayDNS, config.TransportMasterDNSVPN:
		// valid
	default:
		return fmt.Errorf("invalid transport '%s' (must be slipstream, dnstt, vaydns, or masterdnsvpn)", toTransportStr)
	}

	if toTransport == tunnelCfg.Transport {
		return fmt.Errorf("tunnel '%s' is already using %s transport", tunnelCfg.Tag, toTransportStr)
	}

	backendTag := ctx.GetString("backend")
	if toTransport != config.TransportMasterDNSVPN && backendTag == "" {
		return fmt.Errorf("--backend (-b) flag is required for %s transport", toTransportStr)
	}
	if toTransport == config.TransportMasterDNSVPN {
		backendTag = ""
	}

	return doConvertTunnel(ctx, cfg, tunnelCfg, toTransport, backendTag)
}

func doConvertTunnel(ctx *actions.Context, cfg *config.Config, tunnelCfg *config.TunnelConfig, toTransport config.TransportType, backendTag string) error {
	fromTransportName := config.GetTransportTypeDisplayName(tunnelCfg.Transport)
	toTransportName := config.GetTransportTypeDisplayName(toTransport)

	beginProgress(ctx, fmt.Sprintf("Convert: %s → %s", fromTransportName, toTransportName))
	if !ctx.IsInteractive {
		ctx.Output.Println()
	}

	const totalSteps = 5
	currentStep := 0

	// Step 1: Stop the tunnel
	currentStep++
	ctx.Output.Step(currentStep, totalSteps, "Stopping tunnel...")
	tunnel := router.NewTunnel(tunnelCfg)
	if tunnel.IsActive() {
		if err := tunnel.Stop(); err != nil {
			ctx.Output.Warning("Stop warning: " + err.Error())
		}
	}
	ctx.Output.Status("Tunnel stopped")

	// Step 2: Install required binaries for new transport.
	// For MasterDnsVPN, use the version-aware installer so that --masterdnsvpn-version
	// is honoured (SetupMasterDNSVPN will then copy the shared binary to the tunnel dir).
	currentStep++
	ctx.Output.Step(currentStep, totalSteps, "Installing transport binaries...")
	if toTransport == config.TransportMasterDNSVPN {
		mdnsVersionTag := ctx.GetString("masterdnsvpn-version") // "" = latest
		statusFn := func(msg string) { ctx.Output.Status(msg) }
		if err := transport.EnsureMasterDNSVPNInstalledVersion(mdnsVersionTag, statusFn); err != nil {
			return failProgress(ctx, fmt.Errorf("failed to install masterdnsvpn: %w", err))
		}
	} else {
		if err := transport.EnsureTransportBinariesInstalled(toTransport); err != nil {
			return failProgress(ctx, fmt.Errorf("failed to install binaries: %w", err))
		}
	}
	ctx.Output.Status("Transport binaries ready")

	// Step 3: Generate crypto material for new transport
	currentStep++
	ctx.Output.Step(currentStep, totalSteps, "Generating cryptographic material...")

	tunnelDir := filepath.Join(config.TunnelsDir, tunnelCfg.Tag)

	// Determine service mode once — used for MasterDNSVPN bind config and service regen
	sg := router.NewServiceGenerator()
	serviceMode := router.ServiceModeMulti
	if cfg.IsSingleMode() {
		serviceMode = router.ServiceModeSingle
	}

	// Clear old transport-specific fields and apply new transport
	tunnelCfg.Transport = toTransport
	tunnelCfg.Backend = backendTag
	tunnelCfg.Slipstream = nil
	tunnelCfg.DNSTT = nil
	tunnelCfg.VayDNS = nil
	tunnelCfg.MasterDNSVPN = nil

	var fingerprint, publicKey, masterDNSVPNKey string

	switch toTransport {
	case config.TransportSlipstream:
		certInfo, err := certs.GetOrCreateInDir(tunnelDir, tunnelCfg.Domain)
		if err != nil {
			return failProgress(ctx, fmt.Errorf("failed to generate certificate: %w", err))
		}
		fingerprint = certInfo.Fingerprint
		tunnelCfg.Slipstream = &config.SlipstreamConfig{
			Cert: certInfo.CertPath,
			Key:  certInfo.KeyPath,
		}
		ctx.Output.Status("TLS certificate ready")

	case config.TransportDNSTT:
		keyInfo, err := keys.GetOrCreateInDir(tunnelDir)
		if err != nil {
			return failProgress(ctx, fmt.Errorf("failed to generate keys: %w", err))
		}
		publicKey = keyInfo.PublicKey
		tunnelCfg.DNSTT = &config.DNSTTConfig{MTU: 1232, PrivateKey: keyInfo.PrivateKeyPath}
		ctx.Output.Status("Curve25519 keys ready")

	case config.TransportVayDNS:
		keyInfo, err := keys.GetOrCreateInDir(tunnelDir)
		if err != nil {
			return failProgress(ctx, fmt.Errorf("failed to generate keys: %w", err))
		}
		publicKey = keyInfo.PublicKey
		tunnelCfg.VayDNS = &config.VayDNSConfig{MTU: 1232, PrivateKey: keyInfo.PrivateKeyPath}
		ctx.Output.Status("Curve25519 keys ready")

	case config.TransportMasterDNSVPN:
		bindOpts, err := sg.GetBindOptions(tunnelCfg, serviceMode)
		if err != nil {
			return failProgress(ctx, fmt.Errorf("failed to get bind options: %w", err))
		}
		encKey, cfgPath, binPath, setupErr := transport.SetupMasterDNSVPN(tunnelDir, tunnelCfg.Domain, bindOpts.BindHost, bindOpts.BindPort)
		if setupErr != nil {
			return failProgress(ctx, fmt.Errorf("failed to setup masterdnsvpn: %w", setupErr))
		}
		masterDNSVPNKey = encKey
		tunnelCfg.MasterDNSVPN = &config.MasterDNSVPNConfig{ConfigFile: cfgPath, BinaryPath: binPath}
		ctx.Output.Status("Encryption key generated")
	}

	// Step 4: Regenerate systemd service
	currentStep++
	ctx.Output.Step(currentStep, totalSteps, "Regenerating service...")

	backend := cfg.GetBackendByTag(backendTag)
	if backend == nil && toTransport != config.TransportMasterDNSVPN {
		return failProgress(ctx, actions.BackendNotFoundError(backendTag))
	}

	bindOpts, err := sg.GetBindOptions(tunnelCfg, serviceMode)
	if err != nil {
		return failProgress(ctx, fmt.Errorf("failed to get bind options: %w", err))
	}

	builder := transport.NewBuilder()
	if err := builder.RegenerateTunnelService(tunnelCfg, backend, bindOpts); err != nil {
		return failProgress(ctx, fmt.Errorf("failed to regenerate service: %w", err))
	}
	ctx.Output.Status("Service regenerated")

	// Step 5: Save config and start tunnel
	currentStep++
	ctx.Output.Step(currentStep, totalSteps, "Saving configuration...")
	if err := cfg.Save(); err != nil {
		return failProgress(ctx, fmt.Errorf("failed to save config: %w", err))
	}

	tunnel = router.NewTunnel(tunnelCfg)
	if err := enableAndStartTunnel(ctx, cfg, tunnel); err != nil {
		ctx.Output.Warning("Failed to start tunnel: " + err.Error())
	} else {
		ctx.Output.Status("Tunnel started")
	}

	ctx.Output.Success(fmt.Sprintf("Tunnel '%s' converted from %s to %s!", tunnelCfg.Tag, fromTransportName, toTransportName))

	if fingerprint != "" {
		ctx.Output.Println()
		ctx.Output.Info("Certificate Fingerprint:")
		ctx.Output.Println(certs.FormatFingerprint(fingerprint))
	}
	if publicKey != "" {
		ctx.Output.Println()
		ctx.Output.Info("Public Key (share with clients):")
		ctx.Output.Println(publicKey)
	}
	if masterDNSVPNKey != "" {
		ctx.Output.Println()
		ctx.Output.Info("Encryption Key (copy to client config):")
		ctx.Output.Println(masterDNSVPNKey)
	}

	if !ctx.IsInteractive {
		ctx.Output.Println()
	}

	endProgress(ctx)
	return nil
}

// HandleTunnelConvertAll converts all tunnels of a given transport type to another in one pass.
func HandleTunnelConvertAll(ctx *actions.Context) error {
	cfg, err := RequireConfig(ctx)
	if err != nil {
		return err
	}

	if len(cfg.Tunnels) == 0 {
		return fmt.Errorf("no tunnels configured")
	}

	if ctx.IsInteractive {
		return convertAllInteractive(ctx, cfg)
	}
	return convertAllNonInteractive(ctx, cfg)
}

func convertAllInteractive(ctx *actions.Context, cfg *config.Config) error {
	// Build "from" menu: only transport types that have at least one tunnel.
	counts := make(map[config.TransportType]int)
	for _, t := range cfg.Tunnels {
		counts[t.Transport]++
	}

	var fromOptions []tui.MenuOption
	for _, t := range []struct {
		label string
		value config.TransportType
	}{
		{"VayDNS", config.TransportVayDNS},
		{"DNSTT", config.TransportDNSTT},
		{"Slipstream", config.TransportSlipstream},
		{"MasterDnsVPN", config.TransportMasterDNSVPN},
	} {
		if n := counts[t.value]; n > 0 {
			label := fmt.Sprintf("%s (%d tunnel", t.label, n)
			if n != 1 {
				label += "s"
			}
			label += ")"
			fromOptions = append(fromOptions, tui.MenuOption{Label: label, Value: string(t.value)})
		}
	}

	if len(fromOptions) == 0 {
		return fmt.Errorf("no tunnels to convert")
	}

	fromStr, err := tui.RunMenu(tui.MenuConfig{
		Title:   "Convert From (source transport)",
		Options: fromOptions,
	})
	if err != nil || fromStr == "" {
		return nil
	}
	fromTransport := config.TransportType(fromStr)

	// Build "to" menu: all transports except the chosen source.
	var toOptions []tui.MenuOption
	for _, t := range []struct {
		label string
		value config.TransportType
	}{
		{"VayDNS", config.TransportVayDNS},
		{"DNSTT", config.TransportDNSTT},
		{"Slipstream", config.TransportSlipstream},
		{"MasterDnsVPN", config.TransportMasterDNSVPN},
	} {
		if t.value != fromTransport {
			toOptions = append(toOptions, tui.MenuOption{Label: t.label, Value: string(t.value)})
		}
	}

	toStr, err := tui.RunMenu(tui.MenuConfig{
		Title:   fmt.Sprintf("Convert To (target transport for %s tunnels)", config.GetTransportTypeDisplayName(fromTransport)),
		Options: toOptions,
	})
	if err != nil || toStr == "" {
		return nil
	}
	toTransport := config.TransportType(toStr)

	// Select backend if required.
	var backendTag string
	if toTransport != config.TransportMasterDNSVPN {
		backendOptions := buildBackendOptions(cfg, toTransport)
		if len(backendOptions) == 0 {
			return actions.NewActionError(
				"no compatible backends available",
				"Add a backend first with 'dnstm backend add'",
			)
		}
		backendTag, err = tui.RunMenu(tui.MenuConfig{
			Title:   "Backend",
			Options: backendOptions,
		})
		if err != nil || backendTag == "" {
			return nil
		}
	}

	return doConvertAllTunnels(ctx, cfg, fromTransport, toTransport, backendTag)
}

func convertAllNonInteractive(ctx *actions.Context, cfg *config.Config) error {
	fromStr := ctx.GetString("from")
	if fromStr == "" {
		return fmt.Errorf("--from flag is required\n\nUsage: dnstm tunnel convert-all --from TRANSPORT --to TRANSPORT [-b BACKEND]")
	}
	toStr := ctx.GetString("to")
	if toStr == "" {
		return fmt.Errorf("--to flag is required\n\nUsage: dnstm tunnel convert-all --from TRANSPORT --to TRANSPORT [-b BACKEND]")
	}

	fromTransport := config.TransportType(fromStr)
	toTransport := config.TransportType(toStr)

	for _, t := range []config.TransportType{fromTransport, toTransport} {
		switch t {
		case config.TransportSlipstream, config.TransportDNSTT, config.TransportVayDNS, config.TransportMasterDNSVPN:
			// valid
		default:
			return fmt.Errorf("invalid transport '%s' (must be slipstream, dnstt, vaydns, or masterdnsvpn)", string(t))
		}
	}

	if fromTransport == toTransport {
		return fmt.Errorf("--from and --to must be different transport types")
	}

	backendTag := ctx.GetString("backend")
	if toTransport != config.TransportMasterDNSVPN && backendTag == "" {
		return fmt.Errorf("--backend (-b) flag is required for %s transport", toStr)
	}
	if toTransport == config.TransportMasterDNSVPN {
		backendTag = ""
	}

	return doConvertAllTunnels(ctx, cfg, fromTransport, toTransport, backendTag)
}

func doConvertAllTunnels(ctx *actions.Context, cfg *config.Config, fromTransport, toTransport config.TransportType, backendTag string) error {
	// Collect matching tunnels upfront.
	var targets []*config.TunnelConfig
	for i := range cfg.Tunnels {
		if cfg.Tunnels[i].Transport == fromTransport {
			targets = append(targets, &cfg.Tunnels[i])
		}
	}

	if len(targets) == 0 {
		return fmt.Errorf("no tunnels using %s transport", config.GetTransportTypeDisplayName(fromTransport))
	}

	fromName := config.GetTransportTypeDisplayName(fromTransport)
	toName := config.GetTransportTypeDisplayName(toTransport)

	ctx.Output.Info(fmt.Sprintf("Converting %d tunnel(s) from %s to %s...", len(targets), fromName, toName))

	// In single-mode with multiple tunnels, warn up front — only one tunnel can
	// serve traffic at a time. The active tunnel will be started; the rest will
	// be configured with multi-mode binding and kept stopped.
	isSingle := cfg.IsSingleMode()
	if isSingle && len(targets) > 1 {
		ctx.Output.Warning("Single-mode: only the active tunnel will be started after conversion. Run 'dnstm router mode multi' to run all tunnels simultaneously.")
	}

	if !ctx.IsInteractive {
		ctx.Output.Println()
	}

	var failedTags []string
	for i, tunnelCfg := range targets {
		ctx.Output.Info(fmt.Sprintf("[%d/%d] %s", i+1, len(targets), tunnelCfg.Tag))
		if err := doConvertTunnel(ctx, cfg, tunnelCfg, toTransport, backendTag); err != nil {
			ctx.Output.Warning(fmt.Sprintf("Failed to convert '%s': %v", tunnelCfg.Tag, err))
			failedTags = append(failedTags, tunnelCfg.Tag)
		}
	}

	// ── Single-mode post-processing ────────────────────────────────────────────
	// doConvertTunnel gives every tunnel single-mode binding (EXTERNAL_IP:53).
	// That causes port-53 conflicts when multiple tunnels are converted in one
	// pass.  Fix this by re-assigning bindings and tunnel state correctly:
	//   • active tunnel  → single-mode binding, enabled, started
	//   • all others     → multi-mode binding (127.0.0.1:PORT), disabled, stopped
	if isSingle && len(targets) > 1 {
		activeTag := cfg.Route.Active

		// If no active tunnel is set yet, pick the first successfully converted one.
		if activeTag == "" {
			for _, t := range targets {
				if !sliceContains(failedTags, t.Tag) {
					activeTag = t.Tag
					cfg.Route.Active = activeTag
					break
				}
			}
		}

		builder := transport.NewBuilder()
		sg := router.NewServiceGenerator()

		for _, tunnelCfg := range targets {
			if sliceContains(failedTags, tunnelCfg.Tag) {
				continue
			}
			backend := cfg.GetBackendByTag(tunnelCfg.Backend)
			tun := router.NewTunnel(tunnelCfg)

			if tunnelCfg.Tag == activeTag {
				// Active tunnel: single-mode binding, enabled, started.
				singleOpts, err := sg.GetBindOptions(tunnelCfg, router.ServiceModeSingle)
				if err == nil {
					_ = builder.RegenerateTunnelService(tunnelCfg, backend, singleOpts)
				}
				enabled := true
				tunnelCfg.Enabled = &enabled
				if !tun.IsActive() {
					if err := tun.Start(); err != nil {
						ctx.Output.Warning(fmt.Sprintf("Failed to start active tunnel '%s': %v", tunnelCfg.Tag, err))
					} else {
						ctx.Output.Status(fmt.Sprintf("Tunnel '%s' started", tunnelCfg.Tag))
					}
				}
			} else {
				// Non-active tunnel: multi-mode binding, disabled, stopped.
				multiOpts, err := sg.GetBindOptions(tunnelCfg, router.ServiceModeMulti)
				if err == nil {
					_ = builder.RegenerateTunnelService(tunnelCfg, backend, multiOpts)
				}
				disabled := false
				tunnelCfg.Enabled = &disabled
				if tun.IsActive() {
					_ = tun.Stop()
				}
			}
		}

		if err := cfg.Save(); err != nil {
			ctx.Output.Warning("Failed to save config after binding fixup: " + err.Error())
		}
	}
	// ──────────────────────────────────────────────────────────────────────────

	if len(failedTags) > 0 {
		return fmt.Errorf("%d/%d tunnel(s) failed to convert: %s", len(failedTags), len(targets), strings.Join(failedTags, ", "))
	}

	ctx.Output.Success(fmt.Sprintf("All %d tunnel(s) converted from %s to %s!", len(targets), fromName, toName))
	return nil
}

// sliceContains reports whether s is in the slice.
func sliceContains(slice []string, s string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}
