package handlers

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/net2share/dnstm/internal/actions"
	"github.com/net2share/dnstm/internal/config"
	"github.com/net2share/dnstm/internal/router"
	"github.com/net2share/go-corelib/tui"
)

func init() {
	actions.SetTunnelHandler(actions.ActionTunnelSetEncryption, HandleTunnelSetEncryption)
	actions.SetTunnelHandler(actions.ActionTunnelSetEncryptionAll, HandleTunnelSetEncryptionAll)
}

var encryptionMethodOptions = []tui.MenuOption{
	{Label: "0 - None", Value: "0"},
	{Label: "1 - XOR", Value: "1"},
	{Label: "2 - ChaCha20", Value: "2"},
	{Label: "3 - AES-128-GCM", Value: "3"},
	{Label: "4 - AES-192-GCM", Value: "4"},
	{Label: "5 - AES-256-GCM", Value: "5"},
}

var encryptionMethodNames = map[int]string{
	0: "None",
	1: "XOR",
	2: "ChaCha20",
	3: "AES-128-GCM",
	4: "AES-192-GCM",
	5: "AES-256-GCM",
}

func encryptionMethodName(method int) string {
	if name, ok := encryptionMethodNames[method]; ok {
		return fmt.Sprintf("%d (%s)", method, name)
	}
	return fmt.Sprintf("%d", method)
}

// HandleTunnelSetEncryption changes the encryption method for a single MasterDnsVPN tunnel.
func HandleTunnelSetEncryption(ctx *actions.Context) error {
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
	if tunnelCfg.Transport != config.TransportMasterDNSVPN || tunnelCfg.MasterDNSVPN == nil {
		return fmt.Errorf("tunnel '%s' is not a MasterDnsVPN tunnel", tag)
	}

	currentMethod, _ := readEncryptionMethod(tunnelCfg.MasterDNSVPN.ConfigFile)

	methodStr, err := tui.RunMenu(tui.MenuConfig{
		Title:   fmt.Sprintf("Encryption for '%s' (current: %s)", tag, encryptionMethodName(currentMethod)),
		Options: encryptionMethodOptions,
	})
	if err != nil || methodStr == "" {
		return nil
	}

	var method int
	fmt.Sscanf(methodStr, "%d", &method)

	beginProgress(ctx, fmt.Sprintf("Set Encryption: '%s' → %s", tag, encryptionMethodName(method)))

	tunnelObj := router.NewTunnel(tunnelCfg)
	wasRunning := tunnelObj.IsActive()

	ctx.Output.Step(1, 3, "Updating encryption method in config...")
	if err := updateEncryptionMethod(tunnelCfg.MasterDNSVPN.ConfigFile, method); err != nil {
		return failProgress(ctx, fmt.Errorf("failed to update config: %w", err))
	}
	ctx.Output.Status("Config updated")

	ctx.Output.Step(2, 3, "Regenerating encryption key...")
	newKey, err := regenerateEncryptionKey(tunnelCfg.MasterDNSVPN.ConfigFile, tunnelCfg.MasterDNSVPN.BinaryPath)
	if err != nil {
		return failProgress(ctx, err)
	}
	ctx.Output.Status("Key regenerated")

	ctx.Output.Step(3, 3, "Applying changes...")
	if wasRunning {
		if err := tunnelObj.Restart(); err != nil {
			ctx.Output.Warning("Failed to restart tunnel: " + err.Error())
		} else {
			ctx.Output.Status("Tunnel restarted")
		}
	} else {
		ctx.Output.Status("Tunnel not running — changes apply on next start")
	}

	ctx.Output.Success(fmt.Sprintf("Encryption method set to %s for '%s'", encryptionMethodName(method), tag))
	ctx.Output.Println()
	ctx.Output.Info("New Encryption Key (copy to client config):")
	ctx.Output.Println(newKey)

	endProgress(ctx)
	return nil
}

// HandleTunnelSetEncryptionAll changes the encryption method for all MasterDnsVPN tunnels.
func HandleTunnelSetEncryptionAll(ctx *actions.Context) error {
	cfg, err := RequireConfig(ctx)
	if err != nil {
		return err
	}

	var mdnsTunnels []config.TunnelConfig
	for _, t := range cfg.Tunnels {
		if t.Transport == config.TransportMasterDNSVPN && t.MasterDNSVPN != nil {
			mdnsTunnels = append(mdnsTunnels, t)
		}
	}

	if len(mdnsTunnels) == 0 {
		return fmt.Errorf("no MasterDnsVPN tunnels configured")
	}

	methodStr, err := tui.RunMenu(tui.MenuConfig{
		Title:   fmt.Sprintf("Encryption Method for all %d MasterDnsVPN tunnels", len(mdnsTunnels)),
		Options: encryptionMethodOptions,
	})
	if err != nil || methodStr == "" {
		return nil
	}

	var method int
	fmt.Sscanf(methodStr, "%d", &method)

	beginProgress(ctx, fmt.Sprintf("Set Encryption: %s (%d tunnels)", encryptionMethodName(method), len(mdnsTunnels)))

	type result struct {
		tag string
		key string
		err error
	}
	results := make([]result, len(mdnsTunnels))

	for i, tunnelCfg := range mdnsTunnels {
		ctx.Output.Step(i+1, len(mdnsTunnels), fmt.Sprintf("Updating '%s'...", tunnelCfg.Tag))

		tc := tunnelCfg // local copy
		tunnelObj := router.NewTunnel(&tc)
		wasRunning := tunnelObj.IsActive()

		newKey, updateErr := func() (string, error) {
			if err := updateEncryptionMethod(tc.MasterDNSVPN.ConfigFile, method); err != nil {
				return "", fmt.Errorf("failed to update config: %w", err)
			}
			return regenerateEncryptionKey(tc.MasterDNSVPN.ConfigFile, tc.MasterDNSVPN.BinaryPath)
		}()

		results[i] = result{tag: tc.Tag, key: newKey, err: updateErr}
		if updateErr != nil {
			ctx.Output.Warning(fmt.Sprintf("'%s': %v", tc.Tag, updateErr))
			continue
		}

		if wasRunning {
			if err := tunnelObj.Restart(); err != nil {
				ctx.Output.Warning(fmt.Sprintf("'%s': failed to restart: %v", tc.Tag, err))
			}
		}
		ctx.Output.Status(fmt.Sprintf("'%s' updated", tc.Tag))
	}

	succeeded := 0
	for _, r := range results {
		if r.err == nil {
			succeeded++
		}
	}

	ctx.Output.Success(fmt.Sprintf("Updated %d / %d tunnels to %s", succeeded, len(mdnsTunnels), encryptionMethodName(method)))

	for _, r := range results {
		if r.err == nil && r.key != "" {
			ctx.Output.Println()
			ctx.Output.Info(fmt.Sprintf("New key for '%s' (copy to client config):", r.tag))
			ctx.Output.Println(r.key)
		}
	}

	endProgress(ctx)
	return nil
}

// regenerateEncryptionKey runs -genkey -nowait against the tunnel binary and returns
// the new key content. The DATA_ENCRYPTION_METHOD in configFile must already be updated.
func regenerateEncryptionKey(configFile, binaryPath string) (string, error) {
	tunnelDir := filepath.Dir(configFile)
	keyFilePath := filepath.Join(tunnelDir, "encrypt_key.txt")

	genkeyCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cmd := exec.CommandContext(genkeyCtx, binaryPath, "-genkey", "-nowait")
	cmd.Dir = tunnelDir
	if out, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("key generation failed: %w\nOutput: %s", err, out)
	}

	keyData, err := os.ReadFile(keyFilePath)
	if err != nil {
		return "", fmt.Errorf("failed to read generated key: %w", err)
	}
	return strings.TrimSpace(string(keyData)), nil
}

// readEncryptionMethod reads the current DATA_ENCRYPTION_METHOD value from a config file.
// Returns 1 (XOR) as the default if the field is not found.
func readEncryptionMethod(configFile string) (int, error) {
	data, err := os.ReadFile(configFile)
	if err != nil {
		return 1, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "DATA_ENCRYPTION_METHOD") {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				var method int
				if _, scanErr := fmt.Sscanf(strings.TrimSpace(parts[1]), "%d", &method); scanErr == nil {
					return method, nil
				}
			}
		}
	}
	return 1, nil
}

// updateEncryptionMethod replaces the DATA_ENCRYPTION_METHOD line in a config file.
// If the field is absent it is appended.
func updateEncryptionMethod(configFile string, method int) error {
	data, err := os.ReadFile(configFile)
	if err != nil {
		return err
	}
	lines := strings.Split(string(data), "\n")
	found := false
	for i, line := range lines {
		if strings.HasPrefix(line, "DATA_ENCRYPTION_METHOD") {
			lines[i] = fmt.Sprintf("DATA_ENCRYPTION_METHOD = %d", method)
			found = true
			break
		}
	}
	if !found {
		lines = append(lines, fmt.Sprintf("DATA_ENCRYPTION_METHOD = %d", method))
	}
	return os.WriteFile(configFile, []byte(strings.Join(lines, "\n")), 0640)
}
