package config

import (
	"strings"
	"testing"
)

func TestValidate_MasterDNSVPN(t *testing.T) {
	tests := []struct {
		name    string
		cfg     *Config
		wantErr string
	}{
		{
			name: "valid masterdnsvpn tunnel without backend",
			cfg: &Config{
				Tunnels: []TunnelConfig{
					{Tag: "vpn1", Transport: TransportMasterDNSVPN, Domain: "t.example.com", Port: 5310},
				},
			},
			wantErr: "",
		},
		{
			name: "masterdnsvpn without domain fails",
			cfg: &Config{
				Tunnels: []TunnelConfig{
					{Tag: "vpn1", Transport: TransportMasterDNSVPN, Port: 5310},
				},
			},
			wantErr: "domain is required",
		},
		{
			name: "non-masterdnsvpn tunnel without backend still fails",
			cfg: &Config{
				Backends: []BackendConfig{},
				Tunnels: []TunnelConfig{
					{Tag: "slip1", Transport: TransportSlipstream, Domain: "t.example.com"},
				},
			},
			wantErr: "backend is required",
		},
		{
			name: "masterdnsvpn with port out of range fails",
			cfg: &Config{
				Tunnels: []TunnelConfig{
					{Tag: "vpn1", Transport: TransportMasterDNSVPN, Domain: "t.example.com", Port: 80},
				},
			},
			wantErr: "port must be between 1024 and 65535",
		},
		{
			name: "two masterdnsvpn tunnels on different ports and domains",
			cfg: &Config{
				Tunnels: []TunnelConfig{
					{Tag: "vpn1", Transport: TransportMasterDNSVPN, Domain: "t1.example.com", Port: 5310},
					{Tag: "vpn2", Transport: TransportMasterDNSVPN, Domain: "t2.example.com", Port: 5311},
				},
				Route: RouteConfig{Mode: "multi"},
			},
			wantErr: "",
		},
		{
			name: "two masterdnsvpn tunnels duplicate port",
			cfg: &Config{
				Tunnels: []TunnelConfig{
					{Tag: "vpn1", Transport: TransportMasterDNSVPN, Domain: "t1.example.com", Port: 5310},
					{Tag: "vpn2", Transport: TransportMasterDNSVPN, Domain: "t2.example.com", Port: 5310},
				},
			},
			wantErr: "port 5310 already used by",
		},
		{
			name: "masterdnsvpn duplicate domain in multi mode fails",
			cfg: &Config{
				Tunnels: []TunnelConfig{
					{Tag: "vpn1", Transport: TransportMasterDNSVPN, Domain: "t.example.com", Port: 5310},
					{Tag: "vpn2", Transport: TransportMasterDNSVPN, Domain: "t.example.com", Port: 5311},
				},
				Route: RouteConfig{Mode: "multi"},
			},
			wantErr: "domain 't.example.com' already used by",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate()
			if tt.wantErr == "" {
				if err != nil {
					t.Errorf("Validate() unexpected error: %v", err)
				}
			} else {
				if err == nil {
					t.Error("Validate() expected error, got nil")
				} else if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("Validate() error = %q, want containing %q", err.Error(), tt.wantErr)
				}
			}
		})
	}
}

func TestTunnelConfig_IsMasterDNSVPN(t *testing.T) {
	tests := []struct {
		transport TransportType
		want      bool
	}{
		{TransportMasterDNSVPN, true},
		{TransportSlipstream, false},
		{TransportDNSTT, false},
		{TransportVayDNS, false},
	}
	for _, tt := range tests {
		t.Run(string(tt.transport), func(t *testing.T) {
			tc := &TunnelConfig{Transport: tt.transport}
			if got := tc.IsMasterDNSVPN(); got != tt.want {
				t.Errorf("IsMasterDNSVPN() = %v, want %v", got, tt.want)
			}
		})
	}
}
