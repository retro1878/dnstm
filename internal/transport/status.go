package transport

import (
	"github.com/net2share/dnstm/internal/binary"
)

// coreBinaries are the transport binaries required for DNSTM to operate.
// MasterDnsVPN is excluded here because it is an optional transport installed
// on demand during "tunnel add"; its absence should not block the system install.
var coreBinaries = []binary.BinaryType{
	binary.BinaryDNSTTServer,
	binary.BinarySlipstreamServer,
	binary.BinarySSServer,
	binary.BinaryVayDNSServer,
}

// IsInstalled checks if all core transport binaries are installed.
func IsInstalled() bool {
	mgr := binary.NewDefaultManager()
	for _, bin := range coreBinaries {
		if _, err := mgr.GetPath(bin); err != nil {
			return false
		}
	}
	return true
}

// GetMissingBinaries returns a list of missing core transport binaries.
func GetMissingBinaries() []string {
	mgr := binary.NewDefaultManager()
	var missing []string
	for _, bin := range coreBinaries {
		if _, err := mgr.GetPath(bin); err != nil {
			missing = append(missing, string(bin))
		}
	}
	return missing
}
