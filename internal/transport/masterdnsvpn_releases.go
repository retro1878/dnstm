package transport

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

const (
	masterDNSVPNVersionFile = "/etc/dnstm/.masterdnsvpn-version"
	masterDNSVPNReleasesAPI = "https://api.github.com/repos/masterking32/MasterDnsVPN/releases?per_page=20"
	masterDNSVPNReleaseBase = "https://github.com/masterking32/MasterDnsVPN/releases/download"
	masterDNSVPNLatestURL   = "https://github.com/masterking32/MasterDnsVPN/releases/latest/download/MasterDnsVPN_Server_Linux_AMD64.zip"
)

type githubRelease struct {
	TagName string `json:"tag_name"`
}

// FetchMasterDNSVPNReleases fetches up to 20 release tags from GitHub, newest first.
// Returns an error if the API is unreachable or rate-limited.
func FetchMasterDNSVPNReleases() ([]string, error) {
	client := &http.Client{Timeout: 5 * time.Second}

	req, err := http.NewRequest("GET", masterDNSVPNReleasesAPI, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch releases: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub API returned HTTP %d", resp.StatusCode)
	}

	var releases []githubRelease
	if err := json.NewDecoder(resp.Body).Decode(&releases); err != nil {
		return nil, fmt.Errorf("failed to parse releases: %w", err)
	}

	tags := make([]string, 0, len(releases))
	for _, r := range releases {
		if r.TagName != "" {
			tags = append(tags, r.TagName)
		}
	}
	return tags, nil
}

// ReadInstalledMasterDNSVPNVersion returns the installed version tag, or "" if unknown.
func ReadInstalledMasterDNSVPNVersion() string {
	data, err := os.ReadFile(masterDNSVPNVersionFile)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// writeInstalledMasterDNSVPNVersion persists the installed version tag.
func writeInstalledMasterDNSVPNVersion(version string) {
	_ = os.WriteFile(masterDNSVPNVersionFile, []byte(version+"\n"), 0644)
}

// masterDNSVPNZipURL returns the ZIP download URL for a release tag.
// Pass "" for the latest release.
func masterDNSVPNZipURL(tag string) string {
	if tag == "" {
		return masterDNSVPNLatestURL
	}
	return fmt.Sprintf("%s/%s/MasterDnsVPN_Server_Linux_AMD64.zip", masterDNSVPNReleaseBase, tag)
}
