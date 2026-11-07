package updater

import "context"

// LatestGeodataReleaseAPI is the GitHub API endpoint for Loyalsoldier/v2ray-rules-dat releases.
var LatestGeodataReleaseAPI = "https://api.github.com/repos/Loyalsoldier/v2ray-rules-dat/releases/latest"

// CheckLatestGeodata fetches the latest release metadata for Loyalsoldier/v2ray-rules-dat.
func CheckLatestGeodata(ctx context.Context, opts HTTPClientOptions) (*Release, error) {
	return CheckLatestFromURL(ctx, LatestGeodataReleaseAPI, opts)
}
