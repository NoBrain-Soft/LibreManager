// Package version holds build metadata injected via -ldflags.
package version

// Set at build time:
//
//	-ldflags "-X github.com/nobrain-soft/libremanager/internal/common/version.Version=v0.1.0"
var (
	Version = "dev"
	Commit  = "unknown"
	Date    = "unknown"
)

// String returns a human-readable version string.
func String() string {
	return Version + " (" + Commit + ", " + Date + ")"
}
