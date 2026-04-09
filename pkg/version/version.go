package version

import "fmt"

var (
	Version = "0.1.0-dev"
	Commit  = "unknown"
	Date    = "unknown"
)

func String() string {
	return fmt.Sprintf("%s (commit=%s date=%s)", Version, Commit, Date)
}
