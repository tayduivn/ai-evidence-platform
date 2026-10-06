package cmd

import (
	"fmt"
	"io"
)

var (
	Version   = "1.0.0"
	GitCommit = "release"
	BuildDate = "2026-10-05"
)

func PrintVersion(w io.Writer) {
	fmt.Fprintf(w, "ai-evidence-cli v%s (commit: %s, built: %s, standalone offline)\n", Version, GitCommit, BuildDate)
}
