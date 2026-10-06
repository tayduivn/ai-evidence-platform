package main

import (
	"os"

	"ei-evidence-platform/cli/ai-evidence-cli/cmd"
)

func main() {
	exitCode := cmd.Execute(os.Args[1:])
	os.Exit(exitCode)
}
