package cmd

import (
	"fmt"
	"io"
	"os"

	"ei-evidence-platform/cli/ai-evidence-cli/internal/verifier"
)

// Execute routes CLI subcommands and returns the appropriate exit code.
func Execute(args []string) int {
	return ExecuteWithIO(args, os.Stdout, os.Stderr)
}

// ExecuteWithIO allows injecting stdout and stderr for testing.
func ExecuteWithIO(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		PrintHelp(stderr)
		return int(verifier.ExitGeneralFail)
	}

	command := args[0]
	cmdArgs := args[1:]

	switch command {
	case "verify":
		return runVerify(cmdArgs, stdout, stderr)
	case "inspect":
		return runInspect(cmdArgs, stdout, stderr)
	case "pack":
		return runPack(cmdArgs, stdout, stderr)
	case "version", "--version", "-V":
		PrintVersion(stdout)
		return int(verifier.ExitSuccess)
	case "help", "--help", "-h":
		PrintHelp(stdout)
		return int(verifier.ExitSuccess)
	default:
		fmt.Fprintf(stderr, "Unknown command: %s\n\n", command)
		PrintHelp(stderr)
		return int(verifier.ExitGeneralFail)
	}
}
