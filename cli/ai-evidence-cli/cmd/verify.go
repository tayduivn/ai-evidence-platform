package cmd

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"ei-evidence-platform/cli/ai-evidence-cli/internal/verifier"
)

func runVerify(args []string, stdout, stderr io.Writer) int {
	var flagArgs []string
	var posArgs []string

	for i := 0; i < len(args); i++ {
		arg := args[i]
		if strings.HasPrefix(arg, "-") {
			flagArgs = append(flagArgs, arg)
			if (arg == "-d" || arg == "--min-dwell" || arg == "-c" || arg == "--root-ca") && i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				i++
				flagArgs = append(flagArgs, args[i])
			}
		} else {
			posArgs = append(posArgs, arg)
		}
	}

	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	fs.SetOutput(stderr)

	var minDwell int
	fs.IntVar(&minDwell, "min-dwell", 10, "Minimum required dwell time in seconds")
	fs.IntVar(&minDwell, "d", 10, "Minimum required dwell time in seconds (shorthand)")

	var jsonOutput bool
	fs.BoolVar(&jsonOutput, "json", false, "Output structured JSON report")
	fs.BoolVar(&jsonOutput, "j", false, "Output structured JSON report (shorthand)")

	var verbose bool
	fs.BoolVar(&verbose, "verbose", false, "Display step-by-step layer validation logs")
	fs.BoolVar(&verbose, "v", false, "Display step-by-step layer validation logs (shorthand)")

	var rootCAPath string
	fs.StringVar(&rootCAPath, "root-ca", "", "Path to override Root CA certificate PEM")
	fs.StringVar(&rootCAPath, "c", "", "Path to override Root CA certificate PEM (shorthand)")

	if err := fs.Parse(flagArgs); err != nil {
		fmt.Fprintf(stderr, "Error parsing flags: %v\n", err)
		return int(verifier.ExitGeneralFail)
	}

	remaining := append(posArgs, fs.Args()...)
	if len(remaining) == 0 {
		fmt.Fprintln(stderr, "Error: missing path to evidence pack ZIP archive")
		fmt.Fprintln(stderr, "Usage: ai-evidence-cli verify <path_to_pack.zip> [flags]")
		return int(verifier.ExitGeneralFail)
	}

	packPath := remaining[0]

	opts := verifier.VerifyOptions{
		MinDwellSeconds: minDwell,
		Verbose:         verbose,
	}

	if rootCAPath != "" {
		pemBytes, err := os.ReadFile(rootCAPath)
		if err != nil {
			fmt.Fprintf(stderr, "Failed to read Root CA file %s: %v\n", rootCAPath, err)
			return int(verifier.ExitGeneralFail)
		}
		opts.RootCAOverride = pemBytes
	}

	report, err := verifier.Verify(packPath, opts)
	if err != nil {
		fmt.Fprintf(stderr, "Verification failed with unexpected error: %v\n", err)
		return int(verifier.ExitGeneralFail)
	}

	if verbose && len(report.VerboseLogs) > 0 {
		for _, logLine := range report.VerboseLogs {
			fmt.Fprintln(stdout, logLine)
		}
	}

	if jsonOutput {
		outBytes, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			fmt.Fprintf(stderr, "Failed to serialize report to JSON: %v\n", err)
			return int(verifier.ExitGeneralFail)
		}
		fmt.Fprintln(stdout, string(outBytes))
	} else {
		if report.ExitCode == verifier.ExitSuccess {
			fmt.Fprintln(stdout, report.Message)
		} else {
			if report.Error != "" {
				fmt.Fprintln(stdout, report.Error)
			} else {
				fmt.Fprintln(stdout, report.Message)
			}
		}
	}

	return int(report.ExitCode)
}
