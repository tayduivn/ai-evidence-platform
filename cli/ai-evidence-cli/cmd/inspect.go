package cmd

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"strings"

	"ei-evidence-platform/cli/ai-evidence-cli/internal/inspector"
	"ei-evidence-platform/cli/ai-evidence-cli/internal/verifier"
)

func runInspect(args []string, stdout, stderr io.Writer) int {
	var flagArgs []string
	var posArgs []string

	for _, arg := range args {
		if strings.HasPrefix(arg, "-") {
			flagArgs = append(flagArgs, arg)
		} else {
			posArgs = append(posArgs, arg)
		}
	}

	fs := flag.NewFlagSet("inspect", flag.ContinueOnError)
	fs.SetOutput(stderr)

	var jsonOutput bool
	fs.BoolVar(&jsonOutput, "json", false, "Output inspection report as structured JSON")
	fs.BoolVar(&jsonOutput, "j", false, "Output inspection report as structured JSON (shorthand)")

	var showPayloads bool
	fs.BoolVar(&showPayloads, "show-payloads", false, "Include raw unmasked payloads in inspection")

	if err := fs.Parse(flagArgs); err != nil {
		fmt.Fprintf(stderr, "Error parsing flags: %v\n", err)
		return int(verifier.ExitGeneralFail)
	}

	remaining := append(posArgs, fs.Args()...)
	if len(remaining) == 0 {
		fmt.Fprintln(stderr, "Error: missing path to evidence pack ZIP archive")
		fmt.Fprintln(stderr, "Usage: ai-evidence-cli inspect <path_to_pack.zip> [flags]")
		return int(verifier.ExitGeneralFail)
	}

	packPath := remaining[0]

	report, err := inspector.Inspect(packPath, inspector.InspectOptions{
		ShowPayloads: showPayloads,
	})
	if err != nil {
		fmt.Fprintf(stderr, "Inspection failed: %v\n", err)
		return int(verifier.ExitGeneralFail)
	}

	if jsonOutput {
		outBytes, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			fmt.Fprintf(stderr, "Failed to serialize inspection to JSON: %v\n", err)
			return int(verifier.ExitGeneralFail)
		}
		fmt.Fprintln(stdout, string(outBytes))
	} else {
		fmt.Fprint(stdout, report.TextSummary(showPayloads))
	}

	return int(verifier.ExitSuccess)
}
