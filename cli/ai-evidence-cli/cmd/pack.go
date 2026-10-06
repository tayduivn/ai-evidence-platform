package cmd

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"ei-evidence-platform/cli/ai-evidence-cli/internal/packer"
	"ei-evidence-platform/cli/ai-evidence-cli/internal/verifier"
)

func runPack(args []string, stdout, stderr io.Writer) int {
	var flagArgs []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if strings.HasPrefix(arg, "-") {
			flagArgs = append(flagArgs, arg)
			if (arg == "-o" || arg == "--output" || arg == "--dir" || arg == "--events" ||
				arg == "--proof" || arg == "--signatures" || arg == "--certs" ||
				arg == "--root-ca" || arg == "--anchor") && i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				i++
				flagArgs = append(flagArgs, args[i])
			}
		}
	}

	fs := flag.NewFlagSet("pack", flag.ContinueOnError)
	fs.SetOutput(stderr)

	var dirPath string
	fs.StringVar(&dirPath, "dir", "", "Path to staged directory containing evidence files")

	var eventsPath string
	fs.StringVar(&eventsPath, "events", "", "Path to events.json")

	var proofPath string
	fs.StringVar(&proofPath, "proof", "", "Path to merkle_proof.json")

	var sigsDir string
	fs.StringVar(&sigsDir, "signatures", "", "Directory containing signature_*.json files")

	var certsDir string
	fs.StringVar(&certsDir, "certs", "", "Directory containing signer_*.pem and root_ca.pem files")

	var rootCAPath string
	fs.StringVar(&rootCAPath, "root-ca", "", "Path to root_ca.pem")

	var anchorPath string
	fs.StringVar(&anchorPath, "anchor", "", "Path to optional rfc3161_timestamp.tsr")

	var outputPath string
	fs.StringVar(&outputPath, "output", "", "Destination path for evidence pack ZIP")
	fs.StringVar(&outputPath, "o", "", "Destination path for evidence pack ZIP (shorthand)")

	if err := fs.Parse(flagArgs); err != nil {
		fmt.Fprintf(stderr, "Error parsing flags: %v\n", err)
		return int(verifier.ExitGeneralFail)
	}

	if outputPath == "" {
		fmt.Fprintln(stderr, "Error: missing output path (-o, --output)")
		fmt.Fprintln(stderr, "Usage: ai-evidence-cli pack --dir <dir> -o <pack.zip>")
		return int(verifier.ExitGeneralFail)
	}

	ctx := context.Background()

	// Mode 1: Pack existing directory
	if dirPath != "" {
		manifest, err := packer.PackDirectory(ctx, dirPath, outputPath)
		if err != nil {
			fmt.Fprintf(stderr, "Failed to pack directory %s: %v\n", dirPath, err)
			return int(verifier.ExitGeneralFail)
		}
		fmt.Fprintf(stdout, "Successfully assembled evidence pack: %s (Decision ID: %s, Files: %d)\n",
			outputPath, manifest.DecisionID, len(manifest.Files))
		return int(verifier.ExitSuccess)
	}

	// Mode 2: Assemble from individual components
	if eventsPath == "" {
		fmt.Fprintln(stderr, "Error: must specify either --dir or --events")
		return int(verifier.ExitGeneralFail)
	}

	eventsBytes, err := os.ReadFile(eventsPath)
	if err != nil {
		fmt.Fprintf(stderr, "Failed to read events file %s: %v\n", eventsPath, err)
		return int(verifier.ExitGeneralFail)
	}
	var events []any
	if err := json.Unmarshal(eventsBytes, &events); err != nil {
		fmt.Fprintf(stderr, "Failed to parse events JSON: %v\n", err)
		return int(verifier.ExitGeneralFail)
	}

	decisionID := "dec-unknown"
	if len(events) > 0 {
		if m, ok := events[0].(map[string]any); ok {
			if id, ok := m["event_id"].(string); ok {
				decisionID = id
			}
		}
	}

	var proof *verifier.MerkleProofData
	if proofPath != "" {
		proofBytes, err := os.ReadFile(proofPath)
		if err != nil {
			fmt.Fprintf(stderr, "Failed to read merkle proof file %s: %v\n", proofPath, err)
			return int(verifier.ExitGeneralFail)
		}
		var p verifier.MerkleProofData
		if err := json.Unmarshal(proofBytes, &p); err != nil {
			fmt.Fprintf(stderr, "Failed to parse merkle proof JSON: %v\n", err)
			return int(verifier.ExitGeneralFail)
		}
		proof = &p
	}

	var signatures []verifier.SignatureRecord
	var signerCerts [][]byte
	var rootCAPEM []byte

	if rootCAPath != "" {
		rootCAPEM, err = os.ReadFile(rootCAPath)
		if err != nil {
			fmt.Fprintf(stderr, "Failed to read root CA file %s: %v\n", rootCAPath, err)
			return int(verifier.ExitGeneralFail)
		}
	} else if certsDir != "" {
		candidate := filepath.Join(certsDir, "root_ca.pem")
		if data, err := os.ReadFile(candidate); err == nil {
			rootCAPEM = data
		}
	}

	if sigsDir != "" {
		entries, err := os.ReadDir(sigsDir)
		if err == nil {
			for _, e := range entries {
				if strings.HasPrefix(e.Name(), "signature_") && strings.HasSuffix(e.Name(), ".json") {
					data, err := os.ReadFile(filepath.Join(sigsDir, e.Name()))
					if err == nil {
						var s verifier.SignatureRecord
						if json.Unmarshal(data, &s) == nil {
							signatures = append(signatures, s)
							idx := strings.TrimPrefix(e.Name(), "signature_")
							idx = strings.TrimSuffix(idx, ".json")
							if certsDir != "" {
								certFile := filepath.Join(certsDir, fmt.Sprintf("signer_%s.pem", idx))
								certData, err := os.ReadFile(certFile)
								if err == nil {
									signerCerts = append(signerCerts, certData)
								}
							}
						}
					}
				}
			}
		}
	}

	var anchorData []byte
	if anchorPath != "" {
		anchorData, _ = os.ReadFile(anchorPath)
	}

	inputs := &packer.PackInputs{
		DecisionID:  decisionID,
		CreatedAt:   time.Now().UTC(),
		Events:      events,
		MerkleProof: proof,
		Signatures:  signatures,
		SignerCerts: signerCerts,
		RootCACert:  rootCAPEM,
		RFC3161TSR:  anchorData,
	}

	manifest, err := packer.BuildPackToFile(ctx, inputs, outputPath)
	if err != nil {
		fmt.Fprintf(stderr, "Packaging failed: %v\n", err)
		return int(verifier.ExitGeneralFail)
	}

	fmt.Fprintf(stdout, "Successfully assembled evidence pack: %s (Decision ID: %s, Files: %d)\n",
		outputPath, manifest.DecisionID, len(manifest.Files))
	return int(verifier.ExitSuccess)
}
