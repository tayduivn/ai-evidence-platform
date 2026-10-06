package cmd

import (
	"fmt"
	"io"
)

const HelpText = `ai-evidence-cli - Standalone Offline AI Evidence Verifier

USAGE:
  ai-evidence-cli <command> [arguments] [flags]

COMMANDS:
  verify <pack.zip>   Verify cryptographic integrity and policy of an Evidence Pack
  inspect <pack.zip>  Extract and display human-readable forensic summary
  pack [options]      Assemble an Evidence Pack ZIP archive
  version             Display version and build information
  help                Display this help reference

VERIFY FLAGS:
  --min-dwell, -d <sec>   Minimum required dwell time in seconds (default: 10)
  --json, -j              Output structured JSON report
  --verbose, -v           Display step-by-step layer validation logs
  --root-ca, -c <path>    Optional path to override Root CA certificate PEM

INSPECT FLAGS:
  --json, -j              Output inspection as structured JSON
  --show-payloads         Display raw unmasked prompts and responses

PACK FLAGS:
  --dir <dir>             Pack all evidence files from an existing directory
  --events <file>         Path to events.json
  --proof <file>          Path to merkle_proof.json
  --signatures <dir>      Directory containing signature_*.json files
  --certs <dir>           Directory containing signer_*.pem and root_ca.pem
  --anchor <file>         Path to optional rfc3161_timestamp.tsr
  -o, --output <path>     Destination output path for Evidence Pack ZIP (required)

EXIT CODES (verify command):
  0: VERIFICATION_SUCCESS  All integrity and policy checks passed
  1: EXIT_MANIFEST_FAIL    Manifest missing, corrupted, or file hash mismatch
  2: EXIT_MERKLE_FAIL      Merkle proof leaf or root hash mismatch
  3: EXIT_SIGNATURE_FAIL   Digital signature verification failed or signatures missing
  4: EXIT_CERT_FAIL        Certificate chain untrusted, expired, or Root CA missing
  5: EXIT_POLICY_FAIL      Policy violation (4-Eyes duplicate, self-approval, dwell time)
  6: EXIT_GENERAL_FAIL     File not found, invalid ZIP archive, or general I/O error
`

func PrintHelp(w io.Writer) {
	fmt.Fprint(w, HelpText)
}
