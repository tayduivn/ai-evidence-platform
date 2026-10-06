package ledger

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// VerifyInclusionProof verifies an audit path against a leaf hash and expected state root hash.
func VerifyInclusionProof(leafHash [32]byte, expectedRoot [32]byte, path []AuditStep) bool {
	current := leafHash
	for _, step := range path {
		siblingBytes, err := hex.DecodeString(step.Hash)
		if err != nil || len(siblingBytes) != 32 {
			return false
		}
		var sibling [32]byte
		copy(sibling[:], siblingBytes)

		switch step.Direction {
		case "left":
			current = ComputeNodeHash(sibling, current)
		case "right":
			current = ComputeNodeHash(current, sibling)
		default:
			return false
		}
	}
	return current == expectedRoot
}

// VerifyConsistencyProof implements RFC 9162 Section 2.1.4.2 consistency proof verification.
func VerifyConsistencyProof(firstSize, secondSize int64, firstRoot, secondRoot [32]byte, proofHex []string) bool {
	if firstSize == secondSize {
		return len(proofHex) == 0 && firstRoot == secondRoot
	}
	if firstSize <= 0 || firstSize > secondSize {
		return false
	}
	if len(proofHex) == 0 {
		return false
	}

	proof := make([][32]byte, 0, len(proofHex))
	for _, h := range proofHex {
		b, err := hex.DecodeString(h)
		if err != nil || len(b) != 32 {
			return false
		}
		var arr [32]byte
		copy(arr[:], b)
		proof = append(proof, arr)
	}

	// Step 3: If firstSize is an exact power of 2, prepend firstRoot to proof
	if (firstSize & (firstSize - 1)) == 0 {
		proof = append([][32]byte{firstRoot}, proof...)
	}

	fn := firstSize - 1
	sn := secondSize - 1

	// Step 5: While LSB(fn) == 1, shift right
	for (fn & 1) == 1 {
		fn >>= 1
		sn >>= 1
	}

	if len(proof) == 0 {
		return false
	}

	fr := proof[0]
	sr := proof[0]

	for _, c := range proof[1:] {
		if sn == 0 {
			return false
		}
		if (fn&1) == 1 || fn == sn {
			fr = ComputeNodeHash(c, fr)
			sr = ComputeNodeHash(c, sr)
			for (fn&1) == 0 && fn != 0 {
				fn >>= 1
				sn >>= 1
			}
		} else {
			sr = ComputeNodeHash(sr, c)
		}
		fn >>= 1
		sn >>= 1
	}

	return fr == firstRoot && sr == secondRoot && sn == 0
}

// SerializeProofJSON formats an InclusionProof into canonical JSON for merkle_proof.json.
func SerializeProofJSON(proof *InclusionProof) ([]byte, error) {
	if proof == nil {
		return nil, fmt.Errorf("proof cannot be nil")
	}
	return json.MarshalIndent(proof, "", "  ")
}

// DeserializeProofJSON parses a merkle_proof.json document into an InclusionProof.
func DeserializeProofJSON(data []byte) (*InclusionProof, error) {
	var proof InclusionProof
	if err := json.Unmarshal(data, &proof); err != nil {
		return nil, fmt.Errorf("invalid merkle proof json: %w", err)
	}
	return &proof, nil
}
