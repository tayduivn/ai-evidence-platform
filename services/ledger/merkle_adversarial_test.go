package ledger

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"testing"
)

// ============================================================================
// ADVERSARIAL CHALLENGE 1: MERKLE TREE BOUNDARIES & EDGE CASES
// ============================================================================

func TestAdversarial_Merkle_EdgeCases(t *testing.T) {
	t.Run("ZeroLeaves_EmptyTree", func(t *testing.T) {
		tree := NewMemoryMerkleTree()
		if tree.Size() != 0 {
			t.Fatalf("Expected size 0, got %d", tree.Size())
		}

		// RFC 6962: MTH({}) = SHA-256("")
		root := tree.Root()
		expectedEmpty := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
		if hex.EncodeToString(root[:]) != expectedEmpty {
			t.Fatalf("Empty tree root mismatch: got %s, expected %s", hex.EncodeToString(root[:]), expectedEmpty)
		}

		// Inclusion proof requests must be rejected
		if _, err := tree.InclusionProof(0); err != ErrEmptyTree {
			t.Errorf("Expected ErrEmptyTree for index 0, got %v", err)
		}
		if _, err := tree.InclusionProof(-1); err != ErrEmptyTree {
			t.Errorf("Expected ErrEmptyTree for negative index, got %v", err)
		}
		if _, err := tree.InclusionProof(100); err != ErrEmptyTree {
			t.Errorf("Expected ErrEmptyTree for index 100, got %v", err)
		}

		// LeafHashAt on empty tree
		if _, err := tree.LeafHashAt(0); err != ErrIndexOutOfBounds {
			t.Errorf("Expected ErrIndexOutOfBounds, got %v", err)
		}

		// Consistency proofs on empty tree
		if _, err := tree.ConsistencyProof(0); err != ErrInvalidConsistency {
			t.Errorf("Expected ErrInvalidConsistency for pastSize=0, got %v", err)
		}
		if _, err := tree.ConsistencyProof(1); err != ErrInvalidConsistency {
			t.Errorf("Expected ErrInvalidConsistency for pastSize=1, got %v", err)
		}

		// Empty batch append should not corrupt tree state
		start, end, r, err := tree.AppendBatch(nil)
		if err != nil || start != 0 || end != 0 || r != root || tree.Size() != 0 {
			t.Errorf("AppendBatch(nil) corrupted empty tree state")
		}

		// Verification with zero hash against empty root must fail
		var zeroHash [32]byte
		if VerifyInclusionProof(zeroHash, root, nil) {
			t.Errorf("VerifyInclusionProof with zero hash against empty root must fail")
		}
	})

	t.Run("SingleLeaf", func(t *testing.T) {
		tree := NewMemoryMerkleTree()
		payload := []byte("audit-event-single-decision-42")
		idx, lh, root, err := tree.Append(payload)
		if err != nil {
			t.Fatalf("Append failed: %v", err)
		}
		if idx != 0 {
			t.Fatalf("Expected index 0, got %d", idx)
		}
		if tree.Size() != 1 {
			t.Fatalf("Expected size 1, got %d", tree.Size())
		}

		// RFC 6962: MTH({d0}) = SHA-256(0x00 || d0)
		expectedLeaf := ComputeLeafHash(payload)
		if lh != expectedLeaf {
			t.Fatalf("Leaf hash mismatch: got %x, expected %x", lh, expectedLeaf)
		}
		if root != expectedLeaf {
			t.Fatalf("Root for 1-leaf tree must equal leaf hash: got %x, expected %x", root, expectedLeaf)
		}

		// Inclusion proof for single leaf must have empty audit path
		proof, err := tree.InclusionProof(0)
		if err != nil {
			t.Fatalf("InclusionProof(0) failed: %v", err)
		}
		if len(proof.AuditPath) != 0 {
			t.Fatalf("Expected empty audit path for 1-leaf tree, got %d steps", len(proof.AuditPath))
		}
		if !VerifyInclusionProof(lh, root, proof.AuditPath) {
			t.Fatalf("Valid 1-leaf inclusion proof failed verification")
		}

		// Tampering attacks on single leaf proof
		mutatedLeaf := lh
		mutatedLeaf[0] ^= 0x01
		if VerifyInclusionProof(mutatedLeaf, root, proof.AuditPath) {
			t.Errorf("Tampered leaf accepted on 1-leaf tree")
		}

		mutatedRoot := root
		mutatedRoot[31] ^= 0x80
		if VerifyInclusionProof(lh, mutatedRoot, proof.AuditPath) {
			t.Errorf("Tampered root accepted on 1-leaf tree")
		}

		bogusStep := []AuditStep{{Direction: "right", Hash: hex.EncodeToString(lh[:])}}
		if VerifyInclusionProof(lh, root, bogusStep) {
			t.Errorf("Bogus audit step accepted on 1-leaf tree")
		}

		// Consistency proof 1 -> 1
		cProof, err := tree.ConsistencyProof(1)
		if err != nil {
			t.Fatalf("ConsistencyProof(1) failed: %v", err)
		}
		if len(cProof.ConsistencyPath) != 0 {
			t.Errorf("ConsistencyPath for 1 -> 1 must be empty, got %d", len(cProof.ConsistencyPath))
		}
		if !VerifyConsistencyProof(1, 1, root, root, cProof.ConsistencyPath) {
			t.Errorf("VerifyConsistencyProof(1, 1) failed")
		}
	})

	t.Run("UnbalancedTrees", func(t *testing.T) {
		unbalancedSizes := []int{2, 3, 5, 7, 9, 13, 15, 17, 31, 33, 63, 65, 127, 129, 255, 257}
		for _, size := range unbalancedSizes {
			tree := NewMemoryMerkleTree()
			rawLeaves := make([][]byte, size)
			leafHashes := make([][32]byte, size)

			for i := 0; i < size; i++ {
				data := []byte(fmt.Sprintf("unbalanced-tree-sz%d-idx%d-data", size, i))
				rawLeaves[i] = data
				idx, lh, _, err := tree.Append(data)
				if err != nil {
					t.Fatalf("Append failed: %v", err)
				}
				if idx != int64(i) {
					t.Fatalf("Expected index %d, got %d", i, idx)
				}
				leafHashes[i] = lh
			}

			root := tree.Root()
			expectedRoot := ComputeMTH(leafHashes)
			if root != expectedRoot {
				t.Fatalf("Size %d root mismatch with ComputeMTH", size)
			}

			// Verify AppendBatch parity
			batchTree := NewMemoryMerkleTree()
			sIdx, eIdx, batchRoot, err := batchTree.AppendBatch(rawLeaves)
			if err != nil || sIdx != 0 || eIdx != int64(size-1) || batchRoot != root {
				t.Fatalf("Size %d batch append parity failed", size)
			}

			// Verify inclusion proof for every single leaf
			for i := 0; i < size; i++ {
				proof, err := tree.InclusionProof(int64(i))
				if err != nil {
					t.Fatalf("InclusionProof(%d) failed for size %d: %v", i, size, err)
				}
				if !VerifyInclusionProof(leafHashes[i], root, proof.AuditPath) {
					t.Fatalf("Inclusion verification failed for leaf %d in size %d", i, size)
				}

				// Adversarial bit-flip check on sample
				if i == 0 || i == size-1 || i == size/2 {
					badLeaf := leafHashes[i]
					badLeaf[0] ^= 0x55
					if VerifyInclusionProof(badLeaf, root, proof.AuditPath) {
						t.Fatalf("Tampered leaf accepted at index %d in size %d", i, size)
					}
				}
			}
		}
	})

	t.Run("Scale1000Leaves", func(t *testing.T) {
		const total = 1000
		tree := NewMemoryMerkleTree()
		rawLeaves := make([][]byte, total)
		leafHashes := make([][32]byte, total)

		for i := 0; i < total; i++ {
			data := []byte(fmt.Sprintf("scale-1000-leaf-%04d", i))
			rawLeaves[i] = data
			idx, lh, _, err := tree.Append(data)
			if err != nil {
				t.Fatalf("Append failed at %d: %v", i, err)
			}
			if idx != int64(i) {
				t.Fatalf("Index mismatch at %d: got %d", i, idx)
			}
			leafHashes[i] = lh
		}

		root := tree.Root()

		// Batch parity
		batchTree := NewMemoryMerkleTree()
		_, _, batchRoot, err := batchTree.AppendBatch(rawLeaves)
		if err != nil || batchRoot != root {
			t.Fatalf("Scale 1000 batch root mismatch with incremental root")
		}

		// Verify inclusion proof for all 1000 leaves
		maxPathLen := 11 // ceil(log2(1000)) = 10
		for i := 0; i < total; i++ {
			proof, err := tree.InclusionProof(int64(i))
			if err != nil {
				t.Fatalf("InclusionProof failed for leaf %d: %v", i, err)
			}
			if len(proof.AuditPath) > maxPathLen {
				t.Errorf("Path length for leaf %d exceeds bound: %d > %d", i, len(proof.AuditPath), maxPathLen)
			}
			if !VerifyInclusionProof(leafHashes[i], root, proof.AuditPath) {
				t.Fatalf("Proof verification failed for leaf %d of 1000", i)
			}

			// Tamper check on sample
			if i%100 == 0 {
				tampered := leafHashes[i]
				tampered[15] ^= 0xAA
				if VerifyInclusionProof(tampered, root, proof.AuditPath) {
					t.Fatalf("Tampered leaf %d accepted!", i)
				}
			}
		}
	})
}

// ============================================================================
// ADVERSARIAL CHALLENGE 2: INCLUSION PROOF TAMPERING DETECTION
// ============================================================================

func TestAdversarial_Merkle_InclusionTampering(t *testing.T) {
	tree := NewMemoryMerkleTree()
	const n = 16
	for i := 0; i < n; i++ {
		_, _, _, _ = tree.Append([]byte(fmt.Sprintf("tamper-vector-event-%d", i)))
	}
	root := tree.Root()

	for _, targetIdx := range []int64{3, 7, 12} {
		t.Run(fmt.Sprintf("TargetLeaf_%d", targetIdx), func(t *testing.T) {
			lh, err := tree.LeafHashAt(targetIdx)
			if err != nil {
				t.Fatalf("LeafHashAt(%d) failed: %v", targetIdx, err)
			}
			proof, err := tree.InclusionProof(targetIdx)
			if err != nil {
				t.Fatalf("InclusionProof(%d) failed: %v", targetIdx, err)
			}

			// Baseline verification must succeed
			if !VerifyInclusionProof(lh, root, proof.AuditPath) {
				t.Fatalf("Baseline valid proof failed verification")
			}

			// Attack 1: Mutate every byte position of leaf hash
			for bytePos := 0; bytePos < 32; bytePos++ {
				for _, mask := range []byte{0x01, 0x80, 0xFF} {
					tamperedLeaf := lh
					tamperedLeaf[bytePos] ^= mask
					if VerifyInclusionProof(tamperedLeaf, root, proof.AuditPath) {
						t.Fatalf("Tampered leaf accepted at byte %d mask %x", bytePos, mask)
					}
				}
			}

			// Attack 2: Mutate every byte position of root hash
			for bytePos := 0; bytePos < 32; bytePos++ {
				for _, mask := range []byte{0x01, 0x80, 0xFF} {
					tamperedRoot := root
					tamperedRoot[bytePos] ^= mask
					if VerifyInclusionProof(lh, tamperedRoot, proof.AuditPath) {
						t.Fatalf("Tampered root accepted at byte %d mask %x", bytePos, mask)
					}
				}
			}

			// Attack 3: Invert direction of each step
			for stepIdx := range proof.AuditPath {
				tamperedPath := make([]AuditStep, len(proof.AuditPath))
				copy(tamperedPath, proof.AuditPath)
				if tamperedPath[stepIdx].Direction == "left" {
					tamperedPath[stepIdx].Direction = "right"
				} else {
					tamperedPath[stepIdx].Direction = "left"
				}
				if VerifyInclusionProof(lh, root, tamperedPath) {
					t.Fatalf("Inverted direction at step %d was accepted", stepIdx)
				}
			}

			// Attack 4: Invalid direction values
			badDirections := []string{"", " ", "top", "bottom", "LEFT", "RIGHT", "Left", "Right", "1", "0", "center"}
			for _, badDir := range badDirections {
				tamperedPath := make([]AuditStep, len(proof.AuditPath))
				copy(tamperedPath, proof.AuditPath)
				tamperedPath[0].Direction = badDir
				if VerifyInclusionProof(lh, root, tamperedPath) {
					t.Fatalf("Invalid direction '%s' was accepted", badDir)
				}
			}

			// Attack 5: Corrupt sibling hash in each step
			for stepIdx := range proof.AuditPath {
				tamperedPath := make([]AuditStep, len(proof.AuditPath))
				copy(tamperedPath, proof.AuditPath)
				rawBytes, _ := hex.DecodeString(tamperedPath[stepIdx].Hash)
				rawBytes[0] ^= 0xFE
				tamperedPath[stepIdx].Hash = hex.EncodeToString(rawBytes)
				if VerifyInclusionProof(lh, root, tamperedPath) {
					t.Fatalf("Corrupted sibling hash at step %d was accepted", stepIdx)
				}
			}

			// Attack 6: Malformed hex strings in audit path
			malformedHex := []string{"", "xyz", "12ab", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde"}
			for _, mHex := range malformedHex {
				tamperedPath := make([]AuditStep, len(proof.AuditPath))
				copy(tamperedPath, proof.AuditPath)
				tamperedPath[0].Hash = mHex
				if VerifyInclusionProof(lh, root, tamperedPath) {
					t.Fatalf("Malformed hex '%s' was accepted", mHex)
				}
			}

			// Attack 7: Truncation of audit path
			if VerifyInclusionProof(lh, root, proof.AuditPath[1:]) {
				t.Fatalf("Truncated audit path (missing step 0) was accepted")
			}
			if VerifyInclusionProof(lh, root, proof.AuditPath[:len(proof.AuditPath)-1]) {
				t.Fatalf("Truncated audit path (missing last step) was accepted")
			}

			// Attack 8: Extension with spurious steps
			extraStep := AuditStep{Direction: "right", Hash: hex.EncodeToString(lh[:])}
			if VerifyInclusionProof(lh, root, append([]AuditStep{extraStep}, proof.AuditPath...)) {
				t.Fatalf("Prepended spurious step was accepted")
			}
			if VerifyInclusionProof(lh, root, append(proof.AuditPath, extraStep)) {
				t.Fatalf("Appended spurious step was accepted")
			}

			// Attack 9: Step reordering
			if len(proof.AuditPath) >= 2 {
				reordered := make([]AuditStep, len(proof.AuditPath))
				copy(reordered, proof.AuditPath)
				reordered[0], reordered[1] = reordered[1], reordered[0]
				if VerifyInclusionProof(lh, root, reordered) {
					t.Fatalf("Reordered audit steps were accepted")
				}
			}

			// Attack 10: Cross-leaf replay
			otherIdx := (targetIdx + 1) % n
			otherProof, _ := tree.InclusionProof(otherIdx)
			if VerifyInclusionProof(lh, root, otherProof.AuditPath) {
				t.Fatalf("Cross-leaf proof replay accepted for leaf %d with leaf %d's proof", targetIdx, otherIdx)
			}
		})
	}

	// Out of bounds leaf index checks
	t.Run("OutOfBoundsLeafIndex", func(t *testing.T) {
		if _, err := tree.InclusionProof(-1); err != ErrIndexOutOfBounds {
			t.Errorf("Expected ErrIndexOutOfBounds for -1, got %v", err)
		}
		if _, err := tree.InclusionProof(n); err != ErrIndexOutOfBounds {
			t.Errorf("Expected ErrIndexOutOfBounds for n, got %v", err)
		}
		if _, err := tree.InclusionProof(1000); err != ErrIndexOutOfBounds {
			t.Errorf("Expected ErrIndexOutOfBounds for 1000, got %v", err)
		}
	})
}

// ============================================================================
// ADVERSARIAL CHALLENGE 3: DYNAMIC CONSISTENCY PROOFS ACROSS TRANSITIONS
// ============================================================================

func TestAdversarial_Merkle_ConsistencyTransitions(t *testing.T) {
	t.Run("ExhaustiveMatrix_1_to_32", func(t *testing.T) {
		const maxSize = 32
		tree := NewMemoryMerkleTree()
		roots := make([][32]byte, maxSize+1)

		for i := 1; i <= maxSize; i++ {
			_, _, _, _ = tree.Append([]byte(fmt.Sprintf("matrix-event-%d", i)))
			roots[i] = tree.Root()
		}

		for n := int64(1); n <= maxSize; n++ {
			subTree := NewMemoryMerkleTree()
			for i := int64(1); i <= n; i++ {
				_, _, _, _ = subTree.Append([]byte(fmt.Sprintf("matrix-event-%d", i)))
			}

			for m := int64(1); m <= n; m++ {
				proof, err := subTree.ConsistencyProof(m)
				if err != nil {
					t.Fatalf("ConsistencyProof(%d -> %d) failed: %v", m, n, err)
				}
				if proof.FirstSize != m || proof.SecondSize != n {
					t.Fatalf("Proof metadata mismatch: (%d, %d)", proof.FirstSize, proof.SecondSize)
				}
				if !VerifyConsistencyProof(m, n, roots[m], roots[n], proof.ConsistencyPath) {
					t.Fatalf("Consistency proof verification failed for transition %d -> %d", m, n)
				}
			}
		}
	})

	t.Run("DynamicCheckpoints_1000Leaves", func(t *testing.T) {
		const total = 1000
		tree := NewMemoryMerkleTree()
		snapshotRoots := make(map[int64][32]byte)
		checkpoints := []int64{1, 2, 3, 4, 7, 8, 15, 16, 31, 32, 63, 64, 100, 128, 255, 256, 500, 512, 750, 999, 1000}

		for i := int64(1); i <= total; i++ {
			_, _, root, err := tree.Append([]byte(fmt.Sprintf("dyn-check-%d", i)))
			if err != nil {
				t.Fatalf("Append failed: %v", err)
			}
			snapshotRoots[i] = root
		}

		for i := 0; i < len(checkpoints); i++ {
			m := checkpoints[i]
			for j := i; j < len(checkpoints); j++ {
				n := checkpoints[j]
				var proof *ConsistencyProof
				var err error

				if n == total {
					proof, err = tree.ConsistencyProof(m)
				} else {
					sub := NewMemoryMerkleTree()
					for k := int64(1); k <= n; k++ {
						_, _, _, _ = sub.Append([]byte(fmt.Sprintf("dyn-check-%d", k)))
					}
					proof, err = sub.ConsistencyProof(m)
				}

				if err != nil {
					t.Fatalf("ConsistencyProof(%d -> %d) failed: %v", m, n, err)
				}
				if !VerifyConsistencyProof(m, n, snapshotRoots[m], snapshotRoots[n], proof.ConsistencyPath) {
					t.Fatalf("Large consistency proof failed for %d -> %d", m, n)
				}
			}
		}
	})

	t.Run("AdversarialConsistencyTampering", func(t *testing.T) {
		tree := NewMemoryMerkleTree()
		roots := make([][32]byte, 17)
		for i := 1; i <= 16; i++ {
			_, _, _, _ = tree.Append([]byte(fmt.Sprintf("adv-const-node-%d", i)))
			roots[i] = tree.Root()
		}

		m := int64(5)
		n := int64(16)
		proof, err := tree.ConsistencyProof(m)
		if err != nil {
			t.Fatalf("ConsistencyProof failed: %v", err)
		}
		firstRoot := roots[m]
		secondRoot := roots[n]

		// Baseline
		if !VerifyConsistencyProof(m, n, firstRoot, secondRoot, proof.ConsistencyPath) {
			t.Fatalf("Baseline consistency proof failed")
		}

		// Mutate first root
		tamperedFirst := firstRoot
		tamperedFirst[0] ^= 0x01
		if VerifyConsistencyProof(m, n, tamperedFirst, secondRoot, proof.ConsistencyPath) {
			t.Errorf("Accepted consistency proof with tampered firstRoot")
		}

		// Mutate second root
		tamperedSecond := secondRoot
		tamperedSecond[31] ^= 0x80
		if VerifyConsistencyProof(m, n, firstRoot, tamperedSecond, proof.ConsistencyPath) {
			t.Errorf("Accepted consistency proof with tampered secondRoot")
		}

		// Mutate path hashes
		for idx := range proof.ConsistencyPath {
			tamperedPath := make([]string, len(proof.ConsistencyPath))
			copy(tamperedPath, proof.ConsistencyPath)
			rawBytes, _ := hex.DecodeString(tamperedPath[idx])
			rawBytes[0] ^= 0x42
			tamperedPath[idx] = hex.EncodeToString(rawBytes)
			if VerifyConsistencyProof(m, n, firstRoot, secondRoot, tamperedPath) {
				t.Errorf("Accepted consistency proof with tampered path at step %d", idx)
			}
		}

		// Truncate path
		if len(proof.ConsistencyPath) > 0 {
			if VerifyConsistencyProof(m, n, firstRoot, secondRoot, proof.ConsistencyPath[:len(proof.ConsistencyPath)-1]) {
				t.Errorf("Accepted truncated consistency path")
			}
		}

		// Spurious hash injection
		spurious := append(proof.ConsistencyPath, hex.EncodeToString(firstRoot[:]))
		if VerifyConsistencyProof(m, n, firstRoot, secondRoot, spurious) {
			t.Errorf("Accepted consistency proof with spurious hash appended")
		}

		// Malformed hex in path
		badHex := make([]string, len(proof.ConsistencyPath))
		copy(badHex, proof.ConsistencyPath)
		badHex[0] = "not-a-valid-hex-hash"
		if VerifyConsistencyProof(m, n, firstRoot, secondRoot, badHex) {
			t.Errorf("Accepted consistency proof with invalid hex")
		}

		// Boundary violations
		if VerifyConsistencyProof(0, n, firstRoot, secondRoot, proof.ConsistencyPath) {
			t.Errorf("Accepted firstSize = 0")
		}
		if VerifyConsistencyProof(-5, n, firstRoot, secondRoot, proof.ConsistencyPath) {
			t.Errorf("Accepted negative firstSize")
		}
		if VerifyConsistencyProof(n+1, n, firstRoot, secondRoot, proof.ConsistencyPath) {
			t.Errorf("Accepted firstSize > secondSize")
		}
		if VerifyConsistencyProof(m, n, firstRoot, secondRoot, []string{}) {
			t.Errorf("Accepted empty consistency path for m < n")
		}
	})
}

// ============================================================================
// ADVERSARIAL CHALLENGE 4: MERKLE_PROOF.JSON SERIALIZATION & SCHEMA
// ============================================================================

func TestAdversarial_Merkle_JSONSerialization(t *testing.T) {
	tree := NewMemoryMerkleTree()
	for i := 0; i < 9; i++ {
		_, _, _, _ = tree.Append([]byte(fmt.Sprintf("json-proof-event-%d", i)))
	}

	proof, err := tree.InclusionProof(4)
	if err != nil {
		t.Fatalf("InclusionProof failed: %v", err)
	}

	// 1. Serialization nil safety
	if _, err := SerializeProofJSON(nil); err == nil {
		t.Fatalf("SerializeProofJSON(nil) should return error")
	}

	// 2. Normal serialization
	rawJSON, err := SerializeProofJSON(proof)
	if err != nil {
		t.Fatalf("SerializeProofJSON failed: %v", err)
	}

	// 3. Schema field verification
	var rawMap map[string]interface{}
	if err := json.Unmarshal(rawJSON, &rawMap); err != nil {
		t.Fatalf("Failed to parse serialized JSON into map: %v", err)
	}
	expectedKeys := []string{"tree_size", "leaf_index", "leaf_hash", "root_hash", "audit_path"}
	for _, key := range expectedKeys {
		if _, ok := rawMap[key]; !ok {
			t.Errorf("Serialized JSON missing required schema field '%s'", key)
		}
	}

	// 4. Roundtrip deserialization
	deserialized, err := DeserializeProofJSON(rawJSON)
	if err != nil {
		t.Fatalf("DeserializeProofJSON failed: %v", err)
	}
	if deserialized.TreeSize != proof.TreeSize || deserialized.LeafIndex != proof.LeafIndex {
		t.Errorf("Metadata mismatch after roundtrip")
	}
	if deserialized.LeafHash != proof.LeafHash || deserialized.RootHash != proof.RootHash {
		t.Errorf("Hashes mismatch after roundtrip")
	}
	if len(deserialized.AuditPath) != len(proof.AuditPath) {
		t.Errorf("AuditPath length mismatch after roundtrip")
	}

	// Cryptographic verification of deserialized object
	var lhBytes, rootBytes [32]byte
	lb, _ := hex.DecodeString(deserialized.LeafHash)
	rb, _ := hex.DecodeString(deserialized.RootHash)
	copy(lhBytes[:], lb)
	copy(rootBytes[:], rb)
	if !VerifyInclusionProof(lhBytes, rootBytes, deserialized.AuditPath) {
		t.Errorf("Deserialized proof failed cryptographic verification")
	}

	// 5. Malformed inputs to DeserializeProofJSON
	malformedInputs := [][]byte{
		[]byte(""),
		[]byte("{"),
		[]byte(`{"tree_size": "not-an-integer"}`),
		[]byte(`{"audit_path": "not-an-array"}`),
		[]byte(`{"tree_size": 100, `),
	}
	for _, m := range malformedInputs {
		if _, err := DeserializeProofJSON(m); err == nil {
			t.Errorf("Expected deserialization error for input: %s", string(m))
		}
	}

	// 6. Null / empty JSON object handling: Even if unmarshaled to zero struct, verification against tree root must fail
	nullProof, err := DeserializeProofJSON([]byte("null"))
	if err == nil {
		var zeroLeaf [32]byte
		if VerifyInclusionProof(zeroLeaf, rootBytes, nullProof.AuditPath) {
			t.Errorf("Zero/null proof should never pass cryptographic verification against real root")
		}
	}

	// 6. Tampered JSON text
	tamperedJSON := []byte(fmt.Sprintf(`{
  "tree_size": %d,
  "leaf_index": %d,
  "leaf_hash": "%s",
  "root_hash": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
  "audit_path": %s
}`, proof.TreeSize, proof.LeafIndex, proof.LeafHash, func() string {
		b, _ := json.Marshal(proof.AuditPath)
		return string(b)
	}()))

	tamperedObj, err := DeserializeProofJSON(tamperedJSON)
	if err != nil {
		t.Fatalf("Tampered JSON should still deserialize: %v", err)
	}
	var tamperedRoot [32]byte
	trb, _ := hex.DecodeString(tamperedObj.RootHash)
	copy(tamperedRoot[:], trb)
	if VerifyInclusionProof(lhBytes, tamperedRoot, tamperedObj.AuditPath) {
		t.Errorf("Tampered root hash in JSON was incorrectly accepted!")
	}
}

// ============================================================================
// ADVERSARIAL CHALLENGE 5: HIGH-CONTENTION CONCURRENCY & THREAD SAFETY
// ============================================================================

func TestAdversarial_Merkle_ConcurrencyContention(t *testing.T) {
	tree := NewMemoryMerkleTree()
	const numWriters = 30
	const appendsPerWriter = 40
	const totalAppends = numWriters * appendsPerWriter
	const numReaders = 10

	var wg sync.WaitGroup
	wg.Add(numWriters + numReaders)

	// Writers
	for w := 0; w < numWriters; w++ {
		go func(writerID int) {
			defer wg.Done()
			for i := 0; i < appendsPerWriter; i++ {
				data := []byte(fmt.Sprintf("concurrent-writer-%d-iter-%d", writerID, i))
				if _, _, _, err := tree.Append(data); err != nil {
					t.Errorf("Concurrent Append error: %v", err)
				}
			}
		}(w)
	}

	// Concurrent Readers
	for r := 0; r < numReaders; r++ {
		go func(readerID int) {
			defer wg.Done()
			for i := 0; i < 50; i++ {
				_ = tree.Size()
				_ = tree.Root()
				sz := tree.Size()
				if sz > 0 {
					_, _ = tree.LeafHashAt(sz - 1)
					_, _ = tree.InclusionProof(sz - 1)
				}
			}
		}(r)
	}

	wg.Wait()

	if tree.Size() != int64(totalAppends) {
		t.Fatalf("Expected final size %d, got %d", totalAppends, tree.Size())
	}

	// Verify all leaves and proofs after high contention
	root := tree.Root()
	for i := int64(0); i < int64(totalAppends); i++ {
		lh, err := tree.LeafHashAt(i)
		if err != nil {
			t.Fatalf("LeafHashAt(%d) failed: %v", i, err)
		}
		proof, err := tree.InclusionProof(i)
		if err != nil {
			t.Fatalf("InclusionProof(%d) failed: %v", i, err)
		}
		if !VerifyInclusionProof(lh, root, proof.AuditPath) {
			t.Fatalf("Inclusion proof failed for leaf %d after concurrent writes", i)
		}
	}
}

// ============================================================================
// ADVERSARIAL CHALLENGE 6: RFC 6962 SECOND PREIMAGE & DOMAIN SEPARATION ATTACK
// ============================================================================

func TestAdversarial_Merkle_DomainSeparationPrefixAttack(t *testing.T) {
	// RFC 6962 enforces domain separation prefixes:
	// Leaf hash = SHA256(0x00 || data)
	// Interior node hash = SHA256(0x01 || left || right)
	//
	// Attack scenario: Adversary crafts a leaf payload D whose content is exactly 64 bytes:
	// D = LeftHash || RightHash
	// If domain separation is absent, LeafHash(D) would equal NodeHash(LeftHash, RightHash),
	// allowing an interior node in a tree of height H to be substituted as a leaf in a tree of height H-1
	// (second preimage / leaf-node ambiguity attack).

	for trial := 0; trial < 100; trial++ {
		var left, right [32]byte
		_, _ = rand.Read(left[:])
		_, _ = rand.Read(right[:])

		craftedLeafPayload := append(left[:], right[:]...)

		leafHash := ComputeLeafHash(craftedLeafPayload)
		nodeHash := ComputeNodeHash(left, right)

		if leafHash == nodeHash {
			t.Fatalf("CRITICAL SECURITY FLAW: Domain separation prefix failed! LeafHash == NodeHash for payload %x", craftedLeafPayload)
		}
	}
}
