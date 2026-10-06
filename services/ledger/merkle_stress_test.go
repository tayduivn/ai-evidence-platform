package ledger

import (
	"encoding/hex"
	"fmt"
	"sync"
	"testing"
)

// ==============================================================================
// 1. EDGE CASES: 0 LEAVES, 1 LEAF, UNBALANCED TREES, 1000 LEAVES
// ==============================================================================

// TestMerkleStress_EdgeCase_0Leaves tests all behaviors on an empty tree.
func TestMerkleStress_EdgeCase_0Leaves(t *testing.T) {
	tree := NewMemoryMerkleTree()

	if tree.Size() != 0 {
		t.Fatalf("Expected size 0, got %d", tree.Size())
	}

	// RFC 6962: MTH({}) = SHA-256()
	emptyRoot := tree.Root()
	expectedEmptyHex := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	if hex.EncodeToString(emptyRoot[:]) != expectedEmptyHex {
		t.Fatalf("Empty tree root mismatch: got %s, expected %s", hex.EncodeToString(emptyRoot[:]), expectedEmptyHex)
	}

	// InclusionProof on empty tree
	if _, err := tree.InclusionProof(0); err != ErrEmptyTree {
		t.Errorf("Expected ErrEmptyTree, got %v", err)
	}
	if _, err := tree.InclusionProof(-1); err != ErrEmptyTree {
		t.Errorf("Expected ErrEmptyTree for negative index on empty tree, got %v", err)
	}
	if _, err := tree.InclusionProof(10); err != ErrEmptyTree {
		t.Errorf("Expected ErrEmptyTree for index 10 on empty tree, got %v", err)
	}

	// LeafHashAt on empty tree
	if _, err := tree.LeafHashAt(0); err != ErrIndexOutOfBounds {
		t.Errorf("Expected ErrIndexOutOfBounds, got %v", err)
	}

	// ConsistencyProof on empty tree
	if _, err := tree.ConsistencyProof(0); err != ErrInvalidConsistency {
		t.Errorf("Expected ErrInvalidConsistency for pastSize=0, got %v", err)
	}
	if _, err := tree.ConsistencyProof(1); err != ErrInvalidConsistency {
		t.Errorf("Expected ErrInvalidConsistency for pastSize=1 on empty tree, got %v", err)
	}

	// AppendBatch with empty batch does not corrupt empty tree
	start, end, rootAfter, err := tree.AppendBatch(nil)
	if err != nil {
		t.Errorf("AppendBatch(nil) returned error: %v", err)
	}
	if start != 0 || end != 0 || rootAfter != emptyRoot {
		t.Errorf("AppendBatch(nil) unexpected return: start=%d, end=%d", start, end)
	}
	if tree.Size() != 0 {
		t.Errorf("Tree size mutated after AppendBatch(nil): %d", tree.Size())
	}

	// VerifyInclusionProof with empty leaf and empty path against empty root must fail
	var zeroLeaf [32]byte
	if VerifyInclusionProof(zeroLeaf, emptyRoot, []AuditStep{}) {
		t.Errorf("VerifyInclusionProof with zeroLeaf should fail against empty root")
	}
}

// TestMerkleStress_EdgeCase_1Leaf tests all behaviors on a 1-leaf tree.
func TestMerkleStress_EdgeCase_1Leaf(t *testing.T) {
	tree := NewMemoryMerkleTree()
	raw := []byte("event-single-leaf-payload")
	idx, lh, root, err := tree.Append(raw)
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
	expectedLeafHash := ComputeLeafHash(raw)
	if lh != expectedLeafHash {
		t.Fatalf("Leaf hash mismatch: got %x, expected %x", lh, expectedLeafHash)
	}
	if root != expectedLeafHash {
		t.Fatalf("Root for 1-leaf tree must equal leaf hash: got %x, expected %x", root, expectedLeafHash)
	}

	// InclusionProof for index 0
	proof, err := tree.InclusionProof(0)
	if err != nil {
		t.Fatalf("InclusionProof(0) failed: %v", err)
	}
	if proof.TreeSize != 1 || proof.LeafIndex != 0 {
		t.Errorf("Proof metadata wrong: TreeSize=%d, LeafIndex=%d", proof.TreeSize, proof.LeafIndex)
	}
	if len(proof.AuditPath) != 0 {
		t.Errorf("AuditPath for 1-leaf tree must be empty, got length %d", len(proof.AuditPath))
	}

	// Valid verification
	if !VerifyInclusionProof(lh, root, proof.AuditPath) {
		t.Errorf("Valid 1-leaf inclusion proof failed verification")
	}

	// Tampering tests on 1-leaf proof
	tamperedLeaf := lh
	tamperedLeaf[0] ^= 0x01
	if VerifyInclusionProof(tamperedLeaf, root, proof.AuditPath) {
		t.Errorf("VerifyInclusionProof accepted tampered leaf on 1-leaf tree")
	}

	tamperedRoot := root
	tamperedRoot[31] ^= 0xFF
	if VerifyInclusionProof(lh, tamperedRoot, proof.AuditPath) {
		t.Errorf("VerifyInclusionProof accepted tampered root on 1-leaf tree")
	}

	// Bogus extra audit step must fail
	bogusStep := []AuditStep{{Direction: "right", Hash: hex.EncodeToString(lh[:])}}
	if VerifyInclusionProof(lh, root, bogusStep) {
		t.Errorf("VerifyInclusionProof accepted bogus step on 1-leaf tree")
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

	// Invalid past sizes
	if _, err := tree.ConsistencyProof(0); err != ErrInvalidConsistency {
		t.Errorf("Expected ErrInvalidConsistency for pastSize=0")
	}
	if _, err := tree.ConsistencyProof(2); err != ErrInvalidConsistency {
		t.Errorf("Expected ErrInvalidConsistency for pastSize=2 on 1-leaf tree")
	}
}

// TestMerkleStress_EdgeCase_UnbalancedTrees verifies trees of arbitrary non-power-of-2 sizes.
func TestMerkleStress_EdgeCase_UnbalancedTrees(t *testing.T) {
	unbalancedSizes := []int{3, 5, 6, 7, 9, 10, 11, 13, 15, 17, 23, 31, 33, 63, 65, 127, 129}

	for _, size := range unbalancedSizes {
		t.Run(fmt.Sprintf("Size_%d", size), func(t *testing.T) {
			tree := NewMemoryMerkleTree()
			leafHashes := make([][32]byte, size)

			for i := 0; i < size; i++ {
				data := []byte(fmt.Sprintf("unbalanced-tree-%d-leaf-%d", size, i))
				idx, lh, _, err := tree.Append(data)
				if err != nil {
					t.Fatalf("Append failed at %d: %v", i, err)
				}
				if idx != int64(i) {
					t.Fatalf("Expected index %d, got %d", i, idx)
				}
				leafHashes[i] = lh
			}

			if tree.Size() != int64(size) {
				t.Fatalf("Expected size %d, got %d", size, tree.Size())
			}

			root := tree.Root()
			expectedRoot := ComputeMTH(leafHashes)
			if root != expectedRoot {
				t.Fatalf("Tree size %d root mismatch with ComputeMTH", size)
			}

			// Verify inclusion proof for EVERY leaf in the unbalanced tree
			for i := 0; i < size; i++ {
				proof, err := tree.InclusionProof(int64(i))
				if err != nil {
					t.Fatalf("InclusionProof(%d) failed for size %d: %v", i, size, err)
				}

				if proof.TreeSize != int64(size) || proof.LeafIndex != int64(i) {
					t.Errorf("Proof metadata mismatch: size=%d, idx=%d", proof.TreeSize, proof.LeafIndex)
				}

				// Must verify against valid leaf and root
				if !VerifyInclusionProof(leafHashes[i], root, proof.AuditPath) {
					t.Fatalf("Verification failed for leaf %d in tree size %d", i, size)
				}

				// Adversarial check: tamper leaf hash
				tamperedLeaf := leafHashes[i]
				tamperedLeaf[0] ^= 0x42
				if VerifyInclusionProof(tamperedLeaf, root, proof.AuditPath) {
					t.Fatalf("Tampered leaf accepted at index %d in tree size %d", i, size)
				}

				// Adversarial check: tamper root hash
				tamperedRoot := root
				tamperedRoot[31] ^= 0x42
				if VerifyInclusionProof(leafHashes[i], tamperedRoot, proof.AuditPath) {
					t.Fatalf("Tampered root accepted at index %d in tree size %d", i, size)
				}
			}
		})
	}
}

// TestMerkleStress_Scale_1000Leaves tests scalability, inclusion proofs, and batching on 1000 leaves.
func TestMerkleStress_Scale_1000Leaves(t *testing.T) {
	const totalLeaves = 1000

	tree := NewMemoryMerkleTree()
	leafHashes := make([][32]byte, totalLeaves)
	rawLeaves := make([][]byte, totalLeaves)

	for i := 0; i < totalLeaves; i++ {
		data := []byte(fmt.Sprintf("audit-transaction-payload-%06d-data-uuid", i))
		rawLeaves[i] = data
		idx, lh, _, err := tree.Append(data)
		if err != nil {
			t.Fatalf("Append failed at %d: %v", i, err)
		}
		if idx != int64(i) {
			t.Fatalf("Expected index %d, got %d", i, idx)
		}
		leafHashes[i] = lh
	}

	if tree.Size() != totalLeaves {
		t.Fatalf("Expected tree size %d, got %d", totalLeaves, tree.Size())
	}

	root := tree.Root()

	// 1. Verify Batch Append parity: AppendBatch with all 1000 leaves must yield the exact same root
	batchTree := NewMemoryMerkleTree()
	startIdx, endIdx, batchRoot, err := batchTree.AppendBatch(rawLeaves)
	if err != nil {
		t.Fatalf("AppendBatch failed: %v", err)
	}
	if startIdx != 0 || endIdx != totalLeaves-1 {
		t.Errorf("AppendBatch indices wrong: start=%d, end=%d", startIdx, endIdx)
	}
	if batchRoot != root {
		t.Fatalf("AppendBatch root does not match incremental append root: %x vs %x", batchRoot, root)
	}

	// 2. Test Inclusion Proofs for ALL 1000 leaves
	maxExpectedPathLen := 11 // ceil(log2(1000)) = 10, bounded by 11
	for i := 0; i < totalLeaves; i++ {
		proof, err := tree.InclusionProof(int64(i))
		if err != nil {
			t.Fatalf("InclusionProof failed for leaf %d: %v", i, err)
		}

		if len(proof.AuditPath) > maxExpectedPathLen {
			t.Errorf("Audit path for leaf %d too long: %d > %d", i, len(proof.AuditPath), maxExpectedPathLen)
		}

		if !VerifyInclusionProof(leafHashes[i], root, proof.AuditPath) {
			t.Fatalf("Inclusion proof verification failed for leaf %d of 1000", i)
		}

		// Tampering test on sample of leaves (every 100th leaf)
		if i%100 == 0 {
			tampered := leafHashes[i]
			tampered[0] ^= 0x01
			if VerifyInclusionProof(tampered, root, proof.AuditPath) {
				t.Fatalf("Tampered leaf %d accepted!", i)
			}
		}
	}
}

// ==============================================================================
// 2. INCLUSION PROOF TAMPERING DETECTION (ADVERSARIAL HARNESS)
// ==============================================================================

// TestMerkleStress_InclusionTampering_Comprehensive runs exhaustive attacks against inclusion proofs.
func TestMerkleStress_InclusionTampering_Comprehensive(t *testing.T) {
	tree := NewMemoryMerkleTree()
	const n = 16
	for i := 0; i < n; i++ {
		_, _, _, _ = tree.Append([]byte(fmt.Sprintf("tamper-test-event-%d", i)))
	}

	root := tree.Root()

	// Attack target leaf: leaf 7 (right subtree of left child)
	targetIdx := int64(7)
	lh, err := tree.LeafHashAt(targetIdx)
	if err != nil {
		t.Fatalf("LeafHashAt failed: %v", err)
	}

	proof, err := tree.InclusionProof(targetIdx)
	if err != nil {
		t.Fatalf("InclusionProof failed: %v", err)
	}

	// Baseline sanity check
	if !VerifyInclusionProof(lh, root, proof.AuditPath) {
		t.Fatalf("Baseline valid proof failed verification")
	}

	// Attack Vector 1: Bit flip at all byte positions of leaf hash
	for bytePos := 0; bytePos < 32; bytePos++ {
		mutatedLeaf := lh
		mutatedLeaf[bytePos] ^= 0x80
		if VerifyInclusionProof(mutatedLeaf, root, proof.AuditPath) {
			t.Fatalf("Attack Vector 1 failed: Bit flip at byte %d in leaf hash was accepted", bytePos)
		}
	}

	// Attack Vector 2: Bit flip at all byte positions of root hash
	for bytePos := 0; bytePos < 32; bytePos++ {
		mutatedRoot := root
		mutatedRoot[bytePos] ^= 0x80
		if VerifyInclusionProof(lh, mutatedRoot, proof.AuditPath) {
			t.Fatalf("Attack Vector 2 failed: Bit flip at byte %d in root hash was accepted", bytePos)
		}
	}

	// Attack Vector 3: Tamper direction of every step
	for stepIdx := range proof.AuditPath {
		tamperedSteps := make([]AuditStep, len(proof.AuditPath))
		copy(tamperedSteps, proof.AuditPath)

		// Invert direction
		if tamperedSteps[stepIdx].Direction == "left" {
			tamperedSteps[stepIdx].Direction = "right"
		} else {
			tamperedSteps[stepIdx].Direction = "left"
		}

		if VerifyInclusionProof(lh, root, tamperedSteps) {
			t.Fatalf("Attack Vector 3 failed: Inverted direction at step %d was accepted", stepIdx)
		}
	}

	// Attack Vector 4: Corrupt sibling hash in each step
	for stepIdx := range proof.AuditPath {
		tamperedSteps := make([]AuditStep, len(proof.AuditPath))
		copy(tamperedSteps, proof.AuditPath)

		raw, _ := hex.DecodeString(tamperedSteps[stepIdx].Hash)
		raw[0] ^= 0xFF
		tamperedSteps[stepIdx].Hash = hex.EncodeToString(raw)

		if VerifyInclusionProof(lh, root, tamperedSteps) {
			t.Fatalf("Attack Vector 4 failed: Corrupted sibling hash at step %d was accepted", stepIdx)
		}
	}

	// Attack Vector 5: Invalid direction strings
	invalidDirections := []string{"", " ", "up", "down", "LEFT", "RIGHT", "center", "Left", "Right", "1", "0"}
	for _, invDir := range invalidDirections {
		tamperedSteps := make([]AuditStep, len(proof.AuditPath))
		copy(tamperedSteps, proof.AuditPath)
		tamperedSteps[0].Direction = invDir

		if VerifyInclusionProof(lh, root, tamperedSteps) {
			t.Fatalf("Attack Vector 5 failed: Invalid direction '%s' was accepted", invDir)
		}
	}

	// Attack Vector 6: Malformed hex strings in audit path
	malformedHexStrings := []string{
		"xyz",                                                              // non-hex characters
		"abcdef",                                                           // valid hex but only 3 bytes
		"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde", // 63 hex chars (odd length)
		"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef00", // 33 bytes (66 hex chars)
		"",                                                                 // empty string
	}
	for _, malHex := range malformedHexStrings {
		tamperedSteps := make([]AuditStep, len(proof.AuditPath))
		copy(tamperedSteps, proof.AuditPath)
		tamperedSteps[0].Hash = malHex

		if VerifyInclusionProof(lh, root, tamperedSteps) {
			t.Fatalf("Attack Vector 6 failed: Malformed hex '%s' was accepted", malHex)
		}
	}

	// Attack Vector 7: Truncation attacks (omitting steps)
	// Remove first step
	if VerifyInclusionProof(lh, root, proof.AuditPath[1:]) {
		t.Fatalf("Attack Vector 7a failed: Truncated audit path (missing step 0) was accepted")
	}
	// Remove last step
	if VerifyInclusionProof(lh, root, proof.AuditPath[:len(proof.AuditPath)-1]) {
		t.Fatalf("Attack Vector 7b failed: Truncated audit path (missing last step) was accepted")
	}

	// Attack Vector 8: Extension attacks (injecting spurious steps)
	spuriousStep := AuditStep{
		Direction: "right",
		Hash:      hex.EncodeToString(lh[:]),
	}
	extendedPathPre := append([]AuditStep{spuriousStep}, proof.AuditPath...)
	if VerifyInclusionProof(lh, root, extendedPathPre) {
		t.Fatalf("Attack Vector 8a failed: Extended audit path (prepended step) was accepted")
	}
	extendedPathPost := append(proof.AuditPath, spuriousStep)
	if VerifyInclusionProof(lh, root, extendedPathPost) {
		t.Fatalf("Attack Vector 8b failed: Extended audit path (appended step) was accepted")
	}

	// Attack Vector 9: Step reordering
	if len(proof.AuditPath) >= 2 {
		reordered := make([]AuditStep, len(proof.AuditPath))
		copy(reordered, proof.AuditPath)
		reordered[0], reordered[1] = reordered[1], reordered[0]
		if VerifyInclusionProof(lh, root, reordered) {
			t.Fatalf("Attack Vector 9 failed: Reordered audit steps were accepted")
		}
	}

	// Attack Vector 10: Cross-leaf proof replay
	otherLeafIdx := int64(3)
	otherProof, _ := tree.InclusionProof(otherLeafIdx)
	if VerifyInclusionProof(lh, root, otherProof.AuditPath) {
		t.Fatalf("Attack Vector 10 failed: Cross-leaf proof replay was accepted")
	}
}

// ==============================================================================
// 3. DYNAMIC CONSISTENCY PROOFS ACROSS DIVERSE TRANSITIONS
// ==============================================================================

// TestMerkleStress_Consistency_Matrix tests consistency proofs across all (m, n) for 1 <= m <= n <= 32.
func TestMerkleStress_Consistency_Matrix(t *testing.T) {
	const maxSize = 32
	tree := NewMemoryMerkleTree()
	roots := make([][32]byte, maxSize+1)

	for i := 1; i <= maxSize; i++ {
		_, _, _, _ = tree.Append([]byte(fmt.Sprintf("consistency-event-%d", i)))
		roots[i] = tree.Root()
	}

	// Test all pairs (m, n) where 1 <= m <= n <= maxSize
	for n := int64(1); n <= maxSize; n++ {
		// Construct tree up to size n
		subTree := NewMemoryMerkleTree()
		for i := int64(1); i <= n; i++ {
			_, _, _, _ = subTree.Append([]byte(fmt.Sprintf("consistency-event-%d", i)))
		}

		for m := int64(1); m <= n; m++ {
			proof, err := subTree.ConsistencyProof(m)
			if err != nil {
				t.Fatalf("ConsistencyProof(%d) on tree size %d failed: %v", m, n, err)
			}

			if proof.FirstSize != m || proof.SecondSize != n {
				t.Errorf("Metadata mismatch for (%d, %d): first=%d, second=%d", m, n, proof.FirstSize, proof.SecondSize)
			}

			firstRoot := roots[m]
			secondRoot := roots[n]

			// Verify consistency proof
			if !VerifyConsistencyProof(m, n, firstRoot, secondRoot, proof.ConsistencyPath) {
				t.Fatalf("VerifyConsistencyProof failed for transition %d -> %d", m, n)
			}
		}
	}
}

// TestMerkleStress_Consistency_LargeTransitions tests consistency proofs on larger trees up to 1000 leaves.
func TestMerkleStress_Consistency_LargeTransitions(t *testing.T) {
	const total = 1000
	tree := NewMemoryMerkleTree()
	snapshotRoots := make(map[int64][32]byte)

	checkpoints := []int64{1, 2, 3, 4, 7, 8, 15, 16, 31, 32, 63, 64, 100, 128, 255, 256, 500, 512, 750, 999, 1000}

	for i := int64(1); i <= total; i++ {
		_, _, root, err := tree.Append([]byte(fmt.Sprintf("large-consistency-node-%d", i)))
		if err != nil {
			t.Fatalf("Append failed at %d: %v", i, err)
		}
		snapshotRoots[i] = root
	}

	// Test transitions between all pairs of checkpoints where m <= n
	for i := 0; i < len(checkpoints); i++ {
		m := checkpoints[i]
		for j := i; j < len(checkpoints); j++ {
			n := checkpoints[j]

			// Build tree of size n to generate proof
			// (or generate directly if tree size == total and we test past size m)
			var proof *ConsistencyProof
			var err error
			if n == total {
				proof, err = tree.ConsistencyProof(m)
			} else {
				// Create sub-tree of size n
				tempTree := NewMemoryMerkleTree()
				for k := int64(1); k <= n; k++ {
					_, _, _, _ = tempTree.Append([]byte(fmt.Sprintf("large-consistency-node-%d", k)))
				}
				proof, err = tempTree.ConsistencyProof(m)
			}

			if err != nil {
				t.Fatalf("ConsistencyProof(%d -> %d) failed: %v", m, n, err)
			}

			firstRoot := snapshotRoots[m]
			secondRoot := snapshotRoots[n]

			if !VerifyConsistencyProof(m, n, firstRoot, secondRoot, proof.ConsistencyPath) {
				t.Fatalf("Large consistency proof failed for %d -> %d", m, n)
			}
		}
	}
}

// TestMerkleStress_Consistency_TamperingAdversarial tests adversary attacks against consistency proofs.
func TestMerkleStress_Consistency_TamperingAdversarial(t *testing.T) {
	tree := NewMemoryMerkleTree()
	roots := make([][32]byte, 17)

	for i := 1; i <= 16; i++ {
		_, _, _, _ = tree.Append([]byte(fmt.Sprintf("consistency-tamper-%d", i)))
		roots[i] = tree.Root()
	}

	m := int64(6)
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

	// Adversarial Attack 1: Tamper first root
	tamperedFirstRoot := firstRoot
	tamperedFirstRoot[0] ^= 0xFF
	if VerifyConsistencyProof(m, n, tamperedFirstRoot, secondRoot, proof.ConsistencyPath) {
		t.Errorf("Accepted consistency proof with tampered firstRoot")
	}

	// Adversarial Attack 2: Tamper second root
	tamperedSecondRoot := secondRoot
	tamperedSecondRoot[31] ^= 0xFF
	if VerifyConsistencyProof(m, n, firstRoot, tamperedSecondRoot, proof.ConsistencyPath) {
		t.Errorf("Accepted consistency proof with tampered secondRoot")
	}

	// Adversarial Attack 3: Tamper each step in consistency path
	for idx := range proof.ConsistencyPath {
		tamperedPath := make([]string, len(proof.ConsistencyPath))
		copy(tamperedPath, proof.ConsistencyPath)

		raw, _ := hex.DecodeString(tamperedPath[idx])
		raw[0] ^= 0xEE
		tamperedPath[idx] = hex.EncodeToString(raw)

		if VerifyConsistencyProof(m, n, firstRoot, secondRoot, tamperedPath) {
			t.Errorf("Accepted consistency proof with tampered path at step %d", idx)
		}
	}

	// Adversarial Attack 4: Truncate path
	if len(proof.ConsistencyPath) > 0 {
		if VerifyConsistencyProof(m, n, firstRoot, secondRoot, proof.ConsistencyPath[:len(proof.ConsistencyPath)-1]) {
			t.Errorf("Accepted truncated consistency path")
		}
	}

	// Adversarial Attack 5: Extra spurious hash appended to path
	extraPath := append(proof.ConsistencyPath, hex.EncodeToString(firstRoot[:]))
	if VerifyConsistencyProof(m, n, firstRoot, secondRoot, extraPath) {
		t.Errorf("Accepted consistency path with extra spurious hash")
	}

	// Adversarial Attack 6: Invalid hex in consistency path
	if len(proof.ConsistencyPath) > 0 {
		badHexPath := make([]string, len(proof.ConsistencyPath))
		copy(badHexPath, proof.ConsistencyPath)
		badHexPath[0] = "invalid-hex-string-here"
		if VerifyConsistencyProof(m, n, firstRoot, secondRoot, badHexPath) {
			t.Errorf("Accepted consistency path with invalid hex")
		}
	}

	// Adversarial Attack 7: Wrong hash length in consistency path (not 32 bytes)
	if len(proof.ConsistencyPath) > 0 {
		shortHexPath := make([]string, len(proof.ConsistencyPath))
		copy(shortHexPath, proof.ConsistencyPath)
		shortHexPath[0] = "aabbcc"
		if VerifyConsistencyProof(m, n, firstRoot, secondRoot, shortHexPath) {
			t.Errorf("Accepted consistency path with 3-byte hash")
		}
	}

	// Adversarial Attack 8: Illegal boundary conditions
	if VerifyConsistencyProof(0, n, firstRoot, secondRoot, proof.ConsistencyPath) {
		t.Errorf("Accepted firstSize = 0")
	}
	if VerifyConsistencyProof(-1, n, firstRoot, secondRoot, proof.ConsistencyPath) {
		t.Errorf("Accepted firstSize = -1")
	}
	if VerifyConsistencyProof(n+1, n, firstRoot, secondRoot, proof.ConsistencyPath) {
		t.Errorf("Accepted firstSize > secondSize")
	}
	if VerifyConsistencyProof(m, n, firstRoot, secondRoot, []string{}) {
		t.Errorf("Accepted empty proof for m < n")
	}
}

// ==============================================================================
// 4. MERKLE_PROOF.JSON SERIALIZATION & PROTOCOL CONFORMANCE
// ==============================================================================

// TestMerkleStress_JSON_SerializationConformance verifies strict compliance with PROJECT.md Evidence Pack spec.
func TestMerkleStress_JSON_SerializationConformance(t *testing.T) {
	tree := NewMemoryMerkleTree()
	for i := 0; i < 7; i++ {
		_, _, _, _ = tree.Append([]byte(fmt.Sprintf("conformance-event-%d", i)))
	}

	proof, err := tree.InclusionProof(3)
	if err != nil {
		t.Fatalf("InclusionProof failed: %v", err)
	}

	// Test 1: Serialize nil proof
	if _, err := SerializeProofJSON(nil); err == nil {
		t.Errorf("Expected error serializing nil proof")
	}

	// Test 2: Standard serialization
	data, err := SerializeProofJSON(proof)
	if err != nil {
		t.Fatalf("SerializeProofJSON failed: %v", err)
	}

	// Test 3: Roundtrip deserialization
	deserialized, err := DeserializeProofJSON(data)
	if err != nil {
		t.Fatalf("DeserializeProofJSON failed: %v", err)
	}

	if deserialized.TreeSize != proof.TreeSize {
		t.Errorf("TreeSize mismatch: %d vs %d", deserialized.TreeSize, proof.TreeSize)
	}
	if deserialized.LeafIndex != proof.LeafIndex {
		t.Errorf("LeafIndex mismatch: %d vs %d", deserialized.LeafIndex, proof.LeafIndex)
	}
	if deserialized.LeafHash != proof.LeafHash {
		t.Errorf("LeafHash mismatch: %s vs %s", deserialized.LeafHash, proof.LeafHash)
	}
	if deserialized.RootHash != proof.RootHash {
		t.Errorf("RootHash mismatch: %s vs %s", deserialized.RootHash, proof.RootHash)
	}
	if len(deserialized.AuditPath) != len(proof.AuditPath) {
		t.Fatalf("AuditPath length mismatch: %d vs %d", len(deserialized.AuditPath), len(proof.AuditPath))
	}
	for i := range proof.AuditPath {
		if deserialized.AuditPath[i].Direction != proof.AuditPath[i].Direction {
			t.Errorf("AuditPath[%d] Direction mismatch", i)
		}
		if deserialized.AuditPath[i].Hash != proof.AuditPath[i].Hash {
			t.Errorf("AuditPath[%d] Hash mismatch", i)
		}
	}

	// Test 4: Deserialization with malformed inputs
	malformedInputs := [][]byte{
		[]byte(""),
		[]byte("not a json"),
		[]byte(`{"tree_size": "not-a-number"}`),
		[]byte(`{"audit_path": [{"direction": 123}]}`),
		[]byte(`{"tree_size": 100, `), // truncated JSON
	}
	for _, mal := range malformedInputs {
		if _, err := DeserializeProofJSON(mal); err == nil {
			t.Errorf("Expected error deserializing malformed input: %s", string(mal))
		}
	}

	// Test 5: Verify deserialized proof still verifies cryptographically
	var lhBytes, rootBytes [32]byte
	lb, _ := hex.DecodeString(deserialized.LeafHash)
	rb, _ := hex.DecodeString(deserialized.RootHash)
	copy(lhBytes[:], lb)
	copy(rootBytes[:], rb)

	if !VerifyInclusionProof(lhBytes, rootBytes, deserialized.AuditPath) {
		t.Errorf("Deserialized proof failed cryptographic verification")
	}
}

// ==============================================================================
// 5. CONCURRENCY & THREAD SAFETY STRESS TEST
// ==============================================================================

// TestMerkleStress_Concurrency_ThreadSafety verifies that MemoryMerkleTree is thread-safe under concurrent appends and reads.
func TestMerkleStress_Concurrency_ThreadSafety(t *testing.T) {
	tree := NewMemoryMerkleTree()
	const numGoroutines = 20
	const appendsPerGoroutine = 50
	const totalAppends = numGoroutines * appendsPerGoroutine

	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	for g := 0; g < numGoroutines; g++ {
		go func(goroutineID int) {
			defer wg.Done()
			for i := 0; i < appendsPerGoroutine; i++ {
				data := []byte(fmt.Sprintf("concurrent-payload-g%d-i%d", goroutineID, i))
				_, _, _, err := tree.Append(data)
				if err != nil {
					t.Errorf("Concurrent Append failed: %v", err)
				}
				// Concurrent read of Size and Root
				_ = tree.Size()
				_ = tree.Root()
			}
		}(g)
	}

	wg.Wait()

	if tree.Size() != int64(totalAppends) {
		t.Fatalf("Expected total size %d, got %d", totalAppends, tree.Size())
	}

	// Verify all leaves have valid inclusion proofs
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
			t.Fatalf("Inclusion proof failed for leaf %d after concurrent appends", i)
		}
	}
}
