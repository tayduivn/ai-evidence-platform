package ledger

import (
	"encoding/hex"
	"fmt"
	"testing"
)

func TestMerkle_EmptyTree(t *testing.T) {
	tree := NewMemoryMerkleTree()
	if tree.Size() != 0 {
		t.Fatalf("Expected size 0, got %d", tree.Size())
	}

	root := tree.Root()
	expectedEmptyHex := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	if hex.EncodeToString(root[:]) != expectedEmptyHex {
		t.Errorf("Empty root mismatch: got %s, expected %s", hex.EncodeToString(root[:]), expectedEmptyHex)
	}

	if _, err := tree.InclusionProof(0); err == nil {
		t.Errorf("Expected error requesting inclusion proof on empty tree")
	}
}

func TestMerkle_SingleLeaf(t *testing.T) {
	tree := NewMemoryMerkleTree()
	data := []byte("single-decision-event")
	idx, lh, root, err := tree.Append(data)
	if err != nil {
		t.Fatalf("Append failed: %v", err)
	}

	if idx != 0 {
		t.Errorf("Expected leaf index 0, got %d", idx)
	}
	if lh != root {
		t.Errorf("For single leaf tree, root must equal leaf hash")
	}

	proof, err := tree.InclusionProof(0)
	if err != nil {
		t.Fatalf("InclusionProof failed: %v", err)
	}
	if len(proof.AuditPath) != 0 {
		t.Errorf("Expected empty audit path for single leaf, got %d steps", len(proof.AuditPath))
	}

	if !VerifyInclusionProof(lh, root, proof.AuditPath) {
		t.Errorf("Verification of single leaf inclusion proof failed")
	}
}

func TestMerkle_RFC6962_ExactTestVectors(t *testing.T) {
	// Test vector leaves from Explorer M1.2
	expectedLeaves := []string{
		"f2d48bc2ac2677aec33221bb278f901a9d739014e9735be206402b2338f79c07", // Leaf 0
		"7a2c24c66076b20938231feb7856735b0a0a64bde2a9a69a3eb154ff2151cbb3", // Leaf 1
		"b80fd7a397c9e822b37680df02b36a62c9181a338ba143b6e0100f6936752aee", // Leaf 2
		"cc5c3a0197f40d589f66c32c3700da722a1b4736c8d36d6eda8ca939bc93194b", // Leaf 3
		"caccf0419a0f8ed2cf3d7291a37073ff3384bf87ceb188c7f7b936347263942d", // Leaf 4
		"124e766733a81f23f74eca970fd8fcb8f814e33efe2cfecee79da40706a74f34", // Leaf 5
		"9a8bfa43f2070682fdcc90651cc57411441a8310806571c1a6cec36a7fd1c6a5", // Leaf 6
		"18dd9957f234223d43aabc57f1265b216f772dad9ffd94501f0abfc461ffc25b", // Leaf 7
	}

	expectedRoots := map[int]string{
		1: "f2d48bc2ac2677aec33221bb278f901a9d739014e9735be206402b2338f79c07",
		2: "d24594d4f26c43e88f8014a0a37524aea816dfb912ccfbfbbc4d07ff54d70476",
		3: "c0f2b5f13a57f3c4089ccbd2b9aaa3e9f447829fdea2bcbe6fcdd4eb2890ef51",
		4: "c76f40b72cca646303a38c8aca89dc3d3eaf59cd6a03ad86b5051cb768b4d0ce",
		7: "6b48cea90349b4665a7d46b07e1300f12acde80ef604cb811e263ba7cb969145",
		8: "38806ce346e99bdd8ce5d48a3cdf817689059197fe99934a59930ccf23353dd9",
	}

	tree := NewMemoryMerkleTree()

	for i := 0; i < 8; i++ {
		raw := []byte(fmt.Sprintf("audit-event-%d", i))
		idx, lh, root, err := tree.Append(raw)
		if err != nil {
			t.Fatalf("Append failed at index %d: %v", i, err)
		}
		if idx != int64(i) {
			t.Errorf("Expected index %d, got %d", i, idx)
		}

		actualLeafHex := hex.EncodeToString(lh[:])
		if actualLeafHex != expectedLeaves[i] {
			t.Errorf("Leaf %d hash mismatch: got %s, expected %s", i, actualLeafHex, expectedLeaves[i])
		}

		size := i + 1
		if expectedRootHex, ok := expectedRoots[size]; ok {
			actualRootHex := hex.EncodeToString(root[:])
			if actualRootHex != expectedRootHex {
				t.Errorf("Tree size %d root mismatch: got %s, expected %s", size, actualRootHex, expectedRootHex)
			}
		}
	}
}

func TestMerkle_InclusionProofs_N4(t *testing.T) {
	tree := NewMemoryMerkleTree()
	for i := 0; i < 4; i++ {
		_, _, _, _ = tree.Append([]byte(fmt.Sprintf("audit-event-%d", i)))
	}

	root := tree.Root()

	for leafIdx := int64(0); leafIdx < 4; leafIdx++ {
		proof, err := tree.InclusionProof(leafIdx)
		if err != nil {
			t.Fatalf("InclusionProof failed for leaf %d: %v", leafIdx, err)
		}

		if proof.TreeSize != 4 {
			t.Errorf("Expected TreeSize=4, got %d", proof.TreeSize)
		}
		if proof.LeafIndex != leafIdx {
			t.Errorf("Expected LeafIndex=%d, got %d", leafIdx, proof.LeafIndex)
		}

		lh, _ := tree.LeafHashAt(leafIdx)
		if !VerifyInclusionProof(lh, root, proof.AuditPath) {
			t.Errorf("Inclusion proof verification failed for leaf %d", leafIdx)
		}
	}
}

func TestMerkle_TamperRejection(t *testing.T) {
	tree := NewMemoryMerkleTree()
	for i := 0; i < 4; i++ {
		_, _, _, _ = tree.Append([]byte(fmt.Sprintf("audit-event-%d", i)))
	}

	root := tree.Root()
	lh, _ := tree.LeafHashAt(0)
	proof, _ := tree.InclusionProof(0)

	// 1. Legitimate proof verifies
	if !VerifyInclusionProof(lh, root, proof.AuditPath) {
		t.Fatalf("Valid proof failed")
	}

	// 2. Tampered leaf hash rejected
	tamperedLeaf := lh
	tamperedLeaf[0] ^= 0xFF
	if VerifyInclusionProof(tamperedLeaf, root, proof.AuditPath) {
		t.Errorf("Tampered leaf was incorrectly accepted")
	}

	// 3. Tampered direction rejected
	tamperedPath := make([]AuditStep, len(proof.AuditPath))
	copy(tamperedPath, proof.AuditPath)
	tamperedPath[0].Direction = "left" // Should have been "right"
	if VerifyInclusionProof(lh, root, tamperedPath) {
		t.Errorf("Tampered direction was incorrectly accepted")
	}

	// 4. Tampered sibling hash rejected
	tamperedSiblingPath := make([]AuditStep, len(proof.AuditPath))
	copy(tamperedSiblingPath, proof.AuditPath)
	corruptBytes, _ := hex.DecodeString(tamperedSiblingPath[0].Hash)
	corruptBytes[0] ^= 0xFF
	tamperedSiblingPath[0].Hash = hex.EncodeToString(corruptBytes)
	if VerifyInclusionProof(lh, root, tamperedSiblingPath) {
		t.Errorf("Tampered sibling hash was incorrectly accepted")
	}

	// 5. Tampered root rejected
	wrongRoot := root
	wrongRoot[0] ^= 0xFF
	if VerifyInclusionProof(lh, wrongRoot, proof.AuditPath) {
		t.Errorf("Verification against tampered root incorrectly passed")
	}
}

func TestMerkle_ConsistencyProofs_RFC9162(t *testing.T) {
	tree := NewMemoryMerkleTree()
	roots := make([][32]byte, 9)

	for i := 1; i <= 8; i++ {
		_, _, _, _ = tree.Append([]byte(fmt.Sprintf("audit-event-%d", i-1)))
		roots[i] = tree.Root()
	}

	transitions := []struct {
		m, n int64
	}{
		{1, 2},
		{1, 3},
		{2, 3},
		{2, 4},
		{3, 4},
		{4, 8},
		{2, 7},
		{5, 8},
		{6, 8},
	}

	for _, tr := range transitions {
		proof, err := tree.ConsistencyProof(tr.m)
		if err != nil {
			t.Fatalf("ConsistencyProof(%d) failed: %v", tr.m, err)
		}

		firstRoot := roots[tr.m]
		secondRoot := roots[tree.Size()]

		if !VerifyConsistencyProof(tr.m, tree.Size(), firstRoot, secondRoot, proof.ConsistencyPath) {
			t.Errorf("Consistency proof verification failed for transition %d -> %d", tr.m, tree.Size())
		}
	}

	// Negative test: invalid past size
	if _, err := tree.ConsistencyProof(0); err == nil {
		t.Errorf("Expected error for pastSize <= 0")
	}
	if _, err := tree.ConsistencyProof(tree.Size() + 1); err == nil {
		t.Errorf("Expected error for pastSize > current size")
	}
}

func TestMerkle_JSON_Serialization(t *testing.T) {
	tree := NewMemoryMerkleTree()
	for i := 0; i < 4; i++ {
		_, _, _, _ = tree.Append([]byte(fmt.Sprintf("audit-event-%d", i)))
	}

	proof, err := tree.InclusionProof(2)
	if err != nil {
		t.Fatalf("InclusionProof failed: %v", err)
	}

	data, err := SerializeProofJSON(proof)
	if err != nil {
		t.Fatalf("SerializeProofJSON failed: %v", err)
	}

	parsed, err := DeserializeProofJSON(data)
	if err != nil {
		t.Fatalf("DeserializeProofJSON failed: %v", err)
	}

	if parsed.TreeSize != proof.TreeSize || parsed.LeafIndex != proof.LeafIndex {
		t.Errorf("Parsed proof metadata mismatch")
	}
	if parsed.LeafHash != proof.LeafHash || parsed.RootHash != proof.RootHash {
		t.Errorf("Parsed hashes mismatch")
	}
	if len(parsed.AuditPath) != len(proof.AuditPath) {
		t.Errorf("Parsed audit path length mismatch")
	}
}

func TestMerkle_BoundsAndAppendBatch(t *testing.T) {
	tree := NewMemoryMerkleTree()

	// Append empty batch
	start, end, _, err := tree.AppendBatch(nil)
	if err != nil || start != 0 || end != 0 {
		t.Errorf("Empty batch should return without error")
	}

	// Append non-empty batch
	batch := [][]byte{[]byte("leaf-a"), []byte("leaf-b")}
	start, end, _, err = tree.AppendBatch(batch)
	if err != nil || start != 0 || end != 1 {
		t.Errorf("Expected start 0, end 1, got start %d, end %d", start, end)
	}

	// LeafHashAt bounds
	if _, err := tree.LeafHashAt(-1); err == nil {
		t.Errorf("Expected error for negative index")
	}
	if _, err := tree.LeafHashAt(100); err == nil {
		t.Errorf("Expected error for out of range index")
	}

	// InclusionProof bounds
	if _, err := tree.InclusionProof(-1); err == nil {
		t.Errorf("Expected error for negative leaf index")
	}
	if _, err := tree.InclusionProof(100); err == nil {
		t.Errorf("Expected error for out of range leaf index")
	}

	// Invalid hex in VerifyInclusionProof
	invalidStep := []AuditStep{{Direction: "right", Hash: "not-hex"}}
	lh, _ := tree.LeafHashAt(0)
	if VerifyInclusionProof(lh, tree.Root(), invalidStep) {
		t.Errorf("Expected verification failure on invalid hex")
	}
}
