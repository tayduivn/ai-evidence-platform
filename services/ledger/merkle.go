package ledger

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sync"
)

var (
	ErrEmptyTree          = errors.New("merkle tree is empty")
	ErrIndexOutOfBounds   = errors.New("merkle leaf index out of bounds")
	ErrInvalidConsistency = errors.New("invalid sizes for consistency proof")
)

// MerkleTree defines the interface for an append-only RFC 6962 Merkle tree.
type MerkleTree interface {
	Append(leafData []byte) (leafIndex int64, leafHash [32]byte, newRoot [32]byte, err error)
	AppendBatch(batch [][]byte) (startIdx, endIdx int64, newRoot [32]byte, err error)
	Size() int64
	Root() [32]byte
	LeafHashAt(index int64) ([32]byte, error)
	InclusionProof(leafIndex int64) (*InclusionProof, error)
	ConsistencyProof(pastSize int64) (*ConsistencyProof, error)
}

// ComputeLeafHash computes RFC 6962 leaf hash: SHA256(0x00 || data).
func ComputeLeafHash(data []byte) [32]byte {
	h := sha256.New()
	h.Write([]byte{0x00})
	h.Write(data)
	var digest [32]byte
	copy(digest[:], h.Sum(nil))
	return digest
}

// ComputeNodeHash computes RFC 6962 interior node hash: SHA256(0x01 || left || right).
func ComputeNodeHash(left, right [32]byte) [32]byte {
	h := sha256.New()
	h.Write([]byte{0x01})
	h.Write(left[:])
	h.Write(right[:])
	var digest [32]byte
	copy(digest[:], h.Sum(nil))
	return digest
}

// LargestPowerOf2LessThan returns the largest power of 2 strictly less than n (for n > 1).
func LargestPowerOf2LessThan(n int64) int64 {
	if n <= 1 {
		return 0
	}
	k := int64(1)
	for k*2 < n {
		k *= 2
	}
	return k
}

// ComputeMTH computes the Merkle Tree Hash of a slice of leaf hashes according to RFC 6962 Section 2.1.
func ComputeMTH(leaves [][32]byte) [32]byte {
	n := int64(len(leaves))
	if n == 0 {
		return sha256.Sum256([]byte{})
	}
	if n == 1 {
		return leaves[0]
	}

	k := LargestPowerOf2LessThan(n)
	leftRoot := ComputeMTH(leaves[:k])
	rightRoot := ComputeMTH(leaves[k:])
	return ComputeNodeHash(leftRoot, rightRoot)
}

// MemoryMerkleTree provides a thread-safe in-memory RFC 6962 Merkle tree.
type MemoryMerkleTree struct {
	mu     sync.RWMutex
	leaves [][32]byte
}

// NewMemoryMerkleTree initializes an empty in-memory Merkle tree.
func NewMemoryMerkleTree() *MemoryMerkleTree {
	return &MemoryMerkleTree{
		leaves: make([][32]byte, 0, 1024),
	}
}

// Append computes the leaf hash and appends it to the tree.
func (t *MemoryMerkleTree) Append(leafData []byte) (int64, [32]byte, [32]byte, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	lh := ComputeLeafHash(leafData)
	idx := int64(len(t.leaves))
	t.leaves = append(t.leaves, lh)
	root := ComputeMTH(t.leaves)
	return idx, lh, root, nil
}

// AppendBatch atomically appends a batch of leaves and returns the updated state root.
func (t *MemoryMerkleTree) AppendBatch(batch [][]byte) (int64, int64, [32]byte, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if len(batch) == 0 {
		return 0, 0, ComputeMTH(t.leaves), nil
	}

	startIdx := int64(len(t.leaves))
	for _, data := range batch {
		t.leaves = append(t.leaves, ComputeLeafHash(data))
	}
	endIdx := int64(len(t.leaves) - 1)
	root := ComputeMTH(t.leaves)
	return startIdx, endIdx, root, nil
}

// Size returns the total count of committed leaves in the tree.
func (t *MemoryMerkleTree) Size() int64 {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return int64(len(t.leaves))
}

// Root returns the current RFC 6962 Merkle Tree Hash of all committed leaves.
func (t *MemoryMerkleTree) Root() [32]byte {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return ComputeMTH(t.leaves)
}

// LeafHashAt returns the leaf hash at a specific index.
func (t *MemoryMerkleTree) LeafHashAt(index int64) ([32]byte, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if index < 0 || index >= int64(len(t.leaves)) {
		return [32]byte{}, ErrIndexOutOfBounds
	}
	return t.leaves[index], nil
}

// InclusionProof generates an inclusion proof for the leaf at index.
func (t *MemoryMerkleTree) InclusionProof(leafIndex int64) (*InclusionProof, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	n := int64(len(t.leaves))
	if n == 0 {
		return nil, ErrEmptyTree
	}
	if leafIndex < 0 || leafIndex >= n {
		return nil, ErrIndexOutOfBounds
	}

	path := computeInclusionPath(leafIndex, t.leaves)
	leafHash := t.leaves[leafIndex]
	root := ComputeMTH(t.leaves)

	return &InclusionProof{
		TreeSize:  n,
		LeafIndex: leafIndex,
		LeafHash:  hex.EncodeToString(leafHash[:]),
		RootHash:  hex.EncodeToString(root[:]),
		AuditPath: path,
	}, nil
}

// computeInclusionPath recursively constructs the audit path from leaf to root.
func computeInclusionPath(m int64, leaves [][32]byte) []AuditStep {
	n := int64(len(leaves))
	if n <= 1 {
		return []AuditStep{}
	}

	k := LargestPowerOf2LessThan(n)
	if m < k {
		// Target leaf is in the left subtree
		path := computeInclusionPath(m, leaves[:k])
		rightRoot := ComputeMTH(leaves[k:])
		path = append(path, AuditStep{
			Direction: "right",
			Hash:      hex.EncodeToString(rightRoot[:]),
		})
		return path
	}

	// Target leaf is in the right subtree
	path := computeInclusionPath(m-k, leaves[k:])
	leftRoot := ComputeMTH(leaves[:k])
	path = append(path, AuditStep{
		Direction: "left",
		Hash:      hex.EncodeToString(leftRoot[:]),
	})
	return path
}

// ConsistencyProof generates an RFC 6962 / RFC 9162 consistency proof from pastSize to current size.
func (t *MemoryMerkleTree) ConsistencyProof(pastSize int64) (*ConsistencyProof, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	n := int64(len(t.leaves))
	if pastSize <= 0 || pastSize > n {
		return nil, ErrInvalidConsistency
	}

	firstRoot := ComputeMTH(t.leaves[:pastSize])
	secondRoot := ComputeMTH(t.leaves)

	if pastSize == n {
		return &ConsistencyProof{
			FirstSize:       pastSize,
			SecondSize:      n,
			FirstRoot:       hex.EncodeToString(firstRoot[:]),
			SecondRoot:      hex.EncodeToString(secondRoot[:]),
			ConsistencyPath: []string{},
		}, nil
	}

	rawProof := subProof(pastSize, t.leaves, true)
	pathHex := make([]string, len(rawProof))
	for i, h := range rawProof {
		pathHex[i] = hex.EncodeToString(h[:])
	}

	return &ConsistencyProof{
		FirstSize:       pastSize,
		SecondSize:      n,
		FirstRoot:       hex.EncodeToString(firstRoot[:]),
		SecondRoot:      hex.EncodeToString(secondRoot[:]),
		ConsistencyPath: pathHex,
	}, nil
}

// subProof implements RFC 6962 Section 2.1.2 consistency proof generation.
func subProof(m int64, leaves [][32]byte, b bool) [][32]byte {
	n := int64(len(leaves))
	if m == n {
		if b {
			return [][32]byte{}
		}
		return [][32]byte{ComputeMTH(leaves)}
	}

	k := LargestPowerOf2LessThan(n)
	if m <= k {
		res := subProof(m, leaves[:k], b)
		res = append(res, ComputeMTH(leaves[k:]))
		return res
	}

	res := subProof(m-k, leaves[k:], false)
	res = append(res, ComputeMTH(leaves[:k]))
	return res
}
