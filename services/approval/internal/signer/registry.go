package signer

import (
	"sync"
)

// Registry manages registered polymorphic Signers in a thread-safe manner.
type Registry struct {
	mu      sync.RWMutex
	signers map[string]Signer
}

// NewRegistry constructs a new empty Signer Registry.
func NewRegistry() *Registry {
	return &Registry{
		signers: make(map[string]Signer),
	}
}

// Register registers a Signer implementation under its Type().
func (r *Registry) Register(s Signer) {
	if s == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.signers[s.Type()] = s
}

// Get retrieves a Signer by identifier.
func (r *Registry) Get(signerType string) (Signer, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	s, exists := r.signers[signerType]
	if !exists {
		return nil, ErrSignerNotFound
	}
	return s, nil
}

// List returns all registered signer types.
func (r *Registry) List() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	types := make([]string, 0, len(r.signers))
	for k := range r.signers {
		types = append(types, k)
	}
	return types
}
