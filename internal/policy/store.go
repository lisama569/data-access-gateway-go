// Package policy stores immutable, versioned access policies and resolves
// the policy version applicable to a request.
package policy

import (
	"errors"
	"sync"
	"time"

	"github.com/lisama569/data-access-gateway-go/internal/model"
)

var (
	// ErrDuplicateVersion is returned when an already published (immutable)
	// version is published again.
	ErrDuplicateVersion = errors.New("policy: version already exists and is immutable")
	// ErrEmptyVersion is returned when a policy has no version label.
	ErrEmptyVersion = errors.New("policy: empty version")
	// ErrNoActivePolicy is returned when no policy version is active at a
	// given time. Callers can distinguish this from a valid deny.
	ErrNoActivePolicy = errors.New("policy: no active policy version at requested time")
)

// Store keeps every published policy version. Old versions are retained for
// historical replay; a version past its EffectiveUntil is "retired" rather
// than deleted. All methods are safe for concurrent use.
type Store struct {
	mu       sync.RWMutex
	versions map[string]*model.Policy
	order    []string
}

// NewStore returns an empty policy store.
func NewStore() *Store {
	return &Store{versions: make(map[string]*model.Policy)}
}

// Publish stores a new immutable policy version. The policy is copied so the
// caller cannot mutate it afterwards.
func (s *Store) Publish(p *model.Policy) error {
	if p == nil || p.Version == "" {
		return ErrEmptyVersion
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.versions[p.Version]; exists {
		return ErrDuplicateVersion
	}
	cp := *p
	cp.Rules = append([]model.Rule(nil), p.Rules...)
	s.versions[p.Version] = &cp
	s.order = append(s.order, p.Version)
	return nil
}

// Get returns the policy with the given version and whether it exists.
// Retired versions are still returned here so historical decisions can be
// replayed.
func (s *Store) Get(version string) (*model.Policy, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	p, ok := s.versions[version]
	if !ok {
		return nil, false
	}
	cp := *p
	return &cp, true
}

// Active returns the policy whose effective window contains t. When several
// overlap, the one with the latest EffectiveFrom wins (ties broken by the
// later publication order).
func (s *Store) Active(t time.Time) (*model.Policy, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var best *model.Policy
	bestIdx := -1
	for idx, v := range s.order {
		p := s.versions[v]
		if !p.EffectiveFrom.IsZero() && t.Before(p.EffectiveFrom) {
			continue
		}
		if !p.EffectiveUntil.IsZero() && !t.Before(p.EffectiveUntil) {
			continue // t >= EffectiveUntil: version has retired
		}
		if best == nil ||
			p.EffectiveFrom.After(best.EffectiveFrom) ||
			(p.EffectiveFrom.Equal(best.EffectiveFrom) && idx > bestIdx) {
			best = p
			bestIdx = idx
		}
	}
	if best == nil {
		return nil, ErrNoActivePolicy
	}
	cp := *best
	return &cp, nil
}
