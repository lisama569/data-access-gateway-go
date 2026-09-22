// Package dataset provides the in-memory protected data and live subject
// directory used to simulate the protected data source.
package dataset

import (
	"sync"

	"github.com/lisama569/data-access-gateway-go/internal/model"
)

// Provider is an in-memory, concurrency-safe data and subject source.
type Provider struct {
	mu        sync.RWMutex
	resources map[string]model.Resource
	records   map[string]map[string]string
	subjects  map[string]model.Subject
}

// NewProvider returns an empty provider.
func NewProvider() *Provider {
	return &Provider{
		resources: make(map[string]model.Resource),
		records:   make(map[string]map[string]string),
		subjects:  make(map[string]model.Subject),
	}
}

// AddResource registers a resource and its field values. Values are copied.
func (p *Provider) AddResource(res model.Resource, values map[string]string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.resources[res.ID] = res
	cp := make(map[string]string, len(values))
	for k, v := range values {
		cp[k] = v
	}
	p.records[res.ID] = cp
}

// GetResource returns a copy of the resource descriptor.
func (p *Provider) GetResource(id string) (model.Resource, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	res, ok := p.resources[id]
	return res, ok
}

// GetRecord returns a defensive copy of the raw field values so callers can
// never mutate stored data or leak data across concurrent requests.
func (p *Provider) GetRecord(id string) (map[string]string, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	src, ok := p.records[id]
	if !ok {
		return nil, false
	}
	cp := make(map[string]string, len(src))
	for k, v := range src {
		cp[k] = v
	}
	return cp, true
}

// AddSubject registers a subject. Attribute slices are copied.
func (p *Provider) AddSubject(sub model.Subject) {
	p.mu.Lock()
	defer p.mu.Unlock()
	sub.Roles = append([]string(nil), sub.Roles...)
	sub.Departments = append([]string(nil), sub.Departments...)
	p.subjects[sub.ID] = sub
}

// GetSubject returns the current, live state of a subject so that a
// revocation takes effect on the very next request.
func (p *Provider) GetSubject(id string) (model.Subject, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	sub, ok := p.subjects[id]
	if !ok {
		return model.Subject{}, false
	}
	sub.Roles = append([]string(nil), sub.Roles...)
	sub.Departments = append([]string(nil), sub.Departments...)
	return sub, true
}

// Revoke marks a subject revoked immediately.
func (p *Provider) Revoke(id string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if sub, ok := p.subjects[id]; ok {
		sub.Revoked = true
		p.subjects[id] = sub
	}
}
