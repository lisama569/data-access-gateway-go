// Package audit records an immutable trail of access evaluations. Audit
// entries capture the decision, its basis, the hit policy version and any
// produced tokens, but never the original protected field values.
package audit

import (
	"fmt"

	"sync"
	"sync/atomic"
	"time"

	"github.com/lisama569/data-access-gateway-go/internal/model"
)

// Entry is one immutable audit record. Value-bearing slices/maps are copied
// on append and on read so the trail cannot be mutated after the fact.
type Entry struct {
	ID           string
	Time         time.Time
	SubjectID    string
	SubjectRoles []string
	ResourceID   string
	Purpose      string
	Evaluation   model.Evaluation
	MaskedFields []string
	// TokenOutputs stores produced tokens keyed by field. Tokens are stored,
	// never the original plaintext values.
	TokenOutputs map[string]string
}

func (e Entry) clone() Entry {
	cp := e
	cp.SubjectRoles = append([]string(nil), e.SubjectRoles...)
	cp.MaskedFields = append([]string(nil), e.MaskedFields...)
	cp.Evaluation.Basis = append([]string(nil), e.Evaluation.Basis...)
	if e.TokenOutputs != nil {
		cp.TokenOutputs = make(map[string]string, len(e.TokenOutputs))
		for k, v := range e.TokenOutputs {
			cp.TokenOutputs[k] = v
		}
	}
	return cp
}

// Log is an append-only, concurrency-safe audit trail.
type Log struct {
	mu      sync.RWMutex
	entries []Entry
	byID    map[string]int
	seq     atomic.Uint64
}

// NewLog returns an empty audit log.
func NewLog() *Log {
	return &Log{byID: make(map[string]int)}
}

// Append records an entry and returns its assigned stable ID. The stored
// record and the returned record are independent copies.
func (l *Log) Append(e Entry) string {
	stored := e.clone()
	if stored.Time.IsZero() {
		stored.Time = time.Now().UTC()
	}

	l.mu.Lock()
	n := l.seq.Add(1)
	if stored.ID == "" {
		stored.ID = fmt.Sprintf("audit-%012d", n)
	}
	l.byID[stored.ID] = len(l.entries)
	l.entries = append(l.entries, stored)
	l.mu.Unlock()
	return stored.ID
}

// Get retrieves an independent copy of an entry by ID.
func (l *Log) Get(id string) (Entry, bool) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	idx, ok := l.byID[id]
	if !ok {
		return Entry{}, false
	}
	return l.entries[idx].clone(), true
}

// List returns independent copies of all entries in append order.
func (l *Log) List() []Entry {
	l.mu.RLock()
	defer l.mu.RUnlock()
	out := make([]Entry, len(l.entries))
	for i, e := range l.entries {
		out[i] = e.clone()
	}
	return out
}
