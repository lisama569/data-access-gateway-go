package audit

import (
	"sync"
	"testing"

	"github.com/lisama569/data-access-gateway-go/internal/model"
)

func TestAppendGetImmutable(t *testing.T) {
	l := NewLog()
	basis := []string{"b1", "b2"}
	id := l.Append(Entry{
		SubjectID:    "s1",
		SubjectRoles: []string{"analyst"},
		ResourceID:   "r1",
		Purpose:      "analytics",
		Evaluation:   model.Evaluation{Decision: model.DecisionMask, PolicyVersion: "v1", Basis: basis},
		TokenOutputs: map[string]string{"email": "tok_abc"},
	})
	if id == "" {
		t.Fatal("expected audit id")
	}
	e, ok := l.Get(id)
	if !ok {
		t.Fatal("entry missing")
	}
	// Mutating returned data must not change the stored trail.
	e.Evaluation.Basis[0] = "tampered"
	e.SubjectRoles[0] = "owner"
	e.TokenOutputs["email"] = "raw-value"
	again, _ := l.Get(id)
	if again.Evaluation.Basis[0] != "b1" || again.SubjectRoles[0] != "analyst" || again.TokenOutputs["email"] != "tok_abc" {
		t.Fatalf("audit trail was mutated after append: %+v", again)
	}
}

func TestConcurrentAppendUniqueIDs(t *testing.T) {
	l := NewLog()
	var wg sync.WaitGroup
	const n = 200
	ids := make(chan string, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ids <- l.Append(Entry{Evaluation: model.Evaluation{Decision: model.DecisionAllow}})
		}()
	}
	wg.Wait()
	close(ids)
	seen := make(map[string]struct{}, n)
	for id := range ids {
		if _, dup := seen[id]; dup {
			t.Fatalf("duplicate audit id %s", id)
		}
		seen[id] = struct{}{}
	}
	if len(l.List()) != n {
		t.Fatalf("expected %d entries, got %d", n, len(l.List()))
	}
}
