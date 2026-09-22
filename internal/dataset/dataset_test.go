package dataset

import (
	"sync"
	"testing"

	"github.com/lisama569/data-access-gateway-go/internal/model"
)

func TestDefensiveCopiesAndRevocation(t *testing.T) {
	p := NewProvider()
	p.AddSubject(model.Subject{ID: "s", Roles: []string{"analyst"}})
	p.AddResource(model.Resource{ID: "r", Fields: []string{"email"}}, map[string]string{"email": "secret"})

	rec, _ := p.GetRecord("r")
	rec["email"] = "mutated"
	again, _ := p.GetRecord("r")
	if again["email"] != "secret" {
		t.Fatalf("stored record leaked mutation: %q", again["email"])
	}

	p.Revoke("s")
	sub, _ := p.GetSubject("s")
	if !sub.Revoked {
		t.Fatal("revocation must be visible immediately")
	}
}

func TestConcurrentReads(t *testing.T) {
	p := NewProvider()
	p.AddSubject(model.Subject{ID: "s", Roles: []string{"a"}})
	p.AddResource(model.Resource{ID: "r"}, map[string]string{"k": "v"})
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = p.GetSubject("s")
			_, _ = p.GetRecord("r")
		}()
	}
	wg.Wait()
}
