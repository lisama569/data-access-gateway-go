package dataset

import (
	"sync"
	"testing"
	"time"

	"github.com/lisama569/data-access-gateway-go/internal/model"
)

func TestRecordDefensiveCopy(t *testing.T) {
	now := time.Date(2026, 9, 23, 0, 0, 0, 0, time.UTC)
	d := New(func() time.Time { return now })
	orig := model.Record{Resource: "r1", Fields: map[string]string{"a": "1"}}
	d.PutRecord(orig)
	got, ok := d.GetRecord("r1")
	if !ok {
		t.Fatal("record missing")
	}
	got.Fields["a"] = "mutated"
	again, _ := d.GetRecord("r1")
	if again.Fields["a"] != "1" {
		t.Fatalf("shared mutable state leaked: %q", again.Fields["a"])
	}
}

func TestGrantRevocationImmediate(t *testing.T) {
	now := time.Date(2026, 9, 23, 0, 0, 0, 0, time.UTC)
	d := New(func() time.Time { return now })
	d.PutGrant(model.Grant{ID: "g1", SubjectID: "u1", Resource: "r1", Purposes: []string{"p"}})
	if g := d.FindGrant("u1", "r1"); g == nil || g.Revoked {
		t.Fatal("grant should be active")
	}
	if !d.RevokeGrant("g1", now.Add(time.Second)) {
		t.Fatal("revoke should succeed")
	}
	g := d.FindGrant("u1", "r1")
	if g == nil || !g.Revoked {
		t.Fatal("revocation must be immediately visible")
	}
	if d.RevokeGrant("g1", now.Add(time.Second)) {
		t.Fatal("revoking twice must return false")
	}
	if d.RevokeGrant("ghost", now) {
		t.Fatal("revoking unknown grant must return false")
	}
}

func TestConcurrentGrantsAndRecords(t *testing.T) {
	now := time.Date(2026, 9, 23, 0, 0, 0, 0, time.UTC)
	d := New(func() time.Time { return now })
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(3)
		i := i
		go func() {
			defer wg.Done()
			d.PutRecord(model.Record{Resource: "r", Fields: map[string]string{"k": "v"}})
		}()
		go func() {
			defer wg.Done()
			d.GetRecord("r")
		}()
		go func() {
			defer wg.Done()
			id := "g"
			d.PutGrant(model.Grant{ID: id, SubjectID: "u", Resource: "r", UpdatedAt: now.Add(time.Duration(i))})
			d.RevokeGrant(id, now.Add(time.Duration(i)))
		}()
	}
	wg.Wait()
}
