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

func TestReclassify(t *testing.T) {
	now := time.Date(2026, 9, 23, 0, 0, 0, 0, time.UTC)
	d := New(func() time.Time { return now })
	d.PutRecord(model.Record{
		Resource: "r1", Sensitivity: model.SensitivityPublic,
		Fields: map[string]string{"k": "v"},
	})

	if d.Reclassify("ghost", model.SensitivityRestricted) {
		t.Fatal("reclassifying unknown resource must return false")
	}
	if !d.Reclassify("r1", model.SensitivityConfidential) {
		t.Fatal("reclassify failed")
	}
	rec, ok := d.GetRecord("r1")
	if !ok {
		t.Fatal("record missing")
	}
	if rec.Sensitivity != model.SensitivityConfidential {
		t.Fatalf("sensitivity = %v, want confidential", rec.Sensitivity)
	}
	// 分级调整不应触碰字段内容。
	if rec.Fields["k"] != "v" {
		t.Fatalf("fields changed: %v", rec.Fields)
	}
}

func TestConcurrentReclassifyAndRead(t *testing.T) {
	now := time.Date(2026, 9, 23, 0, 0, 0, 0, time.UTC)
	d := New(func() time.Time { return now })
	d.PutRecord(model.Record{Resource: "r", Sensitivity: model.SensitivityPublic})
	levels := []model.Sensitivity{
		model.SensitivityPublic, model.SensitivityInternal,
		model.SensitivityConfidential, model.SensitivityRestricted,
	}
	var wg sync.WaitGroup
	for i := 0; i < 40; i++ {
		wg.Add(2)
		i := i
		go func() {
			defer wg.Done()
			d.Reclassify("r", levels[i%len(levels)])
		}()
		go func() {
			defer wg.Done()
			rec, ok := d.GetRecord("r")
			if !ok {
				t.Error("record missing")
				return
			}
			// 单次读取必须看到一个完整、合法的分级值。
			if rec.Sensitivity < model.SensitivityPublic || rec.Sensitivity > model.SensitivityRestricted {
				t.Errorf("torn sensitivity read: %d", rec.Sensitivity)
			}
		}()
	}
	wg.Wait()
}
