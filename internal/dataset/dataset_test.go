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

func TestGrantDefensiveCopyOfSensitivityCap(t *testing.T) {
	now := time.Date(2026, 9, 23, 0, 0, 0, 0, time.UTC)
	d := New(func() time.Time { return now })
	cap := model.SensitivityConfidential
	g := model.Grant{ID: "g1", SubjectID: "u1", Resource: "r1", Purposes: []string{"p"}, MaxSensitivity: &cap}
	d.PutGrant(g)
	// 调用方写入后再改自己的指针，不得影响存储内授权。
	cap = model.SensitivityPublic
	got := d.FindGrant("u1", "r1")
	if got.MaxSensitivity == nil || *got.MaxSensitivity != model.SensitivityConfidential {
		t.Fatalf("grant cap leaked external mutation: %v", got.MaxSensitivity)
	}
}

func TestReclassifyImmediate(t *testing.T) {
	now := time.Date(2026, 9, 23, 0, 0, 0, 0, time.UTC)
	d := New(func() time.Time { return now })
	d.PutRecord(model.Record{
		Resource: "r1", Sensitivity: model.SensitivityPublic, Fields: map[string]string{"a": "1"},
	})
	if got, _ := d.GetRecord("r1"); got.Sensitivity != model.SensitivityPublic {
		t.Fatalf("setup level = %s", got.Sensitivity)
	}
	if !d.Reclassify("r1", model.SensitivityRestricted, now) {
		t.Fatal("reclassify existing record must succeed")
	}
	// 调整后立即对后续读取生效。
	got, _ := d.GetRecord("r1")
	if got.Sensitivity != model.SensitivityRestricted {
		t.Fatalf("level after reclassify = %s, want restricted", got.Sensitivity)
	}
	// 分级调整不应破坏字段内容。
	if got.Fields["a"] != "1" {
		t.Fatalf("fields corrupted after reclassify: %v", got.Fields)
	}
	// 不存在的记录返回 false。
	if d.Reclassify("ghost", model.SensitivityInternal, now) {
		t.Fatal("reclassify missing record must return false")
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
	stop := make(chan struct{})
	wg.Add(2)
	go func() { // 重分级者：持续在两级之间切换。
		defer wg.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
				d.Reclassify("r", levels[i%len(levels)], now)
			}
		}
	}()
	go func() { // 读者：读到的分级必须始终是合法枚举值，绝不会读到撕裂状态。
		defer wg.Done()
		for i := 0; i < 2000; i++ {
			rec, ok := d.GetRecord("r")
			if !ok {
				t.Error("record vanished during reclassify")
				return
			}
			if rec.Sensitivity < model.SensitivityPublic || rec.Sensitivity > model.SensitivityRestricted {
				t.Errorf("torn sensitivity read: %d", rec.Sensitivity)
				return
			}
		}
		close(stop)
	}()
	wg.Wait()
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
