package policy

import (
	"testing"
	"time"

	"github.com/lisama569/data-access-gateway-go/internal/model"
)

func TestStoreVersionLifecycle(t *testing.T) {
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	s := NewStore()
	p1 := model.Policy{Version: "v1", EffectiveAt: t0, RetiresAt: t0.AddDate(0, 6, 0)}
	p2 := model.Policy{Version: "v2", EffectiveAt: t0.AddDate(0, 6, 0)}
	if err := s.Publish(p1); err != nil {
		t.Fatalf("publish v1: %v", err)
	}
	if err := s.Publish(p1); err == nil {
		t.Fatal("duplicate version must be rejected")
	}
	if err := s.Publish(model.Policy{Version: "bad", EffectiveAt: t0.Add(time.Hour), RetiresAt: t0}); err == nil {
		t.Fatal("effective >= retires must be rejected")
	}
	if err := s.Publish(p2); err != nil {
		t.Fatalf("publish v2: %v", err)
	}

	if got, err := s.Active(t0.AddDate(0, 3, 0)); err != nil || got.Version != "v1" {
		t.Fatalf("expect v1 active, got %v err=%v", got.Version, err)
	}
	// v1 已退役：新访问必须走 v2；v1 仍可按版本读取用于复现。
	if got, err := s.Active(t0.AddDate(0, 7, 0)); err != nil || got.Version != "v2" {
		t.Fatalf("expect v2 active, got %v err=%v", got.Version, err)
	}
	if _, ok := s.Version("v1"); !ok {
		t.Fatal("retired v1 must remain archived")
	}
	if got := s.Versions(); len(got) != 2 || got[0] != "v1" || got[1] != "v2" {
		t.Fatalf("versions order = %v", got)
	}
}

func TestStoreNoActiveBeforeEffective(t *testing.T) {
	s := NewStore()
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	_ = s.Publish(model.Policy{Version: "v1", EffectiveAt: t0})
	if _, err := s.Active(t0.Add(-time.Second)); err == nil {
		t.Fatal("no active policy expected before effective time")
	}
}
