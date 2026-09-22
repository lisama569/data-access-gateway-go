package policy

import (
	"errors"
	"testing"
	"time"

	"github.com/lisama569/data-access-gateway-go/internal/model"
)

func TestPublishImmutableAndRetrievable(t *testing.T) {
	s := NewStore()
	p := &model.Policy{Version: "v1", Rules: []model.Rule{{Name: "r1", Allow: true}},
		EffectiveFrom: time.Unix(0, 0)}
	if err := s.Publish(p); err != nil {
		t.Fatal(err)
	}
	// Mutating the caller's copy must not change the stored policy.
	p.Rules[0].Name = "mutated"
	p.Version = "v999"
	got, ok := s.Get("v1")
	if !ok || got.Rules[0].Name != "r1" {
		t.Fatalf("stored policy mutated after publish: %+v", got)
	}
	if err := s.Publish(&model.Policy{Version: "v1"}); !errors.Is(err, ErrDuplicateVersion) {
		t.Fatalf("expected ErrDuplicateVersion, got %v", err)
	}
	if err := s.Publish(&model.Policy{}); !errors.Is(err, ErrEmptyVersion) {
		t.Fatalf("expected ErrEmptyVersion, got %v", err)
	}
}

func TestActiveRespectsEffectiveWindow(t *testing.T) {
	s := NewStore()
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	t1 := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	if err := s.Publish(&model.Policy{Version: "v1", EffectiveFrom: t0, EffectiveUntil: t1}); err != nil {
		t.Fatal(err)
	}
	if err := s.Publish(&model.Policy{Version: "v2", EffectiveFrom: t1}); err != nil {
		t.Fatal(err)
	}

	if p, err := s.Active(t0.Add(time.Hour)); err != nil || p.Version != "v1" {
		t.Fatalf("expected v1, got %s err=%v", p.Version, err)
	}
	// Exactly at EffectiveUntil the old version is retired.
	if p, err := s.Active(t1); err != nil || p.Version != "v2" {
		t.Fatalf("expected v2 at boundary, got %s err=%v", p.Version, err)
	}
	// Retired versions are retained for replay.
	if _, ok := s.Get("v1"); !ok {
		t.Fatal("retired v1 must remain retrievable for historical replay")
	}
	if _, err := s.Active(t0.Add(-time.Hour)); !errors.Is(err, ErrNoActivePolicy) {
		t.Fatalf("expected ErrNoActivePolicy before window, got %v", err)
	}
}
