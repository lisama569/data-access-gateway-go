package pdp

import (
	"errors"
	"testing"
	"time"

	"github.com/lisama569/data-access-gateway-go/internal/model"
)

var t0 = time.Date(2026, 9, 23, 0, 0, 0, 0, time.UTC)

func testPolicy(retires ...time.Time) model.Policy {
	p := model.Policy{
		Version:     "v1",
		EffectiveAt: t0.AddDate(-1, 0, 0),
		Rules: []model.Rule{{
			Resources:    []string{"res:1"},
			Purposes:     []string{"research"},
			MinClearance: 2,
			Effect:       model.EffectMask,
			FieldRules:   []model.FieldRule{{Field: "name", Transform: "mask"}},
		}},
	}
	if len(retires) > 0 {
		p.RetiresAt = retires[0]
	}
	return p
}

type fakeStore struct{ pols map[string]model.Policy }

func (f fakeStore) Active(at time.Time) (model.Policy, error) {
	for _, p := range f.pols {
		if !at.Before(p.EffectiveAt) && (p.RetiresAt.IsZero() || at.Before(p.RetiresAt)) {
			return p, nil
		}
	}
	return model.Policy{}, errors.New("no active policy")
}
func (f fakeStore) Version(v string) (model.Policy, bool) {
	p, ok := f.pols[v]
	return p, ok
}

func validGrant() *model.Grant {
	return &model.Grant{ID: "g1", SubjectID: "u1", Resource: "res:1", Purposes: []string{"research"}, ExpiresAt: t0.Add(time.Hour), UpdatedAt: t0}
}

func baseReq(g *model.Grant) model.AccessRequest {
	return model.AccessRequest{
		Subject:     model.Subject{ID: "u1", Clearance: 3},
		Grant:       g,
		Resource:    "res:1",
		Purpose:     "research",
		RequestedAt: t0,
	}
}

func TestVerdictReasons(t *testing.T) {
	store := fakeStore{pols: map[string]model.Policy{"v1": testPolicy()}}
	rec := &model.Record{Resource: "res:1", ExpiresAt: t0.Add(time.Hour)}

	tests := []struct {
		name   string
		mutate func(*model.AccessRequest)
		store  fakeStore
		want   model.Reason
	}{
		{name: "mask ok", want: model.ReasonNone},
		{name: "grant missing", mutate: func(r *model.AccessRequest) { r.Grant = nil }, want: model.ReasonGrantMissing},
		{name: "grant revoked", mutate: func(r *model.AccessRequest) { r.Grant.Revoked = true }, want: model.ReasonGrantRevoked},
		{name: "grant expired", mutate: func(r *model.AccessRequest) { r.Grant.ExpiresAt = t0.Add(-time.Minute) }, want: model.ReasonGrantMissing},
		{name: "purpose mismatch grant", mutate: func(r *model.AccessRequest) { r.Purpose = "marketing" }, want: model.ReasonPurposeMismatch},
		{name: "clearance insufficient", mutate: func(r *model.AccessRequest) { r.Subject.Clearance = 1 }, want: model.ReasonClearanceInsufficient},
		{name: "data retention expired", mutate: func(r *model.AccessRequest) {
			rec.ExpiresAt = t0.Add(-time.Minute)
		}, want: model.ReasonDataRetentionExpired},
		{name: "no active policy", store: fakeStore{pols: map[string]model.Policy{}}, want: model.ReasonNoApplicablePolicy},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			engStore := store
			if tc.store.pols != nil {
				engStore = tc.store
			}
			eng := NewEngine(engStore, func() time.Time { return t0 })
			rec := &model.Record{Resource: "res:1", ExpiresAt: t0.Add(time.Hour)}
			if tc.name == "data retention expired" {
				rec.ExpiresAt = t0.Add(-time.Minute)
			}
			req := baseReq(validGrant())
			if tc.mutate != nil {
				tc.mutate(&req)
			}
			d, reason, _, basis := eng.Verdict(req, rec)
			t.Logf("input={subject=%s resource=%s purpose=%s grant=%v} reason=%q factors=%v",
				req.Subject.ID, req.Resource, req.Purpose, req.Grant != nil, reason, basis.Factors)
			if reason != tc.want {
				t.Fatalf("reason = %q, want %q (decision=%d)", reason, tc.want, d)
			}
			if tc.want == model.ReasonNone && d != model.DecisionMask {
				t.Fatalf("decision = %d, want mask", d)
			}
			if tc.want != model.ReasonNone && d != model.DecisionDeny {
				t.Fatalf("decision = %d, want deny", d)
			}
		})
	}
}

func TestVerdictPolicyRetention(t *testing.T) {
	retired := testPolicy(t0.Add(-time.Hour))
	store := fakeStore{pols: map[string]model.Policy{"v1": retired}}
	e := NewEngine(store, func() time.Time { return t0 })
	rec := &model.Record{Resource: "res:1", ExpiresAt: t0.Add(time.Hour)}

	// 未固定版本：退役版本不服务新访问。
	if _, reason, _, _ := e.Verdict(baseReq(validGrant()), rec); reason != model.ReasonNoApplicablePolicy {
		t.Fatalf("active lookup got %q", reason)
	}
	// 显式固定一个已退役版本：明确的策略保留期拒绝，可与普通拒绝区分。
	req := baseReq(validGrant())
	req.PinnedVersion = "v1"
	d, reason, pol, _ := e.Verdict(req, rec)
	if reason != model.ReasonPolicyRetentionExpired || d != model.DecisionDeny || pol.Version != "v1" {
		t.Fatalf("pinned retired got d=%d reason=%q pol=%s", d, reason, pol.Version)
	}

	// 固定不存在的版本。
	req2 := baseReq(validGrant())
	req2.PinnedVersion = "ghost"
	if _, reason, _, _ := e.Verdict(req2, rec); reason != model.ReasonNoApplicablePolicy {
		t.Fatalf("missing pinned version got %q", reason)
	}
}

func TestVerdictExplicitRuleDeny(t *testing.T) {
	p := testPolicy()
	p.Rules[0].Effect = model.EffectDeny
	store := fakeStore{pols: map[string]model.Policy{"v1": p}}
	e := NewEngine(store, func() time.Time { return t0 })
	d, reason, _, _ := e.Verdict(baseReq(validGrant()), &model.Record{Resource: "res:1"})
	if d != model.DecisionDeny || reason != model.ReasonRuleDenied {
		t.Fatalf("got d=%d reason=%q", d, reason)
	}
}

func TestVerdictDeterministic(t *testing.T) {
	store := fakeStore{pols: map[string]model.Policy{"v1": testPolicy()}}
	e := NewEngine(store, func() time.Time { return t0 })
	rec := &model.Record{Resource: "res:1"}
	for i := 0; i < 10; i++ {
		d, reason, pol, basis := e.Verdict(baseReq(validGrant()), rec)
		if d != model.DecisionMask || reason != model.ReasonNone || pol.Version != "v1" || !basis.MatchedRule {
			t.Fatalf("iter %d nondeterministic: d=%d reason=%q", i, d, reason)
		}
	}
}
