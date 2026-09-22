package pdp

import (
	"testing"
	"time"

	"github.com/lisama569/data-access-gateway-go/internal/model"
	"github.com/lisama569/data-access-gateway-go/internal/policy"
)

func testSetup(t *testing.T) (*StoreShim, time.Time, time.Time) {
	t.Helper()
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	t1 := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	s := policy.NewStore()
	if err := s.Publish(&model.Policy{
		Version: "v1", EffectiveFrom: t0, EffectiveUntil: t1,
		Rules: []model.Rule{
			{Name: "analyst-mask", Allow: true, RequireMask: true, MaskingProfile: "prof",
				Roles: []string{"analyst"}, Sensitivities: []model.Sensitivity{model.SensitivityConfident},
				Purposes: []string{"analytics", "support"}},
			{Name: "auditor-full", Allow: true,
				Roles: []string{"auditor"}, Sensitivities: []model.Sensitivity{model.SensitivityConfident, model.SensitivityRestricted}},
			{Name: "explicit-deny-contractor", Allow: false,
				Roles: []string{"contractor"}, Sensitivities: []model.Sensitivity{model.SensitivityConfident}},
		},
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.Publish(&model.Policy{
		Version: "v2", EffectiveFrom: t1,
		Rules: []model.Rule{
			{Name: "analyst-token", Allow: true, RequireMask: true, MaskingProfile: "prof2",
				Roles: []string{"analyst"}, Sensitivities: []model.Sensitivity{model.SensitivityConfident},
				Purposes: []string{"analytics"}},
			{Name: "auditor-full", Allow: true,
				Roles: []string{"auditor"}, Sensitivities: []model.Sensitivity{model.SensitivityConfident, model.SensitivityRestricted}},
		},
	}); err != nil {
		t.Fatal(err)
	}
	return &StoreShim{s}, t0, t1
}

type StoreShim struct{ s *policy.Store }

func (sh *StoreShim) engine() *Engine { return NewEngine(sh.s) }

func TestDecisionMatrix(t *testing.T) {
	sh, t0, t1 := testSetup(t)
	e := sh.engine()

	res := model.Resource{ID: "r", Sensitivity: model.SensitivityConfident}
	analyst := model.Subject{ID: "a", Roles: []string{"analyst"}}
	auditor := model.Subject{ID: "u", Roles: []string{"auditor"}}
	contractor := model.Subject{ID: "c", Roles: []string{"contractor"}}
	expired := model.Resource{ID: "old", Sensitivity: model.SensitivityConfident, RetentionUntil: t0.Add(30 * 24 * time.Hour)}

	cases := []struct {
		name     string
		req      model.AccessRequest
		decision model.Decision
		reason   model.DenyReason
		policy   string
		rule     string
	}{
		{"allow unmasked", model.AccessRequest{Subject: auditor, ResourceID: "r", Purpose: "anything", At: t0.Add(time.Hour)},
			model.DecisionAllow, model.DenyNone, "v1", "auditor-full"},
		{"mask required", model.AccessRequest{Subject: analyst, ResourceID: "r", Purpose: "analytics", At: t0.Add(time.Hour)},
			model.DecisionMask, model.DenyNone, "v1", "analyst-mask"},
		{"purpose mismatch", model.AccessRequest{Subject: analyst, ResourceID: "r", Purpose: "marketing", At: t0.Add(time.Hour)},
			model.DecisionDeny, model.DenyPurposeMismatch, "v1", ""},
		{"no authorization", model.AccessRequest{Subject: model.Subject{ID: "x", Roles: []string{"guest"}}, ResourceID: "r", Purpose: "analytics", At: t0.Add(time.Hour)},
			model.DecisionDeny, model.DenyNoAuthorization, "v1", ""},
		{"explicit deny rule", model.AccessRequest{Subject: contractor, ResourceID: "r", Purpose: "analytics", At: t0.Add(time.Hour)},
			model.DecisionDeny, model.DenyNoAuthorization, "v1", "explicit-deny-contractor"},
		{"revoked subject", model.AccessRequest{Subject: model.Subject{ID: "a2", Roles: []string{"analyst"}, Revoked: true}, ResourceID: "r", Purpose: "analytics", At: t0.Add(time.Hour)},
			model.DecisionDeny, model.DenySubjectRevoked, "", ""},
		{"retention expired", model.AccessRequest{Subject: auditor, ResourceID: "old", Purpose: "x", At: t1},
			model.DecisionDeny, model.DenyRetentionExpired, "", ""},
		{"retired version pinned", model.AccessRequest{Subject: analyst, ResourceID: "r", Purpose: "analytics", At: t1, PolicyVersion: "v1"},
			model.DecisionDeny, model.DenyPolicyVersionExpired, "", ""},
		{"unknown version", model.AccessRequest{Subject: analyst, ResourceID: "r", Purpose: "analytics", At: t0, PolicyVersion: "vX"},
			model.DecisionDeny, model.DenyPolicyVersionExpired, "", ""},
		{"v2 changes purpose set", model.AccessRequest{Subject: analyst, ResourceID: "r", Purpose: "support", At: t1.Add(time.Hour)},
			model.DecisionDeny, model.DenyPurposeMismatch, "v2", ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resource := res
			if tc.req.ResourceID == "old" {
				resource = expired
			}
			ev := e.Evaluate(tc.req, resource)
			logInputAndBasis(t, tc.req, resource, ev)
			if ev.Decision != tc.decision || ev.DenyReason != tc.reason ||
				ev.PolicyVersion != tc.policy || ev.MatchedRule != tc.rule {
				t.Fatalf("got decision=%s reason=%q policy=%s rule=%q; want %s %q %s %q",
					ev.Decision, ev.DenyReason, ev.PolicyVersion, ev.MatchedRule,
					tc.decision, tc.reason, tc.policy, tc.rule)
			}
		})
	}
}

func TestReplayReproducesHistoricalVersion(t *testing.T) {
	sh, t0, _ := testSetup(t)
	e := sh.engine()
	res := model.Resource{ID: "r", Sensitivity: model.SensitivityConfident}
	req := model.AccessRequest{
		Subject: model.Subject{ID: "a", Roles: []string{"analyst"}},
		Purpose: "support", At: t0.Add(time.Hour), PolicyVersion: "v1",
	}
	ev, err := e.Replay(req, res)
	if err != nil {
		t.Fatal(err)
	}
	// Under v1 "support" was still allowed and masking was required.
	if ev.Decision != model.DecisionMask || ev.MatchedRule != "analyst-mask" {
		t.Fatalf("historical v1 replay mismatch: %s rule=%s", ev.Decision, ev.MatchedRule)
	}
	// Even a currently-revoked subject must reproduce the historical policy
	// conclusion during replay.
	req.Subject.Revoked = true
	ev2, err := e.Replay(req, res)
	if err != nil || ev2.Decision != ev.Decision || ev2.MatchedRule != ev.MatchedRule {
		t.Fatalf("revoked subject altered historical replay: %+v err=%v", ev2, err)
	}

	if _, err := e.Replay(model.AccessRequest{At: t0}, res); err == nil {
		t.Fatal("replay without pinned version must fail")
	}
}

func logInputAndBasis(t *testing.T, req model.AccessRequest, res model.Resource, ev model.Evaluation) {
	t.Helper()
	t.Logf("INPUT subject=%q roles=%v revoked=%t resource=%q sensitivity=%s purpose=%q at=%s policyPin=%q",
		req.Subject.ID, req.Subject.Roles, req.Subject.Revoked, res.ID, res.Sensitivity,
		req.Purpose, req.At.UTC().Format(time.RFC3339), req.PolicyVersion)
	t.Logf("HIT policy=%s rule=%s profile=%s -> decision=%s reason=%q",
		ev.PolicyVersion, ev.MatchedRule, ev.MaskingProfile, ev.Decision, ev.DenyReason)
	for _, b := range ev.Basis {
		t.Logf("  basis: %s", b)
	}
}
