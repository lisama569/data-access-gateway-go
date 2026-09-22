package gateway

import (
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lisama569/data-access-gateway-go/internal/audit"
	"github.com/lisama569/data-access-gateway-go/internal/dataset"
	"github.com/lisama569/data-access-gateway-go/internal/masking"
	"github.com/lisama569/data-access-gateway-go/internal/model"
	"github.com/lisama569/data-access-gateway-go/internal/pdp"
	"github.com/lisama569/data-access-gateway-go/internal/policy"
)

const (
	secretEmail = "alice@example.com"
	secretPhone = "+1-555-0100-777"
)

type fixture struct {
	gw    *Gateway
	data  *dataset.Provider
	log   *audit.Log
	store *policy.Store
	reg   *masking.Registry
	t0    time.Time
	t1    time.Time
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	t1 := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	store := policy.NewStore()
	if err := store.Publish(&model.Policy{
		Version: "v1", EffectiveFrom: t0, EffectiveUntil: t1,
		Rules: []model.Rule{
			{Name: "v1-analyst", Allow: true, RequireMask: true, MaskingProfile: "prof",
				Roles: []string{"analyst"}, Sensitivities: []model.Sensitivity{model.SensitivityConfident},
				Purposes: []string{"analytics", "support"}},
			{Name: "v1-auditor", Allow: true,
				Roles: []string{"auditor"}, Sensitivities: []model.Sensitivity{model.SensitivityConfident}},
		},
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.Publish(&model.Policy{
		Version: "v2", EffectiveFrom: t1,
		Rules: []model.Rule{
			{Name: "v2-analyst", Allow: true, RequireMask: true, MaskingProfile: "prof2",
				Roles: []string{"analyst"}, Sensitivities: []model.Sensitivity{model.SensitivityConfident},
				Purposes: []string{"analytics"}},
			{Name: "v2-auditor", Allow: true,
				Roles: []string{"auditor"}, Sensitivities: []model.Sensitivity{model.SensitivityConfident}},
		},
	}); err != nil {
		t.Fatal(err)
	}

	reg := masking.NewRegistry()
	if err := reg.Register(model.MaskingProfile{Name: "prof", Rules: []model.FieldRule{
		{Field: "email", Transform: model.TransformMask, KeepPrefix: 1, KeepSuffix: 4},
		{Field: "phone", Transform: model.TransformRedact},
	}}); err != nil {
		t.Fatal(err)
	}
	if err := reg.Register(model.MaskingProfile{Name: "prof2", Rules: []model.FieldRule{
		{Field: "email", Transform: model.TransformTokenize, TokenDomain: "crm-email"},
		{Field: "phone", Transform: model.TransformTokenize, TokenDomain: "crm-phone"},
	}}); err != nil {
		t.Fatal(err)
	}

	data := dataset.NewProvider()
	data.AddSubject(model.Subject{ID: "alice", Roles: []string{"analyst"}})
	data.AddSubject(model.Subject{ID: "bob", Roles: []string{"analyst"}})
	data.AddSubject(model.Subject{ID: "uma", Roles: []string{"auditor"}})
	data.AddResource(model.Resource{ID: "cust", Sensitivity: model.SensitivityConfident, Fields: []string{"email", "phone"}},
		map[string]string{"email": secretEmail, "phone": secretPhone})
	data.AddResource(model.Resource{ID: "archived", Sensitivity: model.SensitivityConfident,
		Fields: []string{"email", "phone"}, RetentionUntil: t0.Add(30 * 24 * time.Hour)},
		map[string]string{"email": "old@example.com", "phone": "0"})

	al := audit.NewLog()
	return &fixture{
		gw:   New(data, pdp.NewEngine(store), reg, al),
		data: data, log: al, store: store, reg: reg, t0: t0, t1: t1,
	}
}

func TestAllowMaskAndDenyThroughGateway(t *testing.T) {
	f := newFixture(t)

	// auditor -> unmasked.
	res := f.gw.Access(model.AccessRequest{Subject: model.Subject{ID: "uma"}, ResourceID: "cust", Purpose: "review", At: f.t0.Add(time.Hour)})
	if res.Evaluation.Decision != model.DecisionAllow || res.Data["email"] != secretEmail {
		t.Fatalf("auditor should get raw data: %+v", res)
	}

	// analyst -> masked, raw values must never appear.
	res = f.gw.Access(model.AccessRequest{Subject: model.Subject{ID: "alice"}, ResourceID: "cust", Purpose: "analytics", At: f.t0.Add(time.Hour)})
	logCase(t, "v1 analyst analytics", res)
	if res.Evaluation.Decision != model.DecisionMask || res.Evaluation.PolicyVersion != "v1" {
		t.Fatalf("expected mask under v1, got %+v", res.Evaluation)
	}
	if res.Data["email"] == secretEmail || strings.Contains(res.Data["email"], "alice") {
		t.Fatalf("raw email leaked into masked output: %q", res.Data["email"])
	}
	if res.Data["phone"] != "***" {
		t.Fatalf("phone not redacted: %q", res.Data["phone"])
	}

	// purpose mismatch is distinguishable.
	res = f.gw.Access(model.AccessRequest{Subject: model.Subject{ID: "alice"}, ResourceID: "cust", Purpose: "marketing", At: f.t0.Add(time.Hour)})
	if res.Evaluation.DenyReason != model.DenyPurposeMismatch || res.Data != nil {
		t.Fatalf("expected purpose_mismatch with no data, got %+v", res)
	}

	// retention expiry is distinguishable.
	res = f.gw.Access(model.AccessRequest{Subject: model.Subject{ID: "uma"}, ResourceID: "archived", Purpose: "review", At: f.t1})
	if res.Evaluation.DenyReason != model.DenyRetentionExpired {
		t.Fatalf("expected retention_expired, got %q", res.Evaluation.DenyReason)
	}
}

func TestRevocationTakesEffectImmediately(t *testing.T) {
	f := newFixture(t)
	req := model.AccessRequest{Subject: model.Subject{ID: "bob"}, ResourceID: "cust", Purpose: "analytics", At: f.t0.Add(time.Hour)}
	if got := f.gw.Access(req); got.Evaluation.Decision != model.DecisionMask {
		t.Fatalf("pre-revocation access should succeed (mask), got %q", got.Evaluation.Decision)
	}
	f.data.Revoke("bob")
	got := f.gw.Access(req)
	logCase(t, "post-revocation", got)
	if got.Evaluation.DenyReason != model.DenySubjectRevoked {
		t.Fatalf("revocation must be immediate, got decision=%s reason=%q", got.Evaluation.Decision, got.Evaluation.DenyReason)
	}
	if got.Data != nil {
		t.Fatalf("revoked request must not return data")
	}
}

func TestPolicyVersionChangesConclusionsButHistoryReplays(t *testing.T) {
	f := newFixture(t)

	// Under v1, "support" masked. Capture audit id.
	v1 := f.gw.Access(model.AccessRequest{Subject: model.Subject{ID: "alice"}, ResourceID: "cust", Purpose: "support", At: f.t0.Add(time.Hour)})
	if v1.Evaluation.Decision != model.DecisionMask || v1.Evaluation.PolicyVersion != "v1" || v1.Evaluation.MatchedRule != "v1-analyst" {
		t.Fatalf("v1 support access mismatch: %+v", v1.Evaluation)
	}
	// Under v2, "support" is no longer permitted.
	v2 := f.gw.Access(model.AccessRequest{Subject: model.Subject{ID: "alice"}, ResourceID: "cust", Purpose: "support", At: f.t1.Add(time.Hour)})
	if v2.Evaluation.DenyReason != model.DenyPurposeMismatch || v2.Evaluation.PolicyVersion != "v2" {
		t.Fatalf("v2 support must deny purpose_mismatch: %+v", v2.Evaluation)
	}
	// Historical replay reproduces the v1 conclusion.
	replayed, err := f.gw.Replay(v1.AuditID)
	if err != nil {
		t.Fatal(err)
	}
	if replayed.Decision != model.DecisionMask || replayed.PolicyVersion != "v1" || replayed.MatchedRule != "v1-analyst" {
		t.Fatalf("replay did not reproduce v1 conclusion: %+v", replayed)
	}
}

func TestInvalidMaskingConfigurationDeniedNotDowngraded(t *testing.T) {
	f := newFixture(t)
	// Publish a v3 policy naming a profile that is not registered.
	if err := f.store.Publish(&model.Policy{
		Version: "v3", EffectiveFrom: f.t1.AddDate(1, 0, 0),
		Rules: []model.Rule{{Name: "broken", Allow: true, RequireMask: true, MaskingProfile: "missing",
			Roles: []string{"analyst"}, Sensitivities: []model.Sensitivity{model.SensitivityConfident}, Purposes: []string{"analytics"}}},
	}); err != nil {
		t.Fatal(err)
	}
	res := f.gw.Access(model.AccessRequest{Subject: model.Subject{ID: "alice"}, ResourceID: "cust", Purpose: "analytics",
		At: f.t1.AddDate(1, 0, 0)})
	if res.Evaluation.DenyReason != model.DenyInvalidMaskingConfig || res.Data != nil {
		t.Fatalf("missing masking profile must deny invalid_masking_config without data, got %+v", res.Evaluation)
	}
}

func TestAuditNeverContainsRawValues(t *testing.T) {
	f := newFixture(t)
	res := f.gw.Access(model.AccessRequest{Subject: model.Subject{ID: "alice"}, ResourceID: "cust", Purpose: "analytics", At: f.t0.Add(time.Hour)})
	for _, e := range f.log.List() {
		text := fmt.Sprintf("%v", e)
		if strings.Contains(text, secretEmail) || strings.Contains(text, secretPhone) {
			t.Fatalf("audit entry contains original protected value:\n%s", text)
		}
	}
	entry, ok := f.log.Get(res.AuditID)
	if !ok {
		t.Fatal("audit entry missing")
	}
	if entry.Evaluation.PolicyVersion != "v1" || len(entry.Evaluation.Basis) == 0 {
		t.Fatalf("audit entry must record hit version and basis: %+v", entry)
	}
}

func TestConcurrentRequestsAreConsistentAndIsolated(t *testing.T) {
	f := newFixture(t)
	const goroutines = 64
	const iterations = 40
	var wg sync.WaitGroup
	errCh := make(chan error, goroutines*iterations)

	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				// Deterministic inputs; the conclusion must be identical every time.
				req := model.AccessRequest{Subject: model.Subject{ID: "alice"}, ResourceID: "cust",
					Purpose: "analytics", At: f.t0.Add(time.Hour)}
				res := f.gw.Access(req)
				if res.Evaluation.Decision != model.DecisionMask ||
					res.Evaluation.PolicyVersion != "v1" ||
					res.Evaluation.MatchedRule != "v1-analyst" ||
					res.Data["phone"] != "***" ||
					strings.Contains(res.Data["email"], "alice@") {
					errCh <- fmt.Errorf("goroutine %d iteration %d inconsistent result: %+v data=%v", g, i, res.Evaluation, res.Data)
					return
				}
			}
		}(g)
	}

	// Concurrent revoker racing with an unrelated subject's traffic: alice's
	// own conclusions must remain stable (bob is revoked instead).
	wg.Add(1)
	go func() {
		defer wg.Done()
		f.data.Revoke("bob")
	}()

	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Error(err)
	}

	// Token stability under concurrent masking is guaranteed via the vault.
	tok1 := f.reg.Vault().Tokenize("crm-email", secretEmail)
	tok2 := f.reg.Vault().Tokenize("crm-email", secretEmail)
	if tok1 != tok2 {
		t.Fatalf("tokens unstable under concurrency: %q vs %q", tok1, tok2)
	}
	// Cross-domain reversal is impossible.
	if _, err := f.reg.Vault().Detokenize("crm-phone", tok1); err == nil {
		t.Fatal("email token must not be reversible in the phone domain")
	}
}

func logCase(t *testing.T, label string, res model.AccessResult) {
	t.Helper()
	ev := res.Evaluation
	t.Logf("[%s] -> decision=%s reason=%q policy=%s rule=%s profile=%q audit=%s",
		label, ev.Decision, ev.DenyReason, ev.PolicyVersion, ev.MatchedRule, ev.MaskingProfile, res.AuditID)
	for _, b := range ev.Basis {
		t.Logf("  basis: %s", b)
	}
}
