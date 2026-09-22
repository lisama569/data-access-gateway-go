// Command demo wires the gateway together with an in-memory dataset and runs
// illustrative access requests entirely locally: allow, mask, distinguishable
// denials, immediate revocation, a policy version change and a historical
// replay.
package main

import (
	"fmt"
	"time"

	"github.com/lisama569/data-access-gateway-go/internal/audit"
	"github.com/lisama569/data-access-gateway-go/internal/dataset"
	"github.com/lisama569/data-access-gateway-go/internal/gateway"
	"github.com/lisama569/data-access-gateway-go/internal/masking"
	"github.com/lisama569/data-access-gateway-go/internal/model"
	"github.com/lisama569/data-access-gateway-go/internal/pdp"
	"github.com/lisama569/data-access-gateway-go/internal/policy"
)

func main() {
	day := 24 * time.Hour
	t1 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	t2 := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	now := time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC)

	// --- Policies: v1 is current until June, v2 is active afterwards. ---
	store := policy.NewStore()
	must(store.Publish(&model.Policy{
		Version: "v1",
		Rules: []model.Rule{
			{Name: "v1-analyst-mask", Allow: true, RequireMask: true, MaskingProfile: "pii-basic",
				Roles: []string{"analyst"}, Sensitivities: []model.Sensitivity{model.SensitivityConfident}, Purposes: []string{"analytics", "support"}},
			{Name: "v1-owner-full", Allow: true,
				Roles: []string{"owner"}, Sensitivities: []model.Sensitivity{model.SensitivityConfident}},
		},
		EffectiveFrom: t1, EffectiveUntil: t2,
	}))
	must(store.Publish(&model.Policy{
		Version: "v2",
		Rules: []model.Rule{
			{Name: "v2-analyst-tokenize", Allow: true, RequireMask: true, MaskingProfile: "pii-token",
				Roles: []string{"analyst"}, Sensitivities: []model.Sensitivity{model.SensitivityConfident}, Purposes: []string{"analytics"}},
			{Name: "v2-owner-full", Allow: true,
				Roles: []string{"owner"}, Sensitivities: []model.Sensitivity{model.SensitivityConfident}},
		},
		EffectiveFrom: t2,
	}))

	// --- Masking profiles. ---
	reg := masking.NewRegistry()
	must(reg.Register(model.MaskingProfile{Name: "pii-basic", Rules: []model.FieldRule{
		{Field: "email", Transform: model.TransformMask, KeepPrefix: 1, KeepSuffix: 4},
		{Field: "phone", Transform: model.TransformRedact},
		{Field: "note", Transform: model.TransformRedact},
	}}))
	must(reg.Register(model.MaskingProfile{Name: "pii-token", Rules: []model.FieldRule{
		{Field: "email", Transform: model.TransformTokenize, TokenDomain: "crm-email"},
		{Field: "phone", Transform: model.TransformTokenize, TokenDomain: "crm-phone"},
		{Field: "note", Transform: model.TransformRedact},
	}}))

	// --- In-memory protected data. ---
	data := dataset.NewProvider()
	data.AddSubject(model.Subject{ID: "alice", Roles: []string{"analyst"}})
	data.AddSubject(model.Subject{ID: "bob", Roles: []string{"analyst"}})
	data.AddResource(model.Resource{
		ID: "cust-1", Sensitivity: model.SensitivityConfident,
		Fields: []string{"email", "phone", "note"},
	}, map[string]string{
		"email": "alice@example.com",
		"phone": "+1-555-0100-777",
		"note":  "vip customer",
	})
	data.AddResource(model.Resource{
		ID: "old-1", Sensitivity: model.SensitivityConfident,
		Fields:         []string{"email", "phone", "note"},
		RetentionUntil: t1.Add(30 * day),
	}, map[string]string{"email": "old@example.com", "phone": "0", "note": "archived"})

	gw := gateway.New(data, pdp.NewEngine(store), reg, audit.NewLog())

	run(gw, model.AccessRequest{Subject: model.Subject{ID: "alice"}, ResourceID: "cust-1", Purpose: "analytics", At: t1.Add(day)},
		"v1 era: analyst analytics -> mask")
	run(gw, model.AccessRequest{Subject: model.Subject{ID: "alice"}, ResourceID: "cust-1", Purpose: "marketing", At: t1.Add(day)},
		"v1 era: analyst marketing -> purpose mismatch")
	histID := lastID

	run(gw, model.AccessRequest{Subject: model.Subject{ID: "alice"}, ResourceID: "cust-1", Purpose: "analytics", At: now},
		"v2 era: analyst analytics -> tokenize")
	run(gw, model.AccessRequest{Subject: model.Subject{ID: "bob"}, ResourceID: "old-1", Purpose: "analytics", At: now},
		"expired retention -> retention_expired")
	run(gw, model.AccessRequest{Subject: model.Subject{ID: "bob"}, ResourceID: "cust-1", Purpose: "support", At: now},
		"v2 era: support purpose removed -> purpose mismatch")

	// Revocation takes effect immediately.
	data.Revoke("alice")
	run(gw, model.AccessRequest{Subject: model.Subject{ID: "alice"}, ResourceID: "cust-1", Purpose: "analytics", At: now},
		"after revocation -> subject_revoked")

	// Historical replay under v1 still reproduces the original conclusion.
	replayed, err := gw.Replay(histID)
	must(err)
	fmt.Println("\n== replay of historical v1 decision ==")
	printEval(replayed)
}

var lastID string

func run(gw *gateway.Gateway, req model.AccessRequest, label string) {
	fmt.Printf("\n== %s ==\n", label)
	res := gw.Access(req)
	lastID = res.AuditID
	printEval(res.Evaluation)
	if len(res.Data) > 0 {
		fmt.Printf("data: %v\nmasked: %v\n", res.Data, res.MaskedFields)
	}
}

func printEval(ev model.Evaluation) {
	fmt.Printf("decision=%s reason=%q policy=%s rule=%q\n", ev.Decision, ev.DenyReason, ev.PolicyVersion, ev.MatchedRule)
	for _, b := range ev.Basis {
		fmt.Println("  basis:", b)
	}
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
