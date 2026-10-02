// 本地演示：内存数据 + 策略判定 + 脱敏/令牌化 + 审计复现。
// 运行：go run ./cmd/demo
package main

import (
	"fmt"
	"time"

	"github.com/lisama569/data-access-gateway-go/internal/audit"
	"github.com/lisama569/data-access-gateway-go/internal/dataset"
	"github.com/lisama569/data-access-gateway-go/internal/gateway"
	"github.com/lisama569/data-access-gateway-go/internal/masking"
	"github.com/lisama569/data-access-gateway-go/internal/model"
	"github.com/lisama569/data-access-gateway-go/internal/policy"
)

func main() {
	now := time.Date(2026, 9, 23, 10, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }

	store := policy.NewStore()
	p1 := model.Policy{
		Version:     "2026-01",
		EffectiveAt: now.AddDate(-1, 0, 0),
		Description: "v1: research 目的访问患者数据需脱敏",
		Rules: []model.Rule{{
			Resources: []string{"patient:1001"},
			Purposes:  []string{"research"},
			Effect:    model.EffectMask,
			FieldRules: []model.FieldRule{
				{Field: "name", Transform: "mask"},
				{Field: "ssn", Transform: "tokenize", TokenDomain: "patient-hr"},
			},
		}},
	}
	if err := store.Publish(p1); err != nil {
		panic(err)
	}

	data := dataset.New(clock)
	data.PutRecord(model.Record{
		ID: "1001", Resource: "patient:1001", Sensitivity: model.SensitivityRestricted,
		ExpiresAt: now.AddDate(1, 0, 0),
		Fields: map[string]string{
			"name": "Alice Chen", "ssn": "123-45-6789", "city": "Shanghai",
		},
	})
	data.PutGrant(model.Grant{
		ID: "g1", SubjectID: "u-alice", Resource: "patient:1001",
		Purposes: []string{"research"}, ExpiresAt: now.Add(24 * time.Hour),
	})

	svc := masking.NewService()
	log := audit.NewLog()
	gw := gateway.New(store, data, svc, log, clock)

	subject := model.Subject{ID: "u-alice", Role: "analyst", Clearance: 3}
	req := model.AccessRequest{Subject: subject, Resource: "patient:1001", Purpose: "research"}
	res, entryID := gw.Access(req)
	fmt.Printf("decision=%v reason=%q policy=%s fields=%v masked=%v\n",
		res.Decision, res.Reason, res.PolicyVersion, res.Record.Fields, res.MaskedFields)

	// 令牌域内可逆还原。
	tok := res.Record.Fields["ssn"]
	if plain, ok := svc.Detokenize("patient-hr", tok); ok {
		fmt.Printf("detokenize(same domain) => %s\n", plain)
	}
	if _, ok := svc.Detokenize("other-domain", tok); !ok {
		fmt.Println("detokenize(other domain) => denied (domain isolated)")
	}

	// 策略退役后发布新版本。
	p2 := p1
	p2.Version = "2026-09"
	p2.EffectiveAt = now
	p2.Rules = []model.Rule{{Resources: []string{"patient:1001"}, Purposes: []string{"research"}, Effect: model.EffectDeny}}
	_ = store.Publish(p2)
	res2, _ := gw.Access(model.AccessRequest{Subject: subject, Resource: "patient:1001", Purpose: "research"})
	fmt.Printf("after policy update: decision=%v reason=%q policy=%s\n", res2.Decision, res2.Reason, res2.PolicyVersion)

	// 撤销授权立即生效。
	data.RevokeGrant("g1", now)
	res3, _ := gw.Access(model.AccessRequest{Subject: subject, Resource: "patient:1001", Purpose: "research"})
	fmt.Printf("after revocation: decision=%v reason=%q\n", res3.Decision, res3.Reason)

	// 历史记录按当时版本复现。
	replayed, err := gw.Replay(entryID)
	if err != nil {
		panic(err)
	}
	fmt.Printf("replay entry %d: decision=%v reason=%q policy=%s\n",
		entryID, replayed.Decision, replayed.Reason, replayed.PolicyVersion)

	// 授权分级上限：新授权最多覆盖到 internal，而数据分级为 restricted。
	capInternal := model.SensitivityInternal
	data.PutGrant(model.Grant{
		ID: "g2", SubjectID: "u-alice", Resource: "patient:1001",
		Purposes: []string{"research"}, ExpiresAt: now.Add(24 * time.Hour),
		MaxSensitivity: &capInternal, UpdatedAt: now.Add(time.Minute),
	})
	res4, _ := gw.Access(model.AccessRequest{Subject: subject, Resource: "patient:1001", Purpose: "research"})
	fmt.Printf("capped grant vs restricted data: decision=%v reason=%q factors=%v\n",
		res4.Decision, res4.Reason, res4.Basis.Factors)

	// 分级调整对之后的请求立即生效；历史审计仍按当时分级快照复现。
	data.Reclassify("patient:1001", model.SensitivityInternal)
	res5, entry5 := gw.Access(model.AccessRequest{Subject: subject, Resource: "patient:1001", Purpose: "research"})
	fmt.Printf("after reclassify to internal: decision=%v reason=%q policy=%s\n",
		res5.Decision, res5.Reason, res5.PolicyVersion)
	if _, err := gw.Replay(entry5); err != nil {
		panic(err)
	}
	fmt.Printf("replay entry %d consistent after reclassification\n", entry5)
}
