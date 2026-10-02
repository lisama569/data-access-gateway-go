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
	ptr := func(s model.Sensitivity) *model.Sensitivity { return &s }
	p1 := model.Policy{
		Version:     "2026-01",
		EffectiveAt: now.AddDate(-1, 0, 0),
		Description: "按数据分级：低敏明文 / 机密脱敏 / 受限拒绝",
		Rules: []model.Rule{
			{
				Resources: []string{"patient:1001"}, Purposes: []string{"research"},
				MinSensitivity: ptr(model.SensitivityPublic), MaxSensitivity: ptr(model.SensitivityInternal),
				Effect: model.EffectAllow,
			},
			{
				Resources: []string{"patient:1001"}, Purposes: []string{"research"},
				MinSensitivity: ptr(model.SensitivityConfidential), MaxSensitivity: ptr(model.SensitivityConfidential),
				Effect: model.EffectMask,
				FieldRules: []model.FieldRule{
					{Field: "name", Transform: "mask"},
					{Field: "ssn", Transform: "tokenize", TokenDomain: "patient-hr"},
				},
			},
			{
				Resources: []string{"patient:1001"}, Purposes: []string{"research"},
				MinSensitivity: ptr(model.SensitivityRestricted), MaxSensitivity: ptr(model.SensitivityRestricted),
				Effect: model.EffectDeny,
			},
		},
	}
	if err := store.Publish(p1); err != nil {
		panic(err)
	}

	data := dataset.New(clock)
	data.PutRecord(model.Record{
		ID: "1001", Resource: "patient:1001", Sensitivity: model.SensitivityConfidential,
		ExpiresAt: now.AddDate(1, 0, 0),
		Fields: map[string]string{
			"name": "Alice Chen", "ssn": "123-45-6789", "city": "Shanghai",
		},
	})
	// 授权声明分级上限：最多覆盖到 confidential，restricted 数据一律拒绝。
	capLevel := model.SensitivityConfidential
	data.PutGrant(model.Grant{
		ID: "g1", SubjectID: "u-alice", Resource: "patient:1001",
		Purposes: []string{"research"}, ExpiresAt: now.Add(24 * time.Hour),
		MaxSensitivity: &capLevel,
	})

	svc := masking.NewService()
	log := audit.NewLog()
	gw := gateway.New(store, data, svc, log, clock)

	subject := model.Subject{ID: "u-alice", Role: "analyst", Clearance: 3}
	req := model.AccessRequest{Subject: subject, Resource: "patient:1001", Purpose: "research"}
	res, entryID := gw.Access(req)
	fmt.Printf("confidential: decision=%v reason=%q policy=%s fields=%v masked=%v\n",
		res.Decision, res.Reason, res.PolicyVersion, res.Record.Fields, res.MaskedFields)

	// 令牌域内可逆还原。
	tok := res.Record.Fields["ssn"]
	if plain, ok := svc.Detokenize("patient-hr", tok); ok {
		fmt.Printf("detokenize(same domain) => %s\n", plain)
	}
	if _, ok := svc.Detokenize("other-domain", tok); !ok {
		fmt.Println("detokenize(other domain) => denied (domain isolated)")
	}

	// 只把数据分级从 confidential 升到 restricted：结论立即变严为拒绝。
	data.Reclassify("patient:1001", model.SensitivityRestricted, now)
	resHigh, _ := gw.Access(req)
	fmt.Printf("after reclassify -> restricted: decision=%v reason=%q\n", resHigh.Decision, resHigh.Reason)

	// 历史审计仍按当时 confidential 快照复现出脱敏结论。
	replayed, err := gw.Replay(entryID)
	if err != nil {
		panic(err)
	}
	fmt.Printf("replay historical entry %d: decision=%v reason=%q policy=%s (sensitivity snapshot=confidential)\n",
		entryID, replayed.Decision, replayed.Reason, replayed.PolicyVersion)

	// 降回机密级，证明是分级而非其它因素在主导结论。
	data.Reclassify("patient:1001", model.SensitivityConfidential, now)
	resBack, _ := gw.Access(req)
	fmt.Printf("reclassify back -> confidential: decision=%v reason=%q\n", resBack.Decision, resBack.Reason)
}
