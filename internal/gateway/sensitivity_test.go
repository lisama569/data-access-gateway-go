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
	"github.com/lisama569/data-access-gateway-go/internal/policy"
)

// sensPolicy 分级感知策略：
//   - R0: [public, internal] -> allow
//   - R1: [confidential]     -> mask(name)
//   - R2: 未声明分级          -> allow（陷阱规则：分级越界时绝不允许命中它放行）
//   - restricted 不被任何分级规则覆盖 -> SENSITIVITY_NOT_COVERED
func sensPolicy() model.Policy {
	return model.Policy{
		Version:     "v-sens",
		EffectiveAt: baseTime.AddDate(-1, 0, 0),
		Description: "按数据分级区分 allow/mask/拒绝对陷阱规则",
		Rules: []model.Rule{
			{
				Resources:   []string{"res:graded"},
				Purposes:    []string{"analytics"},
				Sensitivity: &model.SensitivityRange{Min: model.SensitivityPublic, Max: model.SensitivityInternal},
				Effect:      model.EffectAllow,
			},
			{
				Resources:   []string{"res:graded"},
				Purposes:    []string{"analytics"},
				Sensitivity: &model.SensitivityRange{Min: model.SensitivityConfidential, Max: model.SensitivityConfidential},
				Effect:      model.EffectMask,
				FieldRules:  []model.FieldRule{{Field: "name", Transform: "mask"}},
			},
			{
				Resources: []string{"res:graded"},
				Purposes:  []string{"analytics"},
				Effect:    model.EffectAllow, // 未声明分级：候选中有约束规则时必须被遮蔽
			},
		},
	}
}

func newSensHarness(t *testing.T, grant model.Grant) (*Gateway, *dataset.DataSet, *audit.Log) {
	t.Helper()
	clock := func() time.Time { return baseTime }
	store := policy.NewStore()
	if err := store.Publish(sensPolicy()); err != nil {
		t.Fatal(err)
	}
	data := dataset.New(clock)
	data.PutRecord(model.Record{
		ID: "graded-1", Resource: "res:graded", Sensitivity: model.SensitivityPublic,
		ExpiresAt: baseTime.AddDate(1, 0, 0),
		Fields:    map[string]string{"name": "Alice Chen", "city": "Shanghai"},
	})
	if grant.ID != "" {
		data.PutGrant(grant)
	}
	log := audit.NewLog()
	return New(store, data, masking.NewService(), log, clock), data, log
}

func analyticsReq() model.AccessRequest {
	return model.AccessRequest{
		Subject:  model.Subject{ID: "u-bob", Role: "analyst", Clearance: 3},
		Resource: "res:graded",
		Purpose:  "analytics",
	}
}

func logSens(t *testing.T, tag string, level model.Sensitivity, res model.AccessResult, entryID int64) {
	t.Helper()
	t.Logf("[%s] entry=%d input={subject=u-bob resource=res:graded purpose=analytics sensitivity=%s} "+
		"decision=%d reason=%q policy=%s factors=%v",
		tag, entryID, level, res.Decision, res.Reason, res.PolicyVersion, res.Basis.Factors)
}

// 同一输入只改分级：结论必须随之变严，且越界时不得命中未声明分级的允许规则。
func TestSensitivityChangesDecision(t *testing.T) {
	grant := model.Grant{
		ID: "g-bob", SubjectID: "u-bob", Resource: "res:graded",
		Purposes: []string{"analytics"}, ExpiresAt: baseTime.Add(24 * time.Hour),
	}
	gw, data, _ := newSensHarness(t, grant)

	type want struct {
		decision model.Decision
		reason   model.Reason
	}
	steps := []struct {
		level model.Sensitivity
		want  want
	}{
		{model.SensitivityPublic, want{model.DecisionAllow, model.ReasonNone}},
		{model.SensitivityInternal, want{model.DecisionAllow, model.ReasonNone}},
		{model.SensitivityConfidential, want{model.DecisionMask, model.ReasonNone}},
		// restricted 落在所有分级规则覆盖范围之外：必须拒绝，且理由可区分，
		// 绝不能命中未声明分级的陷阱允许规则。
		{model.SensitivityRestricted, want{model.DecisionDeny, model.ReasonSensitivityNotCovered}},
	}
	prevRank := -1
	rank := map[model.Decision]int{model.DecisionDeny: 2, model.DecisionMask: 1, model.DecisionAllow: 0}
	for _, s := range steps {
		if !data.Reclassify("res:graded", s.level) {
			t.Fatal("reclassify failed")
		}
		res, id := gw.Access(analyticsReq())
		logSens(t, "graded", s.level, res, id)
		if res.Decision != s.want.decision || res.Reason != s.want.reason {
			t.Fatalf("level=%s: got decision=%d reason=%q, want %v",
				s.level, res.Decision, res.Reason, s.want)
		}
		if r := rank[res.Decision]; r < prevRank {
			t.Fatalf("level=%s: decision became less strict as sensitivity rose", s.level)
		} else {
			prevRank = r
		}
		if s.level == model.SensitivityRestricted {
			// 判定依据里必须能看到分级未覆盖，而不是命中了 allow 规则。
			joined := strings.Join(res.Basis.Factors, " ")
			if !strings.Contains(joined, "sensitivity_not_covered") {
				t.Fatalf("basis missing sensitivity_not_covered: %v", res.Basis.Factors)
			}
		}
	}
}

// 授权分级上限：超过上限一律拒绝，理由与缺授权/撤销/目的不匹配可区分；
// 未声明上限的存量授权行为不变。
func TestGrantSensitivityCap(t *testing.T) {
	capInternal := model.SensitivityInternal
	capped := model.Grant{
		ID: "g-capped", SubjectID: "u-bob", Resource: "res:graded",
		Purposes: []string{"analytics"}, ExpiresAt: baseTime.Add(24 * time.Hour),
		MaxSensitivity: &capInternal,
	}
	gw, data, _ := newSensHarness(t, capped)

	// 上限内：正常放行。
	res, id := gw.Access(analyticsReq())
	logSens(t, "cap-within", model.SensitivityPublic, res, id)
	if res.Decision != model.DecisionAllow {
		t.Fatalf("within cap: got decision=%d reason=%q", res.Decision, res.Reason)
	}

	// 超过上限：GRANT_SENSITIVITY_CAP，且与其他授权类拒绝理由可区分。
	data.Reclassify("res:graded", model.SensitivityConfidential)
	res, id = gw.Access(analyticsReq())
	logSens(t, "cap-exceeded", model.SensitivityConfidential, res, id)
	if res.Decision != model.DecisionDeny || res.Reason != model.ReasonGrantSensitivityCap {
		t.Fatalf("got decision=%d reason=%q, want deny/%q", res.Decision, res.Reason, model.ReasonGrantSensitivityCap)
	}
	for _, other := range []model.Reason{
		model.ReasonGrantMissing, model.ReasonGrantRevoked,
		model.ReasonPurposeMismatch, model.ReasonSensitivityNotCovered,
	} {
		if res.Reason == other {
			t.Fatalf("cap reason must be distinct from %q", other)
		}
	}

	// 存量授权（未声明上限）：同样的数据分级不得触发上限拒绝。
	legacy := model.Grant{
		ID: "g-legacy", SubjectID: "u-bob", Resource: "res:graded",
		Purposes: []string{"analytics"}, ExpiresAt: baseTime.Add(24 * time.Hour),
		UpdatedAt: baseTime.Add(time.Hour), // 更新的授权优先被 FindGrant 选中
	}
	gw2, data2, _ := newSensHarness(t, legacy)
	data2.Reclassify("res:graded", model.SensitivityConfidential)
	res2, id2 := gw2.Access(analyticsReq())
	logSens(t, "legacy-no-cap", model.SensitivityConfidential, res2, id2)
	if res2.Reason == model.ReasonGrantSensitivityCap {
		t.Fatal("legacy grant without cap must not trigger GRANT_SENSITIVITY_CAP")
	}
	if res2.Decision != model.DecisionMask {
		t.Fatalf("legacy grant: got decision=%d reason=%q, want mask", res2.Decision, res2.Reason)
	}
}

// 重新分级后新请求按新分级判定；历史审计仍按当时分级快照复现。
func TestReclassifyReplayConsistency(t *testing.T) {
	grant := model.Grant{
		ID: "g-bob", SubjectID: "u-bob", Resource: "res:graded",
		Purposes: []string{"analytics"}, ExpiresAt: baseTime.Add(24 * time.Hour),
	}
	gw, data, log := newSensHarness(t, grant)

	// 旧分级 public -> allow，留痕。
	res, id := gw.Access(analyticsReq())
	logSens(t, "before-reclassify", model.SensitivityPublic, res, id)
	if res.Decision != model.DecisionAllow {
		t.Fatalf("got decision=%d reason=%q", res.Decision, res.Reason)
	}
	entry, ok := log.Get(id)
	if !ok {
		t.Fatal("audit entry missing")
	}
	if entry.RecordSensitivity != model.SensitivityPublic {
		t.Fatalf("audit sensitivity snapshot = %v, want public", entry.RecordSensitivity)
	}

	// 调整为 restricted：新请求立即按新分级判定。
	data.Reclassify("res:graded", model.SensitivityRestricted)
	res2, id2 := gw.Access(analyticsReq())
	logSens(t, "after-reclassify", model.SensitivityRestricted, res2, id2)
	if res2.Decision != model.DecisionDeny || res2.Reason != model.ReasonSensitivityNotCovered {
		t.Fatalf("got decision=%d reason=%q", res2.Decision, res2.Reason)
	}

	// 历史记录仍按当时分级快照复现出 allow。
	replayed, err := gw.Replay(id)
	if err != nil {
		t.Fatalf("replay failed: %v", err)
	}
	if replayed.Decision != model.DecisionAllow || replayed.Reason != model.ReasonNone {
		t.Fatalf("replay = decision=%d reason=%q, want allow", replayed.Decision, replayed.Reason)
	}
	t.Logf("[replay] entry=%d decision=%d reason=%q policy=%s factors=%v",
		id, replayed.Decision, replayed.Reason, replayed.PolicyVersion, replayed.Basis.Factors)
}

// 并发调整分级与访问混合：单次判定不得读到撕裂状态，
// 每条审计记录都必须能按其分级快照复现出一致结论。
func TestConcurrentReclassifyAndAccess(t *testing.T) {
	grant := model.Grant{
		ID: "g-bob", SubjectID: "u-bob", Resource: "res:graded",
		Purposes: []string{"analytics"}, ExpiresAt: baseTime.Add(24 * time.Hour),
	}
	gw, data, log := newSensHarness(t, grant)

	levels := []model.Sensitivity{
		model.SensitivityPublic, model.SensitivityInternal,
		model.SensitivityConfidential, model.SensitivityRestricted,
	}
	allowedReasons := map[model.Reason]bool{
		model.ReasonNone:                  true,
		model.ReasonSensitivityNotCovered: true,
	}

	const accessors = 40
	const rounds = 25
	var wg sync.WaitGroup
	errs := make(chan error, accessors*rounds+4)

	for i := 0; i < accessors; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < rounds; j++ {
				res, _ := gw.Access(analyticsReq())
				if !allowedReasons[res.Reason] {
					errs <- fmt.Errorf("unexpected reason %q (decision=%d)", res.Reason, res.Decision)
				}
			}
		}()
	}
	for i := 0; i < 4; i++ {
		wg.Add(1)
		i := i
		go func() {
			defer wg.Done()
			for j := 0; j < rounds; j++ {
				if !data.Reclassify("res:graded", levels[(i+j)%len(levels)]) {
					errs <- fmt.Errorf("reclassify failed")
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}

	// 每条审计记录都必须能按当时的分级快照复现出一致结论：
	// 若单次判定读到了一半旧一半新的分级状态，复现必然漂移。
	entries := log.List()
	if len(entries) != accessors*rounds {
		t.Fatalf("audit entries = %d, want %d", len(entries), accessors*rounds)
	}
	for _, e := range entries {
		if _, err := gw.Replay(e.ID); err != nil {
			t.Fatalf("replay drift for entry %d (sensitivity=%s): %v", e.ID, e.RecordSensitivity, err)
		}
	}
	t.Logf("replayed %d entries consistently under concurrent reclassification", len(entries))
}
