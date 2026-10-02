package gateway

import (
	"fmt"
	"runtime"
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

var baseTime = time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC)

func policyV1() model.Policy {
	return model.Policy{
		Version:     "v1",
		EffectiveAt: baseTime.AddDate(-1, 0, 0),
		Description: "research 访问患者数据需脱敏",
		Rules: []model.Rule{{
			Resources: []string{"res:patient-1"},
			Purposes:  []string{"research"},
			Effect:    model.EffectMask,
			FieldRules: []model.FieldRule{
				{Field: "name", Transform: "mask"},
				{Field: "ssn", Transform: "tokenize", TokenDomain: "hr"},
			},
		}},
	}
}

func newHarness(t *testing.T) (*Gateway, *policy.Store, *dataset.DataSet, *masking.Service, *audit.Log) {
	t.Helper()
	clock := func() time.Time { return baseTime }
	store := policy.NewStore()
	if err := store.Publish(policyV1()); err != nil {
		t.Fatal(err)
	}
	data := dataset.New(clock)
	data.PutRecord(model.Record{
		ID: "patient-1", Resource: "res:patient-1", Sensitivity: model.SensitivityRestricted,
		ExpiresAt: baseTime.AddDate(1, 0, 0),
		Fields:    map[string]string{"name": "Alice Chen", "ssn": "123-45-6789", "city": "Shanghai"},
	})
	data.PutGrant(model.Grant{
		ID: "g-alice", SubjectID: "u-alice", Resource: "res:patient-1",
		Purposes: []string{"research"}, ExpiresAt: baseTime.Add(24 * time.Hour),
	})
	svc := masking.NewService()
	log := audit.NewLog()
	return New(store, data, svc, log, clock), store, data, svc, log
}

func researchReq() model.AccessRequest {
	return model.AccessRequest{
		Subject:  model.Subject{ID: "u-alice", Role: "analyst", Clearance: 3},
		Resource: "res:patient-1",
		Purpose:  "research",
	}
}

func sensPtr(s model.Sensitivity) *model.Sensitivity { return &s }

// sensitivityPolicyV1 分级分段策略：public/internal 允许明文，
// confidential 需脱敏，restricted 显式拒绝。
func sensitivityPolicyV1() model.Policy {
	return model.Policy{
		Version:     "v-sens",
		EffectiveAt: baseTime.AddDate(-1, 0, 0),
		Description: "按数据分级分段：低敏明文 / 机密脱敏 / 受限拒绝",
		Rules: []model.Rule{
			{
				Resources: []string{"res:patient-1"}, Purposes: []string{"research"},
				MinSensitivity: sensPtr(model.SensitivityPublic),
				MaxSensitivity: sensPtr(model.SensitivityInternal),
				Effect:         model.EffectAllow,
			},
			{
				Resources: []string{"res:patient-1"}, Purposes: []string{"research"},
				MinSensitivity: sensPtr(model.SensitivityConfidential),
				MaxSensitivity: sensPtr(model.SensitivityConfidential),
				Effect:         model.EffectMask,
				FieldRules:     []model.FieldRule{{Field: "name", Transform: "mask"}, {Field: "ssn", Transform: "tokenize", TokenDomain: "hr"}},
			},
			{
				Resources: []string{"res:patient-1"}, Purposes: []string{"research"},
				MinSensitivity: sensPtr(model.SensitivityRestricted),
				MaxSensitivity: sensPtr(model.SensitivityRestricted),
				Effect:         model.EffectDeny,
			},
		},
	}
}

func newSensitivityHarness(t *testing.T, startLevel model.Sensitivity) (*Gateway, *policy.Store, *dataset.DataSet, *masking.Service, *audit.Log) {
	t.Helper()
	clock := func() time.Time { return baseTime }
	store := policy.NewStore()
	if err := store.Publish(sensitivityPolicyV1()); err != nil {
		t.Fatal(err)
	}
	data := dataset.New(clock)
	data.PutRecord(model.Record{
		ID: "patient-1", Resource: "res:patient-1", Sensitivity: startLevel,
		ExpiresAt: baseTime.AddDate(1, 0, 0),
		Fields:    map[string]string{"name": "Alice Chen", "ssn": "123-45-6789", "city": "Shanghai"},
	})
	data.PutGrant(model.Grant{
		ID: "g-alice", SubjectID: "u-alice", Resource: "res:patient-1",
		Purposes: []string{"research"}, ExpiresAt: baseTime.Add(24 * time.Hour),
	})
	svc := masking.NewService()
	log := audit.NewLog()
	return New(store, data, svc, log, clock), store, data, svc, log
}

func logSensitivity(t *testing.T, tag string, level model.Sensitivity, res model.AccessResult, entryID int64) {
	t.Helper()
	t.Logf("[%s] entry=%d input={subject=u-alice resource=res:patient-1 purpose=research level=%s policy=%s} decision=%d reason=%q factors=%v",
		tag, entryID, level, res.PolicyVersion, res.Decision, res.Reason, res.Basis.Factors)
}

func logResult(t *testing.T, tag string, res model.AccessResult, entryID int64) {
	t.Helper()
	t.Logf("[%s] entry=%d input={subject=u-alice resource=res:patient-1 purpose=research} decision=%d reason=%q policy=%s factors=%v",
		tag, entryID, res.Decision, res.Reason, res.PolicyVersion, res.Basis.Factors)
}

func TestAccessMaskAndAuditSafe(t *testing.T) {
	gw, _, _, svc, log := newHarness(t)
	res, id := gw.Access(researchReq())
	logResult(t, "mask", res, id)
	if res.Decision != model.DecisionMask || res.Reason != model.ReasonNone || res.PolicyVersion != "v1" {
		t.Fatalf("unexpected: %+v", res)
	}
	if res.Record.Fields["name"] != "***REDACTED***" {
		t.Fatalf("name not masked: %q", res.Record.Fields["name"])
	}
	if strings.Contains(res.Record.Fields["ssn"], "123") {
		t.Fatalf("ssn token leaks: %q", res.Record.Fields["ssn"])
	}
	if plain, ok := svc.Detokenize("hr", res.Record.Fields["ssn"]); !ok || plain != "123-45-6789" {
		t.Fatal("same-domain detokenize failed")
	}
	// 审计记录不得包含任何原文。
	entry, ok := log.Get(id)
	if !ok {
		t.Fatal("audit entry missing")
	}
	for _, dump := range []string{fmt.Sprintf("%v", entry), fmt.Sprintf("%+v", entry)} {
		if strings.Contains(dump, "Alice") || strings.Contains(dump, "123-45-6789") {
			t.Fatalf("audit content leaks raw value: %s", dump)
		}
	}
}

func TestAccessDistinctReasons(t *testing.T) {
	gw, store, data, _, _ := newHarness(t)

	// 缺少授权
	req := researchReq()
	req.Subject.ID = "u-nobody"
	res, id := gw.Access(req)
	logResult(t, "no-grant", res, id)
	if res.Reason != model.ReasonGrantMissing {
		t.Fatalf("got %q", res.Reason)
	}

	// 撤销立即生效
	if data.RevokeGrant("g-alice", baseTime) != true {
		t.Fatal("revoke failed")
	}
	res, id = gw.Access(researchReq())
	logResult(t, "revoked", res, id)
	if res.Reason != model.ReasonGrantRevoked {
		t.Fatalf("got %q", res.Reason)
	}
	// 重复撤销返回 false 且结论稳定。
	if data.RevokeGrant("g-alice", baseTime) != false {
		t.Fatal("double revoke must return false")
	}

	// 目的不匹配：换一条授权主体
	data.PutGrant(model.Grant{
		ID: "g-bob", SubjectID: "u-bob", Resource: "res:patient-1",
		Purposes: []string{"billing"}, ExpiresAt: baseTime.Add(time.Hour),
	})
	req = researchReq()
	req.Subject.ID = "u-bob"
	res, id = gw.Access(req)
	logResult(t, "purpose", res, id)
	if res.Reason != model.ReasonPurposeMismatch {
		t.Fatalf("got %q", res.Reason)
	}

	// 资源不存在
	req = researchReq()
	req.Resource = "res:ghost"
	res, id = gw.Access(req)
	logResult(t, "missing-resource", res, id)
	if res.Reason != model.ReasonResourceNotFound {
		t.Fatalf("got %q", res.Reason)
	}

	// 策略版本保留期：固定已退役版本。
	old := policyV1()
	old.Version = "v0"
	old.EffectiveAt = baseTime.AddDate(-2, 0, 0)
	old.RetiresAt = baseTime.AddDate(-1, 0, 0)
	if err := store.Publish(old); err != nil {
		t.Fatal(err)
	}
	_ = data
	req = researchReq()
	req.Subject.ID = "u-alice"
	req.PinnedVersion = "v0"
	// u-alice 的授权已撤销；先恢复一个授权以隔离策略保留期原因。
	data.PutGrant(model.Grant{
		ID: "g-alice2", SubjectID: "u-alice", Resource: "res:patient-1",
		Purposes: []string{"research"}, ExpiresAt: baseTime.Add(time.Hour),
	})
	res, id = gw.Access(req)
	logResult(t, "policy-retired", res, id)
	if res.Reason != model.ReasonPolicyRetentionExpired {
		t.Fatalf("got %q want POLICY_RETENTION_EXPIRED", res.Reason)
	}
}

func TestPolicyVersionChangeAndReplay(t *testing.T) {
	gw, store, _, _, _ := newHarness(t)

	// v1 下：脱敏允许
	before, beforeID := gw.Access(researchReq())
	logResult(t, "v1", before, beforeID)
	if before.Decision != model.DecisionMask || before.PolicyVersion != "v1" {
		t.Fatalf("v1 result = %d %s", before.Decision, before.PolicyVersion)
	}

	// 发布 v2：对 research 显式拒绝。
	v2 := policyV1()
	v2.Version = "v2"
	v2.EffectiveAt = baseTime
	v2.Description = "research 全面禁止"
	v2.Rules[0].Effect = model.EffectDeny
	v2.Rules[0].FieldRules = nil
	if err := store.Publish(v2); err != nil {
		t.Fatal(err)
	}
	after, afterID := gw.Access(researchReq())
	logResult(t, "v2", after, afterID)
	if after.Decision != model.DecisionDeny || after.Reason != model.ReasonRuleDenied || after.PolicyVersion != "v2" {
		t.Fatalf("v2 result = %d %s %q", after.Decision, after.PolicyVersion, after.Reason)
	}

	// 历史记录仍按 v1 复现，结论与当时一致。
	replayed, err := gw.Replay(beforeID)
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	if replayed.Decision != model.DecisionMask || replayed.Reason != model.ReasonNone || replayed.PolicyVersion != "v1" {
		t.Fatalf("replay drifted: %+v", replayed)
	}
	if replayed.Record != nil {
		t.Fatal("replay must not return record data")
	}
	t.Logf("[replay] entry=%d -> decision=%d reason=%q policy=%s factors=%v",
		beforeID, replayed.Decision, replayed.Reason, replayed.PolicyVersion, replayed.Basis.Factors)

	// 新记录按 v2 复现。
	replayed2, err := gw.Replay(afterID)
	if err != nil {
		t.Fatalf("replay2: %v", err)
	}
	if replayed2.Decision != model.DecisionDeny || replayed2.PolicyVersion != "v2" {
		t.Fatalf("replay2 drifted: %+v", replayed2)
	}
}

func TestInvalidMaskingConfigDenied(t *testing.T) {
	gw, store, _, _, _ := newHarness(t)
	bad := policyV1()
	bad.Version = "vbad"
	bad.EffectiveAt = baseTime
	bad.Rules[0].FieldRules = []model.FieldRule{{Field: "name", Transform: "tokenize"}} // 缺令牌域
	if err := store.Publish(bad); err != nil {
		t.Fatal(err)
	}
	req := researchReq()
	req.PinnedVersion = "vbad"
	res, id := gw.Access(req)
	logResult(t, "bad-mask-config", res, id)
	if res.Reason != model.ReasonMaskConfigInvalid || res.Decision != model.DecisionDeny {
		t.Fatalf("got %d %q, want MASK_CONFIG_INVALID deny", res.Decision, res.Reason)
	}
	if res.Record != nil {
		t.Fatal("invalid config must not return record")
	}
}

func TestConcurrentAccessConsistency(t *testing.T) {
	gw, store, data, _, log := newHarness(t)
	const n = 80
	var wg sync.WaitGroup
	results := make([]model.AccessResult, n)
	ids := make([]int64, n)
	start := make(chan struct{})

	// 一半 goroutine 持续读，一半 goroutine 做撤销/策略变更，验证互不污染。
	wg.Add(3)
	go func() { // 读者
		defer wg.Done()
		<-start
		for i := 0; i < n; i++ {
			res, id := gw.Access(researchReq())
			results[i%n] = res
			ids[i%n] = id
		}
	}()
	go func() { // 撤销者：反复撤销/恢复授权
		defer wg.Done()
		<-start
		for i := 0; i < n; i++ {
			data.RevokeGrant("g-alice", baseTime)
			data.PutGrant(model.Grant{
				ID: "g-alice", SubjectID: "u-alice", Resource: "res:patient-1",
				Purposes: []string{"research"}, ExpiresAt: baseTime.Add(24 * time.Hour), UpdatedAt: baseTime.Add(time.Duration(i) * time.Nanosecond),
			})
		}
	}()
	go func() { // 策略发布者：尝试发布新版本（同版本号重复发布应安全失败）
		defer wg.Done()
		<-start
		for i := 0; i < n; i++ {
			_ = store.Publish(policyV1())
		}
	}()
	close(start)
	wg.Wait()

	// 所有结论都必须是合法、稳定的组合，且每条审计均可复现或与自身一致。
	for i, res := range results {
		if res.Decision == model.DecisionMask {
			if res.Reason != model.ReasonNone || res.PolicyVersion != "v1" || res.Record == nil {
				t.Fatalf("iter %d inconsistent mask: %+v", i, res)
			}
			if res.Record.Fields["name"] != "***REDACTED***" {
				t.Fatalf("iter %d raw name leaked", i)
			}
		} else if res.Decision == model.DecisionDeny {
			if res.Reason != model.ReasonGrantRevoked && res.Reason != model.ReasonGrantMissing {
				t.Fatalf("iter %d unexpected deny reason %q", i, res.Reason)
			}
		} else {
			t.Fatalf("iter %d unexpected decision %d", i, res.Decision)
		}
	}
	if len(log.List()) < n {
		t.Fatalf("audit count = %d, want >= %d", len(log.List()), n)
	}
}

func TestConcurrentSameInputDeterministic(t *testing.T) {
	gw, _, _, _, _ := newHarness(t)
	const n = 100
	var wg sync.WaitGroup
	start := make(chan struct{})
	decisions := make([]model.Decision, n)
	reasons := make([]model.Reason, n)
	tokens := make([]string, n)
	wg.Add(n)
	for i := 0; i < n; i++ {
		i := i
		go func() {
			defer wg.Done()
			<-start
			res, _ := gw.Access(researchReq())
			decisions[i] = res.Decision
			reasons[i] = res.Reason
			if res.Record != nil {
				tokens[i] = res.Record.Fields["ssn"]
			}
		}()
	}
	close(start)
	wg.Wait()
	for i := 0; i < n; i++ {
		if decisions[i] != model.DecisionMask || reasons[i] != model.ReasonNone {
			t.Fatalf("goroutine %d drifted: %d %q", i, decisions[i], reasons[i])
		}
		if i > 0 && tokens[i] != tokens[0] {
			t.Fatalf("token unstable across concurrent calls: %q vs %q", tokens[i], tokens[0])
		}
	}
	t.Logf("concurrency stable: %d identical mask decisions, token=%s", n, tokens[0])
}

func TestDataRetentionExpiredDistinct(t *testing.T) {
	gw, _, data, _, _ := newHarness(t)
	// 直接把数据保留期改到过去。
	rec, _ := data.GetRecord("res:patient-1")
	rec.ExpiresAt = baseTime.Add(-time.Minute)
	data.PutRecord(rec)

	res, id := gw.Access(researchReq())
	logResult(t, "data-retention", res, id)
	if res.Reason != model.ReasonDataRetentionExpired {
		t.Fatalf("got %q want DATA_RETENTION_EXPIRED", res.Reason)
	}
	// 与策略保留期原因码必须不同。
	if res.Reason == model.ReasonPolicyRetentionExpired {
		t.Fatal("data retention and policy retention reasons must differ")
	}
}

func TestReplayAfterGrantRevoked(t *testing.T) {
	gw, _, data, _, _ := newHarness(t)
	res, id := gw.Access(researchReq())
	logResult(t, "before-revoke", res, id)
	if res.Decision != model.DecisionMask {
		t.Fatalf("setup failed: %d %q", res.Decision, res.Reason)
	}
	data.RevokeGrant("g-alice", baseTime)
	now2, _ := gw.Access(researchReq())
	logResult(t, "after-revoke", now2, 0)
	if now2.Reason != model.ReasonGrantRevoked {
		t.Fatalf("revocation not immediate: %q", now2.Reason)
	}
	// 撤销后历史结论仍可复现（审计保存了当时未撤销的授权快照）。
	replayed, err := gw.Replay(id)
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	if replayed.Decision != model.DecisionMask {
		t.Fatalf("historical conclusion drifted: %d %q", replayed.Decision, replayed.Reason)
	}
}

// 端到端：同一主体/数据/目的/策略版本，只调数据分级，结论随之变严。
func TestEndToEndDecisionFollowsSensitivity(t *testing.T) {
	gw, _, data, _, _ := newSensitivityHarness(t, model.SensitivityPublic)

	low, _ := gw.Access(researchReq())
	logSensitivity(t, "public", model.SensitivityPublic, low, 0)
	if low.Decision != model.DecisionAllow || low.PolicyVersion != "v-sens" {
		t.Fatalf("public level got %d %q", low.Decision, low.Reason)
	}

	// 升到 confidential：脱敏。
	data.Reclassify("res:patient-1", model.SensitivityConfidential, baseTime)
	mid, _ := gw.Access(researchReq())
	logSensitivity(t, "confidential", model.SensitivityConfidential, mid, 0)
	if mid.Decision != model.DecisionMask || mid.Record == nil || mid.Record.Fields["name"] != "***REDACTED***" {
		t.Fatalf("confidential level got d=%d reason=%q", mid.Decision, mid.Reason)
	}

	// 升到最高 restricted：显式拒绝。调整对之后请求立即生效。
	data.Reclassify("res:patient-1", model.SensitivityRestricted, baseTime)
	high, _ := gw.Access(researchReq())
	logSensitivity(t, "restricted", model.SensitivityRestricted, high, 0)
	if high.Decision != model.DecisionDeny || high.Reason != model.ReasonRuleDenied {
		t.Fatalf("restricted level got d=%d reason=%q, want deny RULE_DENIED", high.Decision, high.Reason)
	}

	// 验收红线：最低档与最高档结论不同。
	if low.Decision == high.Decision && low.Reason == high.Reason {
		t.Fatal("raising sensitivity alone must change the conclusion")
	}
}

// 端到端：授权分级上限生效，且拒绝理由与缺授权/撤销/目的不匹配可区分。
func TestEndToEndGrantSensitivityCapDistinct(t *testing.T) {
	// 策略规则不按分级筛选（存量策略），由授权上限单独把关。
	gw, _, data, _, _ := newHarness(t)
	capLevel := model.SensitivityInternal
	data.PutGrant(model.Grant{
		ID: "g-capped", SubjectID: "u-capped", Resource: "res:patient-1",
		Purposes: []string{"research"}, ExpiresAt: baseTime.Add(24 * time.Hour),
		MaxSensitivity: &capLevel,
	})
	req := researchReq()
	req.Subject.ID = "u-capped"

	// 数据当前是 restricted（harness 默认），超过 internal 上限。
	res, id := gw.Access(req)
	logResult(t, "grant-cap-exceeded", res, id)
	if res.Decision != model.DecisionDeny || res.Reason != model.ReasonGrantSensitivityCap {
		t.Fatalf("got d=%d reason=%q, want GRANT_SENSITIVITY_EXCEEDED", res.Decision, res.Reason)
	}
	for _, other := range []model.Reason{
		model.ReasonGrantMissing, model.ReasonGrantRevoked,
		model.ReasonPurposeMismatch, model.ReasonRuleDenied,
		model.ReasonSensitivityOutOfScope,
	} {
		if res.Reason == other {
			t.Fatalf("cap reason must be distinct from %q", other)
		}
	}

	// 降到上限以内：结论回到正常脱敏，证明是上限在把关而非其他原因。
	rec, _ := data.GetRecord("res:patient-1")
	rec.Sensitivity = model.SensitivityInternal
	data.PutRecord(rec)
	res2, id2 := gw.Access(req)
	logResult(t, "grant-cap-within", res2, id2)
	if res2.Decision != model.DecisionMask || res2.Reason != model.ReasonNone {
		t.Fatalf("within cap got d=%d reason=%q, want mask", res2.Decision, res2.Reason)
	}
}

// 端到端：重新分级后新请求按新分级判定，而历史审计仍按当时分级复现旧结论。
func TestReclassifyThenReplayUsesHistoricalSnapshot(t *testing.T) {
	gw, _, data, _, _ := newSensitivityHarness(t, model.SensitivityConfidential)

	// 调整前：confidential -> mask，留下审计。
	before, beforeID := gw.Access(researchReq())
	logSensitivity(t, "before-reclassify", model.SensitivityConfidential, before, beforeID)
	if before.Decision != model.DecisionMask {
		t.Fatalf("setup: got d=%d reason=%q", before.Decision, before.Reason)
	}

	// 升到最高：新请求立即按 restricted 判定为拒绝。
	if !data.Reclassify("res:patient-1", model.SensitivityRestricted, baseTime) {
		t.Fatal("reclassify failed")
	}
	after, afterID := gw.Access(researchReq())
	logSensitivity(t, "after-reclassify", model.SensitivityRestricted, after, afterID)
	if after.Decision != model.DecisionDeny || after.Reason != model.ReasonRuleDenied {
		t.Fatalf("new request must follow new level: d=%d reason=%q", after.Decision, after.Reason)
	}

	// 历史审计仍按当时 confidential 快照复现出 mask，结论不漂移。
	replayed, err := gw.Replay(beforeID)
	if err != nil {
		t.Fatalf("replay historical: %v", err)
	}
	t.Logf("[replay-old] entry=%d level-snapshot=confidential decision=%d reason=%q policy=%s factors=%v",
		beforeID, replayed.Decision, replayed.Reason, replayed.PolicyVersion, replayed.Basis.Factors)
	if replayed.Decision != model.DecisionMask || replayed.Reason != model.ReasonNone {
		t.Fatalf("historical replay drifted to d=%d reason=%q", replayed.Decision, replayed.Reason)
	}
	if replayed.Record != nil {
		t.Fatal("replay must not return record data")
	}

	// 新审计按 restricted 复现为拒绝。
	replayed2, err := gw.Replay(afterID)
	if err != nil {
		t.Fatalf("replay new: %v", err)
	}
	if replayed2.Decision != model.DecisionDeny || replayed2.Reason != model.ReasonRuleDenied {
		t.Fatalf("new replay drifted: d=%d reason=%q", replayed2.Decision, replayed2.Reason)
	}

	// 审计条目必须各自携带不同的分级快照。
	e1, _ := gw.log.Get(beforeID)
	e2, _ := gw.log.Get(afterID)
	if e1.RecordSensitivity != model.SensitivityConfidential || e2.RecordSensitivity != model.SensitivityRestricted {
		t.Fatalf("audit sensitivity snapshots wrong: %s vs %s", e1.RecordSensitivity, e2.RecordSensitivity)
	}
}

// 端到端：分级超出策略规则覆盖范围时拒绝，不会被其它允许规则放行。
func TestEndToEndSensitivityOutOfScopeDenied(t *testing.T) {
	clock := func() time.Time { return baseTime }
	store := policy.NewStore()
	p := sensitivityPolicyV1()
	// 删除最高档 deny 规则，使 restricted 不被任何规则覆盖。
	p.Rules = p.Rules[:2]
	if err := store.Publish(p); err != nil {
		t.Fatal(err)
	}
	data := dataset.New(clock)
	data.PutRecord(model.Record{
		ID: "patient-1", Resource: "res:patient-1", Sensitivity: model.SensitivityRestricted,
		Fields: map[string]string{"name": "Alice Chen"},
	})
	data.PutGrant(model.Grant{
		ID: "g-alice", SubjectID: "u-alice", Resource: "res:patient-1",
		Purposes: []string{"research"}, ExpiresAt: baseTime.Add(24 * time.Hour),
	})
	gw := New(store, data, masking.NewService(), audit.NewLog(), clock)

	res, id := gw.Access(researchReq())
	logSensitivity(t, "out-of-scope", model.SensitivityRestricted, res, id)
	if res.Decision != model.DecisionDeny || res.Reason != model.ReasonSensitivityOutOfScope {
		t.Fatalf("got d=%d reason=%q, want SENSITIVITY_OUT_OF_SCOPE", res.Decision, res.Reason)
	}
	if res.Record != nil {
		t.Fatal("out-of-scope deny must not return record")
	}
}

// 并发混合：持续重分级与持续访问交错。要求：
//   - 带 -race 多轮稳定通过（单次判定不会读到撕裂/半新半旧的分级状态）；
//   - 每次结论只能是当前分级分段策略允许的合法组合；
//   - 每条审计事后都能按其分级快照复现出与当时完全一致的结论。
func TestConcurrentReclassifyMixedAccess(t *testing.T) {
	gw, _, data, _, _ := newSensitivityHarness(t, model.SensitivityConfidential)
	const writers, readers, perReader = 4, 8, 60
	levels := []model.Sensitivity{
		model.SensitivityPublic, model.SensitivityInternal,
		model.SensitivityConfidential, model.SensitivityRestricted,
	}
	var (
		writerWg, readerWg sync.WaitGroup
		mu                sync.Mutex
		allIDs            []int64
		seen              = map[model.Decision]int{}
	)
	stop := make(chan struct{})

	for w := 0; w < writers; w++ {
		w := w
		writerWg.Add(1)
		go func() {
			defer writerWg.Done()
			for i := 0; ; i++ {
				select {
				case <-stop:
					return
				default:
					data.Reclassify("res:patient-1", levels[(i+w)%len(levels)], baseTime)
					runtime.Gosched() // 给读者与其它写者让路，制造真实交错
				}
			}
		}()
	}
	for r := 0; r < readers; r++ {
		readerWg.Add(1)
		go func() {
			defer readerWg.Done()
			ids := make([]int64, 0, perReader)
			for i := 0; i < perReader; i++ {
				res, id := gw.Access(researchReq())
				// 分级分段策略下只可能出现这三种合法结论。
				switch res.Decision {
				case model.DecisionAllow:
					if res.Reason != model.ReasonNone {
						t.Errorf("allow with reason %q", res.Reason)
					}
				case model.DecisionMask:
					if res.Reason != model.ReasonNone || res.Record == nil || res.Record.Fields["name"] != "***REDACTED***" {
						t.Errorf("inconsistent mask: reason=%q", res.Reason)
					}
				case model.DecisionDeny:
					if res.Reason != model.ReasonRuleDenied {
						t.Errorf("unexpected deny reason %q", res.Reason)
					}
				}
				ids = append(ids, id)
				mu.Lock()
				seen[res.Decision]++
				mu.Unlock()
			}
			mu.Lock()
			allIDs = append(allIDs, ids...)
			mu.Unlock()
		}()
	}
	readerWg.Wait()
	close(stop)
	writerWg.Wait()

	// 全部审计按各自分级快照复现，结论必须与当时一致（不随并发重分级漂移）。
	mu.Lock()
	ids := append([]int64(nil), allIDs...)
	mu.Unlock()
	if len(ids) != readers*perReader {
		t.Fatalf("collected %d audits, want %d", len(ids), readers*perReader)
	}
	for _, id := range ids {
		e, ok := gw.log.Get(id)
		if !ok {
			t.Fatalf("audit %d missing", id)
		}
		replayed, err := gw.Replay(id)
		if err != nil {
			t.Fatalf("replay %d: %v", id, err)
		}
		if replayed.Decision != e.Decision || replayed.Reason != e.Reason || replayed.PolicyVersion != e.PolicyVersion {
			t.Fatalf("audit %d drifted: orig=(%d %q %s) replay=(%d %q %s)",
				id, e.Decision, e.Reason, e.PolicyVersion,
				replayed.Decision, replayed.Reason, replayed.PolicyVersion)
		}
	}
	t.Logf("[concurrent-reclassify] accesses=%d decisions seen=%v, every audit replayed consistently",
		len(ids), seen)
}
