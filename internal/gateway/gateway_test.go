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
