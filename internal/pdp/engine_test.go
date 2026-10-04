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

// sensitivityPolicy 构造按分级分段的策略：
// public/internal 允许明文；confidential 需脱敏；restricted 显式拒绝。
func sensitivityPolicy() model.Policy {
	ptr := func(s model.Sensitivity) *model.Sensitivity { return &s }
	return model.Policy{
		Version:     "v-sens",
		EffectiveAt: t0.AddDate(-1, 0, 0),
		Rules: []model.Rule{
			{
				Resources: []string{"res:1"}, Purposes: []string{"research"},
				MinSensitivity: ptr(model.SensitivityPublic), MaxSensitivity: ptr(model.SensitivityInternal),
				Effect: model.EffectAllow,
			},
			{
				Resources: []string{"res:1"}, Purposes: []string{"research"},
				MinSensitivity: ptr(model.SensitivityConfidential), MaxSensitivity: ptr(model.SensitivityConfidential),
				Effect:     model.EffectMask,
				FieldRules: []model.FieldRule{{Field: "name", Transform: "mask"}},
			},
			{
				Resources: []string{"res:1"}, Purposes: []string{"research"},
				MinSensitivity: ptr(model.SensitivityRestricted), MaxSensitivity: ptr(model.SensitivityRestricted),
				Effect: model.EffectDeny,
			},
		},
	}
}

// 同一数据/主体/目的/策略版本，只调数据分级，结论必须随之变严。
func TestSensitivityLevelChangesDecision(t *testing.T) {
	store := fakeStore{pols: map[string]model.Policy{"v-sens": sensitivityPolicy()}}
	e := NewEngine(store, func() time.Time { return t0 })

	cases := []struct {
		level  model.Sensitivity
		wantD  model.Decision
		wantR  model.Reason
	}{
		{model.SensitivityPublic, model.DecisionAllow, model.ReasonNone},
		{model.SensitivityInternal, model.DecisionAllow, model.ReasonNone},
		{model.SensitivityConfidential, model.DecisionMask, model.ReasonNone},
		{model.SensitivityRestricted, model.DecisionDeny, model.ReasonRuleDenied},
	}
	var prev model.Decision
	for i, tc := range cases {
		rec := &model.Record{Resource: "res:1", Sensitivity: tc.level}
		req := baseReq(validGrant())
		d, reason, pol, basis := e.Verdict(req, rec)
		t.Logf("[level=%s] input={subject=u1 resource=res:1 purpose=research level=%s policy=%s} decision=%d reason=%q factors=%v",
			tc.level, tc.level, pol.Version, d, reason, basis.Factors)
		if d != tc.wantD || reason != tc.wantR {
			t.Fatalf("level %s: got d=%d reason=%q, want d=%d reason=%q",
				tc.level, d, reason, tc.wantD, tc.wantR)
		}
		// 枚举序 Deny(0) < Mask(1) < Allow(2)：数值变大意味着变宽松。
		if i > 0 && d > prev {
			t.Fatalf("decision must not get more permissive as sensitivity rises: %d -> %d", prev, d)
		}
		prev = d
	}

	// 验收红线：最低档与最高档结论必须不同（不能还是原来的结论）。
	loRec := &model.Record{Resource: "res:1", Sensitivity: model.SensitivityPublic}
	hiRec := &model.Record{Resource: "res:1", Sensitivity: model.SensitivityRestricted}
	lo, loReason, _, _ := e.Verdict(baseReq(validGrant()), loRec)
	hi, hiReason, _, _ := e.Verdict(baseReq(validGrant()), hiRec)
	if lo == hi && loReason == hiReason {
		t.Fatalf("lowest and highest sensitivity must yield distinguishable conclusions, both = %d %q", lo, loReason)
	}
}

// 分级落在所有规则覆盖范围之外时，必须拒绝且不能误命中后面的允许规则。
func TestSensitivityOutOfScopeNoBypass(t *testing.T) {
	ptr := func(s model.Sensitivity) *model.Sensitivity { return &s }
	p := model.Policy{
		Version:     "v-scope",
		EffectiveAt: t0.AddDate(-1, 0, 0),
		Rules: []model.Rule{
			// 只覆盖最低两级。
			{
				Resources: []string{"res:1"}, Purposes: []string{"research"},
				MinSensitivity: ptr(model.SensitivityPublic), MaxSensitivity: ptr(model.SensitivityInternal),
				Effect: model.EffectMask,
				FieldRules: []model.FieldRule{{Field: "name", Transform: "mask"}},
			},
			// 陷阱：一条通配允许规则也只声明覆盖低档，高档数据绝不能借它放行。
			{
				Resources: []string{"*"}, Purposes: []string{"*"},
				MinSensitivity: ptr(model.SensitivityPublic), MaxSensitivity: ptr(model.SensitivityConfidential),
				Effect: model.EffectAllow,
			},
		},
	}
	store := fakeStore{pols: map[string]model.Policy{"v-scope": p}}
	e := NewEngine(store, func() time.Time { return t0 })

	// 低档仍按第一条规则脱敏。
	low := &model.Record{Resource: "res:1", Sensitivity: model.SensitivityInternal}
	d, reason, _, basis := e.Verdict(baseReq(validGrant()), low)
	t.Logf("[in-scope level=internal] decision=%d reason=%q factors=%v", d, reason, basis.Factors)
	if d != model.DecisionMask {
		t.Fatalf("in-scope low level got d=%d, want mask", d)
	}

	// 最高档超出两条规则的覆盖区间：必须拒绝为 SENSITIVITY_OUT_OF_SCOPE，
	// 且绝不能被第二条通配 allow 放行。
	high := &model.Record{Resource: "res:1", Sensitivity: model.SensitivityRestricted}
	d, reason, _, basis = e.Verdict(baseReq(validGrant()), high)
	t.Logf("[out-of-scope level=restricted] decision=%d reason=%q factors=%v", d, reason, basis.Factors)
	if d != model.DecisionDeny || reason != model.ReasonSensitivityOutOfScope {
		t.Fatalf("out-of-scope high level got d=%d reason=%q, want deny SENSITIVITY_OUT_OF_SCOPE", d, reason)
	}
}

// 规则未声明分级区间时，任何分级都适用——存量策略语义保持不变。
func TestRuleWithoutSensitivityMatchesAllLevels(t *testing.T) {
	store := fakeStore{pols: map[string]model.Policy{"v1": testPolicy()}} // 规则无分级声明
	e := NewEngine(store, func() time.Time { return t0 })
	for _, level := range []model.Sensitivity{
		model.SensitivityPublic, model.SensitivityInternal,
		model.SensitivityConfidential, model.SensitivityRestricted,
	} {
		rec := &model.Record{Resource: "res:1", Sensitivity: level}
		d, reason, _, basis := e.Verdict(baseReq(validGrant()), rec)
		t.Logf("[legacy rule level=%s] decision=%d reason=%q factors=%v", level, d, reason, basis.Factors)
		if d != model.DecisionMask || reason != model.ReasonNone {
			t.Fatalf("legacy rule must ignore sensitivity, level=%s got d=%d reason=%q", level, d, reason)
		}
	}
}

// 授权声明分级上限：超过上限一律拒绝，原因码必须与其他拒绝可区分。
func TestGrantSensitivityCap(t *testing.T) {
	store := fakeStore{pols: map[string]model.Policy{"v1": testPolicy()}} // 规则不按分级筛选
	e := NewEngine(store, func() time.Time { return t0 })
	capLevel := model.SensitivityConfidential

	// 分级恰好等于上限（闭区间）：不触发上限拒绝，正常走规则结论。
	atCap := baseReq(validGrant())
	atCap.Grant.MaxSensitivity = &capLevel
	rec := &model.Record{Resource: "res:1", Sensitivity: model.SensitivityConfidential}
	d, reason, _, basis := e.Verdict(atCap, rec)
	t.Logf("[at-cap level=confidential] decision=%d reason=%q factors=%v", d, reason, basis.Factors)
	if d != model.DecisionMask || reason != model.ReasonNone {
		t.Fatalf("level at cap got d=%d reason=%q, want mask", d, reason)
	}

	// 分级高于上限：拒绝，且原因码独立可区分。
	over := baseReq(validGrant())
	over.Grant.MaxSensitivity = &capLevel
	recHigh := &model.Record{Resource: "res:1", Sensitivity: model.SensitivityRestricted}
	d, reason, _, basis = e.Verdict(over, recHigh)
	t.Logf("[over-cap level=restricted] decision=%d reason=%q factors=%v", d, reason, basis.Factors)
	if d != model.DecisionDeny || reason != model.ReasonGrantSensitivityCap {
		t.Fatalf("over cap got d=%d reason=%q, want GRANT_SENSITIVITY_EXCEEDED", d, reason)
	}
	for _, other := range []model.Reason{
		model.ReasonGrantMissing, model.ReasonGrantRevoked, model.ReasonPurposeMismatch,
		model.ReasonClearanceInsufficient, model.ReasonSensitivityOutOfScope,
	} {
		if reason == other {
			t.Fatalf("grant cap reason must be distinct from %q", other)
		}
	}
}

// 存量授权（未声明上限）在任意分级下行为不变，不因扩展被改变结论。
func TestLegacyGrantWithoutCapUnaffected(t *testing.T) {
	store := fakeStore{pols: map[string]model.Policy{"v1": testPolicy()}}
	e := NewEngine(store, func() time.Time { return t0 })
	g := validGrant() // MaxSensitivity == nil
	if g.MaxSensitivity != nil {
		t.Fatal("setup: legacy grant must have nil cap")
	}
	for _, level := range []model.Sensitivity{
		model.SensitivityPublic, model.SensitivityInternal,
		model.SensitivityConfidential, model.SensitivityRestricted,
	} {
		rec := &model.Record{Resource: "res:1", Sensitivity: level}
		d, reason, _, _ := e.Verdict(baseReq(validGrant()), rec)
		if d != model.DecisionMask || reason != model.ReasonNone {
			t.Fatalf("legacy grant changed at level=%s: d=%d reason=%q", level, d, reason)
		}
	}
}

// mixedScopePolicy 复现漏放路径的策略：
// 第一条规则写明只覆盖 public..internal（mask），
// 第二条是没写分级范围的存量兜底 allow（陷阱）。
// 修复前：confidential/restricted 跳过第一条后落到第二条被放行；
// 修复后：超出所有写明范围一律 SENSITIVITY_OUT_OF_SCOPE。
func mixedScopePolicy() model.Policy {
	ptr := func(s model.Sensitivity) *model.Sensitivity { return &s }
	return model.Policy{
		Version:     "v-mixed",
		EffectiveAt: t0.AddDate(-1, 0, 0),
		Rules: []model.Rule{
			{
				Resources: []string{"res:1"}, Purposes: []string{"research"},
				MinSensitivity: ptr(model.SensitivityPublic), MaxSensitivity: ptr(model.SensitivityInternal),
				Effect:     model.EffectMask,
				FieldRules: []model.FieldRule{{Field: "name", Transform: "mask"}},
			},
			{
				Resources: []string{"res:1"}, Purposes: []string{"research"},
				Effect: model.EffectAllow, // 未声明分级范围的兜底规则
			},
		},
	}
}

// 同一主体/资源/目的/策略版本，只把分级从最低档一路调高：
// 边界（public 下界、internal 上界）仍按写明范围的规则正常判定，
// 一旦超出所有写明范围，结论变为可区分的 SENSITIVITY_OUT_OF_SCOPE 拒绝，
// 绝不落到未声明范围的兜底 allow 上；结论只允许变严、不允许变松。
func TestSensitivityRaiseBlocksUnscopedFallback(t *testing.T) {
	store := fakeStore{pols: map[string]model.Policy{"v-mixed": mixedScopePolicy()}}
	e := NewEngine(store, func() time.Time { return t0 })

	cases := []struct {
		level model.Sensitivity
		wantD model.Decision
		wantR model.Reason
		bound string // 标注是否压在写明范围的边界上
	}{
		{model.SensitivityPublic, model.DecisionMask, model.ReasonNone, "lower-boundary"},
		{model.SensitivityInternal, model.DecisionMask, model.ReasonNone, "upper-boundary"},
		{model.SensitivityConfidential, model.DecisionDeny, model.ReasonSensitivityOutOfScope, "out-of-scope"},
		{model.SensitivityRestricted, model.DecisionDeny, model.ReasonSensitivityOutOfScope, "out-of-scope"},
	}
	var prev model.Decision
	for i, tc := range cases {
		rec := &model.Record{Resource: "res:1", Sensitivity: tc.level}
		req := baseReq(validGrant())
		d, reason, pol, basis := e.Verdict(req, rec)
		t.Logf("[%s level=%s] input={subject=u1 clearance=3 resource=res:1 purpose=research level=%s policy=%s} "+
			"matched_rule=%d decision=%d reason=%q factors=%v",
			tc.bound, tc.level, tc.level, pol.Version, basis.RuleIndex, d, reason, basis.Factors)
		if d != tc.wantD || reason != tc.wantR {
			t.Fatalf("level=%s: got d=%d reason=%q, want d=%d reason=%q",
				tc.level, d, reason, tc.wantD, tc.wantR)
		}
		// 枚举序 Deny(0) < Mask(1) < Allow(2)：调高分级绝不能让结论变宽松。
		if i > 0 && d > prev {
			t.Fatalf("decision must not get more permissive as sensitivity rises: %d -> %d", prev, d)
		}
		prev = d
	}

	// 原因码必须与既有拒绝理由清楚区分。
	hiRec := &model.Record{Resource: "res:1", Sensitivity: model.SensitivityRestricted}
	_, reason, _, basis := e.Verdict(baseReq(validGrant()), hiRec)
	for _, other := range []model.Reason{
		model.ReasonGrantMissing, model.ReasonGrantRevoked, model.ReasonPurposeMismatch,
		model.ReasonClearanceInsufficient, model.ReasonRuleDenied, model.ReasonGrantSensitivityCap,
	} {
		if reason == other {
			t.Fatalf("out-of-scope reason %q must be distinct from %q", reason, other)
		}
	}
	if !containsFactor(basis.Factors, "rule:sensitivity_out_of_scope") {
		t.Fatalf("basis must explain out-of-scope, factors=%v", basis.Factors)
	}
}

func containsFactor(factors []string, want string) bool {
	for _, f := range factors {
		if f == want {
			return true
		}
	}
	return false
}

// 只有单侧边界的写明范围：下界含边界（min 表示该级及以上），边界以下即便有
// 未声明范围的兜底规则也必须越界拒绝；边界及以上正常按写明规则判定。
func TestSensitivityOneSidedRangeBoundary(t *testing.T) {
	ptr := func(s model.Sensitivity) *model.Sensitivity { return &s }
	p := model.Policy{
		Version:     "v-one-sided",
		EffectiveAt: t0.AddDate(-1, 0, 0),
		Rules: []model.Rule{
			{
				Resources: []string{"res:1"}, Purposes: []string{"research"},
				MinSensitivity: ptr(model.SensitivityConfidential), // >= confidential
				Effect:         model.EffectMask,
				FieldRules:     []model.FieldRule{{Field: "name", Transform: "mask"}},
			},
			{Resources: []string{"res:1"}, Purposes: []string{"research"}, Effect: model.EffectAllow},
		},
	}
	e := NewEngine(fakeStore{pols: map[string]model.Policy{"v-one-sided": p}}, func() time.Time { return t0 })
	cases := []struct {
		level model.Sensitivity
		wantD model.Decision
		wantR model.Reason
	}{
		{model.SensitivityPublic, model.DecisionDeny, model.ReasonSensitivityOutOfScope},
		{model.SensitivityInternal, model.DecisionDeny, model.ReasonSensitivityOutOfScope},
		{model.SensitivityConfidential, model.DecisionMask, model.ReasonNone}, // 正好压下界
		{model.SensitivityRestricted, model.DecisionMask, model.ReasonNone},
	}
	for _, tc := range cases {
		rec := &model.Record{Resource: "res:1", Sensitivity: tc.level}
		d, reason, _, basis := e.Verdict(baseReq(validGrant()), rec)
		t.Logf("[one-sided level=%s] input={subject=u1 resource=res:1 purpose=research level=%s} "+
			"matched_rule=%d decision=%d reason=%q factors=%v",
			tc.level, tc.level, basis.RuleIndex, d, reason, basis.Factors)
		if d != tc.wantD || reason != tc.wantR {
			t.Fatalf("level=%s got d=%d reason=%q, want d=%d reason=%q",
				tc.level, d, reason, tc.wantD, tc.wantR)
		}
	}
}

// 存量策略兼容：同一资源/目的下没有任何规则写明分级范围时，
// 兜底规则在任意分级（含最高档）结论都与扩展前完全一致。
func TestAllUnscopedRulesLegacyUnaffected(t *testing.T) {
	store := fakeStore{pols: map[string]model.Policy{"v1": testPolicy()}} // 全部规则无分级声明
	e := NewEngine(store, func() time.Time { return t0 })
	for _, level := range []model.Sensitivity{
		model.SensitivityPublic, model.SensitivityInternal,
		model.SensitivityConfidential, model.SensitivityRestricted,
	} {
		rec := &model.Record{Resource: "res:1", Sensitivity: level}
		d, reason, _, basis := e.Verdict(baseReq(validGrant()), rec)
		t.Logf("[all-unscoped level=%s] decision=%d reason=%q matched_rule=%d factors=%v",
			level, d, reason, basis.RuleIndex, basis.Factors)
		if d != model.DecisionMask || reason != model.ReasonNone || basis.RuleIndex != 0 {
			t.Fatalf("legacy all-unscoped policy changed at level=%s: d=%d reason=%q rule=%d",
				level, d, reason, basis.RuleIndex)
		}
	}
}

// 目的不符不能被越界理由顶掉：分级虽超出写明范围，但访问目的本来就不匹配，
// 必须保持 PURPOSE_MISMATCH（授权已覆盖该目的，排除授权侧目的检查）。
func TestOutOfScopeDoesNotOverridePurposeMismatch(t *testing.T) {
	store := fakeStore{pols: map[string]model.Policy{"v-mixed": mixedScopePolicy()}}
	e := NewEngine(store, func() time.Time { return t0 })

	g := validGrant()
	g.Purposes = []string{"research", "marketing"} // 授权侧覆盖 marketing
	req := baseReq(g)
	req.Purpose = "marketing"
	rec := &model.Record{Resource: "res:1", Sensitivity: model.SensitivityRestricted} // 且分级越界

	d, reason, _, basis := e.Verdict(req, rec)
	t.Logf("[purpose-vs-scope] input={subject=u1 resource=res:1 purpose=marketing level=restricted} "+
		"decision=%d reason=%q factors=%v", d, reason, basis.Factors)
	if d != model.DecisionDeny || reason != model.ReasonPurposeMismatch {
		t.Fatalf("got d=%d reason=%q, want deny PURPOSE_MISMATCH", d, reason)
	}
}

// 写明范围的规则只针对别的目的时，当前目的等于没有分级分段，
// 未声明范围的规则对当前目的仍按存量语义在任意分级生效。
func TestScopedRuleForOtherPurposeDoesNotGate(t *testing.T) {
	ptr := func(s model.Sensitivity) *model.Sensitivity { return &s }
	p := model.Policy{
		Version:     "v-other-purpose",
		EffectiveAt: t0.AddDate(-1, 0, 0),
		Rules: []model.Rule{
			{
				Resources: []string{"res:1"}, Purposes: []string{"billing"},
				MinSensitivity: ptr(model.SensitivityPublic), MaxSensitivity: ptr(model.SensitivityPublic),
				Effect: model.EffectDeny,
			},
			{Resources: []string{"res:1"}, Purposes: []string{"*"}, Effect: model.EffectAllow},
		},
	}
	e := NewEngine(fakeStore{pols: map[string]model.Policy{"v-other-purpose": p}}, func() time.Time { return t0 })
	rec := &model.Record{Resource: "res:1", Sensitivity: model.SensitivityRestricted}
	d, reason, _, basis := e.Verdict(baseReq(validGrant()), rec)
	t.Logf("[other-purpose-scoped level=restricted] decision=%d reason=%q factors=%v", d, reason, basis.Factors)
	if d != model.DecisionAllow || reason != model.ReasonNone {
		t.Fatalf("scoped rule for other purpose must not gate research access: d=%d reason=%q", d, reason)
	}
}

// 越界分级下兜底规则无论自身是 allow 还是显式 deny，都统一判
// SENSITIVITY_OUT_OF_SCOPE：一律拒绝、不返回数据，理由稳定可区分。
func TestOutOfScopeUnscopedFallbackUniform(t *testing.T) {
	for _, fallback := range []model.RuleEffect{model.EffectAllow, model.EffectMask, model.EffectDeny} {
		p := mixedScopePolicy()
		p.Rules[1].Effect = fallback
		e := NewEngine(fakeStore{pols: map[string]model.Policy{"v-mixed": p}}, func() time.Time { return t0 })

		rec := &model.Record{Resource: "res:1", Sensitivity: model.SensitivityRestricted}
		d, reason, _, basis := e.Verdict(baseReq(validGrant()), rec)
		t.Logf("[unscoped-fallback=%d level=restricted] decision=%d reason=%q factors=%v",
			fallback, d, reason, basis.Factors)
		if d != model.DecisionDeny || reason != model.ReasonSensitivityOutOfScope {
			t.Fatalf("fallback effect=%d: got d=%d reason=%q, want deny SENSITIVITY_OUT_OF_SCOPE",
				fallback, d, reason)
		}
	}
}
