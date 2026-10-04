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
		level model.Sensitivity
		wantD model.Decision
		wantR model.Reason
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
				Effect:     model.EffectMask,
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

// 回归：同一资源+目的下同时存在「声明分级范围的规则」与「未声明范围的兜底规则」。
// 数据分级一路调高、超出所有写明范围时，必须拒绝为 SENSITIVITY_OUT_OF_SCOPE，
// 绝不能落到未声明范围的规则上照常放行（分级越高结论反而越松）。
func TestSensitivityScopedAndUnscopedMixed(t *testing.T) {
	ptr := func(s model.Sensitivity) *model.Sensitivity { return &s }
	p := model.Policy{
		Version:     "v-mix",
		EffectiveAt: t0.AddDate(-1, 0, 0),
		Rules: []model.Rule{
			// 写明范围：只覆盖 public..internal，需脱敏。
			{
				Resources: []string{"res:1"}, Purposes: []string{"research"},
				MinSensitivity: ptr(model.SensitivityPublic), MaxSensitivity: ptr(model.SensitivityInternal),
				Effect:     model.EffectMask,
				FieldRules: []model.FieldRule{{Field: "name", Transform: "mask"}},
			},
			// 陷阱：同资源同目的的未声明分级范围规则，effect=allow。
			// 它只应在「没有任何写明范围规则」的存量策略里兜底；
			// 在本策略下绝不能为超出范围的高分级数据兜底放行。
			{
				Resources: []string{"res:1"}, Purposes: []string{"research"},
				Effect: model.EffectAllow,
			},
		},
	}
	store := fakeStore{pols: map[string]model.Policy{"v-mix": p}}
	e := NewEngine(store, func() time.Time { return t0 })

	// 从最低档一路调高：在写明范围内按第一条规则脱敏，边界档位仍正常判定。
	for _, level := range []model.Sensitivity{model.SensitivityPublic, model.SensitivityInternal} {
		rec := &model.Record{Resource: "res:1", Sensitivity: level}
		d, reason, _, basis := e.Verdict(baseReq(validGrant()), rec)
		t.Logf("[mixed in-scope level=%s] decision=%d reason=%q factors=%v", level, d, reason, basis.Factors)
		if d != model.DecisionMask || reason != model.ReasonNone {
			t.Fatalf("in-scope level=%s got d=%d reason=%q, want mask", level, d, reason)
		}
	}

	// 超出所有写明范围：必须拒绝，且原因码独立可区分，绝不能被兜底 allow 放行。
	for _, level := range []model.Sensitivity{model.SensitivityConfidential, model.SensitivityRestricted} {
		rec := &model.Record{Resource: "res:1", Sensitivity: level}
		d, reason, _, basis := e.Verdict(baseReq(validGrant()), rec)
		t.Logf("[mixed out-of-scope level=%s] decision=%d reason=%q factors=%v", level, d, reason, basis.Factors)
		if d != model.DecisionDeny || reason != model.ReasonSensitivityOutOfScope {
			t.Fatalf("out-of-scope level=%s got d=%d reason=%q, want deny SENSITIVITY_OUT_OF_SCOPE", level, d, reason)
		}
		for _, other := range []model.Reason{
			model.ReasonGrantMissing, model.ReasonGrantRevoked,
			model.ReasonPurposeMismatch, model.ReasonClearanceInsufficient,
			model.ReasonGrantSensitivityCap, model.ReasonRuleDenied,
		} {
			if reason == other {
				t.Fatalf("out-of-scope reason must be distinct from %q", other)
			}
		}
	}
}

// 边界：分级正好压在写明范围的上/下边界时仍按那条规则判定，只有真正落在所有
// 写明范围之外才拒绝。分别验证单边边界（只设 Min 或只设 Max）与闭区间。
func TestSensitivityScopeBoundaries(t *testing.T) {
	ptr := func(s model.Sensitivity) *model.Sensitivity { return &s }
	p := model.Policy{
		Version:     "v-boundary",
		EffectiveAt: t0.AddDate(-1, 0, 0),
		Rules: []model.Rule{
			// 只设上界：<=internal 允许。
			{
				Resources: []string{"res:1"}, Purposes: []string{"research"},
				MaxSensitivity: ptr(model.SensitivityInternal),
				Effect:         model.EffectAllow,
			},
			// 只设下界：>=restricted 显式拒绝（制造最高档有覆盖，验证越界拒绝仍优先于兜底）。
			{
				Resources: []string{"res:1"}, Purposes: []string{"research"},
				MinSensitivity: ptr(model.SensitivityRestricted),
				Effect:         model.EffectDeny,
			},
		},
	}
	store := fakeStore{pols: map[string]model.Policy{"v-boundary": p}}
	e := NewEngine(store, func() time.Time { return t0 })

	cases := []struct {
		level model.Sensitivity
		wantD model.Decision
		wantR model.Reason
	}{
		{model.SensitivityPublic, model.DecisionAllow, model.ReasonNone},                       // 远低于上界
		{model.SensitivityInternal, model.DecisionAllow, model.ReasonNone},                     // 正好压在上边界（闭区间）
		{model.SensitivityConfidential, model.DecisionDeny, model.ReasonSensitivityOutOfScope}, // 落在两段之外
		{model.SensitivityRestricted, model.DecisionDeny, model.ReasonRuleDenied},              // 正好压在下边界
	}
	for _, tc := range cases {
		rec := &model.Record{Resource: "res:1", Sensitivity: tc.level}
		d, reason, _, basis := e.Verdict(baseReq(validGrant()), rec)
		t.Logf("[boundary level=%s] decision=%d reason=%q factors=%v", tc.level, d, reason, basis.Factors)
		if d != tc.wantD || reason != tc.wantR {
			t.Fatalf("level=%s got d=%d reason=%q, want d=%d reason=%q",
				tc.level, d, reason, tc.wantD, tc.wantR)
		}
	}
}

// 存量：同一「资源+目的」下没有任何写明区间的规则时，未声明区间的规则对所有
// 分级兜底——即便别的目的上存在写明区间的规则，也不影响本组合的存量行为。
func TestScopedRuleForOtherPurposeDoesNotAffectLegacyPurpose(t *testing.T) {
	ptr := func(s model.Sensitivity) *model.Sensitivity { return &s }
	p := model.Policy{
		Version:     "v-other-purpose",
		EffectiveAt: t0.AddDate(-1, 0, 0),
		Rules: []model.Rule{
			// research 目的：写明范围，只覆盖低档。
			{
				Resources: []string{"res:1"}, Purposes: []string{"research"},
				MinSensitivity: ptr(model.SensitivityPublic), MaxSensitivity: ptr(model.SensitivityInternal),
				Effect:     model.EffectMask,
				FieldRules: []model.FieldRule{{Field: "name", Transform: "mask"}},
			},
			// billing 目的：未声明范围（存量规则），任意分级都应兜底适用。
			{
				Resources: []string{"res:1"}, Purposes: []string{"billing"},
				Effect: model.EffectAllow,
			},
		},
	}
	store := fakeStore{pols: map[string]model.Policy{"v-other-purpose": p}}
	e := NewEngine(store, func() time.Time { return t0 })

	// billing + restricted：本组合下没有写明区间的规则，存量兜底 allow 必须仍然生效，
	// 不能因为 research 组合存在写明区间就给出 SENSITIVITY_OUT_OF_SCOPE。
	g := &model.Grant{ID: "g2", SubjectID: "u1", Resource: "res:1",
		Purposes: []string{"billing"}, ExpiresAt: t0.Add(time.Hour), UpdatedAt: t0}
	req := baseReq(g)
	req.Purpose = "billing"
	rec := &model.Record{Resource: "res:1", Sensitivity: model.SensitivityRestricted}
	d, reason, _, basis := e.Verdict(req, rec)
	t.Logf("[other-purpose level=restricted] input={subject=u1 resource=res:1 purpose=billing} decision=%d reason=%q factors=%v",
		d, reason, basis.Factors)
	if d != model.DecisionAllow || reason != model.ReasonNone {
		t.Fatalf("legacy purpose must stay unaffected, got d=%d reason=%q", d, reason)
	}
}

// 目的不符不能被别的拒绝理由顶替：
//   - 授权目的不覆盖访问目的时，在规则匹配前就短路 PURPOSE_MISMATCH（与分级无关）；
//   - 存量第一匹配语义：第一条资源匹配的规则目的不符即 PURPOSE_MISMATCH，
//     本次分级修复不得把它换成 SENSITIVITY_OUT_OF_SCOPE。
func TestPurposeMismatchStillDistinct(t *testing.T) {
	ptr := func(s model.Sensitivity) *model.Sensitivity { return &s }

	// 场景 A：授权只给 billing、请求 research，策略第一条同资源规则是写范围内的
	// billing 规则。无论分级是否越界，都必须是 PURPOSE_MISMATCH 而非越界拒绝。
	p := model.Policy{
		Version:     "v-purpose-a",
		EffectiveAt: t0.AddDate(-1, 0, 0),
		Rules: []model.Rule{
			{
				Resources: []string{"res:1"}, Purposes: []string{"billing"},
				MinSensitivity: ptr(model.SensitivityPublic), MaxSensitivity: ptr(model.SensitivityInternal),
				Effect: model.EffectAllow,
			},
			{
				Resources: []string{"res:1"}, Purposes: []string{"research"},
				Effect:     model.EffectMask,
				FieldRules: []model.FieldRule{{Field: "name", Transform: "mask"}},
			},
		},
	}
	e := NewEngine(fakeStore{pols: map[string]model.Policy{"v-purpose-a": p}}, func() time.Time { return t0 })

	gbill := &model.Grant{ID: "g1", SubjectID: "u1", Resource: "res:1",
		Purposes: []string{"billing"}, ExpiresAt: t0.Add(time.Hour), UpdatedAt: t0}
	req := baseReq(gbill)
	req.Purpose = "research"
	// restricted 超出第一条规则写明范围：若错误地先判越界，就会掩盖目的不符。
	rec := &model.Record{Resource: "res:1", Sensitivity: model.SensitivityRestricted}
	d, reason, _, basis := e.Verdict(req, rec)
	t.Logf("[grant purpose mismatch level=restricted] decision=%d reason=%q factors=%v", d, reason, basis.Factors)
	if d != model.DecisionDeny || reason != model.ReasonPurposeMismatch {
		t.Fatalf("grant purpose mismatch got d=%d reason=%q, want PURPOSE_MISMATCH", d, reason)
	}

	// 场景 B：授权覆盖 research，策略规则顺序为「billing 写范围规则在前、research
	// 无范围规则在后」。restricted 超出第一条写明范围被跳过；第二条 research 规则
	// 因 research 组合内没有写明范围规则而按存量语义适用——结论是 mask，
	// 证明越界只在「同资源+同目的存在写明范围」时才触发。
	p2 := model.Policy{
		Version:     "v-purpose-b",
		EffectiveAt: t0.AddDate(-1, 0, 0),
		Rules: []model.Rule{
			{
				Resources: []string{"res:1"}, Purposes: []string{"billing"},
				MinSensitivity: ptr(model.SensitivityPublic), MaxSensitivity: ptr(model.SensitivityInternal),
				Effect: model.EffectAllow,
			},
			{
				Resources: []string{"res:1"}, Purposes: []string{"research"},
				Effect:     model.EffectMask,
				FieldRules: []model.FieldRule{{Field: "name", Transform: "mask"}},
			},
		},
	}
	e2 := NewEngine(fakeStore{pols: map[string]model.Policy{"v-purpose-b": p2}}, func() time.Time { return t0 })
	gres := &model.Grant{ID: "g2", SubjectID: "u1", Resource: "res:1",
		Purposes: []string{"research"}, ExpiresAt: t0.Add(time.Hour), UpdatedAt: t0}
	req2 := baseReq(gres)
	req2.Purpose = "research"
	d2, reason2, _, basis2 := e2.Verdict(req2, rec)
	t.Logf("[legacy research fallback level=restricted] decision=%d reason=%q factors=%v", d2, reason2, basis2.Factors)
	if d2 != model.DecisionMask || reason2 != model.ReasonNone {
		t.Fatalf("unscoped research rule must apply for its own purpose, got d=%d reason=%q", d2, reason2)
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
