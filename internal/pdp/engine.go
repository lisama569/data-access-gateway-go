// Package pdp 实现策略判定点：根据主体、授权、资源、目的与策略版本得出结论。
//
// 判定优先级（稳定、可解释，每一步都会写入 Basis.Factors）：
//  1. 选择策略版本：显式 PinnedVersion 必须在请求时刻已生效且未退役，
//     否则 POLICY_RETENTION_EXPIRED；未指定时取当前有效版本，无版本则
//     NO_APPLICABLE_POLICY。
//  2. 授权存在性：缺失 GRANT_MISSING；已撤销 GRANT_REVOKED；过期按缺失处理。
//  3. 授权分级上限：授权声明了 MaxSensitivity 且数据分级超过上限，
//     GRANT_SENSITIVITY_CAP（与缺授权/撤销/目的不匹配可区分）。
//  4. 数据保留期：记录超出保留期 DATA_RETENTION_EXPIRED。
//  5. 目的匹配：授权目的与策略规则目的均须匹配，否则 PURPOSE_MISMATCH。
//  6. 分级匹配：若资源+目的候选规则中存在声明了适用分级范围的规则，
//     只有范围覆盖数据分级的规则可命中；未声明范围的规则被遮蔽（防止
//     分级越界时误命中泛化允许规则）；全部不覆盖则 SENSITIVITY_NOT_COVERED。
//     候选规则均未声明分级时，行为与扩展前完全一致。
//  7. 密级：低于规则要求 CLEARANCE_INSUFFICIENT。
//  8. 规则效果：按规则顺序取第一条匹配规则的 deny/mask/allow。
package pdp

import (
	"strconv"
	"time"

	"github.com/lisama569/data-access-gateway-go/internal/model"
)

// Clock 便于测试中控制时间。
type Clock func() time.Time

// PolicyReader PDP 所需的策略读取能力。
type PolicyReader interface {
	Active(at time.Time) (model.Policy, error)
	Version(version string) (model.Policy, bool)
}

// Engine 策略判定引擎。判定纯函数化：同一输入（含版本与时间）必得同一结论。
type Engine struct {
	store PolicyReader
	clock Clock
}

// NewEngine 创建判定引擎。
func NewEngine(store PolicyReader, clock Clock) *Engine {
	if clock == nil {
		clock = time.Now
	}
	return &Engine{store: store, clock: clock}
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

func matchAny(list []string, v string) bool {
	if len(list) == 0 {
		return true // 空列表表示通配
	}
	if contains(list, "*") {
		return true
	}
	return contains(list, v)
}

// selectPolicy 选择判定所用策略版本。
func (e *Engine) selectPolicy(req model.AccessRequest) (model.Policy, model.Reason, []string) {
	at := req.RequestedAt
	if at.IsZero() {
		at = e.clock()
	}
	if req.PinnedVersion != "" {
		p, ok := e.store.Version(req.PinnedVersion)
		if !ok {
			return p, model.ReasonNoApplicablePolicy, []string{
				"policy:pinned=" + req.PinnedVersion, "policy:not_found",
			}
		}
		factors := []string{"policy:pinned=" + p.Version, "policy:effective_at=" + p.EffectiveAt.Format(time.RFC3339)}
		if at.Before(p.EffectiveAt) {
			return p, model.ReasonPolicyRetentionExpired, append(factors, "policy:not_yet_effective")
		}
		if !p.RetiresAt.IsZero() && !at.Before(p.RetiresAt) {
			factors = append(factors, "policy:retires_at="+p.RetiresAt.Format(time.RFC3339), "policy:retired")
			return p, model.ReasonPolicyRetentionExpired, factors
		}
		return p, model.ReasonNone, append(factors, "policy:active")
	}
	p, err := e.store.Active(at)
	if err != nil {
		return model.Policy{}, model.ReasonNoApplicablePolicy, []string{"policy:no_active_version"}
	}
	return p, model.ReasonNone, []string{"policy:version=" + p.Version, "policy:active"}
}

// Verdict 执行策略层判定（不触碰字段值、不执行脱敏）。
// rec 为数据记录快照（可能含保留期）；为 nil 时跳过数据保留期检查。
func (e *Engine) Verdict(req model.AccessRequest, rec *model.Record) (model.Decision, model.Reason, model.Policy, model.DecisionBasis) {
	basis := model.DecisionBasis{Factors: []string{}}
	deny := func(r model.Reason, p model.Policy) (model.Decision, model.Reason, model.Policy, model.DecisionBasis) {
		basis.Factors = append(basis.Factors, "decision:deny", "reason:"+string(r))
		return model.DecisionDeny, r, p, basis
	}

	p, reason, factors := e.selectPolicy(req)
	basis.Factors = append(basis.Factors, factors...)
	if reason != model.ReasonNone {
		return deny(reason, p)
	}
	basis.Factors = append(basis.Factors, "subject:"+req.Subject.ID, "resource:"+req.Resource, "purpose:"+req.Purpose)

	// 授权存在性与有效性。
	if req.Grant == nil {
		return deny(model.ReasonGrantMissing, p)
	}
	basis.Factors = append(basis.Factors, "grant:"+req.Grant.ID)
	if req.Grant.Revoked {
		basis.Factors = append(basis.Factors, "grant:revoked_at="+req.Grant.UpdatedAt.Format(time.RFC3339))
		return deny(model.ReasonGrantRevoked, p)
	}
	at := req.RequestedAt
	if at.IsZero() {
		at = e.clock()
	}
	if !req.Grant.ExpiresAt.IsZero() && at.After(req.Grant.ExpiresAt) {
		basis.Factors = append(basis.Factors, "grant:expired_at="+req.Grant.ExpiresAt.Format(time.RFC3339))
		return deny(model.ReasonGrantMissing, p)
	}
	basis.Factors = append(basis.Factors, "grant:valid")

	// 授权分级上限：声明了上限且数据分级超过上限时拒绝（理由可区分）。
	if rec != nil {
		basis.Factors = append(basis.Factors, "data:sensitivity="+rec.Sensitivity.String())
	}
	if rec != nil && req.Grant.MaxSensitivity != nil {
		basis.Factors = append(basis.Factors, "grant:max_sensitivity="+req.Grant.MaxSensitivity.String())
		if rec.Sensitivity > *req.Grant.MaxSensitivity {
			basis.Factors = append(basis.Factors, "grant:sensitivity_cap_exceeded")
			return deny(model.ReasonGrantSensitivityCap, p)
		}
	}

	// 数据保留期。
	if rec != nil && !rec.ExpiresAt.IsZero() && at.After(rec.ExpiresAt) {
		basis.Factors = append(basis.Factors, "data:expires_at="+rec.ExpiresAt.Format(time.RFC3339), "data:retention_expired")
		return deny(model.ReasonDataRetentionExpired, p)
	}

	// 授权目的必须覆盖本次访问目的。
	if !matchAny(req.Grant.Purposes, req.Purpose) {
		basis.Factors = append(basis.Factors, "grant:purposes_mismatch")
		return deny(model.ReasonPurposeMismatch, p)
	}

	// 规则匹配：先收集「资源 + 目的」均命中的候选规则。
	type candidate struct {
		idx  int
		rule model.Rule
	}
	var candidates []candidate
	hasConstrained := false // 候选中是否存在声明了分级范围的规则
	for i, rule := range p.Rules {
		if !matchAny(rule.Resources, req.Resource) {
			continue
		}
		if !matchAny(rule.Purposes, req.Purpose) {
			basis.Factors = append(basis.Factors, "rule:purpose_mismatch")
			return deny(model.ReasonPurposeMismatch, p)
		}
		candidates = append(candidates, candidate{idx: i, rule: rule})
		if rule.Sensitivity != nil {
			hasConstrained = true
		}
	}

	// 分级过滤：候选中存在分级约束规则时，只有范围覆盖数据分级的规则
	// 可命中；未声明分级的规则被遮蔽，避免分级越界时误命中泛化允许规则。
	// rec 为 nil 时无分级可读，视为被任何范围覆盖（保持既有调用语义）。
	matchesSensitivity := func(rule model.Rule) bool {
		if rule.Sensitivity == nil {
			return !hasConstrained
		}
		if rec == nil {
			return true
		}
		return rule.Sensitivity.Contains(rec.Sensitivity)
	}

	for _, c := range candidates {
		rule := c.rule
		if rule.Sensitivity != nil {
			basis.Factors = append(basis.Factors,
				"rule:index="+itoa(c.idx),
				"rule:sensitivity_range="+rule.Sensitivity.Min.String()+".."+rule.Sensitivity.Max.String(),
			)
		}
		if !matchesSensitivity(rule) {
			basis.Factors = append(basis.Factors, "rule:sensitivity_out_of_range")
			continue
		}
		basis.RuleIndex = c.idx
		basis.MatchedRule = true
		basis.Factors = append(basis.Factors,
			"rule:index="+itoa(c.idx),
			"rule:min_clearance="+itoa(rule.MinClearance),
			"subject:clearance="+itoa(req.Subject.Clearance),
		)
		if req.Subject.Clearance < rule.MinClearance {
			return deny(model.ReasonClearanceInsufficient, p)
		}
		switch rule.Effect {
		case model.EffectDeny:
			basis.Factors = append(basis.Factors, "decision:deny", "rule:explicit_deny")
			return model.DecisionDeny, model.ReasonRuleDenied, p, basis
		case model.EffectMask:
			basis.Factors = append(basis.Factors, "decision:mask", "field_rules:"+itoa(len(rule.FieldRules)))
			return model.DecisionMask, model.ReasonNone, p, basis
		default:
			basis.Factors = append(basis.Factors, "decision:allow")
			return model.DecisionAllow, model.ReasonNone, p, basis
		}
	}
	if hasConstrained && len(candidates) > 0 {
		// 存在分级约束规则但数据分级未被任何规则覆盖：明确拒绝，
		// 与「无匹配规则」可区分。
		basis.Factors = append(basis.Factors, "rule:sensitivity_not_covered")
		return deny(model.ReasonSensitivityNotCovered, p)
	}
	basis.Factors = append(basis.Factors, "rule:no_match")
	return deny(model.ReasonNoApplicablePolicy, p)
}

func itoa(i int) string { return strconv.Itoa(i) }
