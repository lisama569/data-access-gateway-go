// Package pdp 实现策略判定点：根据主体、授权、资源、目的与策略版本得出结论。
//
// 判定优先级（稳定、可解释，每一步都会写入 Basis.Factors）：
//  1. 选择策略版本：显式 PinnedVersion 必须在请求时刻已生效且未退役，
//     否则 POLICY_RETENTION_EXPIRED；未指定时取当前有效版本，无版本则
//     NO_APPLICABLE_POLICY。
//  2. 授权存在性：缺失 GRANT_MISSING；已撤销 GRANT_REVOKED；过期按缺失处理。
//  3. 数据保留期：记录超出保留期 DATA_RETENTION_EXPIRED。
//  4. 授权分级上限：数据分级超过授权声明的 MaxSensitivity 时
//     GRANT_SENSITIVITY_EXCEEDED；授权未声明上限则跳过（存量授权语义不变）。
//  5. 目的匹配：授权目的与策略规则目的均须匹配，否则 PURPOSE_MISMATCH。
//  6. 密级：低于规则要求 CLEARANCE_INSUFFICIENT。
//  7. 规则分级范围：规则可声明 [MinSensitivity, MaxSensitivity] 适用区间，
//     数据分级不在区间内的规则被跳过。同一「资源+目的」下只要存在写明区间的规则，
//     未声明区间的规则就不能为落在所有写明区间之外的分级兜底（否则会出现
//     「分级越高、结论反而越松」的漏放）；此时统一拒绝 SENSITIVITY_OUT_OF_SCOPE。
//     只有同一「资源+目的」下没有任何规则写明区间（纯存量策略）时，未声明区间的
//     规则才对所有分级适用，保持存量语义不变。
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

// sensitivityInScope 判断数据分级是否落入规则声明的适用区间。
// 两侧边界均为 nil 表示规则不按分级筛选（存量策略语义）。
func sensitivityInScope(level model.Sensitivity, min, max *model.Sensitivity) bool {
	if min != nil && level < *min {
		return false
	}
	if max != nil && level > *max {
		return false
	}
	return true
}

// ruleHasSensitivityRange 判断规则是否显式声明了分级适用区间（任一边界非 nil）。
func ruleHasSensitivityRange(rule model.Rule) bool {
	return rule.MinSensitivity != nil || rule.MaxSensitivity != nil
}

// sensitivityRangeText 生成规则分级区间的可读文本，用于判定依据日志。
func sensitivityRangeText(min, max *model.Sensitivity) string {
	switch {
	case min == nil && max == nil:
		return "any"
	case min == nil:
		return "<=" + max.String()
	case max == nil:
		return ">=" + min.String()
	default:
		return min.String() + ".." + max.String()
	}
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

	// 数据保留期。
	if rec != nil && !rec.ExpiresAt.IsZero() && at.After(rec.ExpiresAt) {
		basis.Factors = append(basis.Factors, "data:expires_at="+rec.ExpiresAt.Format(time.RFC3339), "data:retention_expired")
		return deny(model.ReasonDataRetentionExpired, p)
	}

	// 授权分级上限：仅在授权显式声明 MaxSensitivity 时生效；
	// 未声明（nil）的存量授权一律跳过本检查，行为与扩展前一致。
	if rec != nil {
		basis.Factors = append(basis.Factors, "data:sensitivity="+rec.Sensitivity.String())
		if req.Grant.MaxSensitivity != nil {
			basis.Factors = append(basis.Factors, "grant:max_sensitivity="+req.Grant.MaxSensitivity.String())
			if rec.Sensitivity > *req.Grant.MaxSensitivity {
				basis.Factors = append(basis.Factors, "grant:sensitivity_exceeded")
				return deny(model.ReasonGrantSensitivityCap, p)
			}
			basis.Factors = append(basis.Factors, "grant:sensitivity_within_cap")
		}
	}

	// 授权目的必须覆盖本次访问目的。
	if !matchAny(req.Grant.Purposes, req.Purpose) {
		basis.Factors = append(basis.Factors, "grant:purposes_mismatch")
		return deny(model.ReasonPurposeMismatch, p)
	}

	// 规则匹配：按顺序取第一条「资源 + 分级 + 目的」均匹配的规则。
	//
	// 先按「同资源 + 同目的」预计算写明分级区间的覆盖情况：只要该组合下存在
	// 写明区间的规则，未声明区间的规则就只在存量语义（该组合下没有任何写明区间）
	// 下适用；当前分级落在所有写明区间之外时，未声明区间的规则不得兜底放行，
	// 否则会出现「分级一路调高、结论反而越来越松」的漏放。
	purposeHasScoped := false
	levelCovered := false
	if rec != nil {
		for _, rule := range p.Rules {
			if !matchAny(rule.Resources, req.Resource) || !matchAny(rule.Purposes, req.Purpose) {
				continue
			}
			if ruleHasSensitivityRange(rule) {
				purposeHasScoped = true
				if sensitivityInScope(rec.Sensitivity, rule.MinSensitivity, rule.MaxSensitivity) {
					levelCovered = true
				}
			}
		}
		if purposeHasScoped {
			basis.Factors = append(basis.Factors,
				"rule:sensitivity_level="+rec.Sensitivity.String(),
				"rule:sensitivity_declared_ranges_present",
			)
			if levelCovered {
				basis.Factors = append(basis.Factors, "rule:sensitivity_covered_by_range")
			} else {
				basis.Factors = append(basis.Factors,
					"rule:sensitivity_outside_all_ranges",
					"rule:unscoped_rules_cannot_backfill",
				)
			}
		}
	}

	resourceMatched := false
	for i, rule := range p.Rules {
		if !matchAny(rule.Resources, req.Resource) {
			continue
		}
		resourceMatched = true
		if rec != nil && ruleHasSensitivityRange(rule) &&
			!sensitivityInScope(rec.Sensitivity, rule.MinSensitivity, rule.MaxSensitivity) {
			// 写明了区间但当前分级不在区间内：跳过该规则继续向后匹配。
			basis.Factors = append(basis.Factors,
				"rule:index="+itoa(i),
				"rule:sensitivity_scope="+sensitivityRangeText(rule.MinSensitivity, rule.MaxSensitivity),
				"rule:sensitivity_skipped",
			)
			continue
		}
		if rec != nil && !ruleHasSensitivityRange(rule) && purposeHasScoped && !levelCovered {
			// 未声明区间的规则不得为「超出所有写明区间」的分级兜底放行。
			basis.Factors = append(basis.Factors,
				"rule:index="+itoa(i),
				"rule:sensitivity_scope=any",
				"rule:unscoped_backfill_blocked",
			)
			continue
		}
		if !matchAny(rule.Purposes, req.Purpose) {
			basis.Factors = append(basis.Factors, "rule:purpose_mismatch")
			return deny(model.ReasonPurposeMismatch, p)
		}
		basis.RuleIndex = i
		basis.MatchedRule = true
		basis.Factors = append(basis.Factors,
			"rule:index="+itoa(i),
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
	if resourceMatched {
		// 有规则针对该资源，但数据分级不落入任何一条规则的覆盖区间。
		basis.Factors = append(basis.Factors, "rule:sensitivity_out_of_scope")
		return deny(model.ReasonSensitivityOutOfScope, p)
	}
	basis.Factors = append(basis.Factors, "rule:no_match")
	return deny(model.ReasonNoApplicablePolicy, p)
}

func itoa(i int) string { return strconv.Itoa(i) }
