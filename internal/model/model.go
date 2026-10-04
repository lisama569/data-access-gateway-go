// Package model 定义数据访问网关使用的核心领域类型。
package model

import "time"

// Sensitivity 资源敏感级别。
type Sensitivity int

const (
	SensitivityPublic Sensitivity = iota
	SensitivityInternal
	SensitivityConfidential
	SensitivityRestricted
)

// String 返回分级的稳定名称，便于日志与判定依据可读。
func (s Sensitivity) String() string {
	switch s {
	case SensitivityPublic:
		return "public"
	case SensitivityInternal:
		return "internal"
	case SensitivityConfidential:
		return "confidential"
	case SensitivityRestricted:
		return "restricted"
	default:
		return "unknown"
	}
}

// Decision 访问判定结论。
type Decision int

const (
	DecisionDeny  Decision = iota // 拒绝
	DecisionMask                  // 允许但必须脱敏
	DecisionAllow                 // 原样允许
)

// Reason 稳定的拒绝/提示原因码，便于区分失败原因。
type Reason string

const (
	ReasonNone                   Reason = ""
	ReasonGrantMissing           Reason = "GRANT_MISSING"              // 缺少授权
	ReasonGrantRevoked           Reason = "GRANT_REVOKED"              // 授权已撤销
	ReasonPurposeMismatch        Reason = "PURPOSE_MISMATCH"           // 目的不匹配
	ReasonClearanceInsufficient  Reason = "CLEARANCE_INSUFFICIENT"     // 密级不足
	ReasonDataRetentionExpired   Reason = "DATA_RETENTION_EXPIRED"     // 数据超出保留期
	ReasonPolicyRetentionExpired Reason = "POLICY_RETENTION_EXPIRED"   // 策略版本超出保留期
	ReasonNoApplicablePolicy     Reason = "NO_APPLICABLE_POLICY"       // 无可用策略版本
	ReasonResourceNotFound       Reason = "RESOURCE_NOT_FOUND"         // 资源不存在
	ReasonMaskConfigInvalid      Reason = "MASK_CONFIG_INVALID"        // 脱敏配置非法或缺失
	ReasonRuleDenied             Reason = "RULE_DENIED"                // 命中策略规则显式拒绝
	ReasonGrantSensitivityCap    Reason = "GRANT_SENSITIVITY_EXCEEDED" // 数据分级超过授权覆盖上限
	ReasonSensitivityOutOfScope  Reason = "SENSITIVITY_OUT_OF_SCOPE"   // 分级无任何策略规则覆盖
	ReasonInternalError          Reason = "INTERNAL_ERROR"             // 内部错误（细节不透出）
)

// Grant 表示主体持有的一条数据授权。
type Grant struct {
	ID        string
	SubjectID string
	Resource  string // 资源标识
	Purposes  []string
	ExpiresAt time.Time
	Revoked   bool
	UpdatedAt time.Time // 撤销/最近变更时间，用于判定依据
	// MaxSensitivity 声明本授权最多覆盖到的数据分级（含该级别）。
	// 为 nil 时表示不设上限，保持存量授权行为。
	MaxSensitivity *Sensitivity
}

// Subject 主体属性（判定输入快照）。
type Subject struct {
	ID         string
	Department string
	Role       string
	Clearance  int // 密级
	Groups     []string
}

// Record 内存数据集中的一条受保护记录。
type Record struct {
	ID          string
	Resource    string
	Sensitivity Sensitivity
	ExpiresAt   time.Time // 数据保留期
	Fields      map[string]string
}

// FieldRule 字段级变换规则。
type FieldRule struct {
	Field       string
	Transform   string // "mask" | "tokenize"
	TokenDomain string
}

// RuleEffect 单条策略规则的效果。
type RuleEffect int

const (
	EffectDeny RuleEffect = iota
	EffectMask
	EffectAllow
)

// Rule 策略规则：资源 + 目的匹配后的效果与字段规则。
//
// 数据分级适用性（兼容存量策略）：
//   - MinSensitivity 与 MaxSensitivity 同时为 nil 时，规则本身不按分级筛选；
//   - 否则规则只在数据分级落入 [MinSensitivity, MaxSensitivity] 闭区间时适用：
//     任一边界为 nil 表示该侧不设限；分级正好压在上/下边界时仍按该规则判定。
//
// 同一「资源 + 目的」组合下的兜底关系：
//   - 只要该组合下存在至少一条「写明了分级区间」的规则，数据分级落在所有写明
//     区间之外时，一律判定为 SENSITIVITY_OUT_OF_SCOPE 拒绝；此时未声明区间的
//     规则不得为越界分级兜底放行（防止分级调高后反而落到宽松规则上）；
//   - 只有该组合下没有任何规则写明区间（纯存量策略）时，未声明区间的规则才对
//     所有分级适用，匹配与结论与扩展前完全一致。
type Rule struct {
	Resources      []string
	Purposes       []string
	MinClearance   int
	Effect         RuleEffect
	FieldRules     []FieldRule
	MinSensitivity *Sensitivity
	MaxSensitivity *Sensitivity
}

// Policy 一个不可变的策略版本。
type Policy struct {
	Version     string
	EffectiveAt time.Time
	RetiresAt   time.Time // 该版本停止服务新访问（进入归档，仅可复现历史）
	Description string
	Rules       []Rule
}

// AccessRequest 一次访问请求的输入。
type AccessRequest struct {
	Subject       Subject
	Grant         *Grant // 命中的授权（可能为 nil）
	Resource      string
	Purpose       string
	PinnedVersion string // 可选：显式指定按某策略版本判定
	RequestedAt   time.Time
}

// DecisionBasis 判定依据（可解释）。
type DecisionBasis struct {
	RuleIndex   int
	MatchedRule bool
	Factors     []string // 命中因素说明，如 "grant:valid"、"purpose:research"
}

// AccessResult 网关对一次访问的对外结论。
type AccessResult struct {
	Decision      Decision
	Reason        Reason
	PolicyVersion string
	Basis         DecisionBasis
	Record        *Record // 允许/脱敏时的输出记录（已变换）
	MaskedFields  []string
	RequestedAt   time.Time
}
