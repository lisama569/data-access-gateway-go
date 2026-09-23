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
	ReasonGrantMissing           Reason = "GRANT_MISSING"            // 缺少授权
	ReasonGrantRevoked           Reason = "GRANT_REVOKED"            // 授权已撤销
	ReasonPurposeMismatch        Reason = "PURPOSE_MISMATCH"         // 目的不匹配
	ReasonClearanceInsufficient  Reason = "CLEARANCE_INSUFFICIENT"   // 密级不足
	ReasonDataRetentionExpired   Reason = "DATA_RETENTION_EXPIRED"   // 数据超出保留期
	ReasonPolicyRetentionExpired Reason = "POLICY_RETENTION_EXPIRED" // 策略版本超出保留期
	ReasonNoApplicablePolicy     Reason = "NO_APPLICABLE_POLICY"     // 无可用策略版本
	ReasonResourceNotFound       Reason = "RESOURCE_NOT_FOUND"       // 资源不存在
	ReasonMaskConfigInvalid      Reason = "MASK_CONFIG_INVALID"      // 脱敏配置非法或缺失
	ReasonRuleDenied             Reason = "RULE_DENIED"              // 命中策略规则显式拒绝
	ReasonInternalError          Reason = "INTERNAL_ERROR"           // 内部错误（细节不透出）
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
type Rule struct {
	Resources    []string
	Purposes     []string
	MinClearance int
	Effect       RuleEffect
	FieldRules   []FieldRule
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
