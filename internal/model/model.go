// Package model defines the shared domain types for the local data-access
// policy enforcement, masking and audit gateway.
package model

import "time"

// Sensitivity classifies how sensitive a protected resource field is.
type Sensitivity string

const (
	SensitivityPublic     Sensitivity = "public"
	SensitivityInternal   Sensitivity = "internal"
	SensitivityConfident  Sensitivity = "confidential"
	SensitivityRestricted Sensitivity = "restricted"
)

// Decision is the externally visible conclusion of an access evaluation.
type Decision string

const (
	DecisionAllow Decision = "allow"
	DecisionMask  Decision = "mask"
	DecisionDeny  Decision = "deny"
)

// DenyReason is a stable, distinguishable machine-readable reason for a deny.
// Internal errors are never surfaced directly: they map to DenyInternalError.
type DenyReason string

const (
	DenyNone                 DenyReason = ""
	DenyNoAuthorization      DenyReason = "no_authorization"
	DenyPurposeMismatch      DenyReason = "purpose_mismatch"
	DenyRetentionExpired     DenyReason = "retention_expired"
	DenyPolicyVersionExpired DenyReason = "policy_version_expired"
	DenyInvalidMaskingConfig DenyReason = "invalid_masking_config"
	DenySubjectRevoked       DenyReason = "subject_revoked"
	DenyResourceNotFound     DenyReason = "resource_not_found"
	DenyInternalError        DenyReason = "internal_error"
)

// Subject describes the requesting principal's attributes.
type Subject struct {
	ID          string
	Roles       []string
	Departments []string
	// Revoked is checked live on every request; a revoked subject loses
	// access immediately.
	Revoked bool
}

// Resource describes the protected object and its attributes.
type Resource struct {
	ID          string
	Owner       string
	Sensitivity Sensitivity
	Fields      []string
	// RetentionUntil is the end of the legal retention window. The zero
	// value means the data does not expire.
	RetentionUntil time.Time
}

// AccessRequest is a single access evaluation input.
type AccessRequest struct {
	Subject    Subject
	ResourceID string
	Purpose    string
	// At fixes the evaluation time so tests are fully reproducible.
	At time.Time
	// PolicyVersion, when non-empty, pins evaluation to a specific policy
	// version (used for historical replay).
	PolicyVersion string
}

// FieldTransform names a masking transform kind.
type FieldTransform string

const (
	TransformRedact   FieldTransform = "redact"
	TransformMask     FieldTransform = "mask"
	TransformTokenize FieldTransform = "tokenize"
)

// FieldRule maps a field name to the transform applied to it.
type FieldRule struct {
	Field     string
	Transform FieldTransform
	// KeepPrefix/KeepSuffix drive the irreversible mask transform.
	KeepPrefix int
	KeepSuffix int
	// TokenDomain scopes reversible tokenization. Tokens are stable and
	// reversible only within the same domain and never across domains.
	TokenDomain string
}

// MaskingProfile is a named, validated field-level masking configuration.
type MaskingProfile struct {
	Name  string
	Rules []FieldRule
}

// Rule is one policy rule. Rules are evaluated in order; the first match wins.
type Rule struct {
	Name           string
	Allow          bool
	RequireMask    bool
	MaskingProfile string
	// Matchers
	Roles         []string      // subject must have at least one (empty = any)
	Departments   []string      // subject must have at least one (empty = any)
	Sensitivities []Sensitivity // resource sensitivity must be one (empty = any)
	Purposes      []string      // request purpose must be one (empty = any)
}

// Policy is an immutable, versioned set of rules.
type Policy struct {
	Version string
	Rules   []Rule
	// EffectiveFrom/EffectiveUntil bound the policy's active window.
	// EffectiveUntil zero means still active.
	EffectiveFrom  time.Time
	EffectiveUntil time.Time
}

// Evaluation captures why a decision was reached, for explainability.
type Evaluation struct {
	Decision       Decision
	DenyReason     DenyReason
	PolicyVersion  string
	MatchedRule    string
	MaskingProfile string
	Basis          []string
}

// AccessResult is the full outcome of a gateway access call.
type AccessResult struct {
	Evaluation Evaluation
	// Data holds the returned fields (masked when Decision == mask).
	// It is never populated on deny.
	Data         map[string]string
	MaskedFields []string
	AuditID      string
}
