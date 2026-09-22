// Package pdp is the policy decision point: it evaluates access requests
// against a policy version and produces explainable, reproducible
// conclusions with stable, distinguishable deny reasons.
package pdp

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/lisama569/data-access-gateway-go/internal/model"
	"github.com/lisama569/data-access-gateway-go/internal/policy"
)

// ErrVersionRequired is returned by Replay when no policy version is pinned.
var ErrVersionRequired = errors.New("pdp: replay requires a pinned policy version")

// ErrUnknownVersion is returned by Replay when the pinned version is unknown.
var ErrUnknownVersion = errors.New("pdp: unknown policy version")

// Engine evaluates requests. It is stateless and safe for concurrent use:
// all mutable state lives in the (concurrency-safe) policy store.
type Engine struct {
	store *policy.Store
}

// NewEngine builds a PDP over the given policy store.
func NewEngine(store *policy.Store) *Engine { return &Engine{store: store} }

// Evaluate resolves the applicable policy version (or pins the requested one)
// and evaluates the request. Live revocation and retention checks run first.
func (e *Engine) Evaluate(req model.AccessRequest, res model.Resource) model.Evaluation {
	ev := model.Evaluation{Decision: model.DecisionDeny, DenyReason: model.DenyInternalError}
	ev.Basis = append(ev.Basis, describeSubject(req.Subject)...)
	ev.Basis = append(ev.Basis, describeResource(res)...)

	// Live revocation check: a revoked subject loses access immediately.
	if req.Subject.Revoked {
		return deny(ev, model.DenySubjectRevoked,
			fmt.Sprintf("subject %q authorization has been revoked", req.Subject.ID))
	}
	// Retention check against the request's evaluation time.
	if !res.RetentionUntil.IsZero() && !req.At.Before(res.RetentionUntil) {
		return deny(ev, model.DenyRetentionExpired,
			fmt.Sprintf("resource %q retention window ended at %s; request time %s is outside it",
				res.ID, res.RetentionUntil.UTC().Format("2006-01-02T15:04:05Z"),
				req.At.UTC().Format("2006-01-02T15:04:05Z")))
	}

	// Resolve the policy version.
	var pol *model.Policy
	if req.PolicyVersion != "" {
		p, ok := e.store.Get(req.PolicyVersion)
		if !ok {
			return deny(ev, model.DenyPolicyVersionExpired,
				fmt.Sprintf("requested policy version %q is not known", req.PolicyVersion))
		}
		if !p.EffectiveUntil.IsZero() && !req.At.Before(p.EffectiveUntil) {
			return deny(ev, model.DenyPolicyVersionExpired,
				fmt.Sprintf("policy version %q retired at %s; cannot authorize new access at %s",
					p.Version, p.EffectiveUntil.UTC().Format("2006-01-02T15:04:05Z"),
					req.At.UTC().Format("2006-01-02T15:04:05Z")))
		}
		pol = p
	} else {
		p, err := e.store.Active(req.At)
		if err != nil {
			return deny(ev, model.DenyPolicyVersionExpired,
				fmt.Sprintf("no policy version is effective at %s", req.At.UTC().Format("2006-01-02T15:04:05Z")))
		}
		pol = p
	}
	ev.PolicyVersion = pol.Version
	ev.Basis = append(ev.Basis, fmt.Sprintf("policy version %q selected", pol.Version))

	return evaluateRules(ev, req, res, pol)
}

// Replay reproduces a decision strictly from the pinned policy version so
// historical conclusions stay reproducible after policy updates. The live
// revocation check is intentionally skipped: replay answers "what did the
// policy say at that time", not "is the subject allowed right now".
func (e *Engine) Replay(req model.AccessRequest, res model.Resource) (model.Evaluation, error) {
	if req.PolicyVersion == "" {
		return model.Evaluation{}, ErrVersionRequired
	}
	pol, ok := e.store.Get(req.PolicyVersion)
	if !ok {
		return model.Evaluation{}, ErrUnknownVersion
	}
	ev := model.Evaluation{Decision: model.DecisionDeny, DenyReason: model.DenyInternalError}
	ev.Basis = append(ev.Basis, describeSubject(req.Subject)...)
	ev.Basis = append(ev.Basis, describeResource(res)...)
	if !res.RetentionUntil.IsZero() && !req.At.Before(res.RetentionUntil) {
		return deny(ev, model.DenyRetentionExpired,
			fmt.Sprintf("resource %q retention window ended at %s", res.ID,
				res.RetentionUntil.UTC().Format("2006-01-02T15:04:05Z"))), nil
	}
	ev.PolicyVersion = pol.Version
	ev.Basis = append(ev.Basis, fmt.Sprintf("policy version %q pinned for replay", pol.Version))
	return evaluateRules(ev, req, res, pol), nil
}

// evaluateRules runs the ordered rule list; the first fully matching rule
// decides. Deny reasons distinguish "attributes matched but purpose did not"
// from "no rule authorized this subject at all".
func evaluateRules(ev model.Evaluation, req model.AccessRequest, res model.Resource, pol *model.Policy) model.Evaluation {
	purposeOnlyMiss := false
	for _, rule := range pol.Rules {
		roleOK := matchAny(rule.Roles, req.Subject.Roles)
		deptOK := matchAny(rule.Departments, req.Subject.Departments)
		sensOK := matchSensitivity(rule.Sensitivities, res.Sensitivity)
		purpOK := matchPurpose(rule.Purposes, req.Purpose)

		switch {
		case roleOK && deptOK && sensOK && purpOK:
			ev.MatchedRule = rule.Name
			ev.Basis = append(ev.Basis, fmt.Sprintf(
				"rule %q matched (roles=%v departments=%v sensitivity=%s purpose=%q)",
				rule.Name, rule.Roles, rule.Departments, res.Sensitivity, req.Purpose))
			switch {
			case !rule.Allow:
				return deny(ev, model.DenyNoAuthorization,
					fmt.Sprintf("rule %q explicitly denies access", rule.Name))
			case rule.RequireMask:
				ev.Decision = model.DecisionMask
				ev.DenyReason = model.DenyNone
				ev.MaskingProfile = rule.MaskingProfile
				ev.Basis = append(ev.Basis,
					fmt.Sprintf("rule %q allows access with masking profile %q", rule.Name, rule.MaskingProfile))
				return ev
			default:
				ev.Decision = model.DecisionAllow
				ev.DenyReason = model.DenyNone
				ev.Basis = append(ev.Basis, fmt.Sprintf("rule %q allows access", rule.Name))
				return ev
			}
		case roleOK && deptOK && sensOK && !purpOK:
			purposeOnlyMiss = true
			ev.Basis = append(ev.Basis, fmt.Sprintf(
				"rule %q matched attributes but rejected purpose %q (allowed: %v)",
				rule.Name, req.Purpose, rule.Purposes))
		default:
			ev.Basis = append(ev.Basis, fmt.Sprintf("rule %q did not match subject/resource attributes", rule.Name))
		}
	}
	if purposeOnlyMiss {
		return deny(ev, model.DenyPurposeMismatch,
			fmt.Sprintf("purpose %q is not permitted for this subject and resource", req.Purpose))
	}
	return deny(ev, model.DenyNoAuthorization,
		fmt.Sprintf("no rule in policy version %q authorizes subject %q for resource %q",
			pol.Version, req.Subject.ID, res.ID))
}

func deny(ev model.Evaluation, reason model.DenyReason, basis string) model.Evaluation {
	ev.Decision = model.DecisionDeny
	ev.DenyReason = reason
	ev.Basis = append(ev.Basis, "deny: "+basis)
	return ev
}

func matchAny(allowed, have []string) bool {
	if len(allowed) == 0 {
		return true
	}
	for _, h := range have {
		for _, a := range allowed {
			if h == a {
				return true
			}
		}
	}
	return false
}

func matchSensitivity(allowed []model.Sensitivity, have model.Sensitivity) bool {
	if len(allowed) == 0 {
		return true
	}
	for _, a := range allowed {
		if a == have {
			return true
		}
	}
	return false
}

func matchPurpose(allowed []string, purpose string) bool {
	if len(allowed) == 0 {
		return true
	}
	for _, a := range allowed {
		if a == purpose {
			return true
		}
	}
	return false
}

func describeSubject(s model.Subject) []string {
	roles := append([]string(nil), s.Roles...)
	depts := append([]string(nil), s.Departments...)
	sort.Strings(roles)
	sort.Strings(depts)
	return []string{
		fmt.Sprintf("subject %q roles=[%s] departments=[%s] revoked=%t",
			s.ID, strings.Join(roles, ","), strings.Join(depts, ","), s.Revoked),
	}
}

func describeResource(r model.Resource) []string {
	retention := "none"
	if !r.RetentionUntil.IsZero() {
		retention = r.RetentionUntil.UTC().Format("2006-01-02T15:04:05Z")
	}
	return []string{
		fmt.Sprintf("resource %q sensitivity=%s retention_until=%s", r.ID, r.Sensitivity, retention),
	}
}
