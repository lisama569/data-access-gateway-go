// Package gateway is the enforcement facade: it resolves the live subject and
// resource, asks the PDP for a decision, applies field masking/tokenization
// when required, records an audit entry, and returns a stable external
// result. Internal failures never leak: they map to a generic
// internal_error denial while the cause stays in the decision basis.
package gateway

import (
	"errors"
	"fmt"
	"time"

	"github.com/lisama569/data-access-gateway-go/internal/audit"
	"github.com/lisama569/data-access-gateway-go/internal/dataset"
	"github.com/lisama569/data-access-gateway-go/internal/masking"
	"github.com/lisama569/data-access-gateway-go/internal/model"
	"github.com/lisama569/data-access-gateway-go/internal/pdp"
)

// Gateway ties the data source, PDP, masking registry and audit log together.
type Gateway struct {
	data *dataset.Provider
	eng  *pdp.Engine
	reg  *masking.Registry
	log  *audit.Log
	now  func() time.Time
}

// New builds a Gateway.
func New(data *dataset.Provider, eng *pdp.Engine, reg *masking.Registry, log *audit.Log) *Gateway {
	return &Gateway{data: data, eng: eng, reg: reg, log: log, now: func() time.Time { return time.Now().UTC() }}
}

// Access performs one end-to-end enforcement cycle. Concurrent calls never
// share mutable request state: each call copies the subject and record.
func (g *Gateway) Access(req model.AccessRequest) (result model.AccessResult) {
	if req.At.IsZero() {
		req.At = g.now()
	}
	entry := audit.Entry{
		Time:       req.At,
		ResourceID: req.ResourceID,
		Purpose:    req.Purpose,
	}

	// finish records the evaluation (but never raw protected values) and
	// returns the externally visible result.
	finish := func(ev model.Evaluation) model.AccessResult {
		entry.Evaluation = cloneEvaluation(ev)
		entry.ID = g.log.Append(entry)
		return model.AccessResult{
			Evaluation:   ev,
			Data:         nil,
			MaskedFields: nil,
			AuditID:      entry.ID,
		}
	}

	// Resolve the live subject so revocation applies on this very request.
	sub, ok := g.data.GetSubject(req.Subject.ID)
	if !ok {
		entry.SubjectID = req.Subject.ID
		ev := model.Evaluation{Decision: model.DecisionDeny, DenyReason: model.DenyNoAuthorization}
		ev.Basis = append(ev.Basis, fmt.Sprintf("subject %q is not registered", req.Subject.ID))
		return finish(ev)
	}
	req.Subject = sub
	entry.SubjectID = sub.ID
	entry.SubjectRoles = append([]string(nil), sub.Roles...)

	// Resolve the resource.
	res, ok := g.data.GetResource(req.ResourceID)
	if !ok {
		ev := model.Evaluation{Decision: model.DecisionDeny, DenyReason: model.DenyResourceNotFound}
		ev.Basis = append(ev.Basis, fmt.Sprintf("resource %q is not registered", req.ResourceID))
		return finish(ev)
	}

	// Decide.
	ev := g.eng.Evaluate(req, res)
	if ev.Decision == model.DecisionDeny {
		return finish(ev)
	}

	// Fetch the raw record. Only callers that were authorized reach this.
	record, ok := g.data.GetRecord(req.ResourceID)
	if !ok {
		return finish(internalDeny(ev, fmt.Sprintf("record for resource %q missing despite registration", req.ResourceID)))
	}

	if ev.Decision == model.DecisionAllow {
		ev.Basis = append(ev.Basis, "full unmasked data released")
		res := g.finishWithData(ev, entry, record, nil, nil)
		return res
	}

	// DecisionMask: apply the profile the matched rule named. Configuration
	// problems deny with a distinct reason instead of leaking plaintext.
	applier, err := masking.NewApplier(g.reg, ev.MaskingProfile, res.Fields)
	if err != nil {
		return finish(maskingConfigDeny(ev, err))
	}
	masked, transformed, err := applier.Apply(record)
	if err != nil {
		return finish(maskingConfigDeny(ev, err))
	}
	ev.Basis = append(ev.Basis,
		fmt.Sprintf("applied masking profile %q to %d fields: %v", ev.MaskingProfile, len(transformed), transformed))
	return g.finishWithData(ev, entry, masked, transformed, collectTokens(masked, transformed, res.Fields))
}

// finishWithData audits and returns a data-bearing result. tokenOutputs only
// contains produced tokens (never originals) and is passed separately so the
// audit entry never carries raw values.
func (g *Gateway) finishWithData(ev model.Evaluation, entry audit.Entry, data map[string]string, maskedFields, tokenOutputs []string) model.AccessResult {
	entry.Evaluation = cloneEvaluation(ev)
	entry.MaskedFields = append([]string(nil), maskedFields...)
	if len(tokenOutputs) > 0 {
		entry.TokenOutputs = make(map[string]string, len(tokenOutputs))
		for _, f := range tokenOutputs {
			entry.TokenOutputs[f] = data[f] // data[f] is the token, not the value
		}
	}
	id := g.log.Append(entry)
	return model.AccessResult{
		Evaluation:   ev,
		Data:         data,
		MaskedFields: append([]string(nil), maskedFields...),
		AuditID:      id,
	}
}

// Replay reproduces the decision stored under auditID using the recorded
// inputs and the policy version that was hit. It returns an error if the
// audit entry or policy version no longer exists.
func (g *Gateway) Replay(auditID string) (model.Evaluation, error) {
	entry, ok := g.log.Get(auditID)
	if !ok {
		return model.Evaluation{}, fmt.Errorf("gateway: audit entry %q not found", auditID)
	}
	sub, ok := g.data.GetSubject(entry.SubjectID)
	if !ok {
		return model.Evaluation{}, fmt.Errorf("gateway: subject %q no longer known", entry.SubjectID)
	}
	// Replay the policy question as it was posed then; the live revocation
	// bit must not alter historical conclusions.
	sub.Revoked = false
	res, ok := g.data.GetResource(entry.ResourceID)
	if !ok {
		return model.Evaluation{}, fmt.Errorf("gateway: resource %q no longer known", entry.ResourceID)
	}
	req := model.AccessRequest{
		Subject:       sub,
		ResourceID:    entry.ResourceID,
		Purpose:       entry.Purpose,
		At:            entry.Time,
		PolicyVersion: entry.Evaluation.PolicyVersion,
	}
	return g.eng.Replay(req, res)
}

func cloneEvaluation(ev model.Evaluation) model.Evaluation {
	ev.Basis = append([]string(nil), ev.Basis...)
	return ev
}

// collectTokens returns the names of masked fields whose transform produced a
// token. This requires re-reading the profile; keep it simple by comparing the
// output prefix. Tokens are the only outputs beginning with the token marker.
func collectTokens(masked map[string]string, transformed []string, _ []string) []string {
	var tokens []string
	for _, f := range transformed {
		if len(masked[f]) >= 4 && masked[f][:4] == "tok_" {
			tokens = append(tokens, f)
		}
	}
	return tokens
}

func internalDeny(ev model.Evaluation, cause string) model.Evaluation {
	ev.Decision = model.DecisionDeny
	ev.DenyReason = model.DenyInternalError
	ev.MatchedRule = ""
	ev.MaskingProfile = ""
	ev.Basis = append(ev.Basis, "internal error: "+cause)
	return ev
}

func maskingConfigDeny(ev model.Evaluation, err error) model.Evaluation {
	ev.Decision = model.DecisionDeny
	ev.DenyReason = model.DenyInvalidMaskingConfig
	ev.Basis = append(ev.Basis, "masking configuration rejected: "+err.Error())
	return ev
}

// ErrNoAuditEntry is returned when replay cannot find an audit entry.
var ErrNoAuditEntry = errors.New("gateway: audit entry not found")
