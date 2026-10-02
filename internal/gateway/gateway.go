// Package gateway 组合 PDP、脱敏服务、数据集与审计日志，提供完整访问入口。
//
// 关键不变量：
//   - 每次访问实时读取授权状态，授权撤销在当次请求立即生效；
//   - 每次访问实时选择策略版本，审计中保存命中版本与输入快照，可按当时版本复现；
//   - 审计内容不包含字段原文；内部错误统一映射为 INTERNAL_ERROR，细节不透出；
//   - 所有共享状态通过锁或深拷贝隔离，并发判定互不污染。
package gateway

import (
	"fmt"
	"time"

	"github.com/lisama569/data-access-gateway-go/internal/audit"
	"github.com/lisama569/data-access-gateway-go/internal/dataset"
	"github.com/lisama569/data-access-gateway-go/internal/masking"
	"github.com/lisama569/data-access-gateway-go/internal/model"
	"github.com/lisama569/data-access-gateway-go/internal/pdp"
	"github.com/lisama569/data-access-gateway-go/internal/policy"
)

// Clock 可注入时钟。
type Clock = func() time.Time

// Gateway 数据访问网关。
type Gateway struct {
	store *policy.Store
	data  *dataset.DataSet
	mask  *masking.Service
	log   *audit.Log
	pdp   *pdp.Engine
	clock Clock
}

// New 组装网关。
func New(store *policy.Store, data *dataset.DataSet, mask *masking.Service, log *audit.Log, clock Clock) *Gateway {
	if clock == nil {
		clock = time.Now
	}
	return &Gateway{
		store: store,
		data:  data,
		mask:  mask,
		log:   log,
		pdp:   pdp.NewEngine(store, clock),
		clock: clock,
	}
}

func denyResult(req model.AccessRequest, reason model.Reason, version string, basis model.DecisionBasis) model.AccessResult {
	at := req.RequestedAt
	return model.AccessResult{
		Decision:      model.DecisionDeny,
		Reason:        reason,
		PolicyVersion: version,
		Basis:         basis,
		RequestedAt:   at,
	}
}

// Access 执行一次完整访问：实时读取授权/数据 -> PDP 判定 -> 脱敏/取数 -> 审计。
func (g *Gateway) Access(req model.AccessRequest) (result model.AccessResult, entryID int64) {
	at := req.RequestedAt
	if at.IsZero() {
		at = g.clock()
		req.RequestedAt = at
	}

	// 实时读取授权：不使用调用方可能持有的旧快照，保证撤销立即生效。
	req.Grant = g.data.FindGrant(req.Subject.ID, req.Resource)

	// 实时读取数据（深拷贝，后续变换不影响共享数据集）。
	rec, ok := g.data.GetRecord(req.Resource)

	// 判定输入快照（主体+授权）与命中策略快照随审计保存，供历史复现；
	// 快照中不包含任何字段原文。
	var policySnap model.Policy
	subjectSnap := audit.SubjectSnapshot{Subject: req.Subject, Grant: req.Grant}
	if subjectSnap.Subject.Groups != nil {
		groups := make([]string, len(req.Subject.Groups))
		copy(groups, req.Subject.Groups)
		subjectSnap.Subject.Groups = groups
	}

	defer func() {
		// 兜底：任何意外 panic 映射为稳定内部错误，细节不透出。
		if r := recover(); r != nil {
			result = denyResult(req, model.ReasonInternalError, "", model.DecisionBasis{
				Factors: []string{"internal:panic_recovered"},
			})
		}
		subjectSnap.Grant = req.Grant
		expires := time.Time{}
		sensitivity := model.Sensitivity(0)
		if ok {
			expires = rec.ExpiresAt
			sensitivity = rec.Sensitivity // 数据分级快照：重新分级后历史仍按此复现
		}
		id, err := g.log.Append(audit.Entry{
			Time:              at,
			SubjectID:         req.Subject.ID,
			Resource:          req.Resource,
			Purpose:           req.Purpose,
			PinnedVersion:     req.PinnedVersion,
			Decision:          result.Decision,
			Reason:            result.Reason,
			PolicyVersion:     result.PolicyVersion,
			Basis:             result.Basis,
			MaskedFields:      result.MaskedFields,
			DataExisted:       ok,
			RecordExpiresAt:   expires,
			RecordSensitivity: sensitivity,
			Policy:            policySnap,
			Subject:           subjectSnap,
		})
		if err != nil {
			// 审计失败不应把底层错误泄露给调用方。
			result = denyResult(req, model.ReasonInternalError, result.PolicyVersion, result.Basis)
			return
		}
		entryID = id
	}()

	if !ok {
		result = denyResult(req, model.ReasonResourceNotFound, "", model.DecisionBasis{
			Factors: []string{"resource:not_found"},
		})
		return
	}

	decision, reason, pol, basis := g.pdp.Verdict(req, &rec)
	policySnap = pol
	switch decision {
	case model.DecisionDeny:
		result = denyResult(req, reason, pol.Version, basis)
		return
	case model.DecisionAllow:
		result = model.AccessResult{
			Decision:      model.DecisionAllow,
			PolicyVersion: pol.Version,
			Basis:         basis,
			Record:        &rec,
			RequestedAt:   at,
		}
		return
	case model.DecisionMask:
		rule := pol.Rules[basis.RuleIndex]
		out, changed, err := g.mask.Apply(&rec, rule.FieldRules)
		if err != nil {
			// 非法/缺失脱敏配置：明确拒绝，绝不静默降级为明文允许。
			basis.Factors = append(basis.Factors, "mask:config_invalid")
			result = denyResult(req, model.ReasonMaskConfigInvalid, pol.Version, basis)
			return
		}
		result = model.AccessResult{
			Decision:      model.DecisionMask,
			PolicyVersion: pol.Version,
			Basis:         basis,
			Record:        out,
			MaskedFields:  changed,
			RequestedAt:   at,
		}
		return
	default:
		result = denyResult(req, model.ReasonInternalError, pol.Version, basis)
		return
	}
}

// snapshotPolicyReader 用审计中保存的策略快照构建一次性 PDP，实现按当时版本复现。
type snapshotPolicyReader struct{ pol model.Policy }

func (r snapshotPolicyReader) Active(at time.Time) (model.Policy, error) {
	return r.pol, nil
}

func (r snapshotPolicyReader) Version(version string) (model.Policy, bool) {
	if r.pol.Version == version {
		return r.pol, true
	}
	return model.Policy{}, false
}

// Replay 依据审计记录按当时策略版本与输入快照复现结论。
// 复现只返回判定结论与原因，不返回任何数据内容；与原结论不一致时视为内部错误。
func (g *Gateway) Replay(entryID int64) (model.AccessResult, error) {
	e, ok := g.log.Get(entryID)
	if !ok {
		return model.AccessResult{}, fmt.Errorf("audit entry %d not found", entryID)
	}

	req := model.AccessRequest{
		Subject:       e.Subject.Subject,
		Grant:         e.Subject.Grant,
		Resource:      e.Resource,
		Purpose:       e.Purpose,
		PinnedVersion: e.Policy.Version,
		RequestedAt:   e.Time,
	}
	// 复现时强制走归档版本：即使该版本已退役也必须能还原历史结论。
	eng := pdp.NewEngine(snapshotPolicyReader{pol: e.Policy}, func() time.Time { return e.Time })

	var recPtr *model.Record
	if e.DataExisted {
		// 只有保留期与数据分级参与判定，字段内容不需要、也不应进入复现路径。
		rec := model.Record{
			Resource:    e.Resource,
			ExpiresAt:   e.RecordExpiresAt,
			Sensitivity: e.RecordSensitivity, // 按当时分级快照复现，不受后续重分级影响
		}
		recPtr = &rec
	}

	decision, reason, pol, basis := eng.Verdict(req, recPtr)
	res := model.AccessResult{
		Decision:      decision,
		Reason:        reason,
		PolicyVersion: pol.Version,
		Basis:         basis,
		RequestedAt:   e.Time,
	}
	if decision != e.Decision || reason != e.Reason || pol.Version != e.PolicyVersion {
		return model.AccessResult{}, fmt.Errorf("replay mismatch for entry %d", entryID)
	}
	return res, nil
}
