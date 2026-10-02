// Package audit 实现审计留痕与历史结论复现。
//
// 留痕红线：审计记录中绝不出现记录字段的原始值。对于脱敏/令牌化访问，
// 只记录被变换的字段名与变换方式；数据保留期等元数据以快照形式保存，
// 以便在数据或策略事后变化时仍能按当时条件复现结论。
package audit

import (
	"sync"
	"time"

	"github.com/lisama569/data-access-gateway-go/internal/model"
)

// SubjectSnapshot 判定时主体与授权的快照。
type SubjectSnapshot struct {
	Subject model.Subject
	Grant   *model.Grant
}

// Entry 一条审计记录（不含任何字段原文）。
type Entry struct {
	ID            int64
	Time          time.Time
	SubjectID     string
	Resource      string
	Purpose       string
	PinnedVersion string
	Decision      model.Decision
	Reason        model.Reason
	PolicyVersion string
	Basis         model.DecisionBasis
	MaskedFields  []string // 仅字段名
	// 复现所需快照。
	Policy            model.Policy
	Subject           SubjectSnapshot
	RecordExpiresAt   time.Time            // 数据保留期快照
	RecordSensitivity model.Sensitivity    // 数据分级快照（重新分级后历史仍按当时分级复现）
	DataExisted       bool                 // 请求时记录是否存在
}

// Log 并发安全的内存审计日志。
type Log struct {
	mu      sync.RWMutex
	nextID  int64
	entries map[int64]Entry
	order   []int64
}

// NewLog 创建审计日志。
func NewLog() *Log {
	return &Log{nextID: 1, entries: make(map[int64]Entry)}
}

// cloneEntry 返回审计记录的深拷贝，避免外部修改共享状态造成并发污染。
func cloneEntry(e Entry) Entry {
	if e.MaskedFields != nil {
		mf := make([]string, len(e.MaskedFields))
		copy(mf, e.MaskedFields)
		e.MaskedFields = mf
	}
	if e.Basis.Factors != nil {
		fs := make([]string, len(e.Basis.Factors))
		copy(fs, e.Basis.Factors)
		e.Basis.Factors = fs
	}
	if e.Subject.Subject.Groups != nil {
		g := make([]string, len(e.Subject.Subject.Groups))
		copy(g, e.Subject.Subject.Groups)
		e.Subject.Subject.Groups = g
	}
	if e.Subject.Grant != nil {
		g := *e.Subject.Grant
		if g.Purposes != nil {
			p := make([]string, len(g.Purposes))
			copy(p, g.Purposes)
			g.Purposes = p
		}
		if g.MaxSensitivity != nil {
			cap := *g.MaxSensitivity
			g.MaxSensitivity = &cap
		}
		e.Subject.Grant = &g
	}
	pol := e.Policy
	if len(pol.Rules) > 0 {
		rules := make([]model.Rule, len(pol.Rules))
		copy(rules, pol.Rules)
		for i := range rules {
			if rules[i].MinSensitivity != nil {
				lo := *rules[i].MinSensitivity
				rules[i].MinSensitivity = &lo
			}
			if rules[i].MaxSensitivity != nil {
				hi := *rules[i].MaxSensitivity
				rules[i].MaxSensitivity = &hi
			}
		}
		pol.Rules = rules
	}
	e.Policy = pol
	return e
}

// Append 追加一条审计记录，返回记录 ID。ID 全局单调递增。
func (l *Log) Append(e Entry) (int64, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	e.ID = l.nextID
	l.nextID++
	if e.Time.IsZero() {
		e.Time = time.Now()
	}
	l.entries[e.ID] = cloneEntry(e)
	l.order = append(l.order, e.ID)
	return e.ID, nil
}

// Get 按 ID 读取审计记录（返回拷贝）。
func (l *Log) Get(id int64) (Entry, bool) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	e, ok := l.entries[id]
	if !ok {
		return Entry{}, false
	}
	return cloneEntry(e), true
}

// List 返回全部审计记录（按 ID 顺序），均为拷贝。
func (l *Log) List() []Entry {
	l.mu.RLock()
	defer l.mu.RUnlock()
	out := make([]Entry, 0, len(l.order))
	for _, id := range l.order {
		out = append(out, cloneEntry(l.entries[id]))
	}
	return out
}
